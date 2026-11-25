"""Collection engine.

Design
------
Every organization gets its own runtime (source adapter + shared rate limiter)
and two independent lanes:

``full``
    A rebuild: open a catalog snapshot, page through it, fetch every detail
    into a staging area, catch up on the change feed from the snapshot's
    continuation position, and finally swap the whole published catalog in one
    transaction.

``incremental``
    Reads the change feed from the published watermark, resolves details and
    publishes each window atomically.  It keeps serving while a rebuild runs.

Because the published watermark is monotonically increasing, neither lane can
regress the catalog, resurrect a revoked certificate, or partially apply a
formal correction.  Rate limits, request spacing and ``Retry-After`` are shared
by both lanes of an organization, but each organization has its own runtime, so
one body waiting never blocks another.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from .source import ChangePage, Detail, build_adapter
from .store import Store
from .util import (
    ChannelExpired,
    Conflict,
    NotFound,
    RateLimited,
    SourceUnavailable,
    UpstreamError,
    dumps,
    iso,
    utcnow,
)

log = logging.getLogger("certcollector.engine")

FULL = "full"
INCREMENTAL = "incremental"


class RunAborted(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class ScanExpired(Exception):
    pass


class RebuildContended(Exception):
    pass


class StaleEpoch(Exception):
    """A run/scan belongs to a source epoch that has already been replaced."""

    def __init__(self, run_epoch: int, active_epoch: int):
        super().__init__(f"stale source epoch {run_epoch} (active {active_epoch})")
        self.run_epoch = run_epoch
        self.active_epoch = active_epoch


class IncompleteCorrection(Exception):
    def __init__(self, correction_id: str, details: dict[str, Any]):
        super().__init__(f"correction {correction_id} is incomplete")
        self.correction_id = correction_id
        self.details = details


@dataclass
class WaitState:
    reason: str
    until: float
    detail: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "reason": self.reason,
            "until": iso(datetime_from(self.until)),
            "detail": self.detail,
        }


def datetime_from(ts: float):
    import datetime as dt

    return dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc)


def _entry_from_detail(detail: Detail) -> dict[str, Any]:
    correction = None
    if detail.correction_id:
        correction = {
            "id": detail.correction_id,
            "members": sorted(set(detail.correction_members)),
            "supersedes": sorted(set(detail.correction_supersedes)),
        }
    return {
        "cert_no": detail.cert_no,
        "revision": int(detail.revision),
        "status": detail.status,
        "data": dict(detail.data),
        "source_updated_at": detail.updated_at,
        "revoked_at": detail.revoked_at,
        "correction_id": detail.correction_id,
        "correction": correction,
    }


def _entry_group_key(entry: dict[str, Any]) -> str | None:
    corr = entry.get("correction") or {}
    return corr.get("id") or entry.get("correction_id")


def _group_members(entry: dict[str, Any]) -> set[str]:
    corr = entry.get("correction") or {}
    members = set(corr.get("members") or [])
    members.update(corr.get("supersedes") or [])
    if entry.get("cert_no"):
        members.add(entry["cert_no"])
    return members


class OrgRuntime:
    """Per-organization state: adapter, pacing, wait reporting, statistics."""

    def __init__(self, engine: "Engine", org_id: str):
        self.engine = engine
        self.org_id = org_id
        self._lock = threading.RLock()
        self._adapter = None
        self._adapters: dict[str, Any] = {}
        self._source_key: str | None = None
        self._wait: WaitState | None = None
        self._cooldown_until = 0.0
        self._next_allowed = 0.0
        self._adaptive_interval = 0.0
        self._last_request_mono = 0.0
        self._active = 0
        self._paused_cache: tuple[float, dict[str, Any]] | None = None
        self.stats = {
            "requests": 0,
            "rate_limit_hits": 0,
            "temporary_failures": 0,
            "last_retry_after": None,
            "last_error": None,
            "last_request_at": None,
        }
        self.threads: dict[str, threading.Thread] = {}

    # -- org flags -------------------------------------------------------
    def org(self, force: bool = False) -> dict[str, Any]:
        now = time.time()
        with self._lock:
            cached = self._paused_cache
            if not force and cached and now - cached[0] < 0.25:
                return cached[1]
        org = self.engine.store.get_org(self.org_id)
        with self._lock:
            self._paused_cache = (now, org)
        return org

    def adapter(self, org: dict[str, Any]):
        key = dumps(
            {"source": org["source"], "page_size": (org.get("options") or {}).get("page_size")}
        )
        with self._lock:
            if self._adapter is None or self._source_key != key:
                source_config = {
                    **org["source"],
                    "page_size": (org.get("options") or {}).get("page_size", 10),
                }
                self._adapter = self.engine.build_adapter(source_config)
                self._source_key = key
            return self._adapter

    def adapter_for(self, source: dict[str, Any], options: dict[str, Any] | None = None):
        """Build (and cache) an adapter for an explicit source configuration.

        Switch runs talk to the *target* source while the organization row still
        points at the active source, so their adapter cannot come from
        :meth:`adapter`.
        """
        options = options or {}
        key = dumps({"source": source, "page_size": options.get("page_size")})
        with self._lock:
            cached = self._adapters.get(key)
            if cached is None:
                source_config = {**source, "page_size": options.get("page_size", 10)}
                cached = self.engine.build_adapter(source_config)
                self._adapters[key] = cached
            return cached

    def invalidate(self) -> None:
        with self._lock:
            self._adapter = None
            self._source_key = None
            self._adapters.clear()

    # -- wait reporting --------------------------------------------------
    def set_wait(self, reason: str | None, seconds: float = 0.0, detail: dict[str, Any] | None = None):
        with self._lock:
            if reason is None:
                self._wait = None
            else:
                self._wait = WaitState(reason, time.time() + max(0.0, seconds), detail or {})

    def wait_state(self) -> dict[str, Any] | None:
        with self._lock:
            return self._wait.as_dict() if self._wait else None

    # -- pacing ----------------------------------------------------------
    def _limits(self, org: dict[str, Any]) -> tuple[int, float]:
        limits = org.get("limits") or {}
        concurrency = max(1, int(limits.get("max_concurrency", 2)))
        interval = max(0.0, float(limits.get("min_interval_ms", 0)) / 1000.0)
        return concurrency, interval

    def _check_abort(self):
        if self.engine.stop_event.is_set():
            raise RunAborted("stopped")
        org = self.org()
        if not org["enabled"]:
            raise RunAborted("disabled")
        if org["paused"]:
            raise RunAborted("paused")

    def _acquire_slot(self, org: dict[str, Any]) -> None:
        concurrency, interval = self._limits(org)
        with self._lock:
            interval = max(interval, self._adaptive_interval)
        while True:
            self._check_abort()
            now = time.time()
            with self._lock:
                wait_until = max(self._next_allowed, self._cooldown_until)
                if self._active < concurrency and now >= wait_until:
                    self._active += 1
                    self._next_allowed = now + interval
                    return
                if self._active >= concurrency:
                    wait = 0.02
                    if now < wait_until:
                        self.set_wait("rate_limited", wait_until - now, {"scope": "organization"})
                    else:
                        self.set_wait("concurrency", 0.05, {"in_flight": self._active, "limit": concurrency})
                else:
                    wait = min(0.2, max(0.01, wait_until - now))
                    self.set_wait("pacing", wait, {"min_interval_ms": int(interval * 1000)})
            self.engine.stop_event.wait(wait)

    def _release_slot(self):
        with self._lock:
            if self._active > 0:
                self._active -= 1

    def _sleep(self, seconds: float):
        if seconds > 0:
            self.engine.stop_event.wait(min(seconds, 60.0))
        self._check_abort()

    def note_retry_after(self, seconds: float):
        """Honour Retry-After and learn the upstream's required spacing.

        ``Retry-After`` tells us how long to wait *from now*; combined with the
        time that has elapsed since the rejected request it yields a direct
        estimate of the minimum spacing the body enforces, which converges in
        one step instead of doubling blindly.
        """
        now = time.time()
        with self._lock:
            elapsed = max(0.0, time.monotonic() - self._last_request_mono)
            required = float(seconds or 0.0)
            estimate = min(5.0, elapsed + required + 0.01)
            self._adaptive_interval = max(self._adaptive_interval, estimate, 0.01)
            self._cooldown_until = max(self._cooldown_until, now + max(required, 0.01))
            self._next_allowed = max(self._next_allowed, self._cooldown_until)

    def note_success(self):
        with self._lock:
            if self._adaptive_interval:
                # decay slowly and keep a floor so we do not oscillate right
                # back into the limit
                self._adaptive_interval = max(0.005, self._adaptive_interval * 0.9 - 0.005)

    def call(self, fn: Callable, *args, adapter: Any = None, **kwargs):
        """Invoke a source operation honouring pacing, retries and Retry-After."""
        org = self.org()
        adapter = adapter or self.adapter(org)
        attempts = int((org.get("options") or {}).get("request_attempts", 4))
        last: Exception | None = None
        for attempt in range(attempts):
            self._acquire_slot(org)
            try:
                with self._lock:
                    self.stats["requests"] += 1
                    self.stats["last_request_at"] = iso(utcnow())
                    self._last_request_mono = time.monotonic()
                result = fn(adapter, *args, **kwargs)
                self.set_wait(None)
                self.note_success()
                return result
            except RateLimited as exc:
                retry = float((exc.details or {}).get("retry_after") or 1)
                with self._lock:
                    self.stats["rate_limit_hits"] += 1
                    self.stats["last_retry_after"] = retry
                self.note_retry_after(retry)
                self.set_wait("rate_limited", retry, {"retry_after": retry, "attempt": attempt + 1})
                last = exc
                self._sleep(retry)
            except SourceUnavailable as exc:
                delay = min(1.0, 0.05 * (2**attempt))
                with self._lock:
                    self.stats["temporary_failures"] += 1
                    self.stats["last_error"] = {"code": "source_unavailable", "message": str(exc)}
                self.set_wait("source_unavailable", delay, {"attempt": attempt + 1, "message": str(exc)})
                last = exc
                self._sleep(delay)
            finally:
                self._release_slot()
        raise last if last else SourceUnavailable("source request failed")


class Engine:
    def __init__(
        self,
        store: Store,
        transport_factory: Callable[[dict[str, Any]], Any] | None = None,
        *,
        poll_interval_ms: int = 1000,
        cleanup_interval: float = 5.0,
        full_retry_delay: float = 0.2,
    ):
        self.store = store
        self.transport_factory = transport_factory
        self.default_poll_ms = poll_interval_ms
        self.cleanup_interval = cleanup_interval
        self.full_retry_delay = full_retry_delay
        self.stop_event = threading.Event()
        self._runtimes: dict[str, OrgRuntime] = {}
        self._lock = threading.Lock()
        self._supervisor: threading.Thread | None = None
        self._cleanup_thread: threading.Thread | None = None
        self._started = False
        self._last_auto: dict[str, float] = {}
        self._full_backoff: dict[str, float] = {}
        self._held_corrections: dict[str, dict[str, dict[str, Any]]] = {}
        self.started_at = iso(utcnow())

    # ------------------------------------------------------------------
    # lifecycle
    def start(self) -> None:
        if self._started:
            return
        self._started = True
        self.stop_event.clear()
        self.store.recover_runs()
        self.store.mark_interrupted_scans()
        self._supervisor = threading.Thread(target=self._supervise, name="cc-supervisor", daemon=True)
        self._supervisor.start()
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, name="cc-cleanup", daemon=True)
        self._cleanup_thread.start()

    def stop(self, timeout: float = 1.0) -> None:
        self.stop_event.set()
        deadline = time.time() + timeout
        for thread in list(self._threads_snapshot()):
            thread.join(max(0.0, deadline - time.time()))
        if self._supervisor:
            self._supervisor.join(max(0.0, deadline - time.time()))
        if self._cleanup_thread:
            self._cleanup_thread.join(max(0.0, deadline - time.time()))
        self._started = False
        with self._lock:
            self._runtimes.clear()

    def _threads_snapshot(self):
        with self._lock:
            for rt in self._runtimes.values():
                for t in rt.threads.values():
                    yield t

    def build_adapter(self, config: dict[str, Any]):
        transport = self.transport_factory(config) if self.transport_factory else None
        return build_adapter(config, transport)

    # ------------------------------------------------------------------
    # runtime / lanes
    def runtime(self, org_id: str) -> OrgRuntime:
        with self._lock:
            rt = self._runtimes.get(org_id)
            if rt is None:
                rt = OrgRuntime(self, org_id)
                self._runtimes[org_id] = rt
            return rt

    def _ensure_lanes(self, org_id: str) -> None:
        rt = self.runtime(org_id)
        with self._lock:
            for kind, target in ((FULL, self._full_lane), (INCREMENTAL, self._incremental_lane)):
                thread = rt.threads.get(kind)
                if thread is None or not thread.is_alive():
                    t = threading.Thread(
                        target=target,
                        args=(org_id,),
                        name=f"cc-{org_id}-{kind}",
                        daemon=True,
                    )
                    rt.threads[kind] = t
                    t.start()

    def _supervise(self) -> None:
        while not self.stop_event.is_set():
            try:
                orgs = self.store.list_orgs()
                for org in orgs:
                    org_id = org["org_id"]
                    self._ensure_lanes(org_id)
                    self._recover_pending_switch(org_id)
                    if org["enabled"] and not org["paused"]:
                        self._maybe_schedule(org)
            except Exception:  # pragma: no cover - defensive
                log.exception("supervisor iteration failed")
            self.stop_event.wait(0.2)

    def _recover_pending_switch(self, org_id: str) -> None:
        """Ensure every pending switch still has a run that will complete it."""
        switch = self.store.get_pending_switch(org_id)
        if switch is None:
            return
        if self.store.has_active_switch_run(org_id, switch["switch_id"]):
            return
        run, _ = self.store.create_run(
            org_id,
            FULL,
            "switch_retry",
            coalesce_incremental=False,
            source_epoch=switch["to_epoch"],
            switch_id=switch["switch_id"],
        )
        self.store.update_switch(switch["switch_id"], run_id=run["run_id"])
        self.store.supersede_runs_for_epoch(org_id, switch["to_epoch"], keep_run_id=run["run_id"])
        self.runtime(org_id).invalidate()

    def _maybe_schedule(self, org: dict[str, Any]) -> None:
        org_id = org["org_id"]
        state = self.store.get_state(org_id)
        options = org.get("options") or {}
        poll_ms = int(options.get("poll_interval_ms", self.default_poll_ms))
        now = time.time()
        # auto retry a rebuild when the catalog is not ready yet
        if not state["ready"]:
            if self.store.has_active_run(org_id, (FULL,)):
                return
            last = self._full_backoff.get(org_id, 0.0)
            if now - last < self.full_retry_delay:
                return
            recent = self.store.list_runs(org_id, limit=5)
            failed_full = [
                r
                for r in recent
                if r["kind"] == FULL and r["status"] == "failed"
            ]
            if failed_full:
                self._full_backoff[org_id] = now
                if self.store.get_pending_switch(org_id) is not None:
                    self._recover_pending_switch(org_id)
                else:
                    self.store.create_run(org_id, FULL, "auto_retry", coalesce_incremental=False)
            return
        # A pending cutover does not stop the *active* source's incremental
        # channel: those runs bind to the current epoch and keep the published
        # catalog fresh until the switch transaction replaces it.  The switch
        # run itself is a full run and is recovered separately above.
        has_incremental = self.store.has_active_run(org_id, (INCREMENTAL,))
        last_auto = self._last_auto.get(org_id)
        if not has_incremental and (last_auto is None or (now - last_auto) * 1000.0 >= poll_ms):
            self._last_auto[org_id] = now
            self.store.create_run(org_id, INCREMENTAL, "schedule")
            self._drain_incremental(org_id)
        elif has_incremental:
            self._last_auto[org_id] = now

    def _drain_incremental(self, org_id: str) -> None:
        """Wake the incremental lane quickly for catch-up bursts."""
        # no-op: lanes poll every 150ms; kept for clarity/testability
        return None

    # ------------------------------------------------------------------
    # public commands
    def request_full(self, org_id: str, trigger: str = "manual", request_key: str | None = None) -> dict[str, Any]:
        org = self.store.get_org(org_id)
        if not org["enabled"]:
            raise RunAborted("disabled")
        switch = self.store.get_pending_switch(org_id)
        if switch is not None and trigger != "switch":
            # While a cutover is pending, ordinary rebuilds join the switch and
            # target the new source rather than the old one.
            run, _ = self.store.create_run(
                org_id,
                FULL,
                trigger,
                request_key=request_key,
                coalesce_incremental=False,
                source_epoch=switch["to_epoch"],
                switch_id=switch["switch_id"],
            )
            coalesced = False
        else:
            run, coalesced = self.store.create_run(
                org_id,
                FULL,
                trigger,
                request_key=request_key,
                coalesce_incremental=False,
            )
        self.runtime(org_id)
        self._ensure_lanes(org_id)
        return {**self.store.get_run(run["run_id"]), "coalesced": coalesced}

    def request_switch(self, org_id: str, source: dict[str, Any]) -> dict[str, Any]:
        """Begin an online cutover to a different upstream source.

        The active catalog and its incremental channel keep serving the old
        source until a full scan of the new source publishes atomically.
        """
        # raises NotFound for an unknown organization
        self.store.get_org(org_id)
        pending = self.store.get_pending_switch(org_id)
        if pending is not None:
            raise Conflict(
                "a source switch is already in progress",
                details={"switch_id": pending["switch_id"]},
            )
        state = self.store.get_state(org_id)
        from_epoch = int(state["active_epoch"])
        to_epoch = from_epoch + 1
        run, _ = self.store.create_run(
            org_id,
            FULL,
            "switch",
            coalesce_incremental=False,
            source_epoch=to_epoch,
        )
        switch = self.store.create_switch(
            org_id,
            source,
            from_epoch=from_epoch,
            to_epoch=to_epoch,
            run_id=run["run_id"],
        )
        self.store.execute_checked(
            "UPDATE runs SET switch_id=? WHERE run_id=?", (switch["switch_id"], run["run_id"])
        )
        # queued/paused old-source work must never start against the new source
        self.store.supersede_runs_for_epoch(org_id, to_epoch, keep_run_id=run["run_id"])
        self.runtime(org_id).invalidate()
        self._ensure_lanes(org_id)
        return self.store.get_switch(switch["switch_id"])

    def request_incremental(self, org_id: str, trigger: str = "manual", request_key: str | None = None) -> dict[str, Any]:
        state = self.store.get_state(org_id)
        run, coalesced = self.store.create_run(
            org_id, INCREMENTAL, trigger, request_key=request_key
        )
        if not state["ready"] and not coalesced:
            self.store.finish_run(
                run["run_id"],
                "failed",
                error={"code": "catalog_not_ready", "message": "a full collection must complete first"},
            )
        self.runtime(org_id)
        self._ensure_lanes(org_id)
        return {**self.store.get_run(run["run_id"]), "coalesced": coalesced}

    def pause(self, org_id: str) -> dict[str, Any]:
        org = self.store.get_org(org_id)
        self.store.set_paused(org_id, True)
        self.store.pause_active_runs(org_id)
        rt = self.runtime(org_id)
        rt._paused_cache = (time.time(), {**org, "paused": True})
        return self.store.get_org(org_id)

    def resume(self, org_id: str) -> dict[str, Any]:
        self.store.set_paused(org_id, False)
        self.store.resume_paused_runs(org_id)
        rt = self.runtime(org_id)
        rt._paused_cache = (time.time(), {**self.store.get_org(org_id), "paused": False})
        return self.store.get_org(org_id)

    # ------------------------------------------------------------------
    # lanes
    def _lane_loop(self, org_id: str, kind: str) -> None:
        while not self.stop_event.is_set():
            try:
                org = self.store.get_org(org_id)
                if not org["enabled"] or org["paused"]:
                    self.stop_event.wait(0.15)
                    continue
                run = self.store.claim_next_run(org_id, (kind,))
                if run is None:
                    self.runtime(org_id).set_wait(None)
                    self.stop_event.wait(0.12)
                    continue
                if self._run_is_stale(run):
                    self._retire_stale_run(run)
                    continue
                rt = self.runtime(org_id)
                try:
                    if kind == FULL:
                        self._run_full(rt, run)
                    else:
                        self._run_incremental(rt, run)
                except StaleEpoch:
                    self._retire_stale_run(run)
                except RunAborted as exc:
                    self._handle_abort(run, exc.reason)
                except Exception as exc:
                    if run.get("switch_id") and self._requeue_failed_switch(run, exc):
                        return
                    log.exception("run %s failed", run["run_id"])
                    self.store.finish_run(
                        run["run_id"], "failed", error={"code": "internal_error", "message": str(exc)}
                    )
            except Exception:  # pragma: no cover - defensive
                log.exception("lane loop error for %s", org_id)
                self.stop_event.wait(0.5)

    def _run_is_stale(self, run: dict[str, Any]) -> bool:
        """A run bound to a source epoch that is no longer current."""
        state = self.store.get_state(run["org_id"])
        active = int(state["active_epoch"])
        run_epoch = int(run["source_epoch"])
        if run["switch_id"]:
            switch = self.store.get_pending_switch(run["org_id"])
            if switch is None or switch["switch_id"] != run["switch_id"]:
                return True
            return False
        return run_epoch != active

    def _retire_stale_run(self, run: dict[str, Any]) -> None:
        current = self.store.get_run(run["run_id"])
        if current["status"] in ("succeeded", "failed", "cancelled", "superseded"):
            return
        self.store.finish_run(
            run["run_id"],
            "superseded",
            error={
                "code": "source_switched",
                "message": "run belonged to a source that has been replaced",
            },
        )

    def _requeue_failed_switch(self, run: dict[str, Any], exc: Exception) -> bool:
        """Keep a pending switch retrying while its target source is unhealthy.

        The previous source keeps serving throughout, so a failed switch
        attempt is retried with bounded back-off instead of terminating the
        cutover.  Returns ``False`` once the switch itself is no longer pending.
        """
        return self._fail_or_retry_switch(
            run,
            {"code": getattr(exc, "code", "upstream_error"), "message": str(exc)},
        )

    def _full_lane(self, org_id: str) -> None:
        self._lane_loop(org_id, FULL)

    def _incremental_lane(self, org_id: str) -> None:
        self._lane_loop(org_id, INCREMENTAL)

    def _handle_abort(self, run: dict[str, Any], reason: str) -> None:
        current = self.store.get_run(run["run_id"])
        if current["status"] in ("succeeded", "failed", "cancelled", "superseded"):
            return
        if reason == "paused":
            self.store.requeue_run(run["run_id"], reason="organization_paused", status="paused")
        elif reason == "disabled":
            self.store.requeue_run(run["run_id"], reason="organization_disabled", status="paused")
        else:
            self.store.requeue_run(run["run_id"], reason="engine_stopped", status="queued")

    def _fail_or_retry_switch(self, run: dict[str, Any], error: dict[str, Any]) -> bool:
        """Terminal failure for ordinary runs; a pending switch run is requeued.

        Returns ``True`` when the run was requeued instead of finished.
        """
        if not run.get("switch_id"):
            self.store.finish_run(run["run_id"], "failed", error=error)
            return False
        switch = self.store.get_pending_switch(run["org_id"])
        if switch is None or switch["switch_id"] != run["switch_id"]:
            self.store.finish_run(run["run_id"], "failed", error=error)
            return False
        progress = dict(run.get("progress") or {})
        attempts = int(progress.get("switch_attempts", 0)) + 1
        self.store.update_run(run["run_id"], progress={**progress, "switch_attempts": attempts}, error=error)
        self.store.requeue_run(run["run_id"], reason=error.get("code", "switch_retry"), status="queued")
        delay = min(5.0, 0.2 * (2 ** min(attempts, 5)))
        self.stop_event.wait(delay)
        return True

    # ------------------------------------------------------------------
    # full rebuild
    def _guard_epoch(self, run: dict[str, Any]) -> None:
        """Raise once the run's source epoch has been replaced."""
        state = self.store.get_state(run["org_id"])
        active = int(state["active_epoch"])
        run_epoch = int(run["source_epoch"])
        if run.get("switch_id"):
            switch = self.store.get_pending_switch(run["org_id"])
            if switch is None or switch["switch_id"] != run["switch_id"]:
                raise StaleEpoch(run_epoch, active)
            return
        if run_epoch != active:
            raise StaleEpoch(run_epoch, active)

    def _run_adapter(self, rt: OrgRuntime, run: dict[str, Any]):
        """Adapter for the source a run actually belongs to."""
        if run.get("switch_id"):
            switch = self.store.get_switch(run["switch_id"])
            org = self.store.get_org(run["org_id"])
            return rt.adapter_for(switch["source"], org.get("options") or {})
        return None

    def _run_full(self, rt: OrgRuntime, run: dict[str, Any]) -> None:
        org_id = run["org_id"]
        run_id = run["run_id"]
        source_epoch = int(run["source_epoch"])
        restarts = int((run.get("progress") or {}).get("scan_restarts", 0))
        contended = int((run.get("progress") or {}).get("contention_restarts", 0))
        while True:
            self._guard_epoch(run)
            scan = self.store.find_scan_for_run(run_id)
            if scan is None or scan["status"] in ("interrupted", "failed", "published"):
                if scan is not None:
                    self.store.delete_scan(scan["scan_id"])
                scan = self.store.create_scan(org_id, run_id, "full", source_epoch=source_epoch)
            self.store.update_run(
                run_id,
                phase="listing",
                progress={"scan_id": scan["scan_id"], "scan_restarts": restarts, "pages_done": scan["pages_done"]},
                clear_error=True,
            )
            try:
                self._full_attempt(rt, run, scan, contended)
                return
            except StaleEpoch:
                raise
            except RebuildContended:
                # An incremental window published newer state while this
                # rebuild was staging.  Restarting from a fresh snapshot is
                # the only safe option: republishing older staged details would
                # regress content.  The window keeps shrinking, so this
                # terminates once the change feed is quiet.
                contended += 1
                self.store.mark_scan(scan["scan_id"], "superseded", {"message": "rebuild contended"})
                self.store.delete_scan(scan["scan_id"])
                if contended > 8:
                    self.store.requeue_run(
                        run["run_id"],
                        reason="rebuild_contended",
                        status="queued",
                    )
                    return
                self.store.update_run(
                    run["run_id"],
                    phase="listing",
                    progress={"contention_restarts": contended, "scan_restarts": restarts},
                    reason="rebuild_contended",
                )
                rt._sleep(0.2 + 0.1 * contended)
                continue
            except IncompleteCorrection as exc:
                error = {
                    "code": "incomplete_correction",
                    "message": str(exc),
                    "correction_id": exc.correction_id,
                    **exc.details,
                }
                self.store.mark_scan(scan["scan_id"], "failed", {"message": str(exc), **exc.details})
                self.store.delete_scan(scan["scan_id"])
                if self._fail_or_retry_switch(run, error):
                    return
                self.store.finish_run(run["run_id"], "failed", error=error)
                return
            except ScanExpired as exc:
                restarts += 1
                self.store.mark_scan(scan["scan_id"], "expired", {"message": str(exc)})
                self.store.delete_scan(scan["scan_id"])
                if restarts > 3:
                    error = {"code": "snapshot_expired", "message": "catalog snapshot kept expiring"}
                    if self._fail_or_retry_switch(run, error):
                        return
                    self.store.finish_run(run_id, "failed", error=error)
                    return
                self.store.update_run(
                    run_id,
                    phase="listing",
                    progress={"scan_restarts": restarts},
                    reason="snapshot_expired_restarting",
                )

    def _full_attempt(
        self, rt: OrgRuntime, run: dict[str, Any], scan: dict[str, Any], contended: int = 0
    ) -> None:
        org_id = run["org_id"]
        run_id = run["run_id"]
        scan_id = scan["scan_id"]
        source_epoch = int(run["source_epoch"])
        attempt = int((run.get("progress") or {}).get("scan_restarts", 0))
        adapter = self._run_adapter(rt, run)

        # 1. list the snapshot -----------------------------------------
        if scan["status"] == "listing":
            token = scan["page_cursor"] if scan["snapshot_id"] else None
            first = token is None
            page_no = scan["pages_done"]
            ordinal = scan["entries_done"]
            while True:
                rt._check_abort()
                self._guard_epoch(run)
                try:
                    if first:
                        page = rt.call(lambda a: a.open_catalog(), adapter=adapter)
                    else:
                        page = rt.call(lambda a, t=token: a.catalog_page(t), adapter=adapter)
                except ChannelExpired as exc:
                    raise ScanExpired(str(exc)) from exc
                except NotFound as exc:
                    raise ScanExpired(str(exc)) from exc
                if first:
                    if not page.change_position:
                        raise ScanExpired("catalog page did not expose a continuation position")
                    scan = self.store.update_scan(
                        scan_id,
                        snapshot_id=page.snapshot_id,
                        change_position=page.change_position,
                        total_hint=page.total,
                    )
                items = [
                    {
                        "cert_no": item.cert_no,
                        "revision": item.revision,
                        "status": "pending",
                        "ordinal": ordinal + idx,
                    }
                    for idx, item in enumerate(page.items)
                ]
                self.store.add_scan_items(scan_id, items)
                page_no += 1
                ordinal += len(items)
                token = page.next_token
                scan = self.store.update_scan(
                    scan_id,
                    pages_done=page_no,
                    entries_done=ordinal,
                    page_cursor=token,
                    status="listing" if token else "fetching",
                )
                self.store.update_run(
                    run_id,
                    phase="listing",
                    progress={
                        "scan_id": scan_id,
                        "scan_restarts": attempt,
                        "pages_done": page_no,
                        "entries_listed": ordinal,
                        "total_hint": page.total,
                    },
                )
                first = False
                if not token:
                    break
            scan = self.store.update_scan(scan_id, status="fetching")

        # 2. fetch missing details -------------------------------------
        if scan["status"] in ("fetching", "listing"):
            pending = self.store.pending_scan_items(scan_id)
            done = 0
            for cert_no in pending:
                rt._check_abort()
                self._guard_epoch(run)
                try:
                    detail = rt.call(lambda a, no=cert_no: a.detail(no), adapter=adapter)
                except NotFound:
                    self.store.set_scan_item(scan_id, cert_no, status="deleted")
                    continue
                entry = _entry_from_detail(detail)
                self.store.set_scan_item(
                    scan_id, cert_no, status="ok", payload=entry, revision=detail.revision
                )
                done += 1
                if done % 10 == 0:
                    counts = self.store.scan_item_counts(scan_id)
                    self.store.update_run(
                        run_id,
                        phase="fetching",
                        progress={
                            "scan_id": scan_id,
                            "scan_restarts": attempt,
                            "details_done": counts.get("ok", 0) + counts.get("deleted", 0),
                            "details_total": counts.get("total", 0),
                        },
                    )
            counts = self.store.scan_item_counts(scan_id)
            self.store.update_run(
                run_id,
                phase="catching_up",
                progress={
                    "scan_id": scan_id,
                    "scan_restarts": attempt,
                    "details_done": counts.get("ok", 0) + counts.get("deleted", 0),
                    "details_total": counts.get("total", 0),
                },
            )
            scan = self.store.update_scan(scan_id, status="catching_up")

        # 3. catch up and publish --------------------------------------
        while True:
            rt._check_abort()
            self._guard_epoch(run)
            self._catch_up_scan(rt, run, scan, adapter=adapter)
            scan = self.store.get_scan(scan_id)
            entries = self._assemble_staged(rt, run, scan)
            watermark_seq = scan["head_seq"]
            if watermark_seq < 0:
                raise ScanExpired("no continuation position read")
            published = self.store.publish_full(
                org_id,
                list(entries.values()),
                watermark_cursor=scan["head_cursor"] or scan["catchup_cursor"],
                watermark_seq=watermark_seq,
                head_cursor=scan["head_cursor"],
                head_seq=scan["head_seq"],
                run_id=run_id,
                source_epoch=source_epoch,
                switch_id=run.get("switch_id"),
            )
            if published is not None:
                self.store.mark_scan(scan_id, "published")
                self.store.update_run(
                    run_id,
                    phase="published",
                    progress={
                        "scan_id": scan_id,
                        "scan_restarts": attempt,
                        "published_version": published["version"],
                        "cert_count": published["cert_count"],
                        "active_epoch": published["active_epoch"],
                    },
                )
                self.store.finish_run(
                    run_id, "succeeded", cursor_after=scan["head_cursor"] or scan["catchup_cursor"]
                )
                if run.get("switch_id"):
                    # cutover committed: drop adapter caches and retire any
                    # in-flight work still bound to the previous source
                    rt.invalidate()
                    self.store.supersede_runs_for_epoch(org_id, published["active_epoch"])
                self._reconcile_pending(rt, run)
                return
            if run.get("switch_id"):
                # another cutover already consumed this switch id
                raise StaleEpoch(source_epoch, self.store.get_state(org_id)["active_epoch"])
            # An incremental run published a newer watermark while this rebuild
            # was staging: staged details are now stale, so the scan restarts
            # from a fresh snapshot instead of overwriting newer content.
            raise RebuildContended("newer catalog version published concurrently")

    def _catch_up_scan(
        self, rt: OrgRuntime, run: dict[str, Any], scan: dict[str, Any], *, adapter: Any = None
    ) -> None:
        scan_id = scan["scan_id"]
        run_id = run["run_id"]
        cursor = scan["catchup_cursor"] or scan["change_position"]
        if not cursor:
            raise ScanExpired("no change position for catch-up")
        batch = int((self.store.get_org(run["org_id"]).get("options") or {}).get("batch_size", 100))
        while True:
            rt._check_abort()
            self._guard_epoch(run)
            try:
                page: ChangePage = rt.call(
                    lambda a, c=cursor: a.changes(c, batch), adapter=adapter
                )
            except ChannelExpired:
                raise ScanExpired("change cursor expired during catch-up")
            except NotFound:
                raise ScanExpired("change cursor was rejected")
            touched = {e.cert_no for e in page.items if e.cert_no}
            # Details are authoritative current content, so resolving every
            # touched certificate (not trusting the event's order/kind) makes
            # duplicated and reordered events harmless.
            present, gone = self._stage_details(
                rt, scan_id, touched, return_status=True, adapter=adapter
            )
            if gone:
                self.store.mark_scan_items_deleted(scan_id, sorted(gone))
            elif present:
                self.store.unmark_scan_items_deleted(scan_id, sorted(present))
            cursor = page.next_cursor
            seq = page.next_seq if page.next_seq is not None else page.head_seq
            scan = self.store.update_scan(
                scan_id,
                catchup_cursor=cursor,
                head_seq=int(seq if seq is not None else 0),
                head_cursor=page.next_cursor,
            )
            self.store.update_run(
                run_id,
                phase="catching_up",
                progress={
                    "scan_id": scan_id,
                    "pages_done": scan["pages_done"],
                    "entries_done": scan["entries_done"],
                    "caught_up_to": int(seq if seq is not None else 0),
                    "source_head": int(page.head_seq or 0),
                },
            )
            if not page.has_more:
                return

    def _stage_details(
        self,
        rt: OrgRuntime,
        scan_id: str,
        cert_nos: set[str],
        *,
        return_status: bool = False,
        adapter: Any = None,
    ):
        present: set[str] = set()
        gone: set[str] = set()
        for cert_no in sorted(cert_nos):
            rt._check_abort()
            try:
                detail = rt.call(lambda a, no=cert_no: a.detail(no), adapter=adapter)
            except NotFound:
                self.store.set_scan_item(scan_id, cert_no, status="deleted")
                gone.add(cert_no)
                continue
            self.store.set_scan_item(
                scan_id,
                cert_no,
                status="ok",
                payload=_entry_from_detail(detail),
                revision=detail.revision,
            )
            present.add(cert_no)
        if return_status:
            return present, gone
        return None

    def _assemble_staged(
        self, rt: OrgRuntime, run: dict[str, Any], scan: dict[str, Any]
    ) -> dict[str, dict[str, Any]]:
        scan_id = scan["scan_id"]
        adapter = self._run_adapter(rt, run)
        for _ in range(4):
            rt._check_abort()
            self._guard_epoch(run)
            items = self.store.scan_items(scan_id)
            entries: dict[str, dict[str, Any]] = {}
            for item in items:
                if item["status"] == "deleted" or not item["payload"]:
                    continue
                entries[item["cert_no"]] = item["payload"]
            groups: dict[str, set[str]] = {}
            for no, entry in entries.items():
                key = _entry_group_key(entry)
                if key:
                    groups.setdefault(key, set()).update(_group_members(entry))
            missing_fetch: set[str] = set()
            incomplete: list[str] = []
            for cid, members in groups.items():
                absent = {m for m in members if m not in entries}
                if absent:
                    missing_fetch |= absent
                    continue
                ids = {
                    (entries[m].get("correction") or {}).get("id")
                    for m in members
                    if m in entries
                }
                if ids != {cid}:
                    incomplete.append(cid)
            if missing_fetch:
                # details already staged may be stale; refetch the absent ones
                fetched_any = self._stage_details_visible(rt, scan_id, missing_fetch, adapter)
                if not fetched_any:
                    raise IncompleteCorrection(
                        next(iter(groups), "unknown"), {"missing": sorted(missing_fetch)}
                    )
                continue
            if incomplete:
                refresh = {
                    m
                    for cid in incomplete
                    for m in groups.get(cid, set())
                    if m in entries
                }
                if refresh and self._stage_details_visible(rt, scan_id, refresh, adapter):
                    continue
                raise IncompleteCorrection(incomplete[0], {"incomplete": incomplete})
            # drop correction members that are not published (deleted upstream)
            return entries
        raise IncompleteCorrection("unknown", {"reason": "group never became consistent"})

    def _stage_details_visible(
        self, rt: OrgRuntime, scan_id: str, cert_nos: set[str], adapter: Any = None
    ) -> bool:
        got = False
        for cert_no in sorted(cert_nos):
            rt._check_abort()
            try:
                detail = rt.call(lambda a, no=cert_no: a.detail(no), adapter=adapter)
            except NotFound:
                self.store.set_scan_item(scan_id, cert_no, status="deleted")
                continue
            self.store.set_scan_item(
                scan_id, cert_no, status="ok", payload=_entry_from_detail(detail), revision=detail.revision
            )
            got = True
        return got

    # ------------------------------------------------------------------
    # incremental
    def _run_incremental(self, rt: OrgRuntime, run: dict[str, Any]) -> None:
        org_id = run["org_id"]
        run_id = run["run_id"]
        state = self.store.get_state(org_id)
        if not state["ready"]:
            self.store.finish_run(
                run_id,
                "failed",
                error={"code": "catalog_not_ready", "message": "full collection has not completed"},
            )
            return
        self._guard_epoch(run)
        cursor = state["watermark_cursor"]
        if not cursor:
            self._schedule_recovery(org_id, "missing_cursor")
            self.store.finish_run(
                run_id, "superseded", error={"code": "cursor_missing", "message": "rebuilding catalog"}
            )
            return
        org = self.store.get_org(org_id)
        batch = int((org.get("options") or {}).get("batch_size", 100))
        self.store.update_run(
            run_id, phase="catching_up", progress={"caught_up_to": state["watermark_seq"]}, clear_error=True
        )
        total_events = 0
        windows = 0
        try:
            while True:
                rt._check_abort()
                self._guard_epoch(run)
                page = rt.call(lambda a, c=cursor: a.changes(c, batch))
                windows += 1
                total_events += len(page.items)
                if page.items:
                    self._apply_change_window(rt, run, page)
                # A source switch may have cut over while the window was being
                # resolved; stop immediately rather than advancing any cursor.
                self._guard_epoch(run)
                cursor = page.next_cursor
                seq = page.next_seq if page.next_seq is not None else page.head_seq
                self.store.update_run(
                    run_id,
                    phase="catching_up",
                    progress={
                        "windows": windows,
                        "events": total_events,
                        "caught_up_to": int(seq or 0),
                        "source_head": int(page.head_seq or 0),
                    },
                )
                if not page.has_more:
                    break
            self.store.finish_run(run_id, "succeeded", cursor_after=cursor)
            self._reconcile_pending(rt, run)
        except StaleEpoch:
            raise
        except ChannelExpired:
            self._schedule_recovery(org_id, "cursor_expired")
            self.store.finish_run(
                run_id,
                "superseded",
                error={"code": "cursor_expired", "message": "continuation position expired; rebuild scheduled"},
                cursor_after=None,
            )
        except NotFound:
            self._schedule_recovery(org_id, "cursor_rejected")
            self.store.finish_run(
                run_id,
                "superseded",
                error={"code": "cursor_expired", "message": "continuation position rejected; rebuild scheduled"},
            )
        except (SourceUnavailable, UpstreamError, RateLimited) as exc:
            self.store.finish_run(
                run_id,
                "failed",
                error={"code": getattr(exc, "code", "upstream_error"), "message": str(exc)},
            )

    def _apply_change_window(self, rt: OrgRuntime, run: dict[str, Any], page: ChangePage) -> None:
        org_id = run["org_id"]
        touched = {e.cert_no for e in page.items if e.cert_no}
        details: dict[str, dict[str, Any]] = {}
        deletes: set[str] = set()
        for cert_no in sorted(touched):
            rt._check_abort()
            try:
                detail = rt.call(lambda a, no=cert_no: a.detail(no))
            except NotFound:
                # whether the event was a delete, a purge, or a stale upsert
                # for something already gone, the live document decides.
                deletes.add(cert_no)
                continue
            details[cert_no] = _entry_from_detail(detail)
        held: list[dict[str, Any]] = []
        entries = self._resolve_incremental_groups(rt, details, held)
        for group in held:
            self.store.upsert_pending_correction(
                org_id,
                group["correction_id"],
                old_cert_nos=group["supersedes"],
                expected=group["expected"],
                state="incomplete",
                last_error={"code": "incomplete_correction", "message": "waiting for all members"},
            )
        seq = page.next_seq if page.next_seq is not None else page.head_seq
        state = self.store.get_state(org_id)
        watermark_seq = int(seq if seq is not None else state["watermark_seq"])
        published = self.store.publish_incremental(
            org_id,
            list(entries.values()),
            sorted(deletes),
            watermark_cursor=page.next_cursor,
            watermark_seq=max(watermark_seq, state["watermark_seq"]),
            head_cursor=page.next_cursor,
            head_seq=int(page.head_seq or watermark_seq),
            source_epoch=int(run["source_epoch"]),
        )
        if published is None:
            # a rebuild published newer state in the meantime (or the source was
            # switched); next cycle re-reads from the current watermark
            if int(run["source_epoch"]) != int(state["active_epoch"]):
                raise StaleEpoch(int(run["source_epoch"]), int(state["active_epoch"]))
            return
        for group in held:
            if not group.get("held"):
                self.store.clear_pending_correction(org_id, group["correction_id"])
                self._clear_correction_failure(org_id, group["correction_id"])

    def _resolve_incremental_groups(
        self,
        rt: OrgRuntime,
        details: dict[str, dict[str, Any]],
        held: list[dict[str, Any]],
    ) -> dict[str, dict[str, Any]]:
        groups: dict[str, set[str]] = {}
        for no, entry in details.items():
            key = _entry_group_key(entry)
            if key:
                groups.setdefault(key, set()).update(_group_members(entry))
        if not groups:
            return dict(details)
        entries = dict(details)
        excluded: set[str] = set()
        cooling = self._correction_cooldown(rt.org_id)
        for cid, members in groups.items():
            if cid in cooling:
                for member in members:
                    entries.pop(member, None)
                held.append(
                    {
                        "correction_id": cid,
                        "held": True,
                        "supersedes": sorted(
                            {
                                old
                                for m in members
                                for old in ((details.get(m) or {}).get("correction") or {}).get(
                                    "supersedes", []
                                )
                            }
                        ),
                    }
                )
                continue
            for _ in range(3):
                absent = {m for m in members if m not in entries and m not in excluded}
                if not absent:
                    break
                for member in sorted(absent):
                    try:
                        detail = rt.call(lambda a, no=member: a.detail(no))
                    except NotFound:
                        excluded.add(member)
                        continue
                    fetched = _entry_from_detail(detail)
                    entries[member] = fetched
                    members |= _group_members(fetched)
            members -= excluded
            present = [m for m in members if m in entries]
            ids = {(entries[m].get("correction") or {}).get("id") for m in present}
            # A member that the listing names but whose detail is gone (purged
            # or never published) must not block the group forever.  The
            # remaining members are published together; the vanished number is
            # simply absent, which is consistent with the live source.
            consistent = bool(present) and ids == {cid} and all(
                (entries[m].get("correction") or {}).get("members") for m in present
            )
            if not consistent and excluded:
                consistent = bool(present) and ids == {cid}
            if not consistent:
                if excluded:
                    self._note_correction_failure(rt.org_id, cid, set(excluded))
                held.append(
                    {
                        "correction_id": cid,
                        "expected": sorted(members | excluded),
                        "supersedes": sorted(
                            {
                                old
                                for m in present
                                for old in ((entries[m].get("correction") or {}).get("supersedes") or [])
                            }
                        ),
                    }
                )
                for member in members | excluded:
                    entries.pop(member, None)
        return entries

    def _correction_cooldown(self, org_id: str) -> set[str]:
        """Corrections whose members keep failing detail lookups recently.

        A group whose listed members cannot all be read is retried a few times
        and then held back for a while, instead of blocking or blindly pruning
        a member that may simply be temporarily unavailable.
        """
        now = time.time()
        cooldown = self._held_corrections.setdefault(org_id, {})
        ready = set()
        for cid, info in list(cooldown.items()):
            if now - info["since"] > 30.0:
                cooldown.pop(cid, None)
                continue
            if info["failures"] >= 3:
                ready.add(cid)
        return ready

    def _note_correction_failure(self, org_id: str, cid: str, missing: set[str]) -> None:
        cooldown = self._held_corrections.setdefault(org_id, {})
        info = cooldown.setdefault(cid, {"failures": 0, "since": time.time(), "missing": []})
        info["failures"] += 1
        info["missing"] = sorted(missing)

    def _clear_correction_failure(self, org_id: str, cid: str) -> None:
        self._held_corrections.get(org_id, {}).pop(cid, None)

    def _reconcile_pending(self, rt: OrgRuntime, run: dict[str, Any]) -> None:
        org_id = run["org_id"]
        pending = self.store.list_pending_corrections(org_id)
        if not pending:
            return
        state = self.store.get_state(org_id)
        if not state["ready"]:
            return
        for item in pending:
            rt._check_abort()
            if item["attempts"] >= 20:
                # unresolvable from the source; keep the old state untouched and
                # surface it through the status endpoint instead of looping.
                if item["state"] != "abandoned":
                    self.store.upsert_pending_correction(
                        org_id,
                        item["correction_id"],
                        old_cert_nos=item["old_cert_nos"],
                        expected=item["expected"],
                        state="abandoned",
                        last_error={
                            "code": "incomplete_correction",
                            "message": "members could not be resolved from the source",
                        },
                    )
                continue
            expected = set(item["expected"]) | set(item["old_cert_nos"])
            details: dict[str, dict[str, Any]] = {}
            blocked = False
            for cert_no in sorted(expected):
                try:
                    detail = rt.call(lambda a, no=cert_no: a.detail(no))
                except NotFound:
                    blocked = True
                    continue
                details[cert_no] = _entry_from_detail(detail)
            held: list[dict[str, Any]] = []
            entries = self._resolve_incremental_groups(rt, details, held)
            if blocked or held:
                self.store.upsert_pending_correction(
                    org_id,
                    item["correction_id"],
                    old_cert_nos=item["old_cert_nos"],
                    expected=sorted(expected),
                    state="incomplete",
                    last_error={"code": "incomplete_correction", "message": "members not fully available"},
                )
                continue
            published = self.store.publish_incremental(
                org_id,
                list(entries.values()),
                [],
                watermark_cursor=state["watermark_cursor"],
                watermark_seq=state["watermark_seq"],
                head_cursor=state["source_head_cursor"],
                head_seq=state["source_head_seq"],
                source_epoch=int(state["active_epoch"]),
            )
            if published is None:
                continue
            self.store.clear_pending_correction(org_id, item["correction_id"])

    def _schedule_recovery(self, org_id: str, reason: str) -> None:
        if self.store.has_active_run(org_id, (FULL,)):
            return
        if self.store.get_pending_switch(org_id) is not None:
            # the switch run is itself the recovery; do not queue a rebuild of
            # the old source on top of it
            return
        self.store.create_run(
            org_id, FULL, f"recovery:{reason}", coalesce_incremental=False
        )

    # ------------------------------------------------------------------
    # diagnostics
    def runtime_state(self, org_id: str) -> dict[str, Any]:
        rt = self.runtime(org_id)
        with rt._lock:
            return {
                "active_requests": rt._active,
                "wait": rt.wait_state(),
                "stats": dict(rt.stats),
                "cooldown_until": iso(datetime_from(rt._cooldown_until)) if rt._cooldown_until else None,
            }

    # ------------------------------------------------------------------
    # maintenance
    def _cleanup_loop(self) -> None:
        while not self.stop_event.wait(self.cleanup_interval):
            try:
                options: dict[str, Any] = {}
                for org in self.store.list_orgs():
                    options = {**options, **(org.get("options") or {})}
                self.store.cleanup(options)
            except Exception:  # pragma: no cover - defensive
                log.exception("cleanup failed")
