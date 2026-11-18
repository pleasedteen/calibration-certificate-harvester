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
SWITCH = "switch"


def _timedelta(seconds: float):
    import datetime as dt

    return dt.timedelta(seconds=seconds)


class RunAborted(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class ScanExpired(Exception):
    pass


class RebuildContended(Exception):
    pass


class SourceChanged(Exception):
    """The catalog moved to another source body; staged work is stale."""

    def __init__(self, message: str, *, code: str = "source_switched"):
        super().__init__(message)
        self.code = code


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
        self._adapters: dict[str, Any] = {}
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

    def adapter(
        self,
        org: dict[str, Any],
        source: dict[str, Any] | None = None,
    ):
        """Return the adapter for one source body.

        During a switch the old body keeps serving incremental collection while
        the new body is scanned, so adapters are cached per source config rather
        than per organization.
        """
        source_config = {**(source or org["source"])}
        key = dumps(
            {"source": source_config, "page_size": (org.get("options") or {}).get("page_size")}
        )
        with self._lock:
            adapter = self._adapters.get(key)
            if adapter is None:
                adapter = self.engine.build_adapter(
                    {
                        **source_config,
                        "page_size": (org.get("options") or {}).get("page_size", 10),
                    }
                )
                # During a switch both bodies are used at once (old body for
                # incremental, new body for the scan), so keep a couple of
                # adapters; anything older is dropped.
                self._adapters = {**self._adapters, key: adapter}
                if len(self._adapters) > 4:
                    self._adapters.pop(next(iter(self._adapters)))
            return adapter

    def invalidate(self) -> None:
        with self._lock:
            self._adapters = {}

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

    def call(self, fn: Callable, *args, source: dict[str, Any] | None = None, **kwargs):
        """Invoke a source operation honouring pacing, retries and Retry-After."""
        org = self.org()
        adapter = self.adapter(org, source)
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
            for kind, target in (
                (FULL, self._full_lane),
                (INCREMENTAL, self._incremental_lane),
                (SWITCH, self._switch_lane),
            ):
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
                    if org["enabled"] and not org["paused"]:
                        self._maybe_schedule(org)
            except Exception:  # pragma: no cover - defensive
                log.exception("supervisor iteration failed")
            self.stop_event.wait(0.2)

    def _maybe_schedule(self, org: dict[str, Any]) -> None:
        org_id = org["org_id"]
        switching = self.store.source_switch_active(org_id)
        state = self.store.get_state(org_id)
        options = org.get("options") or {}
        poll_ms = int(options.get("poll_interval_ms", self.default_poll_ms))
        now = time.time()
        # auto retry a rebuild when the catalog is not ready yet
        if not state["ready"]:
            if switching:
                # the switch's own scan builds the first catalog of the new body
                return
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
                self.store.create_run(org_id, FULL, "auto_retry", coalesce_incremental=False)
            return
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
        run, coalesced = self.store.create_run(
            org_id, FULL, trigger, request_key=request_key, coalesce_incremental=False
        )
        self.runtime(org_id)
        self._ensure_lanes(org_id)
        return {**run, "coalesced": coalesced}

    def request_incremental(self, org_id: str, trigger: str = "manual", request_key: str | None = None) -> dict[str, Any]:
        state = self.store.get_state(org_id)
        run, coalesced = self.store.create_run(org_id, INCREMENTAL, trigger, request_key=request_key)
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
                if kind == FULL and self.store.source_switch_active(org_id):
                    # a rebuild of the old body while the new one is being
                    # scanned would only produce content that is about to be
                    # replaced; leave the request queued until the switch ends
                    self.stop_event.wait(0.15)
                    continue
                run = self.store.claim_next_run(org_id, (kind,))
                if run is None:
                    self.runtime(org_id).set_wait(None)
                    self.stop_event.wait(0.12)
                    continue
                rt = self.runtime(org_id)
                try:
                    if kind == FULL:
                        self._run_full(rt, run)
                    else:
                        self._run_incremental(rt, run)
                except RunAborted as exc:
                    self._handle_abort(run, exc.reason)
                except Exception as exc:  # pragma: no cover - defensive
                    log.exception("run %s failed", run["run_id"])
                    self.store.finish_run(
                        run["run_id"], "failed", error={"code": "internal_error", "message": str(exc)}
                    )
            except Exception:  # pragma: no cover - defensive
                log.exception("lane loop error for %s", org_id)
                self.stop_event.wait(0.5)

    def _full_lane(self, org_id: str) -> None:
        self._lane_loop(org_id, FULL)

    def _incremental_lane(self, org_id: str) -> None:
        self._lane_loop(org_id, INCREMENTAL)

    def _switch_lane(self, org_id: str) -> None:
        while not self.stop_event.is_set():
            try:
                org = self.store.get_org(org_id)
                if not org["enabled"] or org["paused"]:
                    self.stop_event.wait(0.15)
                    continue
                switch = self.store.get_source_switch(org_id)
                if switch is None or not self.store.source_switch_active(org_id):
                    self.stop_event.wait(0.15)
                    continue
                if not self.store.switch_due(org_id):
                    self.stop_event.wait(0.15)
                    continue
                try:
                    self._run_switch(self.runtime(org_id), switch)
                except Exception as exc:  # pragma: no cover - defensive
                    log.exception("source switch for %s failed", org_id)
                    self._record_switch_failure(org_id, switch, exc)
                    self.stop_event.wait(0.2)
            except RunAborted:
                self.stop_event.wait(0.15)
            except Exception:  # pragma: no cover - defensive
                log.exception("switch lane error for %s", org_id)
                self.stop_event.wait(0.5)

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

    def _supersede_run(self, run_id: str, reason: str) -> None:
        current = self.store.get_run(run_id)
        if current["status"] in ("succeeded", "failed", "cancelled", "superseded"):
            return
        self.store.finish_run(
            run_id,
            "superseded",
            error={"code": reason, "message": "catalog moved to another source"},
        )

    def _run_generation_is_current(self, run: dict[str, Any]) -> bool:
        return int(run.get("source_generation") or 0) == self.store.get_state(
            run["org_id"]
        )["source_generation"]

    # ------------------------------------------------------------------
    # full rebuild
    def _run_full(self, rt: OrgRuntime, run: dict[str, Any]) -> None:
        org_id = run["org_id"]
        run_id = run["run_id"]
        state = self.store.get_state(org_id)
        if int(run.get("source_generation") or 0) != state["source_generation"]:
            self._supersede_run(run_id, "source_switched")
            return
        if self.store.source_switch_active(org_id):
            # A rebuild against the old body while a switch is in flight would
            # either publish stale content or collide with the switch scan.
            self.store.requeue_run(run_id, reason="source_switch_in_progress", status="queued")
            return
        restarts = int((run.get("progress") or {}).get("scan_restarts", 0))
        contended = int((run.get("progress") or {}).get("contention_restarts", 0))
        while True:
            state = self.store.get_state(org_id)
            if int(run.get("source_generation") or 0) != state["source_generation"]:
                self._supersede_run(run_id, "source_switched")
                return
            scan = self.store.find_scan_for_run(run_id)
            if scan is None or scan["status"] in ("interrupted", "failed", "published"):
                if scan is not None:
                    self.store.delete_scan(scan["scan_id"])
                scan = self.store.create_scan(
                    org_id,
                    run_id,
                    "full",
                    source_generation=state["source_generation"],
                )
            self.store.update_run(
                run_id,
                phase="listing",
                progress={"scan_id": scan["scan_id"], "scan_restarts": restarts, "pages_done": scan["pages_done"]},
                clear_error=True,
            )
            try:
                self._full_attempt(rt, run, scan, contended)
                return
            except SourceChanged:
                # The organization was moved to another body while this scan was
                # staging.  Nothing from the previous body may reach the catalog.
                self.store.mark_scan(scan["scan_id"], "superseded", {"message": "source switched"})
                self.store.delete_scan(scan["scan_id"])
                self._supersede_run(run["run_id"], "source_switched")
                return
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
                self.store.mark_scan(scan["scan_id"], "failed", {"message": str(exc), **exc.details})
                self.store.delete_scan(scan["scan_id"])
                self.store.finish_run(
                    run["run_id"],
                    "failed",
                    error={
                        "code": "incomplete_correction",
                        "message": str(exc),
                        "correction_id": exc.correction_id,
                        **exc.details,
                    },
                )
                return
            except ScanExpired as exc:
                restarts += 1
                self.store.mark_scan(scan["scan_id"], "expired", {"message": str(exc)})
                self.store.delete_scan(scan["scan_id"])
                if restarts > 3:
                    self.store.finish_run(
                        run_id,
                        "failed",
                        error={"code": "snapshot_expired", "message": "catalog snapshot kept expiring"},
                    )
                    return
                self.store.update_run(
                    run_id,
                    phase="listing",
                    progress={"scan_restarts": restarts},
                    reason="snapshot_expired_restarting",
                )

    def _full_attempt(
        self,
        rt: OrgRuntime,
        run: dict[str, Any],
        scan: dict[str, Any],
        contended: int = 0,
        *,
        source: dict[str, Any] | None = None,
        publish: Callable[
            [dict[str, Any], dict[str, dict[str, Any]]], dict[str, Any] | None
        ]
        | None = None,
    ) -> None:
        org_id = run["org_id"]
        run_id = run["run_id"]
        scan_id = scan["scan_id"]
        attempt = int((run.get("progress") or {}).get("scan_restarts", 0))

        # 1. list the snapshot -----------------------------------------
        if scan["status"] == "listing":
            token = scan["page_cursor"] if scan["snapshot_id"] else None
            first = token is None
            page_no = scan["pages_done"]
            ordinal = scan["entries_done"]
            while True:
                rt._check_abort()
                try:
                    if first:
                        page = rt.call(lambda a: a.open_catalog(), source=source)
                    else:
                        page = rt.call(lambda a: a.catalog_page(token), source=source)
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
                try:
                    detail = rt.call(lambda a, no=cert_no: a.detail(no), source=source)
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
            self._catch_up_scan(rt, run, scan, source=source)
            scan = self.store.get_scan(scan_id)
            entries = self._assemble_staged(rt, run, scan, source=source)
            watermark_seq = scan["head_seq"]
            if watermark_seq < 0:
                raise ScanExpired("no continuation position read")
            if publish is not None:
                published = publish(scan, entries)
                if published is None:
                    raise SourceChanged("the organization moved to another source")
            else:
                published = self.store.publish_full(
                    org_id,
                    list(entries.values()),
                    watermark_cursor=scan["head_cursor"] or scan["catchup_cursor"],
                    watermark_seq=watermark_seq,
                    head_cursor=scan["head_cursor"],
                    head_seq=scan["head_seq"],
                    run_id=run_id,
                    generation=int(run.get("source_generation") or 0),
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
                    },
                )
                self.store.finish_run(
                    run_id, "succeeded", cursor_after=scan["head_cursor"] or scan["catchup_cursor"]
                )
                if publish is None:
                    self._reconcile_pending(rt, run)
                return
            # An incremental run published a newer watermark while this rebuild
            # was staging: staged details are now stale, so the scan restarts
            # from a fresh snapshot instead of overwriting newer content.
            raise RebuildContended("newer catalog version published concurrently")

    def _catch_up_scan(
        self,
        rt: OrgRuntime,
        run: dict[str, Any],
        scan: dict[str, Any],
        *,
        source: dict[str, Any] | None = None,
    ) -> None:
        scan_id = scan["scan_id"]
        run_id = run["run_id"]
        cursor = scan["catchup_cursor"] or scan["change_position"]
        if not cursor:
            raise ScanExpired("no change position for catch-up")
        batch = int((self.store.get_org(run["org_id"]).get("options") or {}).get("batch_size", 100))
        while True:
            rt._check_abort()
            try:
                page: ChangePage = rt.call(lambda a, c=cursor: a.changes(c, batch), source=source)
            except ChannelExpired:
                raise ScanExpired("change cursor expired during catch-up")
            except NotFound:
                raise ScanExpired("change cursor was rejected")
            touched = {e.cert_no for e in page.items if e.cert_no}
            # Details are authoritative current content, so resolving every
            # touched certificate (not trusting the event's order/kind) makes
            # duplicated and reordered events harmless.
            present, gone = self._stage_details(
                rt, scan_id, touched, return_status=True, source=source
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
        source: dict[str, Any] | None = None,
    ):
        present: set[str] = set()
        gone: set[str] = set()
        for cert_no in sorted(cert_nos):
            rt._check_abort()
            try:
                detail = rt.call(lambda a, no=cert_no: a.detail(no), source=source)
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
        self,
        rt: OrgRuntime,
        run: dict[str, Any],
        scan: dict[str, Any],
        *,
        source: dict[str, Any] | None = None,
    ) -> dict[str, dict[str, Any]]:
        scan_id = scan["scan_id"]
        for _ in range(4):
            rt._check_abort()
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
                fetched_any = self._stage_details_visible(
                    rt, scan_id, missing_fetch, source=source
                )
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
                if refresh and self._stage_details_visible(
                    rt, scan_id, refresh, source=source
                ):
                    continue
                raise IncompleteCorrection(incomplete[0], {"incomplete": incomplete})
            # drop correction members that are not published (deleted upstream)
            return entries
        raise IncompleteCorrection("unknown", {"reason": "group never became consistent"})

    def _stage_details_visible(
        self,
        rt: OrgRuntime,
        scan_id: str,
        cert_nos: set[str],
        *,
        source: dict[str, Any] | None = None,
    ) -> bool:
        got = False
        for cert_no in sorted(cert_nos):
            rt._check_abort()
            try:
                detail = rt.call(lambda a, no=cert_no: a.detail(no), source=source)
            except NotFound:
                self.store.set_scan_item(scan_id, cert_no, status="deleted")
                continue
            self.store.set_scan_item(
                scan_id, cert_no, status="ok", payload=_entry_from_detail(detail), revision=detail.revision
            )
            got = True
        return got

    # ------------------------------------------------------------------
    # online source switch
    def request_source_switch(
        self,
        org_id: str,
        source: dict[str, Any],
        *,
        request_key: str | None = None,
    ) -> dict[str, Any]:
        """Ask an organization to move to another body without stopping service.

        The old body keeps its incremental lane until the new body's catalog is
        complete; the switch itself is durable and resumes automatically after
        failure or restart.
        """
        org = self.store.get_org(org_id)
        if not org["enabled"]:
            raise RunAborted("disabled")
        switch, coalesced = self.store.begin_source_switch(
            org_id, source, request_key=request_key
        )
        self.runtime(org_id).invalidate()
        self._ensure_lanes(org_id)
        return {**switch, "coalesced": coalesced}

    def _run_switch(self, rt: OrgRuntime, switch: dict[str, Any]) -> None:
        org_id = switch["org_id"]
        try:
            self._switch_attempt(rt, switch)
        except (RunAborted, SourceChanged):
            # pause / shutdown / a concurrent move: the durable row decides
            # what happens next (resume later, or mark itself superseded)
            return
        except Exception as exc:
            self._record_switch_failure(org_id, switch, exc)

    def _record_switch_failure(
        self, org_id: str, switch: dict[str, Any] | None, exc: Exception
    ) -> None:
        current = self.store.get_source_switch(org_id)
        if current is None or current["status"] not in ("pending", "running", "retrying"):
            return
        attempts = int(current["attempts"]) + 1
        code = getattr(exc, "code", None) or exc.__class__.__name__.lower()
        error = {"code": code, "message": str(exc)}
        details = getattr(exc, "details", None)
        if isinstance(details, dict) and details:
            error["details"] = details
        delay = min(5.0, 0.25 * (2 ** min(attempts, 5)))
        next_at = iso(utcnow() + _timedelta(delay))
        self.store.update_source_switch(
            org_id,
            status="retrying",
            phase="retrying",
            error=error,
            attempts=attempts,
            next_attempt_at=next_at,
        )
        self.store.set_last_error(org_id, error)
        run_id = current.get("run_id")
        if run_id:
            try:
                run = self.store.get_run(run_id)
                if run["status"] in ("queued", "running", "paused"):
                    # Keep the run (and its staged scan) around so the next
                    # attempt resumes where this one stopped.
                    self.store.update_run(
                        run_id,
                        status="queued",
                        phase="retrying",
                        reason="switch_retrying",
                        error=error,
                    )
            except NotFound:
                pass

    def _switch_attempt(self, rt: OrgRuntime, switch: dict[str, Any]) -> None:
        org_id = switch["org_id"]
        source = switch["source"]
        state = self.store.get_state(org_id)
        if int(state["source_generation"]) == int(switch["target_generation"]):
            # committed earlier but the switch row was not marked: finish it
            self.store.commit_source_switch(org_id, switch["target_generation"], source)
            return
        if int(state["source_generation"]) != int(switch["base_generation"]):
            self.store.update_source_switch(
                org_id,
                status="superseded",
                phase="superseded",
                error={
                    "code": "source_switched",
                    "message": "the organization moved to another source",
                },
                finished_at=iso(utcnow()),
            )
            return

        run = self._switch_run(org_id, switch)
        run_id = run["run_id"]
        if not self.store.source_switch_active(org_id):
            return

        self.store.update_source_switch(
            org_id,
            status="running",
            phase="scanning",
            error=None,
            run_id=run_id,
            next_attempt_at=None,
        )
        self.store.update_run(
            run_id,
            status="running",
            phase="scanning",
            progress={
                "switch_id": switch["switch_id"],
                "target_generation": int(switch["target_generation"]),
            },
            clear_error=True,
        )

        generation = int(switch["target_generation"])
        run = self.store.get_run(run_id)
        base_generation = int(switch["base_generation"])

        def publish(
            scanned: dict[str, Any], entries: dict[str, dict[str, Any]]
        ) -> dict[str, Any] | None:
            published = self.store.publish_switch(
                org_id,
                list(entries.values()),
                base_generation=base_generation,
                target_generation=generation,
                source_config=source,
                watermark_cursor=scanned["head_cursor"] or scanned["catchup_cursor"],
                watermark_seq=scanned["head_seq"],
                head_cursor=scanned["head_cursor"],
                head_seq=scanned["head_seq"],
                run_id=run_id,
            )
            if published is None:
                raise SourceChanged("catalog generation changed while switching")
            return published

        try:
            restarts = 0
            while True:
                scan = self._find_switch_scan(org_id, run_id, generation)
                try:
                    self._full_attempt(rt, run, scan, source=source, publish=publish)
                    break
                except ScanExpired as exc:
                    restarts += 1
                    self.store.mark_scan(scan["scan_id"], "expired", {"message": str(exc)})
                    self.store.delete_scan(scan["scan_id"])
                    if restarts > 3:
                        raise SourceUnavailable(
                            "the new body's snapshot kept expiring"
                        ) from exc
                    self.store.update_source_switch(
                        org_id,
                        phase="rescanning",
                        progress={"restarts": restarts, "reason": "snapshot_expired"},
                    )
                    continue
                except RebuildContended as exc:
                    raise SourceUnavailable(
                        "the new body kept changing while switching"
                    ) from exc
        finally:
            rt.invalidate()

        current = self.store.get_source_switch(org_id)
        if current and current["status"] == "succeeded":
            self.store.update_run(
                run_id,
                phase="published",
                progress={
                    "switch_id": switch["switch_id"],
                    "target_generation": generation,
                },
            )
            self.store.finish_run(run_id, "succeeded")
            return
        # publish reported success but the row did not move: retry on the lane
        raise SourceUnavailable("switch publication did not commit")

    def _switch_run(self, org_id: str, switch: dict[str, Any]) -> dict[str, Any]:
        run_id = switch.get("run_id")
        if run_id:
            try:
                run = self.store.get_run(run_id)
                if run["status"] in ("queued", "running", "paused"):
                    return run
            except NotFound:
                pass
        run, _ = self.store.create_run(
            org_id,
            SWITCH,
            f"source_switch:{switch['switch_id']}",
            source_generation=int(switch["target_generation"]),
            source_config=switch["source"],
        )
        return run

    def _find_switch_scan(
        self, org_id: str, run_id: str, generation: int
    ) -> dict[str, Any]:
        scan = self.store.find_scan_for_run(run_id)
        if (
            scan is None
            or scan["source_generation"] != generation
            or scan["status"] not in ("listing", "fetching", "catching_up", "interrupted")
        ):
            if scan is not None:
                self.store.delete_scan(scan["scan_id"])
            scan = self.store.create_scan(
                org_id,
                run_id,
                "switch",
                source_generation=generation,
                source_config=None,
            )
        elif scan["status"] == "interrupted":
            # Resume from the phase the scan had reached instead of starting
            # over: staged details and the continuation position are durable.
            # The recorded phase (not a guess from the staged rows) decides,
            # because an interrupted listing has not seen the catalog tail.
            resumed = scan.get("resume_phase") or "listing"
            if resumed == "listing" and not scan["snapshot_id"]:
                resumed = "listing"
            scan = self.store.update_scan(
                scan["scan_id"], status=resumed, resume_phase=None
            )
        return scan

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
        gen = state["source_generation"]
        cursor = state["watermark_cursor"]
        if not cursor:
            self._schedule_recovery(org_id, "missing_cursor")
            self.store.finish_run(
                run_id, "superseded", error={"code": "cursor_missing", "message": "rebuilding catalog"}
            )
            return
        if int(run.get("source_generation") or 0) != gen:
            self._supersede_run(run_id, "source_switched")
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
                page = rt.call(lambda a, c=cursor: a.changes(c, batch))
                if int(run.get("source_generation") or 0) != self.store.get_state(org_id)[
                    "source_generation"
                ]:
                    raise SourceChanged("source switched while catching up")
                windows += 1
                total_events += len(page.items)
                if page.items:
                    self._apply_change_window(rt, run, page, generation=gen)
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
            if int(run.get("source_generation") or 0) != self.store.get_state(org_id)[
                "source_generation"
            ]:
                raise SourceChanged("source switched before the window was committed")
            self.store.finish_run(run_id, "succeeded", cursor_after=cursor)
            self._reconcile_pending(rt, run)
        except ChannelExpired:
            if self._run_generation_is_current(run):
                self._schedule_recovery(org_id, "cursor_expired")
                self.store.finish_run(
                    run_id,
                    "superseded",
                    error={"code": "cursor_expired", "message": "continuation position expired; rebuild scheduled"},
                    cursor_after=None,
                )
            else:
                self._supersede_run(run_id, "source_switched")
        except NotFound:
            if self._run_generation_is_current(run):
                self._schedule_recovery(org_id, "cursor_rejected")
                self.store.finish_run(
                    run_id,
                    "superseded",
                    error={"code": "cursor_expired", "message": "continuation position rejected; rebuild scheduled"},
                )
            else:
                self._supersede_run(run_id, "source_switched")
        except SourceChanged as exc:
            # The catalog moved to another body while this window was staged;
            # its results must be discarded, not merged into the new catalog.
            self.store.finish_run(
                run_id,
                "superseded",
                error={"code": exc.code, "message": str(exc)},
            )
        except RunAborted:
            raise
        except (SourceUnavailable, UpstreamError, RateLimited) as exc:
            if not self._run_generation_is_current(run):
                self._supersede_run(run_id, "source_switched")
                return
            self.store.finish_run(
                run_id,
                "failed",
                error={"code": getattr(exc, "code", "upstream_error"), "message": str(exc)},
            )

    def _apply_change_window(
        self,
        rt: OrgRuntime,
        run: dict[str, Any],
        page: ChangePage,
        *,
        generation: int | None = None,
    ) -> None:
        org_id = run["org_id"]
        touched = {e.cert_no for e in page.items if e.cert_no}
        details: dict[str, dict[str, Any]] = {}
        deletes: set[str] = set()
        current = self.store.get_state(org_id)
        gen = current["source_generation"] if generation is None else int(generation)
        if int(run.get("source_generation") or 0) != current["source_generation"]:
            raise SourceChanged("run belongs to the previous source")
        if gen != current["source_generation"]:
            raise SourceChanged("window belongs to the previous source")
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
        if self.store.get_state(org_id)["source_generation"] != gen:
            # the catalog moved while these details were being fetched; do not
            # persist anything staged from the previous body
            raise SourceChanged("source switched while applying a window")
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
            generation=gen,
        )
        if published is None:
            # a rebuild published newer state in the meantime, or the source
            # changed; next cycle re-reads from the (new) body
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
        if int(run.get("source_generation") or 0) != state["source_generation"]:
            return
        for item in pending:
            rt._check_abort()
            if int(self.store.get_state(org_id)["source_generation"]) != state["source_generation"]:
                return
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
                generation=state["source_generation"],
            )
            if published is None:
                continue
            self.store.clear_pending_correction(org_id, item["correction_id"])

    def _schedule_recovery(self, org_id: str, reason: str) -> None:
        if self.store.source_switch_active(org_id):
            # the switch's own scan owns recovery until it commits
            return
        if self.store.has_active_run(org_id, (FULL,)):
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
