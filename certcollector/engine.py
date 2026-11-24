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

from .source import CatalogPage, ChangePage, Detail, build_adapter
from .store import Store
from .util import (
    ChannelExpired,
    NotFound,
    RateLimited,
    SourceUnavailable,
    UpstreamError,
    dumps,
    iso,
    parse_iso,
    utcnow,
)

log = logging.getLogger("certcollector.engine")

FULL = "full"
INCREMENTAL = "incremental"

# A detail page that the directory still lists but which temporarily answers
# 404 must not burn the change feed: the group waits and is retried on later
# runs.  This backoff bounds request pressure while keeping retries prompt.
BLOCKED_RETRY_BASE = 0.5
BLOCKED_RETRY_MAX = 5.0


class RunAborted(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class ScanExpired(Exception):
    pass


class RebuildContended(Exception):
    pass


class CorrectionBlocked(Exception):
    """A staged catalog cannot publish yet: a listed member is unreadable.

    The upstream listing still names ``cert_nos`` but their detail pages return
    404 (or a correction group cannot be assembled).  The scan keeps its staged
    work and retries; nothing is published until every listed member resolves
    or is confirmed removed from the directory.
    """

    def __init__(self, cert_nos: set[str], detail: dict[str, Any] | None = None):
        self.cert_nos = set(cert_nos)
        self.detail = detail or {}
        super().__init__(f"blocked on unreadable listed members: {sorted(self.cert_nos)}")


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


def _group_supersedes(entry: dict[str, Any]) -> set[str]:
    corr = entry.get("correction") or {}
    return set(corr.get("supersedes") or [])


def _group_consistent(cid: str, entries: dict[str, dict[str, Any]], members: set[str]) -> bool:
    """Decide whether correction group ``cid`` can be published as staged.

    A formal correction is consistent when every member that the source still
    publishes carries correction metadata, and every member whose current
    correction id differs from ``cid`` can be explained as a *re-correction*:
    the newer correction supersedes this one (its ``supersedes`` intersects the
    group's members).  That is the roll-forward case where an old correction is
    formally corrected again — the newer result simply supersedes the older
    group instead of blocking the catalog forever.
    """
    present = [m for m in members if m in entries]
    if not present:
        return False
    for no in present:
        entry = entries[no]
        current = (entry.get("correction") or {}).get("id")
        if not current:
            return False
        if current == cid:
            continue
        # A different id is only acceptable when this member is the newer face
        # of a correction that supersedes the group under consideration.
        newer = entries.get(no, {}).get("correction") or {}
        if not (set(newer.get("supersedes") or []) & members):
            return False
    return True


class OrgRuntime:
    """Per-organization state: adapter, pacing, wait reporting, statistics."""

    def __init__(self, engine: "Engine", org_id: str):
        self.engine = engine
        self.org_id = org_id
        self._lock = threading.RLock()
        self._adapter = None
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

    def invalidate(self) -> None:
        with self._lock:
            self._adapter = None
            self._source_key = None

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

    def call(self, fn: Callable, *args, **kwargs):
        """Invoke a source operation honouring pacing, retries and Retry-After."""
        org = self.org()
        adapter = self.adapter(org)
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
        # short-lived cache of the authoritative upstream directory per org,
        # used to tell "still listed but 404" apart from "removed upstream"
        self._listing_cache: dict[str, tuple[float, set[str]]] = {}
        self._listing_lock = threading.Lock()
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
        with self._listing_lock:
            self._listing_cache.clear()

    def _threads_snapshot(self):
        with self._lock:
            for rt in self._runtimes.values():
                for t in rt.threads.values():
                    yield t

    def build_adapter(self, config: dict[str, Any]):
        transport = self.transport_factory(config) if self.transport_factory else None
        return build_adapter(config, transport)

    # ------------------------------------------------------------------
    # upstream directory helpers
    def source_listing(self, rt: OrgRuntime, force: bool = False) -> set[str]:
        """Certificate numbers currently published by the upstream directory.

        The listing is the authority that distinguishes a temporarily
        unreadable detail page (the number is still in the directory) from a
        certificate that was actually removed upstream.  Cached briefly so a
        burst of 404s does not re-page the whole catalog each time.
        """
        org_id = rt.org_id
        now = time.time()
        if not force:
            with self._listing_lock:
                cached = self._listing_cache.get(org_id)
                if cached and now - cached[0] < 0.5:
                    return set(cached[1])
        org = self.store.get_org(org_id)
        adapter = rt.adapter(org)
        page: CatalogPage = rt.call(lambda a: a.open_catalog())
        numbers = {item.cert_no for item in page.items}
        token = page.next_token
        while token:
            rt._check_abort()
            page = rt.call(lambda a, t=token: a.catalog_page(t))
            numbers.update(item.cert_no for item in page.items)
            token = page.next_token
        with self._listing_lock:
            self._listing_cache[org_id] = (now, numbers)
        return set(numbers)

    def invalidate_listing(self, org_id: str) -> None:
        with self._listing_lock:
            self._listing_cache.pop(org_id, None)

    def _is_listed(self, rt: OrgRuntime, cert_no: str) -> bool:
        try:
            return cert_no in self.source_listing(rt)
        except (SourceUnavailable, UpstreamError, RateLimited, ChannelExpired):
            # If the directory itself cannot be read, a 404 on one detail page
            # must not be interpreted as a removal: wait and retry.
            return True

    def _record_blocked_reads(self, org_id: str, cert_nos: set[str], reason: str) -> None:
        for cert_no in sorted(cert_nos):
            self.store.upsert_pending_read(
                org_id,
                cert_no,
                reason=reason,
                last_error={"code": "detail_unavailable", "message": "listed upstream but detail returned 404"},
            )

    @staticmethod
    def _blocked_delay(attempts: int) -> float:
        return min(BLOCKED_RETRY_MAX, BLOCKED_RETRY_BASE * (2 ** max(0, attempts - 1)))

    @staticmethod
    def _due(updated_at: str | None, attempts: int) -> bool:
        if not updated_at:
            return True
        stamp = parse_iso(updated_at)
        if stamp is None:
            return True
        elapsed = (utcnow() - stamp).total_seconds()
        return elapsed >= min(BLOCKED_RETRY_MAX, BLOCKED_RETRY_BASE * (2 ** max(0, attempts - 1)))

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
                    if org["enabled"] and not org["paused"]:
                        self._maybe_schedule(org)
            except Exception:  # pragma: no cover - defensive
                log.exception("supervisor iteration failed")
            self.stop_event.wait(0.2)

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

    # ------------------------------------------------------------------
    # full rebuild
    def _run_full(self, rt: OrgRuntime, run: dict[str, Any]) -> None:
        org_id = run["org_id"]
        run_id = run["run_id"]
        restarts = int((run.get("progress") or {}).get("scan_restarts", 0))
        contended = int((run.get("progress") or {}).get("contention_restarts", 0))
        while True:
            scan = self.store.find_scan_for_run(run_id)
            if scan is None or scan["status"] in ("interrupted", "failed", "published"):
                if scan is not None:
                    self.store.delete_scan(scan["scan_id"])
                scan = self.store.create_scan(org_id, run_id, "full")
            self.store.update_run(
                run_id,
                phase="listing",
                progress={"scan_id": scan["scan_id"], "scan_restarts": restarts, "pages_done": scan["pages_done"]},
                clear_error=True,
            )
            try:
                self._full_attempt(rt, run, scan, contended)
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
            except CorrectionBlocked as exc:
                # A certificate the directory still lists has no readable
                # detail page (temporarily 404), or a correction group cannot
                # be assembled yet.  The previous catalog keeps serving; the
                # staged scan is retained and retried until every listed member
                # becomes readable or is confirmed removed from the directory.
                # Re-corrections never fail a rebuild.
                pending = self.store.list_pending_reads(org_id)
                attempts = max([int(p["attempts"]) for p in pending], default=1)
                delay = self._blocked_delay(attempts)
                self.store.update_run(
                    run_id,
                    phase="awaiting_correction",
                    progress={
                        "scan_id": scan["scan_id"],
                        "scan_restarts": restarts,
                        "waiting_on": sorted(exc.cert_nos),
                        **exc.detail,
                    },
                    reason="correction_members_unavailable",
                )
                rt.set_wait(
                    "correction_pending",
                    delay,
                    {"cert_nos": sorted(exc.cert_nos), "attempts": attempts, **exc.detail},
                )
                rt._sleep(delay)
                rt.set_wait(None)
                # A fresh directory view decides whether a member reappeared
                # or was removed while we waited.
                self.invalidate_listing(org_id)
                continue
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
        self, rt: OrgRuntime, run: dict[str, Any], scan: dict[str, Any], contended: int = 0
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
                        page = rt.call(lambda a: a.open_catalog())
                    else:
                        page = rt.call(lambda a: a.catalog_page(token))
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
            blocked: set[str] = set()
            for cert_no in pending:
                rt._check_abort()
                try:
                    detail = rt.call(lambda a, no=cert_no: a.detail(no))
                except NotFound:
                    if self._is_listed(rt, cert_no):
                        # Still in the upstream directory but its detail page
                        # is temporarily 404: keep it staged as pending and wait
                        # instead of treating the certificate as deleted.
                        blocked.add(cert_no)
                        continue
                    self.store.set_scan_item(scan_id, cert_no, status="deleted")
                    done += 1
                    continue
                entry = _entry_from_detail(detail)
                self.store.set_scan_item(
                    scan_id, cert_no, status="ok", payload=entry, revision=detail.revision
                )
                self.store.clear_pending_read(org_id, cert_no)
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
            if blocked:
                self._record_blocked_reads(org_id, blocked, "detail_404_while_listed")
                raise CorrectionBlocked(blocked)
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
            self._catch_up_scan(rt, run, scan)
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
                self._reconcile_pending(rt, run)
                return
            # An incremental run published a newer watermark while this rebuild
            # was staging: staged details are now stale, so the scan restarts
            # from a fresh snapshot instead of overwriting newer content.
            raise RebuildContended("newer catalog version published concurrently")

    def _catch_up_scan(self, rt: OrgRuntime, run: dict[str, Any], scan: dict[str, Any]) -> None:
        scan_id = scan["scan_id"]
        run_id = run["run_id"]
        cursor = scan["catchup_cursor"] or scan["change_position"]
        if not cursor:
            raise ScanExpired("no change position for catch-up")
        batch = int((self.store.get_org(run["org_id"]).get("options") or {}).get("batch_size", 100))
        while True:
            rt._check_abort()
            try:
                page: ChangePage = rt.call(lambda a, c=cursor: a.changes(c, batch))
            except ChannelExpired:
                raise ScanExpired("change cursor expired during catch-up")
            except NotFound:
                raise ScanExpired("change cursor was rejected")
            touched = {e.cert_no for e in page.items if e.cert_no}
            # Details are authoritative current content, so resolving every
            # touched certificate (not trusting the event's order/kind) makes
            # duplicated and reordered events harmless.
            present, gone, blocked = self._stage_details(rt, scan_id, touched, return_status=True)
            if blocked:
                self._record_blocked_reads(run["org_id"], blocked, "detail_404_while_listed")
                raise CorrectionBlocked(blocked)
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
    ):
        present: set[str] = set()
        gone: set[str] = set()
        blocked: set[str] = set()
        for cert_no in sorted(cert_nos):
            rt._check_abort()
            try:
                detail = rt.call(lambda a, no=cert_no: a.detail(no))
            except NotFound:
                if self._is_listed(rt, cert_no):
                    # Directory still lists the number: its detail is only
                    # temporarily unreadable.  Leave any staged row untouched so
                    # the scan waits rather than dropping a live certificate.
                    blocked.add(cert_no)
                    continue
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
            return present, gone, blocked
        return None

    def _assemble_staged(
        self, rt: OrgRuntime, run: dict[str, Any], scan: dict[str, Any]
    ) -> dict[str, dict[str, Any]]:
        """Build the publishable snapshot, waiting on any unreadable member.

        Correction groups are all-or-nothing: a group only publishes when every
        member the upstream directory still lists is present and consistent.
        A 404 on a still-listed member raises :class:`CorrectionBlocked` so the
        whole scan retries without publishing; a member confirmed removed from
        the directory simply stays absent, which matches the live source.
        Re-corrections (a member now pointing at a newer correction that
        supersedes this group) are accepted as consistent roll-forward state.
        """
        org_id = run["org_id"]
        scan_id = scan["scan_id"]
        blocked: set[str] = set()
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
            inconsistent: list[str] = []
            for cid, members in groups.items():
                absent = {m for m in members if m not in entries}
                if absent:
                    missing_fetch |= absent
                    continue
                if not _group_consistent(cid, entries, members):
                    inconsistent.append(cid)
            if missing_fetch:
                # Absent members may be temporarily unreadable details.  Refetch
                # them; any still 404 *and still listed* blocks publication.
                blocked |= self._refetch_or_block(rt, org_id, scan_id, missing_fetch)
                if blocked:
                    self._record_blocked_reads(org_id, blocked, "correction_member_404")
                    raise CorrectionBlocked(blocked, {"groups": sorted(groups)})
                continue
            if inconsistent:
                refresh = {
                    m
                    for cid in inconsistent
                    for m in groups.get(cid, set())
                    if m in entries
                }
                if refresh and self._stage_details_visible(rt, scan_id, refresh):
                    continue
                # Refreshed details still do not line up: treat it as a waiting
                # condition rather than a permanent failure, since a partially
                # published re-correction upstream may resolve on the next read.
                blocked |= refresh
                self._record_blocked_reads(org_id, blocked, "correction_group_inconsistent")
                raise CorrectionBlocked(blocked, {"incomplete": inconsistent})
            return entries
        raise CorrectionBlocked(blocked or set(), {"reason": "group never became consistent"})

    def _refetch_or_block(self, rt: OrgRuntime, org_id: str, scan_id: str, cert_nos: set[str]) -> set[str]:
        """Refetch absent members; return the ones still listed but unreadable."""
        blocked: set[str] = set()
        for cert_no in sorted(cert_nos):
            rt._check_abort()
            try:
                detail = rt.call(lambda a, no=cert_no: a.detail(no))
            except NotFound:
                if self._is_listed(rt, cert_no):
                    blocked.add(cert_no)
                    continue
                self.store.set_scan_item(scan_id, cert_no, status="deleted")
                continue
            self.store.set_scan_item(
                scan_id, cert_no, status="ok", payload=_entry_from_detail(detail), revision=detail.revision
            )
            self.store.clear_pending_read(org_id, cert_no)
        return blocked

    def _stage_details_visible(self, rt: OrgRuntime, scan_id: str, cert_nos: set[str]) -> bool:
        got = False
        for cert_no in sorted(cert_nos):
            rt._check_abort()
            try:
                detail = rt.call(lambda a, no=cert_no: a.detail(no))
            except NotFound:
                if self._is_listed(rt, cert_no):
                    continue
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
                page = rt.call(lambda a, c=cursor: a.changes(c, batch))
                windows += 1
                total_events += len(page.items)
                if page.items:
                    self._apply_change_window(rt, run, page)
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
        unreadable: set[str] = set()
        for cert_no in sorted(touched):
            rt._check_abort()
            try:
                detail = rt.call(lambda a, no=cert_no: a.detail(no))
            except NotFound:
                # A 404 is only a real removal when the number has left the
                # upstream directory.  A still-listed number with a missing
                # detail page is held back and retried later; it never becomes
                # a delete and never blocks unrelated revisions.
                if self._is_listed(rt, cert_no):
                    unreadable.add(cert_no)
                    continue
                deletes.add(cert_no)
                continue
            details[cert_no] = _entry_from_detail(detail)
            self.store.clear_pending_read(org_id, cert_no)
        held: list[dict[str, Any]] = []
        entries = self._resolve_incremental_groups(rt, details, held, unreadable=unreadable)
        for group in held:
            members = set(group.get("expected") or []) | set(group.get("supersedes") or [])
            self.store.upsert_pending_correction(
                org_id,
                group["correction_id"],
                old_cert_nos=group["supersedes"],
                expected=sorted(group.get("expected_members", members)),
                state="incomplete",
                last_error=group.get(
                    "last_error",
                    {"code": "incomplete_correction", "message": "waiting for all members"},
                ),
            )
        for cert_no in unreadable:
            self.store.upsert_pending_read(
                org_id,
                cert_no,
                reason="detail_404_while_listed",
                last_error={"code": "detail_unavailable", "message": "listed upstream but detail returned 404"},
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
        )
        if published is None:
            # a rebuild published newer state in the meantime; next cycle re-reads
            return
        for group in held:
            if not group.get("held"):
                self.store.clear_pending_correction(org_id, group["correction_id"])
        for cert_no in deletes:
            self.store.clear_pending_read(org_id, cert_no)
        # a member confirmed removed from the directory also leaves the read queue
        for cert_no in touched - unreadable:
            self.store.clear_pending_read(org_id, cert_no)

    def _resolve_incremental_groups(
        self,
        rt: OrgRuntime,
        details: dict[str, dict[str, Any]],
        held: list[dict[str, Any]],
        *,
        unreadable: set[str] | None = None,
    ) -> dict[str, dict[str, Any]]:
        """Apply all-or-nothing correction groups to a change window.

        ``unreadable`` are certificate numbers that the change feed touched,
        the upstream directory still lists, but whose detail pages answer 404.
        Any group that references such a member is held back atomically;
        unrelated certificates in the same window are still returned for
        publication.  A member confirmed removed from the directory is simply
        absent and does not block the remaining group.  Re-corrections (a
        member's current correction id differs because a newer correction
        supersedes this one) are accepted as roll-forward consistency.
        """
        unreadable = set(unreadable or set())
        groups: dict[str, set[str]] = {}
        for no, entry in details.items():
            key = _entry_group_key(entry)
            if key:
                groups.setdefault(key, set()).update(_group_members(entry))
        if not groups and not unreadable:
            return dict(details)
        entries = dict(details)
        excluded: set[str] = set()
        for cid, members in groups.items():
            for _ in range(3):
                absent = {m for m in members if m not in entries and m not in excluded and m not in unreadable}
                if not absent:
                    break
                for member in sorted(absent):
                    try:
                        detail = rt.call(lambda a, no=member: a.detail(no))
                    except NotFound:
                        if self._is_listed(rt, member):
                            unreadable.add(member)
                            continue
                        excluded.add(member)
                        continue
                    fetched = _entry_from_detail(detail)
                    entries[member] = fetched
                    members |= _group_members(fetched)
            members -= excluded
            present = [m for m in members if m in entries]
            # A member whose detail cannot be read while it is still listed by
            # the directory holds the whole group until it resolves or leaves
            # the directory.  Everything else in the window still publishes.
            blocked_members = {m for m in members if m in unreadable}
            if blocked_members:
                supersedes = self._group_supersedes(cid, entries, members)
                held.append(
                    {
                        "correction_id": cid,
                        "held": True,
                        "expected": sorted(members | excluded | unreadable),
                        "expected_members": sorted(members | blocked_members),
                        "supersedes": sorted(supersedes),
                        "last_error": {
                            "code": "member_detail_unavailable",
                            "message": "listed member detail returned 404; correction waits",
                            "waiting_on": sorted(blocked_members),
                        },
                    }
                )
                for member in list(members) + list(blocked_members):
                    entries.pop(member, None)
                continue
            if not _group_consistent(cid, entries, members):
                supersedes = self._group_supersedes(cid, entries, members)
                held.append(
                    {
                        "correction_id": cid,
                        "expected": sorted(members | excluded),
                        "expected_members": sorted(members),
                        "supersedes": sorted(supersedes),
                        "last_error": {
                            "code": "incomplete_correction",
                            "message": "correction group not yet consistent upstream",
                        },
                    }
                )
                for member in members | excluded:
                    entries.pop(member, None)
        return entries

    @staticmethod
    def _group_supersedes(
        cid: str, entries: dict[str, dict[str, Any]], members: set[str]
    ) -> set[str]:
        olds: set[str] = set()
        for no in members:
            entry = entries.get(no)
            if entry is None:
                continue
            corr = entry.get("correction") or {}
            if corr.get("id") == cid:
                olds.update(corr.get("supersedes") or [])
        return olds

    def _reconcile_pending(self, rt: OrgRuntime, run: dict[str, Any]) -> None:
        """Retry durable held state until the source resolves it.

        Two durable queues survive restarts: individual listed-but-404 detail
        reads (``pending_reads``) and all-or-nothing correction groups
        (``pending_corrections``).  Neither is ever abandoned: a member that
        becomes readable converges the group; a member confirmed removed from
        the directory converges the remaining members without it.  Backoff is
        stored on the rows themselves so retries stay bounded across restarts.
        """
        org_id = run["org_id"]
        pending_reads = self.store.list_pending_reads(org_id)
        pending = self.store.list_pending_corrections(org_id)
        if not pending_reads and not pending:
            return
        state = self.store.get_state(org_id)
        if not state["ready"]:
            return

        # 1. retry individual unreadable detail pages --------------------
        recovered: dict[str, dict[str, Any]] = {}
        still_blocked: set[str] = set()
        for item in pending_reads:
            rt._check_abort()
            cert_no = item["cert_no"]
            if not self._due(item["updated_at"], item["attempts"]):
                continue
            try:
                detail = rt.call(lambda a, no=cert_no: a.detail(no))
            except NotFound:
                if self._is_listed(rt, cert_no):
                    still_blocked.add(cert_no)
                    self.store.upsert_pending_read(
                        org_id,
                        cert_no,
                        reason=item["reason"],
                        last_error={
                            "code": "detail_unavailable",
                            "message": "listed upstream but detail returned 404",
                        },
                    )
                    continue
                # confirmed removed from the directory: nothing to recover,
                # and the durable wait entry must not linger
                self.store.clear_pending_read(org_id, cert_no)
                continue
            recovered[cert_no] = _entry_from_detail(detail)

        # 2. retry held correction groups --------------------------------
        group_held: list[dict[str, Any]] = []
        for item in pending:
            rt._check_abort()
            if not self._due(item["updated_at"], item["attempts"]):
                continue
            expected = set(item["expected"]) | set(item["old_cert_nos"])
            details: dict[str, dict[str, Any]] = {}
            blocked = False
            removed: set[str] = set()
            for cert_no in sorted(expected):
                try:
                    detail = rt.call(lambda a, no=cert_no: a.detail(no))
                except NotFound:
                    if self._is_listed(rt, cert_no):
                        blocked = True
                        still_blocked.add(cert_no)
                        self.store.upsert_pending_read(
                            org_id,
                            cert_no,
                            reason="correction_member_404",
                            last_error={
                                "code": "detail_unavailable",
                                "message": "listed upstream but detail returned 404",
                            },
                        )
                        continue
                    # removed upstream: simply absent, consistent with source;
                    # drop any durable wait entry for it as well
                    removed.add(cert_no)
                    self.store.clear_pending_read(org_id, cert_no)
                    continue
                details[cert_no] = _entry_from_detail(detail)
            held: list[dict[str, Any]] = []
            entries = self._resolve_incremental_groups(rt, details, held)
            if blocked or held:
                group_held.append((item, held, blocked))
                continue
            self._publish_reconciled(rt, org_id, entries.values(), state)
            self.store.clear_pending_correction(org_id, item["correction_id"])
            for cert_no in expected:
                if cert_no in entries or cert_no in removed:
                    self.store.clear_pending_read(org_id, cert_no)
            state = self.store.get_state(org_id)

        # 3. publish recovered standalone reads --------------------------
        # Members of still-held correction groups are published atomically by
        # step 2; never publish a recovered group member on its own here.
        group_members: set[str] = set()
        for item in pending:
            group_members.update(item["expected"])
            group_members.update(item["old_cert_nos"])
        standalone = {no: entry for no, entry in recovered.items() if no not in group_members}
        if standalone:
            self._publish_reconciled(rt, org_id, standalone.values(), state)
            for cert_no in standalone:
                self.store.clear_pending_read(org_id, cert_no)

        # 4. record whatever is still waiting, with explicit status text -
        for item, held, blocked in group_held:
            expected = set(item["expected"]) | set(item["old_cert_nos"])
            self.store.upsert_pending_correction(
                org_id,
                item["correction_id"],
                old_cert_nos=item["old_cert_nos"],
                expected=sorted(expected),
                state="incomplete",
                last_error={
                    "code": "member_detail_unavailable" if blocked else "incomplete_correction",
                    "message": (
                        "listed member detail returned 404; correction waits"
                        if blocked
                        else "correction group not yet consistent upstream"
                    ),
                    "waiting_on": sorted(
                        {no for h in held for no in (h.get("expected_members") or [])}
                    ),
                },
            )
        if still_blocked:
            delay = self._blocked_delay(
                max(
                    [p["attempts"] for p in self.store.list_pending_reads(org_id)]
                    + [p["attempts"] for p in self.store.list_pending_corrections(org_id)]
                    or [1]
                )
            )
            rt.set_wait(
                "correction_pending",
                delay,
                {"cert_nos": sorted(still_blocked)},
            )

    def _publish_reconciled(
        self, rt: OrgRuntime, org_id: str, entries: Any, state: dict[str, Any]
    ) -> None:
        rows = list(entries)
        if not rows:
            return
        published = self.store.publish_incremental(
            org_id,
            rows,
            [],
            watermark_cursor=state["watermark_cursor"],
            watermark_seq=state["watermark_seq"],
            head_cursor=state["source_head_cursor"],
            head_seq=state["source_head_seq"],
        )
        if published is None:
            return
        self.invalidate_listing(org_id)

    def _schedule_recovery(self, org_id: str, reason: str) -> None:
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
