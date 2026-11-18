"""In-memory state shared by the two simulated calibration bodies.

The world deliberately behaves like a real (but small) upstream:

* a full catalog snapshot can be opened and paged through, it has an expiry;
* a cursor based change feed exists next to it, its cursors expire too;
* certificate details expose the *current* state by default, older revisions
  are available for a retention period only;
* revisions, revocations and multi-certificate corrections are supported;
* events can be duplicated, reordered and carry equal/back-dated display times;
* permissions are rate limited per body (concurrency, request interval) and
  transient failures / slow responses can be injected.

Everything is protected by one lock; HTTP handlers only read copies of the
state under that lock.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import math
import random
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from .util import UTC, iso, utcnow

CERT_PREFIX = "C-"


class WorldError(Exception):
    def __init__(self, status: int, code: str, message: str, *, retry_after: int | None = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.retry_after = retry_after


def _seed_cert(site: str, index: int) -> dict[str, Any]:
    no = f"{CERT_PREFIX}{1001 + index}"
    instruments = ["Analytical balance", "Pressure gauge", "Thermometer", "Oscilloscope", "pH meter"]
    makers = ["Mettler Toledo", "Sartorius", "Shimadzu", "Agilent", "Fluke"]
    return {
        "cert_no": no,
        "instrument": instruments[index % len(instruments)],
        "manufacturer": makers[index % len(makers)],
        "model": f"{site.upper()}-{2000 + index}",
        "serial_no": f"SN-{site.upper()}-{index:04d}",
        "calibration_date": f"2026-{(index % 9) + 1:02d}-{(index % 27) + 1:02d}",
        "valid_until": f"2027-{(index % 9) + 1:02d}-{(index % 27) + 1:02d}",
        "result": "pass",
        "temperature": "20.0 C",
    }


@dataclass
class HistoryEntry:
    revision: int
    status: str
    data: dict[str, Any]
    seq: int
    published_at: str
    retained_until: float


@dataclass
class CertRecord:
    cert_no: str
    revision: int
    status: str
    data: dict[str, Any]
    seq: int
    updated_at: str
    revoked_at: str | None = None
    correction_id: str | None = None
    correction_members: tuple[str, ...] = ()
    correction_olds: tuple[str, ...] = ()
    purged: bool = False
    history: list[HistoryEntry] = field(default_factory=list)


@dataclass
class Snapshot:
    snapshot_id: str
    seq: int
    created_at: float
    expires_at: float
    entries: list[dict[str, Any]]
    change_position: str


class World:
    def __init__(self, site: str, count: int = 20, seed: int = 7):
        self.site = site
        self.lock = threading.RLock()
        self.seq = 0
        self.events: list[dict[str, Any]] = []
        self.certs: dict[str, CertRecord] = {}
        self.snapshots: dict[str, Snapshot] = {}
        self.cursor_epoch = 0.0
        self.rng = random.Random(seed)
        self.config: dict[str, Any] = {
            "max_concurrency": 4,
            "min_interval_ms": 0,
            "failure_rate": 0.0,
            "slow_ms": 0,
            "retry_after": 0,
            "snapshot_ttl": 300.0,
            "cursor_ttl": 300.0,
            "history_retention": 120.0,
            "duplicate_events": False,
            "shuffle_events": False,
            "auto_update_ms": 0,
            "fail_requests": 0,
        }
        self._active = 0
        self._peak_active = 0
        self._last_request = 0.0
        self._auto_thread: threading.Thread | None = None
        self.counters: dict[str, int] = {
            "peak_active": 0,
            "requests": 0,
            "rate_limited": 0,
            "failures_injected": 0,
            "snapshots_opened": 0,
            "changes_calls": 0,
        }
        for i in range(count):
            data = _seed_cert(site, i)
            self.seq += 1
            rec = CertRecord(
                cert_no=data["cert_no"],
                revision=1,
                status="active",
                data=data,
                seq=self.seq,
                updated_at=iso(utcnow()),
            )
            rec.history.append(
                HistoryEntry(
                    revision=1,
                    status="active",
                    data=dict(data),
                    seq=self.seq,
                    published_at=rec.updated_at,
                    retained_until=time.time() + float(self.config["history_retention"]),
                )
            )
            self.certs[rec.cert_no] = rec
            self.events.append(
                self._event(rec.seq, "upsert", rec.cert_no, display_at=rec.updated_at)
            )

    # ------------------------------------------------------------------
    # helpers
    @staticmethod
    def retry_header(seconds: float) -> str:
        return f"{max(0.02, float(seconds)):.2f}"

    def _event(
        self,
        seq: int,
        kind: str,
        cert_no: str | None,
        *,
        correction_id: str | None = None,
        display_at: str | None = None,
    ) -> dict[str, Any]:
        return {
            "seq": seq,
            "event_id": f"{self.site}-ev-{seq}-{uuid.uuid4().hex[:8]}",
            "kind": kind,
            "cert_no": cert_no,
            "correction_id": correction_id,
            "display_at": display_at or iso(utcnow()),
        }

    def _next_seq(self) -> int:
        self.seq += 1
        return self.seq

    def _prune_history_locked(self, now: float | None = None) -> None:
        now = now if now is not None else time.time()
        for rec in self.certs.values():
            rec.history = [h for h in rec.history if h.retained_until > now]

    def _cert_view(self, rec: CertRecord) -> dict[str, Any]:
        correction = None
        if rec.correction_id:
            members = [
                no
                for no in rec.correction_members
                if no in self.certs and not self.certs[no].purged
            ]
            olds = [no for no in rec.correction_olds if no in self.certs and not self.certs[no].purged]
            correction = {
                "id": rec.correction_id,
                "members": members,
                "supersedes": olds,
            }
        return {
            "cert_no": rec.cert_no,
            "revision": rec.revision,
            "status": rec.status,
            "data": dict(rec.data),
            "seq": rec.seq,
            "updated_at": rec.updated_at,
            "revoked_at": rec.revoked_at,
            "correction": correction,
        }

    def _append_history_locked(self, rec: CertRecord, status: str, published_at: str) -> None:
        rec.history.append(
            HistoryEntry(
                revision=rec.revision,
                status=status,
                data=dict(rec.data),
                seq=rec.seq,
                published_at=published_at,
                retained_until=time.time() + float(self.config["history_retention"]),
            )
        )

    # ------------------------------------------------------------------
    # snapshot / cursor tokens
    def _make_cursor(self, seq: int) -> str:
        body = json.dumps(
            {"v": 1, "site": self.site, "seq": seq, "iat": time.time()},
            separators=(",", ":"),
        ).encode()
        return base64.urlsafe_b64encode(body).decode().rstrip("=")

    def _read_cursor(self, token: str) -> dict[str, Any]:
        if not token:
            raise WorldError(400, "invalid_cursor", "empty cursor")
        try:
            padded = token + "=" * (-len(token) % 4)
            body = json.loads(base64.urlsafe_b64decode(padded.encode()).decode())
        except Exception as exc:
            raise WorldError(400, "invalid_cursor", "cursor is not decodable") from exc
        if body.get("site") != self.site:
            raise WorldError(400, "invalid_cursor", "cursor belongs to another site")
        if float(body.get("iat", 0)) < self.cursor_epoch:
            raise WorldError(410, "cursor_expired", "cursor was invalidated")
        ttl = float(self.config["cursor_ttl"])
        if time.time() - float(body.get("iat", 0)) > ttl:
            raise WorldError(410, "cursor_expired", "cursor retention period has elapsed")
        return body

    def open_snapshot(self) -> Snapshot:
        with self.lock:
            now = time.time()
            self._prune_history_locked(now)
            seq = self.seq
            entries = []
            for rec in sorted(self.certs.values(), key=lambda r: r.cert_no):
                if rec.purged:
                    continue
                entries.append(
                    {
                        "cert_no": rec.cert_no,
                        "revision": rec.revision,
                        "status": rec.status,
                        "seq": rec.seq,
                        "updated_at": rec.updated_at,
                    }
                )
            snap = Snapshot(
                snapshot_id=f"snap-{uuid.uuid4().hex}",
                seq=seq,
                created_at=now,
                expires_at=now + float(self.config["snapshot_ttl"]),
                entries=entries,
                change_position=self._make_cursor(seq),
            )
            self.snapshots[snap.snapshot_id] = snap
            # prune old snapshots
            for sid, old in list(self.snapshots.items()):
                if old.expires_at < now - 3600:
                    self.snapshots.pop(sid, None)
            self.counters["snapshots_opened"] += 1
            return snap

    def get_snapshot(self, snapshot_id: str) -> Snapshot:
        with self.lock:
            snap = self.snapshots.get(snapshot_id)
            if snap is None:
                raise WorldError(404, "unknown_snapshot", "snapshot not found")
            if time.time() > snap.expires_at:
                raise WorldError(410, "snapshot_expired", "snapshot retention period has elapsed")
            return snap

    def snapshot_meta(self, snap: Snapshot) -> dict[str, Any]:
        return {
            "snapshot_id": snap.snapshot_id,
            "change_position": snap.change_position,
            "snapshot_seq": snap.seq,
            "expires_at": dt.datetime.fromtimestamp(snap.expires_at, UTC).isoformat().replace("+00:00", "Z"),
            "total": len(snap.entries),
        }

    # ------------------------------------------------------------------
    # reads
    def catalog_page(self, snapshot_id: str, page: int, page_size: int) -> dict[str, Any]:
        snap = self.get_snapshot(snapshot_id)
        if page < 1:
            raise WorldError(400, "invalid_page", "page must be >= 1")
        start = (page - 1) * page_size
        items = snap.entries[start : start + page_size]
        pages = max(1, math.ceil(len(snap.entries) / page_size))
        return {
            "snapshot": self.snapshot_meta(snap),
            "items": [dict(i) for i in items],
            "page": page,
            "page_size": page_size,
            "pages": pages,
            "next_page": page + 1 if page < pages else None,
        }

    def detail(self, cert_no: str, revision: int | None = None) -> dict[str, Any]:
        with self.lock:
            self._prune_history_locked()
            rec = self.certs.get(cert_no)
            if rec is None or rec.purged:
                raise WorldError(404, "cert_not_found", "certificate not found")
            if revision is None or revision == rec.revision:
                return self._cert_view(rec)
            for entry in rec.history:
                if entry.revision == revision:
                    out = {
                        "cert_no": rec.cert_no,
                        "revision": entry.revision,
                        "status": entry.status,
                        "data": dict(entry.data),
                        "seq": entry.seq,
                        "updated_at": entry.published_at,
                        "revoked_at": None,
                        "correction": self._cert_view(rec)["correction"],
                        "historical": True,
                    }
                    return out
            if 1 <= revision < rec.revision:
                raise WorldError(410, "history_expired", "historical revision is no longer retained")
            raise WorldError(404, "revision_not_found", "revision not found")

    def changes(self, cursor: str, limit: int) -> dict[str, Any]:
        with self.lock:
            self.counters["changes_calls"] += 1
            body = self._read_cursor(cursor)
            start = int(body.get("seq", 0))
            if limit <= 0:
                limit = 50
            # The feed window is defined by sequence numbers, not by the order
            # in which events happen to be returned: that keeps reordering and
            # duplicated delivery harmless for consumers.
            window_end = min(self.seq, start + limit)
            candidates = [dict(e) for e in self.events if start < e["seq"] <= window_end]
            if self.config.get("shuffle_events"):
                self.rng.shuffle(candidates)
            if self.config.get("duplicate_events") and candidates:
                dup = dict(candidates[-1])
                dup["duplicate"] = True
                candidates.insert(0, dup)
            return {
                "items": candidates,
                "next_cursor": self._make_cursor(window_end),
                "next_seq": window_end,
                "head_seq": self.seq,
                "has_more": window_end < self.seq,
                "cursor_ttl": self.config["cursor_ttl"],
            }

    # ------------------------------------------------------------------
    # mutations (admin / continuous updates)
    def add_cert(self, cert_no: str, data: dict[str, Any], display_at: str | None = None) -> dict[str, Any]:
        with self.lock:
            self._prune_history_locked()
            if cert_no in self.certs and not self.certs[cert_no].purged:
                raise WorldError(409, "cert_exists", "certificate already exists")
            seq = self._next_seq()
            when = display_at or iso(utcnow())
            payload = dict(data)
            payload["cert_no"] = cert_no
            rec = CertRecord(
                cert_no=cert_no,
                revision=1,
                status="active",
                data=payload,
                seq=seq,
                updated_at=when,
            )
            rec.history.append(
                HistoryEntry(
                    revision=1,
                    status="active",
                    data=dict(payload),
                    seq=seq,
                    published_at=when,
                    retained_until=time.time() + float(self.config["history_retention"]),
                )
            )
            self.certs[cert_no] = rec
            self.events.append(self._event(seq, "upsert", cert_no, display_at=when))
            return self._cert_view(rec)

    def revise_cert(
        self,
        cert_no: str,
        changes: dict[str, Any] | None = None,
        display_at: str | None = None,
    ) -> dict[str, Any]:
        with self.lock:
            self._prune_history_locked()
            rec = self.certs.get(cert_no)
            if rec is None or rec.purged:
                raise WorldError(404, "cert_not_found", "certificate not found")
            if rec.status == "revoked":
                raise WorldError(409, "cert_revoked", "revoked certificates cannot be revised")
            seq = self._next_seq()
            when = display_at or iso(utcnow())
            rec.revision += 1
            rec.seq = seq
            rec.updated_at = when
            rec.data.update(changes or {})
            rec.data["cert_no"] = cert_no
            rec.history.append(
                HistoryEntry(
                    revision=rec.revision,
                    status=rec.status,
                    data=dict(rec.data),
                    seq=seq,
                    published_at=when,
                    retained_until=time.time() + float(self.config["history_retention"]),
                )
            )
            self.events.append(self._event(seq, "upsert", cert_no, display_at=when))
            return self._cert_view(rec)

    def revoke_cert(self, cert_no: str, display_at: str | None = None) -> dict[str, Any]:
        with self.lock:
            self._prune_history_locked()
            rec = self.certs.get(cert_no)
            if rec is None or rec.purged:
                raise WorldError(404, "cert_not_found", "certificate not found")
            if rec.status == "revoked":
                raise WorldError(409, "already_revoked", "certificate already revoked")
            seq = self._next_seq()
            when = display_at or iso(utcnow())
            rec.status = "revoked"
            rec.revoked_at = when
            rec.seq = seq
            rec.updated_at = when
            rec.history.append(
                HistoryEntry(
                    revision=rec.revision,
                    status="revoked",
                    data=dict(rec.data),
                    seq=seq,
                    published_at=when,
                    retained_until=time.time() + float(self.config["history_retention"]),
                )
            )
            self.events.append(self._event(seq, "revoke", cert_no, display_at=when))
            return self._cert_view(rec)

    def correction(
        self,
        old_cert_no: str,
        replacements: list[dict[str, Any]],
        *,
        retire_old: bool = True,
        display_at: str | None = None,
    ) -> dict[str, Any]:
        """Apply a formal correction atomically.

        The old certificate is revoked and every replacement is published in
        one lock acquisition.  Each resulting certificate exposes the complete
        correction membership through its detail response; the change feed only
        gets one event per member, so a client must resolve membership through
        detail pages.
        """
        with self.lock:
            self._prune_history_locked()
            old = self.certs.get(old_cert_no)
            if old is None or old.purged:
                raise WorldError(404, "cert_not_found", "old certificate not found")
            if old.status == "revoked":
                raise WorldError(409, "cert_revoked", "old certificate is already revoked")
            if not replacements:
                raise WorldError(400, "no_replacements", "at least one replacement is required")
            new_nos: list[str] = []
            for rep in replacements:
                no = rep.get("cert_no")
                if not no:
                    raise WorldError(400, "invalid_replacement", "replacement needs cert_no")
                if no == old_cert_no or (no in self.certs and not self.certs[no].purged):
                    raise WorldError(409, "cert_exists", f"replacement {no} already exists")
                if no in new_nos:
                    raise WorldError(409, "cert_exists", f"duplicate replacement {no}")
                new_nos.append(no)

            correction_id = f"corr-{uuid.uuid4().hex[:10]}"
            group = tuple(new_nos + ([old_cert_no] if retire_old else []))
            olds = (old_cert_no,) if retire_old else ()
            when = display_at or iso(utcnow())
            created: list[dict[str, Any]] = []

            # publish replacements first
            for rep, no in zip(replacements, new_nos):
                seq = self._next_seq()
                payload = dict(rep.get("data") or {})
                payload.pop("cert_no", None)
                payload["cert_no"] = no
                rec = CertRecord(
                    cert_no=no,
                    revision=1,
                    status="active",
                    data=payload,
                    seq=seq,
                    updated_at=rep.get("updated_at") or when,
                    correction_id=correction_id,
                    correction_members=group,
                    correction_olds=olds,
                )
                stamp = rec.updated_at
                rec.history.append(
                    HistoryEntry(
                        revision=1,
                        status="active",
                        data=dict(payload),
                        seq=seq,
                        published_at=stamp,
                        retained_until=time.time() + float(self.config["history_retention"]),
                    )
                )
                self.certs[no] = rec
                self.events.append(
                    self._event(seq, "correction", no, correction_id=correction_id, display_at=stamp)
                )
                created.append(self._cert_view(rec))

            if retire_old:
                seq = self._next_seq()
                old.status = "revoked"
                old.revoked_at = when
                old.seq = seq
                old.updated_at = when
                old.correction_id = correction_id
                old.correction_members = group
                old.correction_olds = olds
                old.history.append(
                    HistoryEntry(
                        revision=old.revision,
                        status="revoked",
                        data=dict(old.data),
                        seq=seq,
                        published_at=when,
                        retained_until=time.time() + float(self.config["history_retention"]),
                    )
                )
                self.events.append(
                    self._event(seq, "correction", old_cert_no, correction_id=correction_id, display_at=when)
                )
            return {
                "correction_id": correction_id,
                "members": list(group),
                "supersedes": list(olds),
                "created": created,
                "old": self._cert_view(old),
            }

    def purge_cert(self, cert_no: str, display_at: str | None = None) -> dict[str, Any]:
        with self.lock:
            rec = self.certs.get(cert_no)
            if rec is None or rec.purged:
                raise WorldError(404, "cert_not_found", "certificate not found")
            seq = self._next_seq()
            when = display_at or iso(utcnow())
            rec.purged = True
            rec.seq = seq
            rec.updated_at = when
            self.events.append(self._event(seq, "delete", cert_no, display_at=when))
            return {"cert_no": cert_no, "deleted": True, "seq": seq}

    # ------------------------------------------------------------------
    # admin helpers
    def state(self) -> dict[str, Any]:
        with self.lock:
            self._prune_history_locked()
            certs = []
            for rec in sorted(self.certs.values(), key=lambda r: r.cert_no):
                if rec.purged:
                    continue
                certs.append(self._cert_view(rec))
            return {
                "site": self.site,
                "seq": self.seq,
                "certs": certs,
                "cert_count": len(certs),
                "corrections": sorted(
                    {
                        r.correction_id
                        for r in self.certs.values()
                        if r.correction_id and not r.purged
                    }
                ),
                "config": dict(self.config),
                "counters": dict(self.counters),
                "active_requests": self._active,
                "snapshots": len(self.snapshots),
            }

    def update_config(self, changes: dict[str, Any]) -> dict[str, Any]:
        with self.lock:
            for key, value in changes.items():
                if key in self.config:
                    self.config[key] = value
            self.cursor_epoch = 0.0
            return dict(self.config)

    def expire_all(self) -> None:
        with self.lock:
            self.cursor_epoch = time.time() + 1.0
            for snap in self.snapshots.values():
                snap.expires_at = time.time() - 1.0
            self.snapshots.clear()
            # expire retained historical revisions as well
            now = time.time()
            for rec in self.certs.values():
                for entry in rec.history:
                    entry.retained_until = min(entry.retained_until, now - 1.0)

    def reset(self, count: int = 20) -> None:
        with self.lock:
            self.stop_auto_updates()
            self.seq = 0
            self.events.clear()
            self.certs.clear()
            self.snapshots.clear()
            self.cursor_epoch = 0.0
            self.counters = {k: 0 for k in self.counters}
            for i in range(count):
                data = _seed_cert(self.site, i)
                self.seq += 1
                when = iso(utcnow())
                rec = CertRecord(
                    cert_no=data["cert_no"],
                    revision=1,
                    status="active",
                    data=data,
                    seq=self.seq,
                    updated_at=when,
                )
                rec.history.append(
                    HistoryEntry(
                        revision=1,
                        status="active",
                        data=dict(data),
                        seq=self.seq,
                        published_at=when,
                        retained_until=time.time() + float(self.config["history_retention"]),
                    )
                )
                self.certs[rec.cert_no] = rec
                self.events.append(self._event(rec.seq, "upsert", rec.cert_no, display_at=when))

    # ------------------------------------------------------------------
    # rate limiting / fault injection
    def acquire(self) -> tuple[int | None, float, float]:
        """Return (error_status, retry_after_seconds, delay_seconds)."""
        with self.lock:
            now = time.time()
            self.counters["requests"] += 1
            max_conc = int(self.config["max_concurrency"])
            interval = float(self.config["min_interval_ms"]) / 1000.0
            retry = float(self.config["retry_after"])
            if max_conc > 0 and self._active >= max_conc:
                self.counters["rate_limited"] += 1
                return 429, retry or 0.05, 0.0
            if interval > 0 and now - self._last_request < interval:
                remain = interval - (now - self._last_request)
                self.counters["rate_limited"] += 1
                # Retry-After must reflect the wait that would actually succeed,
                # so never advertise less than the remaining minimum spacing.
                return 429, max(retry, remain, 0.01), 0.0
            self._active += 1
            if self._active > self.counters["peak_active"]:
                self.counters["peak_active"] = self._active
            self._last_request = now
            delay = float(self.config["slow_ms"]) / 1000.0
            if int(self.config.get("fail_requests") or 0) > 0:
                self.config["fail_requests"] = int(self.config["fail_requests"]) - 1
                self.counters["failures_injected"] += 1
                self._active -= 1
                return 503, retry or 0.05, delay
            if self.config["failure_rate"] and self.rng.random() < float(self.config["failure_rate"]):
                self.counters["failures_injected"] += 1
                self._active -= 1
                return 503, retry or 0.05, delay
            return None, 0.0, delay

    def release(self) -> None:
        with self.lock:
            if self._active > 0:
                self._active -= 1

    # ------------------------------------------------------------------
    # optional continuous updates
    def start_auto_updates(self, interval_ms: int) -> None:
        with self.lock:
            self.stop_auto_updates()
            self.config["auto_update_ms"] = interval_ms
            if interval_ms <= 0:
                return

            def loop():
                while True:
                    time.sleep(max(0.02, interval_ms / 1000.0))
                    with self.lock:
                        if self.config["auto_update_ms"] <= 0:
                            return
                        active = [r for r in self.certs.values() if r.status == "active" and not r.purged]
                        if not active:
                            continue
                        rec = self.rng.choice(active)
                        try:
                            self.revise_cert(
                                rec.cert_no,
                                {"temperature": f"{20 + self.rng.randint(0, 5)}.0 C"},
                            )
                        except WorldError:
                            pass

            thread = threading.Thread(target=loop, name=f"sim-auto-{self.site}", daemon=True)
            self._auto_thread = thread
            thread.start()

    def stop_auto_updates(self) -> None:
        self.config["auto_update_ms"] = 0
        self._auto_thread = None
