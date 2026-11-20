"""Persistence operations for orgs, runs, scans, catalog publication and exports.

A few invariants are enforced here rather than in the engine:

* a published catalog only ever advances its watermark (never regresses);
* full publication replaces the whole certificate set in one transaction;
* an export is a materialized copy of one published catalog version, so all of
  its pages stay consistent while collection and rebuilds keep running;
* retention pruning keeps finished runs/exports from growing unbounded.
"""

from __future__ import annotations

import datetime as dt
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterable

from .db import Database
from .util import (
    Conflict,
    LeaseLost,
    parse_iso,
    Gone,
    NotFound,
    dumps,
    iso,
    loads,
    utcnow,
)

RUN_ACTIVE = ("queued", "running", "paused", "interrupted")
RUN_FINISHED = ("succeeded", "failed", "superseded", "cancelled")


def _now() -> str:
    return iso(utcnow())


@dataclass(frozen=True)
class Lease:
    """Ownership of one organization by one collector process.

    ``epoch`` increases every time ownership changes hands and is the fencing
    token for every write that touches that organization's task state or
    catalog.  A process whose lease has been taken over can keep running its
    (now useless) in-memory work, but none of its late writes can land.
    """

    org_id: str
    owner_id: str
    epoch: int

    def as_dict(self) -> dict[str, Any]:
        return {"org_id": self.org_id, "owner_id": self.owner_id, "epoch": self.epoch}


@dataclass(frozen=True)
class LeaseGrant:
    lease: Lease
    #: True when this call created or took over the lease (as opposed to
    #: simply renewing a lease this process already holds).
    acquired: bool


class Store:
    def __init__(self, db: Database):
        self.db = db
        self._lease_local = threading.local()

    # ------------------------------------------------------------------
    # leases / write fencing
    #
    # Several collector processes may share one database.  Each organization is
    # worked on by exactly one process at a time, which holds a short lease in
    # ``org_leases``.  ``epoch`` is bumped whenever ownership changes hands and
    # is the fencing token: every write that could alter task state or the
    # published catalog is conditioned on the calling thread's bound lease, so
    # a process that lost ownership (was killed, paused too long, or simply
    # outlived its lease) cannot apply late results over the new owner's state.
    @contextmanager
    def fence(self, lease: "Lease | None"):
        previous = getattr(self._lease_local, "lease", None)
        self._lease_local.lease = lease
        try:
            yield lease
        finally:
            self._lease_local.lease = previous

    def _current_lease(self) -> "Lease | None":
        return getattr(self._lease_local, "lease", None)

    def _lease_row(self, tx, org_id: str) -> dict[str, Any] | None:
        sql = "SELECT * FROM org_leases WHERE org_id=?"
        if self.db.is_postgres:
            sql += " FOR UPDATE"
        return tx.fetchone(self.db._translate(sql), (org_id,))

    def _assert_lease_in_tx(
        self, tx, org_id: str, *, row_epoch: int | None = None
    ) -> "Lease | None":
        lease = self._current_lease()
        if lease is None:
            return None
        row = self._lease_row(tx, org_id)
        if (
            row is None
            or row["owner_id"] != lease.owner_id
            or int(row["epoch"]) != lease.epoch
        ):
            raise LeaseLost(
                "organization lease is no longer held by this process",
                details={"org_id": org_id, "epoch": lease.epoch},
            )
        if row_epoch is not None and int(row_epoch) != lease.epoch:
            raise LeaseLost(
                "row belongs to a previous owner",
                details={"org_id": org_id, "row_epoch": int(row_epoch), "epoch": lease.epoch},
            )
        return lease

    # Note: rows written before leases existed (or by internal callers with no
    # bound lease) carry owner_epoch NULL.  Such rows are always claimable by
    # the current owner; ``claim_next_run``/``create_scan`` stamp the epoch on
    # them, after which they are fenced like any other row.

    def try_acquire_lease(self, org_id: str, owner_id: str, ttl: float) -> "LeaseGrant | None":
        """Acquire or renew ``org_id``.

        Returns ``None`` when a *live* lease is held by another owner; the
        caller must then stay passive for this organization.  An expired lease
        is taken over with an incremented epoch.
        """
        now = time.time()
        expires = now + max(0.0, float(ttl))
        stamp = _now()
        with self.db.transaction(write=True) as tx:
            row = self._lease_row(tx, org_id)
            if row is None:
                tx.execute(
                    self.db._translate(
                        "INSERT INTO org_leases(org_id,owner_id,epoch,heartbeat_at,"
                        "expires_at,updated_at) VALUES (?,?,?,?,?,?)"
                    ),
                    (org_id, owner_id, 1, stamp, expires, stamp),
                )
                return LeaseGrant(Lease(org_id, owner_id, 1), True)
            if row["owner_id"] == owner_id:
                if float(row["expires_at"]) > now:
                    tx.execute(
                        self.db._translate(
                            "UPDATE org_leases SET heartbeat_at=?, expires_at=?, updated_at=? "
                            "WHERE org_id=? AND owner_id=?"
                        ),
                        (stamp, expires, stamp, org_id, owner_id),
                    )
                    return LeaseGrant(Lease(org_id, owner_id, int(row["epoch"])), False)
                # Our own lease had lapsed (e.g. this process was restarted
                # under the same owner id).  Re-acquire it as a takeover so
                # left-over work is reclaimed and old-epoch writes are fenced.
                epoch = int(row["epoch"]) + 1
                tx.execute(
                    self.db._translate(
                        "UPDATE org_leases SET epoch=?, heartbeat_at=?, expires_at=?, updated_at=? "
                        "WHERE org_id=? AND epoch=?"
                    ),
                    (epoch, stamp, expires, stamp, org_id, int(row["epoch"])),
                )
                return LeaseGrant(Lease(org_id, owner_id, epoch), True)
            if float(row["expires_at"]) > now:
                return None
            epoch = int(row["epoch"]) + 1
            tx.execute(
                self.db._translate(
                    "UPDATE org_leases SET owner_id=?, epoch=?, heartbeat_at=?, "
                    "expires_at=?, updated_at=? WHERE org_id=? AND epoch=?"
                ),
                (owner_id, epoch, stamp, expires, stamp, org_id, int(row["epoch"])),
            )
            return LeaseGrant(Lease(org_id, owner_id, epoch), True)

    def renew_lease(self, lease: "Lease", ttl: float) -> "Lease | None":
        """Extend a held lease; ``None`` means it was lost to another owner."""
        return self._lease_liveness(lease, ttl)

    def _lease_liveness(self, lease: "Lease", ttl: float) -> "Lease | None":
        now = time.time()
        expires = now + max(0.0, float(ttl))
        stamp = _now()
        with self.db.transaction(write=True) as tx:
            row = self._lease_row(tx, lease.org_id)
            if (
                row is None
                or row["owner_id"] != lease.owner_id
                or int(row["epoch"]) != lease.epoch
            ):
                return None
            tx.execute(
                self.db._translate(
                    "UPDATE org_leases SET heartbeat_at=?, expires_at=?, updated_at=? "
                    "WHERE org_id=? AND owner_id=? AND epoch=?"
                ),
                (stamp, expires, stamp, lease.org_id, lease.owner_id, lease.epoch),
            )
            return lease

    def list_org_leases(self) -> list[dict[str, Any]]:
        now = time.time()
        return [
            {
                "org_id": r["org_id"],
                "owner": r["owner_id"],
                "epoch": int(r["epoch"]),
                "heartbeat_at": r["heartbeat_at"],
                "expires_at": r["expires_at"],
                "live": float(r["expires_at"]) > now,
            }
            for r in self.db.query("SELECT * FROM org_leases ORDER BY org_id")
        ]

    def release_lease(self, lease: "Lease", *, expired: bool = True) -> None:
        """Give up a lease so the next process can take over immediately."""
        with self.db.transaction(write=True) as tx:
            row = self._lease_row(tx, lease.org_id)
            if (
                row is None
                or row["owner_id"] != lease.owner_id
                or int(row["epoch"]) != lease.epoch
            ):
                return
            if expired:
                # Let any other process acquire without waiting out the TTL.
                tx.execute(
                    self.db._translate(
                        "UPDATE org_leases SET expires_at=?, updated_at=? "
                        "WHERE org_id=? AND owner_id=? AND epoch=?"
                    ),
                    (0.0, _now(), lease.org_id, lease.owner_id, lease.epoch),
                )
            else:
                tx.execute(
                    self.db._translate("DELETE FROM org_leases WHERE org_id=?"), (lease.org_id,)
                )

    def reclaim_org_work(self, lease: "Lease") -> dict[str, int]:
        """Take over work left behind by the previous owner.

        Runs that were in flight are queued again; their staged scans are
        marked interrupted so the resuming full lane starts from a fresh
        snapshot instead of trusting half-written staging rows.  Every adopted
        row is stamped with the new epoch, so a late write from the previous
        owner is fenced out.
        """
        stamp = _now()
        with self.db.transaction(write=True) as tx:
            self._assert_lease_in_tx(tx, lease.org_id)
            runs = tx.execute(
                self.db._translate(
                    "UPDATE runs SET status='queued', reason='resumed_after_takeover', "
                    "owner_id=?, owner_epoch=?, updated_at=? "
                    "WHERE org_id=? AND status IN ('running','interrupted')"
                ),
                (lease.owner_id, lease.epoch, stamp, lease.org_id),
            ).rowcount
            scans = tx.execute(
                self.db._translate(
                    "UPDATE scans SET status='interrupted', owner_id=?, owner_epoch=?, "
                    "updated_at=? WHERE org_id=? AND status IN "
                    "('listing','fetching','catching_up','interrupted') "
                    "AND (owner_epoch IS NULL OR owner_epoch <> ?)"
                ),
                (lease.owner_id, lease.epoch, stamp, lease.org_id, lease.epoch),
            ).rowcount
        return {"runs": int(runs or 0), "scans": int(scans or 0)}

    # -- shared access budget -------------------------------------------
    def load_access(self, org_id: str) -> dict[str, float]:
        row = self.db.query_one("SELECT * FROM org_access WHERE org_id=?", (org_id,))
        if row is None:
            return {
                "next_allowed_at": 0.0,
                "cooldown_until": 0.0,
                "adaptive_interval": 0.0,
                "last_request_at": 0.0,
            }
        return {
            "next_allowed_at": float(row["next_allowed_at"]),
            "cooldown_until": float(row["cooldown_until"]),
            "adaptive_interval": float(row["adaptive_interval"]),
            "last_request_at": float(row["last_request_at"]),
        }

    def save_access(
        self,
        org_id: str,
        *,
        next_allowed_at: float,
        cooldown_until: float,
        adaptive_interval: float,
        last_request_at: float,
    ) -> None:
        now = _now()
        with self.db.transaction(write=True) as tx:
            existing = tx.fetchone(
                self.db._translate("SELECT org_id FROM org_access WHERE org_id=?"), (org_id,)
            )
            if existing is None:
                tx.execute(
                    self.db._translate(
                        "INSERT INTO org_access(org_id,next_allowed_at,cooldown_until,"
                        "adaptive_interval,last_request_at,updated_at) VALUES (?,?,?,?,?,?)"
                    ),
                    (org_id, next_allowed_at, cooldown_until, adaptive_interval, last_request_at, now),
                )
            else:
                tx.execute(
                    self.db._translate(
                        "UPDATE org_access SET next_allowed_at=?, cooldown_until=?, "
                        "adaptive_interval=?, last_request_at=?, updated_at=? WHERE org_id=?"
                    ),
                    (
                        next_allowed_at,
                        cooldown_until,
                        adaptive_interval,
                        last_request_at,
                        now,
                        org_id,
                    ),
                )

    # -- collector process registry --------------------------------------
    def register_collector(self, owner_id: str, ttl: float, *, pid: int | None = None,
                           host: str | None = None) -> None:
        now = time.time()
        stamp = _now()
        expires = now + max(0.0, float(ttl))
        with self.db.transaction(write=True) as tx:
            row = tx.fetchone(
                self.db._translate("SELECT owner_id FROM collectors WHERE owner_id=?"), (owner_id,)
            )
            if row is None:
                tx.execute(
                    self.db._translate(
                        "INSERT INTO collectors(owner_id,started_at,heartbeat_at,expires_at,pid,host) "
                        "VALUES (?,?,?,?,?,?)"
                    ),
                    (owner_id, stamp, stamp, expires, pid, host),
                )
            else:
                tx.execute(
                    self.db._translate(
                        "UPDATE collectors SET heartbeat_at=?, expires_at=?, pid=?, host=? "
                        "WHERE owner_id=?"
                    ),
                    (stamp, expires, pid, host, owner_id),
                )

    def heartbeat_collector(self, owner_id: str, ttl: float) -> bool:
        expires = time.time() + max(0.0, float(ttl))
        with self.db.transaction(write=True) as tx:
            row = tx.execute(
                self.db._translate(
                    "UPDATE collectors SET heartbeat_at=?, expires_at=? WHERE owner_id=?"
                ),
                (_now(), expires, owner_id),
            )
            return bool(row.rowcount)

    def unregister_collector(self, owner_id: str) -> None:
        self.execute_checked("DELETE FROM collectors WHERE owner_id=?", (owner_id,))

    def collector_alive(self, owner_id: str | None) -> bool:
        if not owner_id:
            return False
        row = self.db.query_one("SELECT expires_at FROM collectors WHERE owner_id=?", (owner_id,))
        return bool(row and float(row["expires_at"]) > time.time())

    def list_collectors(self) -> list[dict[str, Any]]:
        now = time.time()
        return [
            {
                "owner_id": r["owner_id"],
                "started_at": r["started_at"],
                "heartbeat_at": r["heartbeat_at"],
                "expires_at": r["expires_at"],
                "alive": float(r["expires_at"]) > now,
                "pid": r["pid"],
                "host": r["host"],
            }
            for r in self.db.query("SELECT * FROM collectors ORDER BY owner_id")
        ]

    # ------------------------------------------------------------------
    # orgs
    def upsert_org(
        self,
        org_id: str,
        name: str,
        source: dict[str, Any],
        limits: dict[str, Any],
        options: dict[str, Any],
    ) -> dict[str, Any]:
        now = _now()
        with self.db.transaction(write=True) as tx:
            existing = tx.fetchone(
                self.db._translate("SELECT * FROM orgs WHERE org_id=?"), (org_id,)
            )
            if existing is None:
                tx.execute(
                    self.db._translate(
                        "INSERT INTO orgs(org_id,name,source_config,limits,options,enabled,paused,"
                        "created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)"
                    ),
                    (org_id, name, dumps(source), dumps(limits), dumps(options), 1, 0, now, now),
                )
                tx.execute(
                    self.db._translate(
                        "INSERT INTO catalog_state(org_id,version,ready,cert_count,updated_at) "
                        "VALUES (?,?,?,?,?)"
                    ),
                    (org_id, 0, 0, 0, now),
                )
            else:
                tx.execute(
                    self.db._translate(
                        "UPDATE orgs SET name=?, source_config=?, limits=?, options=?, updated_at=? "
                        "WHERE org_id=?"
                    ),
                    (name, dumps(source), dumps(limits), dumps(options), now, org_id),
                )
        return self.get_org(org_id)

    def get_org(self, org_id: str) -> dict[str, Any]:
        row = self.db.query_one("SELECT * FROM orgs WHERE org_id=?", (org_id,))
        if row is None:
            raise NotFound("organization not found", details={"org_id": org_id})
        return self._org_view(row)

    def list_orgs(self) -> list[dict[str, Any]]:
        return [self._org_view(r) for r in self.db.query("SELECT * FROM orgs ORDER BY org_id")]

    @staticmethod
    def _org_view(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "org_id": row["org_id"],
            "name": row["name"],
            "source": loads(row["source_config"], {}),
            "limits": loads(row["limits"], {}),
            "options": loads(row["options"], {}),
            "enabled": bool(row["enabled"]),
            "paused": bool(row["paused"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def set_paused(self, org_id: str, paused: bool) -> dict[str, Any]:
        self.execute_checked(
            "UPDATE orgs SET paused=?, updated_at=? WHERE org_id=?", (int(paused), _now(), org_id)
        )
        return self.get_org(org_id)

    def execute_checked(self, sql: str, params: Iterable[Any]) -> None:
        with self.db.transaction(write=True) as tx:
            tx.execute(self.db._translate(sql), tuple(params))

    # ------------------------------------------------------------------
    # catalog state
    def get_state(self, org_id: str) -> dict[str, Any]:
        row = self.db.query_one("SELECT * FROM catalog_state WHERE org_id=?", (org_id,))
        if row is None:
            raise NotFound("catalog state not found", details={"org_id": org_id})
        return {
            "org_id": row["org_id"],
            "version": int(row["version"]),
            "ready": bool(row["ready"]),
            "published_at": row["published_at"],
            "watermark_cursor": row["watermark_cursor"],
            "watermark_seq": int(row["watermark_seq"]),
            "source_head_cursor": row["source_head_cursor"],
            "source_head_seq": int(row["source_head_seq"]),
            "cert_count": int(row["cert_count"]),
            "last_error": loads(row["last_error"]) if row["last_error"] else None,
            "updated_at": row["updated_at"],
            "caught_up": int(row["watermark_seq"]) >= int(row["source_head_seq"])
            and int(row["source_head_seq"]) >= 0,
        }

    def set_last_error(self, org_id: str, error: dict[str, Any] | None) -> None:
        self.execute_checked(
            "UPDATE catalog_state SET last_error=?, updated_at=? WHERE org_id=?",
            (dumps(error) if error else None, _now(), org_id),
        )

    def _cert_row_tuple(self, org_id: str, entry: dict[str, Any], seq: int = -1) -> tuple:
        return (
            org_id,
            entry["cert_no"],
            int(entry["revision"]),
            entry["status"],
            dumps(entry["data"]),
            entry.get("source_updated_at"),
            entry.get("revoked_at"),
            entry.get("correction_id"),
            dumps(entry.get("correction")) if entry.get("correction") else None,
            _now(),
            int(entry.get("source_seq", seq)),
        )

    CERT_INSERT = (
        "INSERT INTO certs(org_id,cert_no,revision,status,payload,source_updated_at,"
        "revoked_at,correction_id,correction,local_updated_at,source_seq) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?) "
        # A rebuild publishes a snapshot that may be older than a row already
        # written by a concurrent incremental window.  Keeping the newer row
        # (higher revision, or a revocation of the same revision) prevents a
        # rebuild from reverting content that is already current.
        "ON CONFLICT(org_id, cert_no) DO UPDATE SET "
        "revision=excluded.revision, status=excluded.status, payload=excluded.payload, "
        "source_updated_at=excluded.source_updated_at, revoked_at=excluded.revoked_at, "
        "correction_id=excluded.correction_id, correction=excluded.correction, "
        "local_updated_at=excluded.local_updated_at "
        "WHERE (excluded.revision > certs.revision) "
        "OR (excluded.revision = certs.revision AND certs.status <> 'revoked')"
    )

    def publish_full(
        self,
        org_id: str,
        entries: list[dict[str, Any]],
        *,
        watermark_cursor: str | None,
        watermark_seq: int,
        head_cursor: str | None,
        head_seq: int,
        run_id: str | None = None,
    ) -> dict[str, Any] | None:
        """Atomically replace the published catalog.

        Returns ``None`` when the swap would move the watermark backwards; in
        that case nothing is written and the caller must catch up first.
        """
        if watermark_seq < 0:
            return None
        with self.db.transaction(write=True) as tx:
            self._assert_lease_in_tx(tx, org_id)
            state = tx.fetchone(
                self.db._translate("SELECT * FROM catalog_state WHERE org_id=?"), (org_id,)
            )
            if state is None:
                raise NotFound("catalog state not found")
            if int(watermark_seq) < int(state["watermark_seq"]):
                return None
            # Rows not in the snapshot must leave the catalog, but the delete is
            # expressed after the upserts so the monotonic guard above decides
            # which version of a shared number survives.
            snapshot_nos = {e["cert_no"] for e in entries}
            existing = {
                r["cert_no"]: int(r["source_seq"])
                for r in tx.fetchall(
                    self.db._translate("SELECT cert_no, source_seq FROM certs WHERE org_id=?"),
                    (org_id,),
                )
            }
            rows = [self._cert_row_tuple(org_id, e, watermark_seq) for e in entries]
            if rows:
                tx.executemany(self.db._translate(self.CERT_INSERT), rows)
            # A row written by a newer incremental window (source_seq beyond the
            # snapshot's position) is current and must not be dropped by a
            # rebuild that has not seen it yet.
            stale = sorted(
                no
                for no, seq in existing.items()
                if no not in snapshot_nos and seq <= int(watermark_seq)
            )
            if stale:
                tx.executemany(
                    self.db._translate("DELETE FROM certs WHERE org_id=? AND cert_no=?"),
                    [(org_id, no) for no in stale],
                )
            now = _now()
            version = int(state["version"]) + 1
            tx.execute(
                self.db._translate(
                    "UPDATE catalog_state SET version=?, ready=1, published_at=?, "
                    "watermark_cursor=?, watermark_seq=?, source_head_cursor=?, "
                    "source_head_seq=?, cert_count=?, last_error=NULL, updated_at=? "
                    "WHERE org_id=?"
                ),
                (
                    version,
                    now,
                    watermark_cursor,
                    int(watermark_seq),
                    head_cursor,
                    int(head_seq),
                    len(entries),
                    now,
                    org_id,
                ),
            )
            return {
                "version": version,
                "published_at": now,
                "cert_count": len(entries),
                "watermark_seq": int(watermark_seq),
            }

    def publish_incremental(
        self,
        org_id: str,
        upserts: list[dict[str, Any]],
        deletes: list[str],
        *,
        watermark_cursor: str | None,
        watermark_seq: int,
        head_cursor: str | None,
        head_seq: int,
    ) -> dict[str, Any] | None:
        with self.db.transaction(write=True) as tx:
            self._assert_lease_in_tx(tx, org_id)
            state = tx.fetchone(
                self.db._translate("SELECT * FROM catalog_state WHERE org_id=?"), (org_id,)
            )
            if state is None:
                raise NotFound("catalog state not found")
            current_wm = int(state["watermark_seq"])
            if watermark_seq < current_wm:
                # A concurrent rebuild/catch-up already published newer state;
                # dropping this batch is safe, the data is re-read next run.
                return None
            if not bool(state["ready"]):
                return None
            for entry in upserts:
                tx.execute(
                    self.db._translate(
                        "INSERT INTO certs(org_id,cert_no,revision,status,payload,"
                        "source_updated_at,revoked_at,correction_id,correction,local_updated_at,"
                        "source_seq) VALUES (?,?,?,?,?,?,?,?,?,?,?) "
                        "ON CONFLICT(org_id, cert_no) DO UPDATE SET "
                        "revision=excluded.revision, status=excluded.status, "
                        "payload=excluded.payload, source_updated_at=excluded.source_updated_at, "
                        "revoked_at=excluded.revoked_at, correction_id=excluded.correction_id, "
                        "correction=excluded.correction, local_updated_at=excluded.local_updated_at "
                        # Monotonic guard: a window staged before a rebuild can
                        # not overwrite a newer revision, and an equal revision
                        # must never resurrect a revoked certificate.
                        "WHERE excluded.revision > certs.revision "
                        "OR (excluded.revision = certs.revision AND certs.status <> 'revoked')"
                    ),
                    self._cert_row_tuple(org_id, entry, watermark_seq),
                )
            if deletes:
                tx.executemany(
                    self.db._translate("DELETE FROM certs WHERE org_id=? AND cert_no=?"),
                    [(org_id, no) for no in deletes],
                )
            now = _now()
            version = int(state["version"]) + 1
            count_row = tx.fetchone(
                self.db._translate("SELECT COUNT(*) AS n FROM certs WHERE org_id=?"), (org_id,)
            )
            tx.execute(
                self.db._translate(
                    "UPDATE catalog_state SET version=?, published_at=?, watermark_cursor=?, "
                    "watermark_seq=?, source_head_cursor=?, source_head_seq=?, cert_count=?, "
                    "last_error=NULL, updated_at=? WHERE org_id=?"
                ),
                (
                    version,
                    now,
                    watermark_cursor,
                    int(watermark_seq),
                    head_cursor,
                    int(head_seq),
                    int(count_row["n"]),
                    now,
                    org_id,
                ),
            )
            return {
                "version": version,
                "published_at": now,
                "cert_count": int(count_row["n"]),
                "watermark_seq": int(watermark_seq),
            }

    # -- cert queries ---------------------------------------------------
    def get_cert(self, org_id: str, cert_no: str) -> dict[str, Any]:
        row = self.db.query_one(
            "SELECT * FROM certs WHERE org_id=? AND cert_no=?", (org_id, cert_no)
        )
        if row is None:
            raise NotFound("certificate not found", details={"org_id": org_id, "cert_no": cert_no})
        return self._cert_view(row)

    @staticmethod
    def _cert_view(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "cert_no": row["cert_no"],
            "revision": int(row["revision"]),
            "status": row["status"],
            "data": loads(row["payload"], {}),
            "updated_at": row["source_updated_at"],
            "revoked_at": row["revoked_at"],
            "correction": loads(row["correction"]) if row["correction"] else None,
        }

    def list_certs(
        self,
        org_id: str,
        *,
        page: int,
        page_size: int,
        status: str | None = None,
    ) -> dict[str, Any]:
        where = "org_id=?"
        params: list[Any] = [org_id]
        if status:
            where += " AND status=?"
            params.append(status)
        total = self.db.query_one(
            f"SELECT COUNT(*) AS n FROM certs WHERE {where}", params
        )["n"]
        rows = self.db.query(
            f"SELECT * FROM certs WHERE {where} ORDER BY cert_no LIMIT ? OFFSET ?",
            params + [page_size, (page - 1) * page_size],
        )
        return {
            "page": page,
            "page_size": page_size,
            "total": int(total),
            "pages": max(1, (int(total) + page_size - 1) // page_size),
            "items": [self._cert_view(r) for r in rows],
        }

    # ------------------------------------------------------------------
    # runs
    def create_run(
        self,
        org_id: str,
        kind: str,
        trigger: str,
        *,
        request_key: str | None = None,
        coalesce_incremental: bool = True,
    ) -> tuple[dict[str, Any], bool]:
        """Create or reuse a run.  Returns ``(run, coalesced)``."""
        with self.db.transaction(write=True) as tx:
            if request_key:
                existing = tx.fetchone(
                    self.db._translate("SELECT * FROM runs WHERE request_key=?"), (request_key,)
                )
                if existing is not None:
                    return self._run_view(existing), True
            if kind == "incremental" and coalesce_incremental:
                existing = tx.fetchone(
                    self.db._translate(
                        "SELECT * FROM runs WHERE org_id=? AND kind='incremental' "
                        "AND status IN ('queued','running','paused') ORDER BY requested_at LIMIT 1"
                    ),
                    (org_id,),
                )
                if existing is not None:
                    return self._run_view(existing), True
            run_id = uuid.uuid4().hex
            now = _now()
            tx.execute(
                self.db._translate(
                    "INSERT INTO runs(run_id,org_id,kind,trigger,status,phase,progress,"
                    "requested_at,updated_at,request_key) VALUES (?,?,?,?,?,?,?,?,?,?)"
                ),
                (run_id, org_id, kind, trigger, "queued", "queued", dumps({}), now, now, request_key),
            )
            row = tx.fetchone(self.db._translate("SELECT * FROM runs WHERE run_id=?"), (run_id,))
            return self._run_view(row), False

    @staticmethod
    def _run_view(row: dict[str, Any]) -> dict[str, Any]:
        owner_id = row["owner_id"] if "owner_id" in row.keys() else None
        owner_epoch = row["owner_epoch"] if "owner_epoch" in row.keys() else None
        return {
            "run_id": row["run_id"],
            "org_id": row["org_id"],
            "kind": row["kind"],
            "trigger": row["trigger"],
            "status": row["status"],
            "phase": row["phase"],
            "progress": loads(row["progress"], {}),
            "error": loads(row["error"]) if row["error"] else None,
            "reason": row["reason"],
            "cursor_before": row["cursor_before"],
            "cursor_after": row["cursor_after"],
            "requested_at": row["requested_at"],
            "started_at": row["started_at"],
            "finished_at": row["finished_at"],
            "updated_at": row["updated_at"],
            "heartbeat_at": row["heartbeat_at"],
            "owner": owner_id,
            "owner_epoch": int(owner_epoch) if owner_epoch is not None else None,
        }

    def get_run(self, run_id: str) -> dict[str, Any]:
        row = self.db.query_one("SELECT * FROM runs WHERE run_id=?", (run_id,))
        if row is None:
            raise NotFound("run not found", details={"run_id": run_id})
        return self._run_view(row)

    def list_runs(self, org_id: str | None, limit: int = 20) -> list[dict[str, Any]]:
        if org_id:
            rows = self.db.query(
                "SELECT * FROM runs WHERE org_id=? ORDER BY requested_at DESC LIMIT ?",
                (org_id, limit),
            )
        else:
            rows = self.db.query("SELECT * FROM runs ORDER BY requested_at DESC LIMIT ?", (limit,))
        return [self._run_view(r) for r in rows]

    def claim_next_run(self, org_id: str, kinds: tuple[str, ...]) -> dict[str, Any] | None:
        placeholders = ",".join("?" for _ in kinds)
        lease = self._current_lease()
        with self.db.transaction(write=True) as tx:
            if lease is not None:
                self._assert_lease_in_tx(tx, org_id)
            row = tx.fetchone(
                self.db._translate(
                    f"SELECT * FROM runs WHERE org_id=? AND status='queued' "
                    f"AND kind IN ({placeholders}) ORDER BY requested_at LIMIT 1"
                ),
                (org_id, *kinds),
            )
            if row is None:
                return None
            now = _now()
            tx.execute(
                self.db._translate(
                    "UPDATE runs SET status='running', started_at=COALESCE(started_at,?), "
                    "phase=?, heartbeat_at=?, updated_at=?, error=NULL, reason=NULL, "
                    "owner_id=?, owner_epoch=? "
                    "WHERE run_id=? AND status='queued'"
                ),
                (
                    now,
                    "starting",
                    now,
                    now,
                    lease.owner_id if lease else None,
                    lease.epoch if lease else None,
                    row["run_id"],
                ),
            )
            fresh = tx.fetchone(
                self.db._translate("SELECT * FROM runs WHERE run_id=?"), (row["run_id"],)
            )
            return self._run_view(fresh)

    def has_active_run(self, org_id: str, kinds: tuple[str, ...]) -> bool:
        placeholders = ",".join("?" for _ in kinds)
        row = self.db.query_one(
            f"SELECT COUNT(*) AS n FROM runs WHERE org_id=? AND status IN ('queued','running','paused') "
            f"AND kind IN ({placeholders})",
            (org_id, *kinds),
        )
        return bool(row and int(row["n"]))

    def update_run(
        self,
        run_id: str,
        *,
        phase: str | None = None,
        progress: dict[str, Any] | None = None,
        reason: str | None = None,
        status: str | None = None,
        error: dict[str, Any] | None = None,
        cursor_before: str | None = None,
        cursor_after: str | None = None,
        finished: bool = False,
        clear_error: bool = False,
    ) -> dict[str, Any]:
        now = _now()
        sets = ["updated_at=?", "heartbeat_at=?"]
        params: list[Any] = [now, now]
        if phase is not None:
            sets.append("phase=?")
            params.append(phase)
        if progress is not None:
            sets.append("progress=?")
            params.append(dumps(progress))
        if reason is not None:
            sets.append("reason=?")
            params.append(reason)
        if status is not None:
            sets.append("status=?")
            params.append(status)
        if error is not None:
            sets.append("error=?")
            params.append(dumps(error))
        if clear_error:
            sets.append("error=NULL")
        if cursor_before is not None:
            sets.append("cursor_before=?")
            params.append(cursor_before)
        if cursor_after is not None:
            sets.append("cursor_after=?")
            params.append(cursor_after)
        if finished:
            sets.append("finished_at=?")
            params.append(now)
        params.append(run_id)
        lease = self._current_lease()
        with self.db.transaction(write=True) as tx:
            if lease is not None:
                row = tx.fetchone(
                    self.db._translate("SELECT org_id, owner_epoch FROM runs WHERE run_id=?"),
                    (run_id,),
                )
                if row is not None:
                    self._assert_lease_in_tx(tx, row["org_id"], row_epoch=row["owner_epoch"])
            tx.execute(self.db._translate(f"UPDATE runs SET {','.join(sets)} WHERE run_id=?"), tuple(params))
            row = tx.fetchone(self.db._translate("SELECT * FROM runs WHERE run_id=?"), (run_id,))
            return self._run_view(row)

    def finish_run(
        self,
        run_id: str,
        status: str,
        *,
        error: dict[str, Any] | None = None,
        cursor_after: str | None = None,
    ) -> dict[str, Any]:
        return self.update_run(
            run_id,
            status=status,
            error=error,
            cursor_after=cursor_after,
            finished=status in ("succeeded", "failed", "cancelled"),
            phase=status,
            reason=None,
        )

    def requeue_run(self, run_id: str, *, reason: str, status: str = "queued") -> None:
        lease = self._current_lease()
        with self.db.transaction(write=True) as tx:
            if lease is not None:
                row = tx.fetchone(
                    self.db._translate("SELECT org_id, owner_epoch FROM runs WHERE run_id=?"),
                    (run_id,),
                )
                if row is not None:
                    self._assert_lease_in_tx(tx, row["org_id"], row_epoch=row["owner_epoch"])
            tx.execute(
                self.db._translate(
                    "UPDATE runs SET status=?, reason=?, updated_at=?, owner_id=NULL, "
                    "owner_epoch=NULL WHERE run_id=?"
                ),
                (status, reason, _now(), run_id),
            )

    def recover_runs(self) -> list[str]:
        """Queue runs left running by a process that no longer owns them.

        Rows written by internal unit tests (no owner) are recovered as well.
        Fenced rows owned by a live collector are deliberately left alone so
        starting a second process cannot interrupt in-flight work; the owner's
        lease (or the takeover path) decides when that work is requeued.
        """
        now = _now()
        recovered: list[str] = []
        with self.db.transaction(write=True) as tx:
            rows = tx.fetchall(
                self.db._translate(
                    "SELECT run_id, owner_id FROM runs WHERE status IN ('running','interrupted')"
                )
            )
            for row in rows:
                if self.collector_alive(row["owner_id"]):
                    continue
                tx.execute(
                    self.db._translate(
                        "UPDATE runs SET status='queued', reason='resumed_after_restart', "
                        "owner_id=NULL, owner_epoch=NULL, updated_at=? WHERE run_id=?"
                    ),
                    (now, row["run_id"]),
                )
                recovered.append(row["run_id"])
        return recovered

    def pause_active_runs(self, org_id: str) -> None:
        self.execute_checked(
            "UPDATE runs SET status='paused', reason='organization_paused', updated_at=? "
            "WHERE org_id=? AND status='running'",
            (_now(), org_id),
        )

    def resume_paused_runs(self, org_id: str) -> None:
        self.execute_checked(
            "UPDATE runs SET status='queued', owner_id=NULL, owner_epoch=NULL, reason='resumed', "
            "updated_at=? WHERE org_id=? AND status='paused'",
            (_now(), org_id),
        )

    # ------------------------------------------------------------------
    # scans (staged full scans)
    def create_scan(self, org_id: str, run_id: str, kind: str) -> dict[str, Any]:
        scan_id = uuid.uuid4().hex
        now = _now()
        lease = self._current_lease()
        with self.db.transaction(write=True) as tx:
            if lease is not None:
                self._assert_lease_in_tx(tx, org_id)
            tx.execute(
                self.db._translate(
                    "INSERT INTO scans(scan_id,org_id,run_id,kind,status,created_at,updated_at,"
                    "owner_id,owner_epoch) VALUES (?,?,?,?,?,?,?,?,?)"
                ),
                (
                    scan_id,
                    org_id,
                    run_id,
                    kind,
                    "listing",
                    now,
                    now,
                    lease.owner_id if lease else None,
                    lease.epoch if lease else None,
                ),
            )
            row = tx.fetchone(self.db._translate("SELECT * FROM scans WHERE scan_id=?"), (scan_id,))
            return self._scan_view(row)

    @staticmethod
    def _scan_view(row: dict[str, Any]) -> dict[str, Any]:
        keys = row.keys()
        return {
            "scan_id": row["scan_id"],
            "org_id": row["org_id"],
            "run_id": row["run_id"],
            "kind": row["kind"],
            "status": row["status"],
            "snapshot_id": row["snapshot_id"],
            "change_position": row["change_position"],
            "catchup_cursor": row["catchup_cursor"],
            "page_cursor": row["page_cursor"],
            "pages_done": int(row["pages_done"]),
            "entries_done": int(row["entries_done"]),
            "total_hint": row["total_hint"],
            "head_seq": int(row["head_seq"]),
            "head_cursor": row["head_cursor"],
            "expires_at": row["expires_at"],
            "error": loads(row["error"]) if row["error"] else None,
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "owner": row["owner_id"] if "owner_id" in keys else None,
            "owner_epoch": int(row["owner_epoch"]) if "owner_epoch" in keys and row["owner_epoch"] is not None else None,
        }

    def get_scan(self, scan_id: str) -> dict[str, Any]:
        row = self.db.query_one("SELECT * FROM scans WHERE scan_id=?", (scan_id,))
        if row is None:
            raise NotFound("scan not found", details={"scan_id": scan_id})
        return self._scan_view(row)

    def find_scan_for_run(self, run_id: str) -> dict[str, Any] | None:
        row = self.db.query_one(
            "SELECT * FROM scans WHERE run_id=? AND status NOT IN ('failed','published') "
            "ORDER BY created_at DESC LIMIT 1",
            (run_id,),
        )
        return self._scan_view(row) if row else None

    def drop_interrupted_scans(self, run_id: str) -> int:
        """Remove staging rows a takeover left behind for ``run_id``."""
        with self.db.transaction(write=True) as tx:
            rows = tx.fetchall(
                self.db._translate(
                    "SELECT scan_id FROM scans WHERE run_id=? AND status='interrupted'"
                ),
                (run_id,),
            )
            for row in rows:
                tx.execute(
                    self.db._translate("DELETE FROM scan_items WHERE scan_id=?"), (row["scan_id"],)
                )
                tx.execute(
                    self.db._translate("DELETE FROM scans WHERE scan_id=?"), (row["scan_id"],)
                )
            return len(rows)

    def latest_scan(self, org_id: str) -> dict[str, Any] | None:
        row = self.db.query_one(
            "SELECT * FROM scans WHERE org_id=? ORDER BY created_at DESC LIMIT 1", (org_id,)
        )
        return self._scan_view(row) if row else None

    def _scan_org(self, scan_id: str) -> str | None:
        row = self.db.query_one("SELECT org_id FROM scans WHERE scan_id=?", (scan_id,))
        return row["org_id"] if row else None

    def _assert_scan_owner_in_tx(self, tx, scan_id: str) -> None:
        """Fence a staging write.

        Without a bound lease this is a no-op (single-process use).  With one,
        both the organization lease and the scan's own ``owner_epoch`` must
        still match, so a process that lost the organization cannot keep
        filling or deleting staging rows the new owner may already rely on.
        """
        lease = self._current_lease()
        if lease is None:
            return
        row = tx.fetchone(
            self.db._translate("SELECT org_id, owner_epoch FROM scans WHERE scan_id=?"),
            (scan_id,),
        )
        if row is None:
            raise LeaseLost("scan no longer exists", details={"scan_id": scan_id})
        row_epoch = int(row["owner_epoch"]) if row["owner_epoch"] is not None else None
        self._assert_lease_in_tx(tx, row["org_id"], row_epoch=row_epoch)

    def update_scan(self, scan_id: str, **fields: Any) -> dict[str, Any]:
        allowed = {
            "status",
            "snapshot_id",
            "change_position",
            "catchup_cursor",
            "page_cursor",
            "pages_done",
            "entries_done",
            "total_hint",
            "head_seq",
            "head_cursor",
            "expires_at",
            "error",
        }
        sets = []
        params: list[Any] = []
        for key, value in fields.items():
            if key not in allowed:
                raise ValueError(f"unknown scan field {key}")
            sets.append(f"{key}=?")
            if key == "error" and value is not None:
                value = dumps(value)
            params.append(value)
        sets.append("updated_at=?")
        params.append(_now())
        params.append(scan_id)
        with self.db.transaction(write=True) as tx:
            self._assert_scan_owner_in_tx(tx, scan_id)
            tx.execute(self.db._translate(f"UPDATE scans SET {','.join(sets)} WHERE scan_id=?"), tuple(params))
            row = tx.fetchone(self.db._translate("SELECT * FROM scans WHERE scan_id=?"), (scan_id,))
            return self._scan_view(row)

    def add_scan_items(self, scan_id: str, items: list[dict[str, Any]]) -> None:
        if not items:
            return
        with self.db.transaction(write=True) as tx:
            self._assert_scan_owner_in_tx(tx, scan_id)
            for item in items:
                tx.execute(
                    self.db._translate(
                        "INSERT INTO scan_items(scan_id,cert_no,revision,status,payload,"
                        "ordinal,discovered) VALUES (?,?,?,?,?,?,?) "
                        "ON CONFLICT(scan_id, cert_no) DO UPDATE SET "
                        "revision=CASE WHEN excluded.revision>scan_items.revision "
                        "THEN excluded.revision ELSE scan_items.revision END, "
                        "payload=CASE WHEN excluded.payload<>'' THEN excluded.payload "
                        "ELSE scan_items.payload END, "
                        "status=CASE WHEN scan_items.status='ok' THEN 'ok' ELSE excluded.status END, "
                        "discovered=CASE WHEN excluded.discovered>scan_items.discovered "
                        "THEN excluded.discovered ELSE scan_items.discovered END"
                    ),
                    (
                        scan_id,
                        item["cert_no"],
                        int(item.get("revision") or 0),
                        item.get("status", "pending"),
                        dumps(item["payload"]) if item.get("payload") is not None else "",
                        int(item.get("ordinal") or 0),
                        int(bool(item.get("discovered", 1))),
                    ),
                )

    def set_scan_item(
        self,
        scan_id: str,
        cert_no: str,
        *,
        status: str,
        payload: dict[str, Any] | None = None,
        revision: int | None = None,
    ) -> None:
        with self.db.transaction(write=True) as tx:
            self._assert_scan_owner_in_tx(tx, scan_id)
            existing = tx.fetchone(
                self.db._translate("SELECT revision, discovered FROM scan_items WHERE scan_id=? AND cert_no=?"),
                (scan_id, cert_no),
            )
            if existing is None:
                tx.execute(
                    self.db._translate(
                        "INSERT INTO scan_items(scan_id,cert_no,revision,status,payload,ordinal,discovered) "
                        "VALUES (?,?,?,?,?,?,?)"
                    ),
                    (
                        scan_id,
                        cert_no,
                        int(revision or 0),
                        status,
                        dumps(payload) if payload is not None else "",
                        0,
                        0,
                    ),
                )
            else:
                tx.execute(
                    self.db._translate(
                        "UPDATE scan_items SET status=?, payload=?, revision=? WHERE scan_id=? AND cert_no=?"
                    ),
                    (
                        status,
                        dumps(payload) if payload is not None else "",
                        int(revision if revision is not None else existing["revision"]),
                        scan_id,
                        cert_no,
                    ),
                )

    def scan_items(self, scan_id: str) -> list[dict[str, Any]]:
        rows = self.db.query(
            "SELECT * FROM scan_items WHERE scan_id=? ORDER BY ordinal, cert_no", (scan_id,)
        )
        out = []
        for row in rows:
            out.append(
                {
                    "scan_id": row["scan_id"],
                    "cert_no": row["cert_no"],
                    "revision": int(row["revision"]),
                    "status": row["status"],
                    "payload": loads(row["payload"]) if row["payload"] else None,
                    "ordinal": int(row["ordinal"]),
                    "discovered": bool(row["discovered"]),
                }
            )
        return out

    def scan_item_counts(self, scan_id: str) -> dict[str, int]:
        rows = self.db.query(
            "SELECT status, COUNT(*) AS n FROM scan_items WHERE scan_id=? GROUP BY status", (scan_id,)
        )
        counts = {r["status"]: int(r["n"]) for r in rows}
        counts["total"] = sum(counts.values())
        return counts

    def pending_scan_items(self, scan_id: str) -> list[str]:
        rows = self.db.query(
            "SELECT cert_no FROM scan_items WHERE scan_id=? AND status='pending' ORDER BY ordinal, cert_no",
            (scan_id,),
        )
        return [r["cert_no"] for r in rows]

    def mark_scan_items_pending(self, scan_id: str, cert_nos: list[str]) -> None:
        if not cert_nos:
            return
        with self.db.transaction(write=True) as tx:
            self._assert_scan_owner_in_tx(tx, scan_id)
            tx.executemany(
                self.db._translate(
                    "UPDATE scan_items SET status='pending' WHERE scan_id=? AND cert_no=?"
                ),
                [(scan_id, no) for no in cert_nos],
            )

    def unmark_scan_items_deleted(self, scan_id: str, cert_nos: list[str]) -> None:
        if not cert_nos:
            return
        with self.db.transaction(write=True) as tx:
            self._assert_scan_owner_in_tx(tx, scan_id)
            tx.executemany(
                self.db._translate(
                    "UPDATE scan_items SET status='pending' WHERE scan_id=? AND cert_no=? "
                    "AND status='deleted'"
                ),
                [(scan_id, no) for no in cert_nos],
            )

    def mark_scan_items_deleted(self, scan_id: str, cert_nos: list[str]) -> None:
        if not cert_nos:
            return
        with self.db.transaction(write=True) as tx:
            self._assert_scan_owner_in_tx(tx, scan_id)
            tx.executemany(
                self.db._translate(
                    "UPDATE scan_items SET status='deleted', payload='' WHERE scan_id=? AND cert_no=?"
                ),
                [(scan_id, no) for no in cert_nos],
            )

    def mark_interrupted_scans(self, org_ids: Iterable[str] | None = None) -> None:
        """Neutralize staging left behind by dead processes only.

        Called at startup.  Scans owned by a collector that is still alive
        (another process on the shared database) are left untouched, so a new
        process starting up never interrupts work in progress elsewhere.  The
        owning process's ``reclaim_org_work`` handles its own leftovers.
        """
        stamp = _now()
        org_filter = list(org_ids) if org_ids is not None else None
        with self.db.transaction(write=True) as tx:
            scans = tx.fetchall(
                self.db._translate(
                    "SELECT scan_id, owner_id FROM scans WHERE status IN "
                    "('listing','fetching','catching_up')"
                )
            )
            for row in scans:
                if self.collector_alive(row["owner_id"]):
                    continue
                if org_filter is not None:
                    scan_org = tx.fetchone(
                        self.db._translate("SELECT org_id FROM scans WHERE scan_id=?"),
                        (row["scan_id"],),
                    )
                    if scan_org is None or scan_org["org_id"] not in org_filter:
                        continue
                tx.execute(
                    self.db._translate(
                        "UPDATE scans SET status='interrupted', owner_id=NULL, owner_epoch=NULL, "
                        "updated_at=? WHERE scan_id=?"
                    ),
                    (stamp, row["scan_id"]),
                )
            runs = tx.fetchall(
                self.db._translate(
                    "SELECT run_id, owner_id FROM runs WHERE status='running'"
                )
            )
            for row in runs:
                if self.collector_alive(row["owner_id"]):
                    continue
                tx.execute(
                    self.db._translate(
                        "UPDATE runs SET status='queued', reason='resumed_after_restart', "
                        "owner_id=NULL, owner_epoch=NULL, updated_at=? WHERE run_id=?"
                    ),
                    (stamp, row["run_id"]),
                )

    def delete_scan(self, scan_id: str) -> None:
        with self.db.transaction(write=True) as tx:
            self._assert_scan_owner_in_tx(tx, scan_id)
            tx.execute(self.db._translate("DELETE FROM scan_items WHERE scan_id=?"), (scan_id,))
            tx.execute(self.db._translate("DELETE FROM scans WHERE scan_id=?"), (scan_id,))

    def mark_scan(self, scan_id: str, status: str, error: dict[str, Any] | None = None) -> None:
        self.update_scan(scan_id, status=status, error=error)

    # ------------------------------------------------------------------
    # pending corrections (groups that could not be applied completely yet)
    def upsert_pending_correction(
        self,
        org_id: str,
        correction_id: str,
        *,
        old_cert_nos: list[str],
        expected: list[str],
        state: str,
        last_error: dict[str, Any] | None = None,
    ) -> None:
        now = _now()
        with self.db.transaction(write=True) as tx:
            self._assert_lease_in_tx(tx, org_id)
            row = tx.fetchone(
                self.db._translate(
                    "SELECT * FROM pending_corrections WHERE org_id=? AND correction_id=?"
                ),
                (org_id, correction_id),
            )
            if row is None:
                tx.execute(
                    self.db._translate(
                        "INSERT INTO pending_corrections(org_id,correction_id,old_cert_nos,expected,"
                        "state,attempts,last_error,first_seen_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?)"
                    ),
                    (
                        org_id,
                        correction_id,
                        dumps(old_cert_nos),
                        dumps(sorted(expected)),
                        state,
                        1,
                        dumps(last_error) if last_error else None,
                        now,
                        now,
                    ),
                )
            else:
                tx.execute(
                    self.db._translate(
                        "UPDATE pending_corrections SET old_cert_nos=?, expected=?, state=?, "
                        "attempts=attempts+1, last_error=?, updated_at=? "
                        "WHERE org_id=? AND correction_id=?"
                    ),
                    (
                        dumps(old_cert_nos),
                        dumps(sorted(expected)),
                        state,
                        dumps(last_error) if last_error else None,
                        now,
                        org_id,
                        correction_id,
                    ),
                )

    def list_pending_corrections(self, org_id: str) -> list[dict[str, Any]]:
        rows = self.db.query(
            "SELECT * FROM pending_corrections WHERE org_id=? AND state<>'applied' ORDER BY first_seen_at",
            (org_id,),
        )
        return [
            {
                "correction_id": r["correction_id"],
                "old_cert_nos": loads(r["old_cert_nos"], []),
                "expected": loads(r["expected"], []),
                "state": r["state"],
                "attempts": int(r["attempts"]),
                "last_error": loads(r["last_error"]) if r["last_error"] else None,
                "first_seen_at": r["first_seen_at"],
            }
            for r in rows
        ]

    def clear_pending_correction(self, org_id: str, correction_id: str) -> None:
        lease = self._current_lease()
        with self.db.transaction(write=True) as tx:
            if lease is not None:
                self._assert_lease_in_tx(tx, org_id)
            tx.execute(
                self.db._translate(
                    "DELETE FROM pending_corrections WHERE org_id=? AND correction_id=?"
                ),
                (org_id, correction_id),
            )

    # ------------------------------------------------------------------
    # exports
    def create_export(
        self, org_id: str, page_size: int, ttl_seconds: int
    ) -> dict[str, Any]:
        token = uuid.uuid4().hex
        now = _now()
        expires = iso(utcnow() + dt.timedelta(seconds=ttl_seconds))
        with self.db.transaction(write=True) as tx:
            state = tx.fetchone(
                self.db._translate("SELECT * FROM catalog_state WHERE org_id=?"), (org_id,)
            )
            if state is None or not bool(state["ready"]):
                raise Conflict("catalog is not ready", details={"org_id": org_id})
            version = int(state["version"])
            rows = tx.fetchall(
                self.db._translate(
                    "SELECT cert_no,revision,status,payload FROM certs WHERE org_id=? ORDER BY cert_no"
                ),
                (org_id,),
            )
            tx.execute(
                self.db._translate(
                    "INSERT INTO exports(token,org_id,page_size,total,catalog_version,state,"
                    "created_at,expires_at,last_accessed_at) VALUES (?,?,?,?,?,?,?,?,?)"
                ),
                (token, org_id, page_size, len(rows), version, "active", now, expires, now),
            )
            for seq, row in enumerate(rows, start=1):
                tx.execute(
                    self.db._translate(
                        "INSERT INTO export_items(token,seq,cert_no,revision,status,payload) "
                        "VALUES (?,?,?,?,?,?)"
                    ),
                    (token, seq, row["cert_no"], int(row["revision"]), row["status"], row["payload"]),
                )
        return self.get_export(token)

    def get_export(self, token: str) -> dict[str, Any]:
        row = self.db.query_one("SELECT * FROM exports WHERE token=?", (token,))
        if row is None:
            raise NotFound("export not found", details={"token": token})
        if row["state"] != "expired" and self._expired(row["expires_at"]):
            self.expire_export(token)
            raise Gone(
                "export credential has expired",
                details={"token": token, "expired_at": row["expires_at"]},
            )
        if row["state"] == "expired":
            raise Gone(
                "export credential has expired",
                details={"token": token, "expired_at": row["expires_at"]},
            )
        return self._export_view(row)

    @staticmethod
    def _expired(expires_at: str) -> bool:
        from .util import parse_iso

        dtv = parse_iso(expires_at)
        return dtv is not None and dtv <= utcnow()

    @staticmethod
    def _export_view(row: dict[str, Any]) -> dict[str, Any]:
        total = int(row["total"])
        size = int(row["page_size"])
        return {
            "token": row["token"],
            "org_id": row["org_id"],
            "page_size": size,
            "total": total,
            "pages": max(1, (total + size - 1) // size),
            "catalog_version": int(row["catalog_version"]),
            "state": row["state"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "last_accessed_at": row["last_accessed_at"],
            "completed_at": row["completed_at"],
        }

    def export_page(self, token: str, page: int) -> dict[str, Any]:
        export = self.get_export(token)
        size = export["page_size"]
        pages = export["pages"]
        if page < 1 or page > pages:
            raise NotFound(
                "export page out of range",
                details={"page": page, "pages": pages},
            )
        rows = self.db.query(
            "SELECT * FROM export_items WHERE token=? AND seq BETWEEN ? AND ? ORDER BY seq",
            (token, (page - 1) * size + 1, min(page * size, export["total"] or 1)),
        )
        items = [
            {
                "cert_no": r["cert_no"],
                "revision": int(r["revision"]),
                "status": r["status"],
                "data": loads(r["payload"], {}),
            }
            for r in rows
        ]
        with self.db.transaction(write=True) as tx:
            tx.execute(
                self.db._translate("UPDATE exports SET last_accessed_at=? WHERE token=?"), (_now(), token)
            )
            if page == pages:
                tx.execute(
                    self.db._translate(
                        "UPDATE exports SET completed_at=COALESCE(completed_at,?) WHERE token=?"
                    ),
                    (_now(), token),
                )

        return {
            **export,
            "page": page,
            "pages": pages,
            "items": items,
            "next_page": page + 1 if page < pages else None,
        }

    def expire_export(self, token: str) -> None:
        with self.db.transaction(write=True) as tx:
            tx.execute(self.db._translate("UPDATE exports SET state='expired' WHERE token=?"), (token,))
            tx.execute(self.db._translate("DELETE FROM export_items WHERE token=?"), (token,))

    # ------------------------------------------------------------------
    # retention
    def cleanup(self, limits: dict[str, Any] | None = None) -> dict[str, int]:
        limits = limits or {}
        run_keep = int(limits.get("keep_runs", 50))
        scan_keep = int(limits.get("keep_scans", 20))
        removed = {"runs": 0, "scans": 0, "exports": 0, "export_items": 0}
        org_ids = [r["org_id"] for r in self.db.query("SELECT org_id FROM orgs")]
        with self.db.transaction(write=True) as tx:
            # Expired exports: materialized rows go immediately (bounded
            # storage) while a small tombstone keeps the credential answer an
            # explicit 410 rather than an anonymous 404.
            grace_seconds = int(limits.get("export_tombstone_seconds", 3600))
            tombstone_keep = int(limits.get("keep_exports", 50))
            rows = tx.fetchall(
                self.db._translate("SELECT token, expires_at, state FROM exports ORDER BY created_at DESC"),
                (),
            )
            for idx, row in enumerate(rows):
                expired = row["state"] == "expired" or self._expired(row["expires_at"])
                if not expired:
                    continue
                tx.execute(self.db._translate("DELETE FROM export_items WHERE token=?"), (row["token"],))
                if row["state"] != "expired":
                    tx.execute(
                        self.db._translate("UPDATE exports SET state='expired' WHERE token=?"),
                        (row["token"],),
                    )
                stamp = parse_iso(row["expires_at"])
                too_old = stamp is not None and (utcnow() - stamp).total_seconds() > grace_seconds
                if too_old or idx >= tombstone_keep:
                    tx.execute(self.db._translate("DELETE FROM exports WHERE token=?"), (row["token"],))
                    removed["exports"] += 1
            for org_id in org_ids:
                # Only *finished* work is pruned: a run still in flight is not
                # in this status set, and staged scans of live work are
                # protected by their status, so another collector sharing the
                # database is never disturbed here.
                finished = tx.fetchall(
                    self.db._translate(
                        "SELECT run_id FROM runs WHERE org_id=? AND status IN "
                        "('succeeded','failed','cancelled','superseded') "
                        "ORDER BY requested_at DESC"
                    ),
                    (org_id,),
                )
                stale_ids = [r["run_id"] for r in finished[run_keep:]]
                for run_id in stale_ids:
                    tx.execute(
                        self.db._translate(
                            "DELETE FROM scan_items WHERE scan_id IN "
                            "(SELECT scan_id FROM scans WHERE run_id=?)"
                        ),
                        (run_id,),
                    )
                    tx.execute(self.db._translate("DELETE FROM scans WHERE run_id=?"), (run_id,))
                    tx.execute(self.db._translate("DELETE FROM runs WHERE run_id=?"), (run_id,))
                    removed["runs"] += 1
                scans = tx.fetchall(
                    self.db._translate(
                        "SELECT scan_id FROM scans WHERE org_id=? AND status IN "
                        "('failed','published','superseded') AND run_id IS NULL "
                        "ORDER BY created_at DESC"
                    ),
                    (org_id,),
                )
                for row in scans[scan_keep:]:
                    tx.execute(self.db._translate("DELETE FROM scan_items WHERE scan_id=?"), (row["scan_id"],))
                    tx.execute(self.db._translate("DELETE FROM scans WHERE scan_id=?"), (row["scan_id"],))
                    removed["scans"] += 1
        # also prune orphaned scan staging that is old and no longer referenced
        return removed

    # ------------------------------------------------------------------
    # diagnostics
    def storage_counts(self) -> dict[str, int]:
        counts = {}
        for table in ("orgs", "runs", "scans", "scan_items", "certs", "exports", "export_items", "pending_corrections"):
            row = self.db.query_one(f"SELECT COUNT(*) AS n FROM {table}")
            counts[table] = int(row["n"]) if row else 0
        return counts
