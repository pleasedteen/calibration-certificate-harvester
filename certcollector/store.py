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
import uuid
from bisect import bisect_left
from typing import Any, Iterable, Iterator

from .db import Database
from .util import (
    Conflict,
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

# A full rebuild streams its staged details out of ``scan_items`` in chunks of
# this many entries instead of materializing the whole catalog at once.  At
# 20k equal-sized details the collector never holds more than two chunks of
# rows at the same time, so the collection-side peak memory stays within a
# small constant factor of the 2k-batch baseline rather than growing tenfold.
PUBLISH_CHUNK_SIZE = 2000


def _now() -> str:
    return iso(utcnow())


class Store:
    def __init__(self, db: Database):
        self.db = db

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

    # Columns that define the content of a certificate row; the rebuild only
    # writes a staged row when one of these differs from what is published.
    _CERT_CONTENT_COLUMNS = (
        "revision",
        "status",
        "payload",
        "source_updated_at",
        "revoked_at",
        "correction_id",
        "correction",
    )

    def iter_scan_entries(
        self, scan_id: str, chunk_size: int = PUBLISH_CHUNK_SIZE
    ) -> Iterator[list[dict[str, Any]]]:
        """Yield staged, still-visible scan entries in bounded-size chunks.

        Rows marked ``deleted`` (the source no longer resolves the number) and
        rows that never received a payload never enter the published catalog;
        they are simply skipped here.
        """
        offset = 0
        while True:
            rows = self.db.query(
                "SELECT cert_no, revision, status, payload FROM scan_items "
                "WHERE scan_id=? AND status <> 'deleted' AND payload <> '' "
                "ORDER BY ordinal, cert_no LIMIT ? OFFSET ?",
                (scan_id, int(chunk_size), offset),
            )
            if not rows:
                return
            yield [
                {
                    "cert_no": r["cert_no"],
                    "revision": int(r["revision"]),
                    "status": r["status"],
                    **(loads(r["payload"], {}) or {}),
                }
                for r in rows
            ]
            offset += len(rows)
            if len(rows) < int(chunk_size):
                return

    def scan_entries_for_certs(
        self, scan_id: str, cert_nos: Iterable[str]
    ) -> dict[str, dict[str, Any]]:
        """Fetch specific staged entries (e.g. correction group members)."""
        wanted = sorted(set(cert_nos))
        entries: dict[str, dict[str, Any]] = {}
        for idx in range(0, len(wanted), PUBLISH_CHUNK_SIZE):
            batch = wanted[idx : idx + PUBLISH_CHUNK_SIZE]
            placeholders = ",".join("?" for _ in batch)
            rows = self.db.query(
                f"SELECT cert_no, revision, status, payload FROM scan_items "
                f"WHERE scan_id=? AND status <> 'deleted' AND payload <> '' "
                f"AND cert_no IN ({placeholders})",
                (scan_id, *batch),
            )
            for r in rows:
                entries[r["cert_no"]] = {
                    "cert_no": r["cert_no"],
                    "revision": int(r["revision"]),
                    "status": r["status"],
                    **(loads(r["payload"], {}) or {}),
                }
        return entries

    def publish_full_from_scan(
        self,
        org_id: str,
        scan_id: str,
        *,
        watermark_cursor: str | None,
        watermark_seq: int,
        head_cursor: str | None,
        head_seq: int,
        run_id: str | None = None,
    ) -> dict[str, Any] | None:
        """Atomically replace the published catalog from a staged scan.

        The staged catalog is streamed out of ``scan_items`` one chunk at a
        time, so the process never holds the whole directory in memory.
        Inside the single swap transaction only rows whose content actually
        changed are upserted, and only certificates that vanished from the
        source (and were not refreshed by a newer incremental window) are
        deleted; its write footprint therefore grows with the number of
        pending changes, not with the directory's total size.

        Returns ``None`` when the swap would move the watermark backwards; in
        that case nothing is written and the caller must catch up first.
        """
        if watermark_seq < 0:
            return None
        wm = int(watermark_seq)
        changed_rows: list[tuple] = []
        with self.db.transaction(write=True) as tx:
            state = tx.fetchone(
                self.db._translate("SELECT * FROM catalog_state WHERE org_id=?"), (org_id,)
            )
            if state is None:
                raise NotFound("catalog state not found")
            if wm < int(state["watermark_seq"]):
                return None
            # Published certificate numbers in a single ordered list plus a
            # one-bit-per-row "still present" marker.  This is O(N) bytes
            # instead of O(N) Python objects, and the row content itself is
            # re-read per scan chunk: no side of the comparison ever
            # materializes the whole directory.
            existing_nos = [
                r["cert_no"]
                for r in tx.fetchall(
                    self.db._translate(
                        "SELECT cert_no FROM certs WHERE org_id=? ORDER BY cert_no"
                    ),
                    (org_id,),
                )
            ]
            present_marker = bytearray((len(existing_nos) + 7) // 8)
            for index in range(len(existing_nos)):
                present_marker[index >> 3] |= 1 << (index & 7)

            def mark_present(cert_no: str) -> None:
                # cert_no ordering matches on both sides (ORDER BY cert_no), so
                # a bisect locates the row without a hash table of N strings.
                position = bisect_left(existing_nos, cert_no)
                if position < len(existing_nos) and existing_nos[position] == cert_no:
                    present_marker[position >> 3] &= ~(1 << (position & 7))

            # Stream the staged catalog in bounded chunks instead of reading
            # every detail back into memory at once.
            offset = 0
            while True:
                rows = tx.fetchall(
                    self.db._translate(
                        "SELECT cert_no, revision, status, payload FROM scan_items "
                        "WHERE scan_id=? AND status <> 'deleted' AND payload <> '' "
                        "ORDER BY ordinal, cert_no LIMIT ? OFFSET ?"
                    ),
                    (scan_id, PUBLISH_CHUNK_SIZE, offset),
                )
                if not rows:
                    break
                batch_nos = [r["cert_no"] for r in rows]
                placeholders = ",".join("?" for _ in batch_nos)
                current_rows = tx.fetchall(
                    self.db._translate(
                        "SELECT cert_no, source_seq, revision, status, payload, "
                        "source_updated_at, revoked_at, correction_id, correction "
                        f"FROM certs WHERE org_id=? AND cert_no IN ({placeholders})"
                    ),
                    (org_id, *batch_nos),
                )
                current_by_no = {r["cert_no"]: r for r in current_rows}
                for row in rows:
                    cert_no = row["cert_no"]
                    mark_present(cert_no)
                    entry = {
                        "cert_no": cert_no,
                        "revision": int(row["revision"]),
                        "status": row["status"],
                        **(loads(row["payload"], {}) or {}),
                    }
                    current = current_by_no.get(cert_no)
                    if current is not None and not self._row_diffs(current, entry):
                        # Identical content: leave the published row (and its
                        # source_seq) untouched so the swap writes only changes.
                        continue
                    changed_rows.append(self._cert_row_tuple(org_id, entry, wm))
                offset += len(rows)
                if len(rows) < PUBLISH_CHUNK_SIZE:
                    break
            if changed_rows:
                tx.executemany(self.db._translate(self.CERT_INSERT), changed_rows)
            # Numbers still marked vanished from the snapshot.  A row written by
            # a newer incremental window (source_seq beyond the snapshot's
            # position) is current and must not be dropped; that check runs
            # inside the database, in bounded batches.
            stale_candidates = [
                existing_nos[index]
                for index in range(len(existing_nos))
                if (present_marker[index >> 3] >> (index & 7)) & 1
            ]
            stale = self._stale_numbers_to_delete(tx, org_id, stale_candidates, wm)
            if stale:
                placeholders = ",".join("?" for _ in stale)
                tx.execute(
                    self.db._translate(
                        f"DELETE FROM certs WHERE org_id=? AND cert_no IN ({placeholders})"
                    ),
                    (org_id, *stale),
                )
            now = _now()
            count_row = tx.fetchone(
                self.db._translate("SELECT COUNT(*) AS n FROM certs WHERE org_id=?"), (org_id,)
            )
            cert_count = int(count_row["n"])
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
                    wm,
                    head_cursor,
                    int(head_seq),
                    cert_count,
                    now,
                    org_id,
                ),
            )
        return {
            "version": version,
            "published_at": now,
            "cert_count": cert_count,
            "watermark_seq": wm,
            "changed_rows": len(changed_rows),
            "deleted_rows": len(stale),
        }

    def _stale_numbers_to_delete(
        self, tx, org_id: str, candidates: list[str], watermark_seq: int
    ) -> list[str]:
        """Vanished numbers whose surviving row is not newer than the snapshot.

        The source_seq check is done inside the database so the full content
        rows never need to be materialized in Python."""
        if not candidates:
            return []
        stale: list[str] = []
        wanted = sorted(candidates)
        for idx in range(0, len(wanted), PUBLISH_CHUNK_SIZE):
            batch = wanted[idx : idx + PUBLISH_CHUNK_SIZE]
            placeholders = ",".join("?" for _ in batch)
            rows = tx.fetchall(
                self.db._translate(
                    f"SELECT cert_no FROM certs WHERE org_id=? AND source_seq <= ? "
                    f"AND cert_no IN ({placeholders})"
                ),
                (org_id, int(watermark_seq), *batch),
            )
            stale.extend(r["cert_no"] for r in rows)
        return sorted(stale)

    @classmethod
    def _row_diffs(cls, current: dict[str, Any], entry: dict[str, Any]) -> bool:
        """True when a staged entry differs from the published certificate."""
        staged = (
            int(entry["revision"]),
            entry["status"],
            dumps(entry.get("data") or {}),
            entry.get("source_updated_at"),
            entry.get("revoked_at"),
            entry.get("correction_id"),
            dumps(entry.get("correction")) if entry.get("correction") else None,
        )
        present = tuple(current[column] for column in cls._CERT_CONTENT_COLUMNS)
        return staged != present

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
        with self.db.transaction(write=True) as tx:
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
                    "phase=?, heartbeat_at=?, updated_at=?, error=NULL, reason=NULL "
                    "WHERE run_id=? AND status='queued'"
                ),
                (now, "starting", now, now, row["run_id"]),
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
        with self.db.transaction(write=True) as tx:
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
        self.execute_checked(
            "UPDATE runs SET status=?, reason=?, updated_at=? WHERE run_id=?", (status, reason, _now(), run_id)
        )

    def recover_runs(self) -> list[str]:
        """Mark interrupted runs as queued so lanes resume them after a restart."""
        now = _now()
        with self.db.transaction(write=True) as tx:
            rows = tx.fetchall(
                self.db._translate("SELECT run_id FROM runs WHERE status IN ('running','interrupted')")
            )
            for row in rows:
                tx.execute(
                    self.db._translate(
                        "UPDATE runs SET status='queued', reason='resumed_after_restart', updated_at=? "
                        "WHERE run_id=?"
                    ),
                    (now, row["run_id"]),
                )
            return [r["run_id"] for r in rows]

    def pause_active_runs(self, org_id: str) -> None:
        self.execute_checked(
            "UPDATE runs SET status='paused', reason='organization_paused', updated_at=? "
            "WHERE org_id=? AND status='running'",
            (_now(), org_id),
        )

    def resume_paused_runs(self, org_id: str) -> None:
        self.execute_checked(
            "UPDATE runs SET status='queued', reason='resumed', updated_at=? "
            "WHERE org_id=? AND status='paused'",
            (_now(), org_id),
        )

    # ------------------------------------------------------------------
    # scans (staged full scans)
    def create_scan(self, org_id: str, run_id: str, kind: str) -> dict[str, Any]:
        scan_id = uuid.uuid4().hex
        now = _now()
        with self.db.transaction(write=True) as tx:
            tx.execute(
                self.db._translate(
                    "INSERT INTO scans(scan_id,org_id,run_id,kind,status,created_at,updated_at) "
                    "VALUES (?,?,?,?,?,?,?)"
                ),
                (scan_id, org_id, run_id, kind, "listing", now, now),
            )
            row = tx.fetchone(self.db._translate("SELECT * FROM scans WHERE scan_id=?"), (scan_id,))
            return self._scan_view(row)

    @staticmethod
    def _scan_view(row: dict[str, Any]) -> dict[str, Any]:
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

    def latest_scan(self, org_id: str) -> dict[str, Any] | None:
        row = self.db.query_one(
            "SELECT * FROM scans WHERE org_id=? ORDER BY created_at DESC LIMIT 1", (org_id,)
        )
        return self._scan_view(row) if row else None

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
            tx.execute(self.db._translate(f"UPDATE scans SET {','.join(sets)} WHERE scan_id=?"), tuple(params))
            row = tx.fetchone(self.db._translate("SELECT * FROM scans WHERE scan_id=?"), (scan_id,))
            return self._scan_view(row)

    def add_scan_items(self, scan_id: str, items: list[dict[str, Any]]) -> None:
        if not items:
            return
        with self.db.transaction(write=True) as tx:
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

    def scan_correction_groups(self, scan_id: str) -> list[dict[str, Any]]:
        """Return the (cert_no, correction_id, correction JSON) of staged rows
        that belong to a formal correction.  The query only touches the small
        subset of entries carrying a correction, so validating groups before a
        swap never reads the whole catalog into memory."""
        rows = self.db.query(
            # ``dumps`` emits compact, sorted JSON (``"correction_id":"..."``),
            # so the LIKE predicate keeps null ids ("correction_id":null) out.
            "SELECT cert_no, payload FROM scan_items "
            "WHERE scan_id=? AND status <> 'deleted' AND payload <> '' "
            "AND payload LIKE '%\"correction_id\":\"%' "
            "ORDER BY ordinal, cert_no",
            (scan_id,),
        )
        groups = []
        for row in rows:
            payload = loads(row["payload"], default=None)
            if not isinstance(payload, dict):
                continue
            correction_id = payload.get("correction_id")
            if not correction_id:
                continue
            groups.append(
                {
                    "cert_no": row["cert_no"],
                    "correction_id": correction_id,
                    "correction": payload.get("correction"),
                }
            )
        return groups

    def bulk_upsert_certs(
        self, org_id: str, entries: list[dict[str, Any]], source_seq: int = -1
    ) -> None:
        """Fast bulk load of published certificate rows (fixtures/benchmarks)."""
        if not entries:
            return
        rows = [self._cert_row_tuple(org_id, entry, source_seq) for entry in entries]
        with self.db.transaction(write=True) as tx:
            tx.executemany(self.db._translate(self.CERT_INSERT), rows)

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
            tx.executemany(
                self.db._translate(
                    "UPDATE scan_items SET status='deleted', payload='' WHERE scan_id=? AND cert_no=?"
                ),
                [(scan_id, no) for no in cert_nos],
            )

    def mark_interrupted_scans(self) -> None:
        self.execute_checked(
            "UPDATE scans SET status='interrupted' WHERE status IN ('listing','fetching','catching_up')",
            (),
        )
        self.execute_checked(
            "UPDATE runs SET status='queued', reason='resumed_after_restart' "
            "WHERE status='running'",
            (),
        )

    def delete_scan(self, scan_id: str) -> None:
        with self.db.transaction(write=True) as tx:
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
        self.execute_checked(
            "DELETE FROM pending_corrections WHERE org_id=? AND correction_id=?", (org_id, correction_id)
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
                        "SELECT scan_id FROM scans WHERE org_id=? AND status IN ('failed','published','superseded') "
                        "AND run_id IS NULL ORDER BY created_at DESC"
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
