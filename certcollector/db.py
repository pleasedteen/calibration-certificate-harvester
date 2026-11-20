"""Thin database layer supporting SQLite (embedded) and PostgreSQL.

All timestamps are stored as ISO-8601 UTF-8 text and JSON documents as text so
that the SQL used by the application is portable between the two backends.
"""

from __future__ import annotations

import os
import sqlite3
import threading
from contextlib import contextmanager
from typing import Any, Iterable, Iterator

from .util import CertCollectorError, ValidationError

SCHEMA = [
    """
    CREATE TABLE IF NOT EXISTS orgs (
        org_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        source_config TEXT NOT NULL,
        limits TEXT NOT NULL,
        options TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        paused INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    # Ownership of an organization by one collector process.  The epoch is the
    # fencing token: it advances on every change of owner, and every write that
    # may alter task state or the published catalog is conditioned on it.
    """
    CREATE TABLE IF NOT EXISTS org_leases (
        org_id TEXT PRIMARY KEY,
        owner_id TEXT NOT NULL,
        epoch BIGINT NOT NULL DEFAULT 1,
        heartbeat_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )
    """,
    # Shared access budget of an organization: pacing and Retry-After state is
    # published here so a process taking over neither violates the body's
    # minimum interval nor ignores a cooldown the previous owner learned.
    """
    CREATE TABLE IF NOT EXISTS org_access (
        org_id TEXT PRIMARY KEY,
        next_allowed_at DOUBLE PRECISION NOT NULL DEFAULT 0,
        cooldown_until DOUBLE PRECISION NOT NULL DEFAULT 0,
        adaptive_interval DOUBLE PRECISION NOT NULL DEFAULT 0,
        last_request_at DOUBLE PRECISION NOT NULL DEFAULT 0,
        updated_at TEXT NOT NULL
    )
    """,
    # Collector processes sharing this database.  A missing or expired row
    # means the process is gone, and its organizations are taken over.
    """
    CREATE TABLE IF NOT EXISTS collectors (
        owner_id TEXT PRIMARY KEY,
        started_at TEXT NOT NULL,
        heartbeat_at TEXT NOT NULL,
        expires_at DOUBLE PRECISION NOT NULL,
        pid INTEGER,
        host TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS runs (
        run_id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        trigger TEXT NOT NULL,
        status TEXT NOT NULL,
        phase TEXT,
        progress TEXT,
        error TEXT,
        reason TEXT,
        cursor_before TEXT,
        cursor_after TEXT,
        requested_at TEXT NOT NULL,
        started_at TEXT,
        finished_at TEXT,
        updated_at TEXT NOT NULL,
        heartbeat_at TEXT,
        request_key TEXT,
        owner_id TEXT,
        owner_epoch BIGINT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_runs_org ON runs(org_id, requested_at)",
    "CREATE INDEX IF NOT EXISTS idx_runs_status ON runs(org_id, status)",
    """
    CREATE TABLE IF NOT EXISTS scans (
        scan_id TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        run_id TEXT,
        kind TEXT NOT NULL,
        status TEXT NOT NULL,
        snapshot_id TEXT,
        change_position TEXT,
        catchup_cursor TEXT,
        page_cursor TEXT,
        pages_done INTEGER NOT NULL DEFAULT 0,
        entries_done INTEGER NOT NULL DEFAULT 0,
        total_hint INTEGER,
        head_seq BIGINT NOT NULL DEFAULT -1,
        head_cursor TEXT,
        expires_at TEXT,
        error TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        owner_id TEXT,
        owner_epoch BIGINT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_scans_org ON scans(org_id, status)",
    """
    CREATE TABLE IF NOT EXISTS scan_items (
        scan_id TEXT NOT NULL,
        cert_no TEXT NOT NULL,
        revision INTEGER NOT NULL,
        status TEXT NOT NULL,
        payload TEXT NOT NULL,
        ordinal INTEGER NOT NULL DEFAULT 0,
        discovered INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (scan_id, cert_no)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS certs (
        org_id TEXT NOT NULL,
        cert_no TEXT NOT NULL,
        revision INTEGER NOT NULL,
        status TEXT NOT NULL,
        payload TEXT NOT NULL,
        source_updated_at TEXT,
        revoked_at TEXT,
        correction_id TEXT,
        correction TEXT,
        source_seq BIGINT NOT NULL DEFAULT -1,
        local_updated_at TEXT NOT NULL,
        PRIMARY KEY (org_id, cert_no)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_certs_org_status ON certs(org_id, status, cert_no)",
    """
    CREATE TABLE IF NOT EXISTS catalog_state (
        org_id TEXT PRIMARY KEY,
        version BIGINT NOT NULL DEFAULT 0,
        ready INTEGER NOT NULL DEFAULT 0,
        published_at TEXT,
        watermark_cursor TEXT,
        watermark_seq BIGINT NOT NULL DEFAULT -1,
        source_head_cursor TEXT,
        source_head_seq BIGINT NOT NULL DEFAULT -1,
        cert_count INTEGER NOT NULL DEFAULT 0,
        last_error TEXT,
        updated_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS pending_corrections (
        org_id TEXT NOT NULL,
        correction_id TEXT NOT NULL,
        old_cert_nos TEXT NOT NULL,
        expected TEXT NOT NULL,
        state TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        last_error TEXT,
        first_seen_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (org_id, correction_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS exports (
        token TEXT PRIMARY KEY,
        org_id TEXT NOT NULL,
        page_size INTEGER NOT NULL,
        total INTEGER NOT NULL,
        catalog_version BIGINT NOT NULL,
        state TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        last_accessed_at TEXT,
        completed_at TEXT
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_exports_org ON exports(org_id, created_at)",
    "CREATE INDEX IF NOT EXISTS idx_exports_expiry ON exports(expires_at)",
    """
    CREATE TABLE IF NOT EXISTS export_items (
        token TEXT NOT NULL,
        seq INTEGER NOT NULL,
        cert_no TEXT NOT NULL,
        revision INTEGER NOT NULL,
        status TEXT NOT NULL,
        payload TEXT NOT NULL,
        PRIMARY KEY (token, seq)
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_export_items_token ON export_items(token)",
]

# Columns added after the first release.  ``CREATE TABLE IF NOT EXISTS`` does
# not add them to an existing database, so they are applied explicitly.
MIGRATIONS_SQLITE = [
    ("runs", "owner_id", "TEXT"),
    ("runs", "owner_epoch", "BIGINT"),
    ("scans", "owner_id", "TEXT"),
    ("scans", "owner_epoch", "BIGINT"),
]
MIGRATIONS_PG = [
    ("runs", "owner_id", "TEXT"),
    ("runs", "owner_epoch", "BIGINT"),
    ("scans", "owner_id", "TEXT"),
    ("scans", "owner_epoch", "BIGINT"),
]


class Database:
    def __init__(self, url: str):
        self.url = url
        self.is_postgres = url.startswith("postgresql://") or url.startswith("postgres://")
        if not self.is_postgres and url == ":memory:":
            raise ValidationError(
                "in-memory SQLite is not supported (one connection per thread); "
                "use a file path or postgresql:// URL"
            )
        self._write_lock = threading.RLock()
        self._local = threading.local()
        self._closed = False
        if self.is_postgres:
            try:
                import psycopg  # type: ignore
            except ImportError as exc:  # pragma: no cover - depends on environment
                raise CertCollectorError(
                    "PostgreSQL URL requested but psycopg is not installed; "
                    "install 'psycopg[binary]'"
                ) from exc
            self._psycopg = psycopg
        else:
            directory = os.path.dirname(os.path.abspath(url))
            if directory:
                os.makedirs(directory, exist_ok=True)
            self.path = url

    # -- connections -----------------------------------------------------
    def _connect(self):
        if self.is_postgres:
            # autocommit keeps single-statement reads/writes independent; all
            # multi-statement writes are wrapped explicitly in transaction().
            return self._psycopg.connect(self.url, autocommit=True)
        conn = sqlite3.connect(
            self.path,
            timeout=15.0,
            isolation_level=None,
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=15000")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def conn(self):
        c = getattr(self._local, "conn", None)
        if c is None or self._closed:
            c = self._connect()
            self._local.conn = c
        return c

    def close(self) -> None:
        self._closed = True
        c = getattr(self._local, "conn", None)
        if c is not None:
            try:
                c.close()
            except Exception:
                pass
            self._local.conn = None

    def close_all(self) -> None:
        self.close()

    # -- SQL helpers -------------------------------------------------------
    def _translate(self, sql: str) -> str:
        if self.is_postgres:
            return sql.replace("?", "%s")
        return sql

    def _rows(self, cur) -> list[dict[str, Any]]:
        if self.is_postgres:
            columns = [d.name for d in cur.description] if cur.description else []
            return [dict(zip(columns, row)) for row in cur.fetchall()]
        return [dict(row) for row in cur.fetchall()]

    def query(self, sql: str, params: Iterable[Any] = ()) -> list[dict[str, Any]]:
        c = self.conn()
        cur = c.execute(self._translate(sql), tuple(params))
        rows = self._rows(cur)
        cur.close()
        return rows

    def query_one(self, sql: str, params: Iterable[Any] = ()) -> dict[str, Any] | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def execute(self, sql: str, params: Iterable[Any] = ()) -> int:
        """Execute a single statement (autocommit for SQLite / commit for PG)."""
        with self.transaction(write=True) as tx:
            return tx.execute(self._translate(sql), tuple(params)).rowcount

    @contextmanager
    def transaction(self, write: bool = False, repeatable_read: bool = False) -> Iterator[Any]:
        if self.is_postgres:
            c = self.conn()
            if write:
                with self._write_lock:
                    tx = _PgTx(c)
                    tx.execute("BEGIN")
                    try:
                        yield tx
                        tx.execute("COMMIT")
                    except BaseException:
                        try:
                            tx.execute("ROLLBACK")
                        except Exception:
                            pass
                        raise
                    return
            tx = _PgTx(c)
            tx.execute("BEGIN")
            if repeatable_read:
                tx.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            try:
                yield tx
                tx.execute("COMMIT")
            except BaseException:
                try:
                    tx.execute("ROLLBACK")
                except Exception:
                    pass
                raise
            return

        c = self.conn()
        if write:
            with self._write_lock:
                c.execute("BEGIN IMMEDIATE")
                try:
                    yield _SqliteTx(c)
                    c.execute("COMMIT")
                except BaseException:
                    try:
                        c.execute("ROLLBACK")
                    except Exception:
                        pass
                    raise
        else:
            c.execute("BEGIN")
            try:
                yield _SqliteTx(c)
                c.execute("COMMIT")
            except BaseException:
                try:
                    c.execute("ROLLBACK")
                except Exception:
                    pass
                raise

    def exec_many(self, sql: str, rows: Iterable[tuple]) -> None:
        with self.transaction(write=True) as tx:
            tx.executemany(self._translate(sql), rows)

    def create_schema(self) -> None:
        if self.is_postgres:
            with self.transaction(write=True) as tx:
                for ddl in SCHEMA:
                    tx.execute(ddl)
            for table, column, ddl in MIGRATIONS_PG:
                tx.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {ddl}")
        else:
            c = self.conn()
            for ddl in SCHEMA:
                c.execute(ddl)
            for table, column, ddl in MIGRATIONS_SQLITE:
                existing = {row["name"] for row in c.execute(f"PRAGMA table_info({table})")}
                if column not in existing:
                    c.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


class _SqliteTx:
    def __init__(self, conn):
        self.conn = conn

    def execute(self, sql: str, params: tuple = ()):
        return self.conn.execute(sql, params)

    def executemany(self, sql: str, rows):
        return self.conn.executemany(sql, rows)

    def fetchall(self, sql: str, params: tuple = ()):
        return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def fetchone(self, sql: str, params: tuple = ()):
        row = self.conn.execute(sql, params).fetchone()
        return dict(row) if row is not None else None


class _PgTx:
    def __init__(self, conn):
        self.conn = conn

    def execute(self, sql: str, params: tuple = ()):
        return self.conn.execute(sql, params)

    def executemany(self, sql: str, rows):
        return self.conn.executemany(sql, rows)

    def fetchall(self, sql: str, params: tuple = ()):
        cur = self.conn.execute(sql, params)
        columns = [d.name for d in cur.description]
        return [dict(zip(columns, row)) for row in cur.fetchall()]

    def fetchone(self, sql: str, params: tuple = ()):
        cur = self.conn.execute(sql, params)
        if cur.description is None:
            return None
        columns = [d.name for d in cur.description]
        row = cur.fetchone()
        return dict(zip(columns, row)) if row is not None else None


def make_database(url: str | None) -> Database:
    if not url:
        raise ValidationError("database URL is empty")
    db = Database(url)
    db.create_schema()
    return db
