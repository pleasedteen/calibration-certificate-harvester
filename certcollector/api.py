"""HTTP API of the collection service (standard library only).

Endpoints
---------
``POST   /api/orgs``                          create or update an organization
``GET    /api/orgs``                          list organizations
``GET    /api/orgs/{org}``                    organization detail
``POST   /api/orgs/{org}/collect``            start full/incremental collection
``POST   /api/orgs/{org}/rebuild``            start an online rebuild (full)
``POST   /api/orgs/{org}/pause``              pause an organization
``POST   /api/orgs/{org}/resume``             resume an organization
``GET    /api/orgs/{org}/status``             progress, wait and failure reasons
``GET    /api/orgs/{org}/runs``               recent runs
``GET    /api/orgs/{org}/runs/{run}``         run detail (+ attempts)
``GET    /api/orgs/{org}/certs``              paged certificate listing
``GET    /api/orgs/{org}/certs/{cert}``       certificate detail
``POST   /api/orgs/{org}/exports``            create a paged, resumable export
``GET    /api/exports/{token}``               export metadata
``GET    /api/exports/{token}/pages/{page}``  one consistent export page
``GET    /api/health``                        liveness
``GET    /api/admin/storage``                 storage row counts
``GET    /api/admin/config``                  effective runtime configuration
``GET    /api/admin/collectors``              sharing processes + organization leases
"""

from __future__ import annotations

import json
import logging
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .engine import Engine
from .store import Store
from .util import (
    CertCollectorError,
    Conflict,
    NotFound,
    ValidationError,
    iso,
    utcnow,
    validate_org_id,
)

log = logging.getLogger("certcollector.api")

DEFAULT_SOURCE = {
    "kind": "html",
    "base_url": "http://127.0.0.1:8801",
    "timeout": 20,
}
DEFAULT_LIMITS = {
    "max_concurrency": 2,
    "min_interval_ms": 0,
    "max_requests_per_second": 10,
}
DEFAULT_OPTIONS = {
    "poll_interval_ms": 1000,
    "page_size": 10,
    "batch_size": 100,
    "request_attempts": 4,
    "export_ttl_seconds": 3600,
    "keep_runs": 50,
    "keep_scans": 20,
    "keep_exports": 50,
    "export_tombstone_seconds": 3600,
}


class Api:
    def __init__(self, store: Store, engine: Engine, config: dict[str, Any] | None = None):
        self.store = store
        self.engine = engine
        self.config = config or {}

    # ------------------------------------------------------------------
    def route(self, method: str, path: str, query: dict[str, str], body: Any) -> tuple[int, Any]:
        try:
            result = self._dispatch(method, path, query, body)
            if isinstance(result, tuple):
                return result
            return 200, result
        except CertCollectorError as exc:
            return exc.status, exc.as_dict()
        except Exception as exc:  # pragma: no cover - defensive
            log.exception("unhandled API error")
            return 500, {"error": "internal_error", "message": str(exc)}

    def _dispatch(self, method: str, path: str, query: dict[str, str], body: Any):
        parts = [p for p in path.split("/") if p]
        if not parts:
            return 404, {"error": "not_found"}
        if parts[0] != "api":
            return 404, {"error": "not_found"}
        parts = parts[1:]
        if not parts:
            return 404, {"error": "not_found"}
        head = parts[0]

        if head == "health" and method == "GET":
            return {"ok": True, "service": "certcollector", "started_at": self.engine.started_at}
        if head == "admin":
            return self._admin(method, parts[1:])
        if head == "exports":
            return self._exports(method, parts[1:], query)
        if head == "orgs":
            return self._orgs(method, parts[1:], query, body)
        return 404, {"error": "not_found"}

    # ------------------------------------------------------------------
    def _orgs(self, method: str, parts: list[str], query: dict[str, str], body: Any):
        if not parts:
            if method == "GET":
                return {"items": [self._org_summary(o) for o in self.store.list_orgs()]}
            if method == "POST":
                return self._create_org(body)
            return 405, {"error": "method_not_allowed"}
        org_id = validate_org_id(parts[0])
        rest = parts[1:]
        if not rest:
            if method == "GET":
                return self._org_detail(org_id)
            return 405, {"error": "method_not_allowed"}
        action = rest[0]
        if action == "collect" and method == "POST":
            payload = body or {}
            mode = payload.get("mode", "auto")
            key = payload.get("request_key")
            if mode == "full":
                run = self.engine.request_full(org_id, "manual", key)
            elif mode == "incremental":
                run = self.engine.request_incremental(org_id, "manual", key)
            elif mode == "auto":
                state = self.store.get_state(org_id)
                if state["ready"] or self.store.has_active_run(org_id, ("full",)):
                    run = self.engine.request_incremental(org_id, "manual", key)
                else:
                    run = self.engine.request_full(org_id, "manual", key)
            else:
                raise ValidationError("mode must be auto, full or incremental")
            return 202, run
        if action == "rebuild" and method == "POST":
            payload = body or {}
            return 202, self.engine.request_full(org_id, "rebuild", payload.get("request_key"))
        if action == "pause" and method == "POST":
            return self.engine.pause(org_id)
        if action == "resume" and method == "POST":
            return self.engine.resume(org_id)
        if action == "status" and method == "GET":
            return self._status(org_id)
        if action == "runs":
            if len(rest) == 1 and method == "GET":
                limit = _int_query(query, "limit", 20)
                return {"items": self.store.list_runs(org_id, limit=limit)}
            if len(rest) == 2 and method == "GET":
                run = self.store.get_run(rest[1])
                if run["org_id"] != org_id:
                    raise NotFound("run not found", details={"run_id": rest[1]})
                return run
        if action == "certs":
            if len(rest) == 1 and method == "GET":
                page = _int_query(query, "page", 1)
                size = min(500, max(1, _int_query(query, "page_size", 50)))
                status = query.get("status")
                return self.store.list_certs(org_id, page=page, page_size=size, status=status)
            if len(rest) == 2 and method == "GET":
                return self.store.get_cert(org_id, urllib.parse.unquote(rest[1]))
        if action == "exports" and method == "POST":
            payload = body or {}
            org = self.store.get_org(org_id)
            page_size = int(payload.get("page_size", 25))
            if page_size < 1 or page_size > 500:
                raise ValidationError("page_size must be between 1 and 500")
            ttl = int(payload.get("ttl_seconds", (org.get("options") or {}).get("export_ttl_seconds", 3600)))
            if ttl < 1:
                raise ValidationError("ttl_seconds must be positive")
            return 201, self.store.create_export(org_id, page_size, ttl)
        if action == "corrections" and method == "GET":
            return {"items": self.store.list_pending_corrections(org_id)}
        return 404, {"error": "not_found"}

    def _exports(self, method: str, parts: list[str], query: dict[str, str]):  # noqa: ARG002
        if not parts or method != "GET":
            return 405, {"error": "method_not_allowed"}
        token = parts[0]
        if len(parts) == 1:
            return self.store.get_export(token)
        if len(parts) == 3 and parts[1] == "pages":
            page = int(parts[2])
            return self.store.export_page(token, page)
        return 404, {"error": "not_found"}

    def _admin(self, method: str, parts: list[str]):
        if method != "GET" or not parts:
            return 405, {"error": "method_not_allowed"}
        if parts[0] == "storage":
            return self.store.storage_counts()
        if parts[0] == "collectors":
            return {
                "self": self.engine.owner_id,
                "items": self.store.list_collectors(),
                "org_leases": [
                    {
                        **lease,
                        "owned_here": bool(
                            self.engine.runtime(lease["org_id"]).lease
                            and self.engine.runtime(lease["org_id"]).lease.owner_id
                            == self.engine.owner_id
                            and self.engine.runtime(lease["org_id"]).lease.epoch
                            == lease["epoch"]
                        ),
                    }
                    for lease in self.store.list_org_leases()
                ],
            }
        if parts[0] == "config":
            return {
                "default_source": DEFAULT_SOURCE,
                "default_limits": DEFAULT_LIMITS,
                "default_options": DEFAULT_OPTIONS,
                "database": "postgresql" if self.store.db.is_postgres else "embedded-sqlite",
            }
        return 404, {"error": "not_found"}

    # ------------------------------------------------------------------
    def _create_org(self, body: Any) -> tuple[int, Any]:
        if not isinstance(body, dict):
            raise ValidationError("request body must be a JSON object")
        org_id = validate_org_id(str(body.get("org_id", "")))
        name = str(body.get("name") or org_id)
        source = {**DEFAULT_SOURCE, **(body.get("source") or {})}
        if source.get("kind") not in ("html", "json"):
            raise ValidationError("source.kind must be html or json")
        if not source.get("base_url") or not isinstance(source["base_url"], str):
            raise ValidationError("source.base_url is required")
        if not source["base_url"].startswith(("http://", "https://")):
            raise ValidationError("source.base_url must be an http(s) URL")
        limits = {**DEFAULT_LIMITS, **(body.get("limits") or {})}
        options = {**DEFAULT_OPTIONS, **(body.get("options") or {})}
        if int(limits.get("max_concurrency", 1)) < 1:
            raise ValidationError("limits.max_concurrency must be >= 1")
        if int(limits.get("max_requests_per_second", 1)) < 1:
            raise ValidationError("limits.max_requests_per_second must be >= 1")
        if float(limits.get("min_interval_ms", 0)) < 0:
            raise ValidationError("limits.min_interval_ms must be >= 0")
        existing = None
        try:
            existing = self.store.get_org(org_id)
        except NotFound:
            pass
        if existing and body.get("reject_existing"):
            raise Conflict("organization already exists", details={"org_id": org_id})
        org = self.store.upsert_org(org_id, name, source, limits, options)
        self.engine.runtime(org_id)
        if existing is None:
            # The process that was asked to create the organization takes
            # ownership of it, so peers collecting other organizations do not
            # steal it later.
            self.engine.claim_now(org_id)
        self.engine._ensure_lanes(org_id)
        if existing is None and body.get("start", True):
            state = self.store.get_state(org_id)
            if not state["ready"]:
                self.engine.request_full(org_id, "initial")
        return (201 if existing is None else 200), self._org_summary(org)

    def _org_detail(self, org_id: str) -> dict[str, Any]:
        org = self.store.get_org(org_id)
        state = self.store.get_state(org_id)
        return {
            **self._org_summary(org),
            "catalog": state,
            "pending_corrections": self.store.list_pending_corrections(org_id),
        }

    @staticmethod
    def _org_summary(org: dict[str, Any]) -> dict[str, Any]:
        return {
            "org_id": org["org_id"],
            "name": org["name"],
            "source": org["source"],
            "limits": org["limits"],
            "options": org["options"],
            "enabled": org["enabled"],
            "paused": org["paused"],
            "created_at": org["created_at"],
            "updated_at": org["updated_at"],
        }

    def _status(self, org_id: str) -> dict[str, Any]:
        org = self.store.get_org(org_id)
        state = self.store.get_state(org_id)
        runs = self.store.list_runs(org_id, limit=10)
        active = [r for r in runs if r["status"] in ("queued", "running", "paused")]
        latest = self.store.latest_scan(org_id)
        runtime = self.engine.runtime_state(org_id)
        if not state["ready"]:
            phase = "initializing"
        elif org["paused"]:
            phase = "paused"
        elif any(r["status"] == "running" and r["kind"] == "full" for r in active):
            phase = "rebuilding"
        elif any(r["status"] == "running" for r in active):
            phase = "collecting"
        elif active:
            phase = "scheduled"
        else:
            phase = "ready" if state["caught_up"] else "idle"
        reasons = []
        if state["last_error"]:
            reasons.append({"scope": "catalog", **state["last_error"]})
        if runtime.get("wait"):
            reasons.append({"scope": "organization", **runtime["wait"]})
        for run in active:
            if run["error"]:
                reasons.append({"scope": f"run:{run['run_id']}", **run["error"]})
        return {
            "org_id": org_id,
            "phase": phase,
            "ready": state["ready"],
            "paused": org["paused"],
            "enabled": org["enabled"],
            "catalog": {
                "version": state["version"],
                "published_at": state["published_at"],
                "cert_count": state["cert_count"],
                "caught_up": state["caught_up"],
                "watermark_seq": state["watermark_seq"],
                "source_head_seq": state["source_head_seq"],
                "watermark_cursor": state["watermark_cursor"],
            },
            "scan": latest,
            "active_runs": active,
            "recent_runs": runs,
            "waiting": runtime.get("wait"),
            "reasons": reasons,
            "upstream": runtime,
            "pending_corrections": self.store.list_pending_corrections(org_id),
            "checked_at": iso(utcnow()),
        }


def _int_query(query: dict[str, str], name: str, default: int) -> int:
    raw = query.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValidationError(f"{name} must be an integer") from exc
    if value < 1:
        raise ValidationError(f"{name} must be >= 1")
    return value


# ---------------------------------------------------------------------------
class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    api: Api
    server_version = "certcollector/1.0"

    def log_message(self, fmt, *args):  # keep test output readable
        log.debug("%s - %s", self.address_string(), fmt % args)

    def _read_json(self) -> Any:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return None
        raw = self.rfile.read(length)
        if not raw.strip():
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValidationError("request body is not valid JSON") from exc

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")

    def do_DELETE(self):
        self._handle("DELETE")

    def _handle(self, method: str):
        split = urllib.parse.urlsplit(self.path)
        query = {k: v[-1] for k, v in urllib.parse.parse_qs(split.query).items()}
        try:
            body = self._read_json()
            status, payload = self.api.route(method, split.path, query, body)
        except CertCollectorError as exc:
            status, payload = exc.status, exc.as_dict()
        except Exception as exc:  # pragma: no cover - defensive
            log.exception("request failed")
            status, payload = 500, {"error": "internal_error", "message": str(exc)}
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)


class ApiServer:
    """Threaded HTTP server wrapper with a clean start/stop for tests and demos."""

    def __init__(self, api: Api, host: str = "127.0.0.1", port: int = 0):
        self.api = api
        handler = type("BoundHandler", (_Handler,), {"api": api})
        self.httpd = ThreadingHTTPServer((host, port), handler)
        self.httpd.daemon_threads = True
        self.host, self.port = self.httpd.server_address[:2]
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self) -> "ApiServer":
        self._thread = threading.Thread(
            target=self.httpd.serve_forever,
            kwargs={"poll_interval": 0.05},
            name="cc-http",
            daemon=True,
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        if self._thread:
            self._thread.join(timeout=5)
        self._thread = None

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()


def make_api(store: Store, engine: Engine, config: dict[str, Any] | None = None) -> Api:
    return Api(store, engine, config)
