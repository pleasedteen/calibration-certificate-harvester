"""HTTP endpoints of the two simulated upstream bodies.

Both sites expose the same logical capabilities with different transports:

``Site A`` (HTML)
    ``GET /catalog?page=N``                 HTML table with pagination links
    ``GET /cert/<no>?rev=N``                HTML detail page
    ``GET /changes?since=<cursor>``         JSON change feed (cursor based)

``Site B`` (JSON)
    ``GET /api/v1/items?cursor=&limit=``    cursor based JSON listing
    ``GET /api/v1/items/<no>?revision=``    JSON detail
    ``GET /api/v1/changes?cursor=``         JSON change feed

Both implement ``/__admin/*`` helpers used by the demos and the test suite.
"""

from __future__ import annotations

import html
import json
import time
import urllib.parse
from typing import Any, Callable

from .sim_world import World, WorldError

Handler = Callable[[dict[str, Any]], tuple[int, dict[str, Any] | str, dict[str, str]]]


def _json_response(status: int, body: Any) -> tuple[int, Any, dict[str, str]]:
    return (
        status,
        json.dumps(body, ensure_ascii=False).encode("utf-8"),
        {"Content-Type": "application/json; charset=utf-8"},
    )


def _html_response(status: int, body: str) -> tuple[int, Any, dict[str, str]]:
    return status, body.encode("utf-8"), {"Content-Type": "text/html; charset=utf-8"}


def _error(exc: WorldError) -> tuple[int, Any, dict[str, str]]:
    headers = {}
    if exc.status == 429:
        headers["Retry-After"] = f"{float(exc.retry_after or 0.05):.2f}"
    elif exc.retry_after:
        headers["Retry-After"] = f"{float(exc.retry_after):.2f}"
    return _json_response(exc.status, {"error": exc.code, "message": exc.message})


# ---------------------------------------------------------------------------
# site A: HTML pagination
class HtmlSite:
    name = "html"

    def __init__(self, world: World):
        self.world = world

    def handle(self, request: dict[str, Any]) -> tuple[int, Any, dict[str, str]]:
        method = request["method"]
        path = request["path"]
        query = request["query"]
        guard = self.world.acquire()
        if guard[0] is not None:
            status, retry, _ = guard
            return (
                status,
                json.dumps(
                    {
                        "error": "rate_limited" if status == 429 else "temporarily_unavailable",
                        "message": "request rejected by upstream",
                        "retry_after": retry,
                    }
                ).encode(),
                {"Content-Type": "application/json", "Retry-After": f"{retry:.2f}"},
            )
        try:
            _, _, delay = guard
            if delay:
                time.sleep(delay)
            # admin helpers accept POST as well (used by demos/tests that drive
            # the simulator from another process)
            if path.startswith("/__admin/"):
                return self._admin(method, path, query, request.get("body"))
            if method != "GET":
                return _json_response(405, {"error": "method_not_allowed"})
            if path == "/health":
                return _json_response(200, {"ok": True, "site": "html"})
            if path == "/catalog":
                return self._catalog(query)
            if path.startswith("/catalog/"):
                return self._catalog(query, snapshot_id=path.split("/", 2)[2])
            if path.startswith("/cert/"):
                cert_no = urllib.parse.unquote(path[len("/cert/") :])
                return self._detail(cert_no, query)
            # second detail entry point: by certificate number query parameter
            if path == "/certificate":
                cert_no = query.get("no") or query.get("cert_no") or ""
                return self._detail(cert_no, query)
            if path == "/changes":
                return self._changes(query)
            return _html_response(404, "<h1>not found</h1>")
        except WorldError as exc:
            return _error(exc)
        finally:
            self.world.release()

    # -- pages ----------------------------------------------------------
    def _catalog(self, query: dict[str, str], snapshot_id: str | None = None) -> tuple[int, Any, dict[str, str]]:
        if snapshot_id is None:
            snapshot_id = query.get("snapshot")
        if not snapshot_id:
            snap = self.world.open_snapshot()
            snapshot_id = snap.snapshot_id
        page = int(query.get("page", "1"))
        size = int(query.get("page_size", "10"))
        body = self.world.catalog_page(snapshot_id, page, size)
        rows = []
        for item in body["items"]:
            no = html.escape(item["cert_no"], quote=True)
            link_q = urllib.parse.urlencode({"snapshot": snapshot_id})
            rows.append(
                "<tr>"
                f"<td><a href='/cert/{urllib.parse.quote(item['cert_no'])}?{link_q}'>{no}</a></td>"
                f"<td>{item['revision']}</td>"
                f"<td>{html.escape(item['status'])}</td>"
                f"<td>{html.escape(item['updated_at'] or '')}</td>"
                "</tr>"
            )
        nav = []
        snap_q = urllib.parse.urlencode({"snapshot": snapshot_id, "page_size": str(size)})
        if body["next_page"]:
            nav.append(f"<a rel='next' href='/catalog?{snap_q}&amp;page={body['next_page']}'>next</a>")
        if page > 1:
            nav.append(f"<a rel='prev' href='/catalog?{snap_q}&amp;page={page - 1}'>prev</a>")
        page_html = (
            "<!doctype html><html><head><meta charset='utf-8'><title>Certificate catalog</title></head>"
            "<body><h1>Certificate catalog</h1>"
            f"<p class='snapshot' data-snapshot-id='{html.escape(snapshot_id, quote=True)}'"
            f" data-change-position='{html.escape(body['snapshot']['change_position'], quote=True)}'"
            f" data-total='{body['snapshot']['total']}'>"
            f"snapshot {html.escape(snapshot_id)} page {page}/{body['pages']}</p>"
            "<table><thead><tr><th>cert_no</th><th>revision</th><th>status</th><th>updated_at</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
            f"<p class='pager'>{' | '.join(nav)}</p>"
            "</body></html>"
        )
        return _html_response(200, page_html)

    def _detail(self, cert_no: str, query: dict[str, str]) -> tuple[int, Any, dict[str, str]]:
        revision = query.get("rev") or query.get("revision")
        view = self.world.detail(cert_no, int(revision) if revision else None)
        correction = view.get("correction") or {}
        members = correction.get("members") or []
        rows = "".join(
            f"<tr><td>{html.escape(k)}</td><td>{html.escape(str(v))}</td></tr>"
            for k, v in view["data"].items()
        )
        corr_html = ""
        if correction:
            links = " ".join(
                f"<a class='correction-member' href='/cert/{urllib.parse.quote(m)}'>{html.escape(m)}</a>"
                for m in members
            )
            corr_html = (
                f"<section id='correction' data-correction-id='{html.escape(correction['id'], quote=True)}'>"
                f"<h2>Correction {html.escape(correction['id'])}</h2>"
                f"<p>supersedes: {', '.join(html.escape(o) for o in correction.get('supersedes', []))}</p>"
                f"<p>members: {links}</p></section>"
            )
        body = (
            "<!doctype html><html><head><meta charset='utf-8'><title>Certificate</title></head><body>"
            f"<h1 data-cert-no='{html.escape(view['cert_no'], quote=True)}'>"
            f"{html.escape(view['cert_no'])}</h1>"
            f"<p data-revision='{view['revision']}' data-status='{html.escape(view['status'])}'"
            f" data-revoked-at='{html.escape(view.get('revoked_at') or '', quote=True)}'>"
            f"revision {view['revision']} &mdash; {html.escape(view['status'])}</p>"
            f"<p class='updated'>updated {html.escape(view.get('updated_at') or '')}</p>"
            "<table>" + rows + "</table>" + corr_html + "</body></html>"
        )
        return _html_response(200, body)

    def _changes(self, query: dict[str, str]) -> tuple[int, Any, dict[str, str]]:
        cursor = query.get("since") or query.get("cursor") or ""
        limit = int(query.get("limit", "50"))
        return _json_response(200, self.world.changes(cursor, limit))

    # -- admin ----------------------------------------------------------
    def _admin(self, method: str, path: str, query: dict[str, str], body: Any) -> tuple[int, Any, dict[str, str]]:
        action = path[len("/__admin/") :]
        if action == "state" and method == "GET":
            return _json_response(200, self.world.state())
        if action == "config":
            data = json.loads(body) if body else {}
            return _json_response(200, self.world.update_config(data))
        if action == "expire":
            self.world.expire_all()
            return _json_response(200, {"expired": True})
        if action == "update":
            data = json.loads(body or "{}")
            return _json_response(200, self.world.update_config(data))
        if action == "reset":
            data = json.loads(body) if body else {}
            self.world.reset(int(data.get("count", 20)))
            return _json_response(200, {"reset": True})
        return _json_response(404, {"error": "unknown_admin_action"})


# ---------------------------------------------------------------------------
# site B: cursor based JSON
class JsonSite:
    name = "json"

    def __init__(self, world: World):
        self.world = world

    def handle(self, request: dict[str, Any]) -> tuple[int, Any, dict[str, str]]:
        method = request["method"]
        path = request["path"]
        query = request["query"]
        guard = self.world.acquire()
        if guard[0] is not None:
            status, retry, _ = guard
            return (
                status,
                json.dumps(
                    {
                        "error": "rate_limited" if status == 429 else "temporarily_unavailable",
                        "message": "request rejected by upstream",
                        "retry_after": retry,
                    }
                ).encode(),
                {"Content-Type": "application/json", "Retry-After": f"{retry:.2f}"},
            )
        try:
            _, _, delay = guard
            if delay:
                time.sleep(delay)
            if path.startswith("/__admin/"):
                return self._admin(method, path, body=request.get("body"))
            if method != "GET":
                return _json_response(405, {"error": "method_not_allowed"})
            if path == "/health":
                return _json_response(200, {"ok": True, "site": "json"})
            if path == "/api/v1/items":
                return self._items(query)
            if path.startswith("/api/v1/items/"):
                cert_no = urllib.parse.unquote(path[len("/api/v1/items/") :])
                return self._detail(cert_no, query)
            # alternate entry point mirroring a document-by-query endpoint
            if path == "/api/v1/certificate":
                cert_no = query.get("no") or query.get("cert_no") or ""
                return self._detail(cert_no, query)
            if path == "/api/v1/changes":
                return self._changes(query)
            return _json_response(404, {"error": "not_found"})
        except WorldError as exc:
            return _error(exc)
        finally:
            self.world.release()

    def _items(self, query: dict[str, str]) -> tuple[int, Any, dict[str, str]]:
        limit = int(query.get("limit", "10"))
        cursor = query.get("cursor")
        if not cursor:
            snap = self.world.open_snapshot()
            page = 1
            snapshot_id = snap.snapshot_id
        else:
            parsed = json.loads(_b64decode(cursor)) if cursor else {}
            snapshot_id = parsed["snapshot_id"]
            page = int(parsed.get("page", 1))
        body = self.world.catalog_page(snapshot_id, page, limit)
        next_cursor = None
        if body["next_page"]:
            next_cursor = _b64encode(
                json.dumps({"snapshot_id": snapshot_id, "page": body["next_page"]}).encode()
            )
        meta = body["snapshot"]
        return _json_response(
            200,
            {
                "snapshot_id": snapshot_id,
                "change_position": meta["change_position"],
                "expires_at": meta["expires_at"],
                "total": meta["total"],
                "items": [
                    {
                        "cert_no": item["cert_no"],
                        "revision": item["revision"],
                        "status": item["status"],
                        "updated_at": item["updated_at"],
                    }
                    for item in body["items"]
                ],
                "next_cursor": next_cursor,
            },
        )

    def _detail(self, cert_no: str, query: dict[str, str]) -> tuple[int, Any, dict[str, str]]:
        revision = query.get("revision") or query.get("rev")
        view = self.world.detail(cert_no, int(revision) if revision else None)
        return _json_response(200, view)

    def _changes(self, query: dict[str, str]) -> tuple[int, Any, dict[str, str]]:
        cursor = query.get("cursor") or ""
        limit = int(query.get("limit", "50"))
        return _json_response(200, self.world.changes(cursor, limit))

    def _admin(self, method: str, path: str, body: Any) -> tuple[int, Any, dict[str, str]]:
        action = path[len("/__admin/") :]
        if action == "state" and method == "GET":
            return _json_response(200, self.world.state())
        if action == "config":
            return _json_response(200, self.world.update_config(json.loads(body or "{}")))
        if action == "expire":
            self.world.expire_all()
            return _json_response(200, {"expired": True})
        if action == "update":
            data = json.loads(body or "{}")
            return _json_response(200, self.world.update_config(data))
        if action == "reset":
            self.world.reset(int(json.loads(body or "{}").get("count", 20)))
            return _json_response(200, {"reset": True})
        return _json_response(404, {"error": "unknown_admin_action"})


def _b64encode(raw: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64decode(text: str) -> bytes:
    import base64

    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def parse_path(raw: str) -> tuple[str, dict[str, str]]:
    parsed = urllib.parse.urlsplit(raw)
    query = {k: v[-1] for k, v in urllib.parse.parse_qs(parsed.query).items()}
    return parsed.path, query
