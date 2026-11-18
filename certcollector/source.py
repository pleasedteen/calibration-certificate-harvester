"""Upstream adapters.

The collector only speaks a normalized model; the two simulators (and any real
body, with a new adapter) map their transport onto that model:

* ``open_catalog()`` -> catalog page + stable ``change_position``
* ``catalog_page(token)`` -> next page
* ``detail(cert_no)`` -> current document incl. correction membership
* ``changes(cursor, limit)`` -> ordered change events + continuation cursor

Every HTTP interaction honours ``Retry-After`` and surfaces rate limits as
:class:`RateLimited`, expiry as :class:`ChannelExpired` and transient failures
as :class:`SourceUnavailable`.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any, Callable, Protocol

from .util import (
    ChannelExpired,
    HistoryExpired,
    NotFound,
    RateLimited,
    SourceUnavailable,
    UpstreamError,
    ValidationError,
)


@dataclass
class CatalogItem:
    cert_no: str
    revision: int
    status: str
    updated_at: str | None = None


@dataclass
class CatalogPage:
    items: list[CatalogItem]
    snapshot_id: str | None
    change_position: str | None
    next_token: str | None
    total: int | None = None
    expires_at: str | None = None


@dataclass
class ChangeEvent:
    seq: int | None
    kind: str
    cert_no: str | None
    event_id: str | None = None
    correction_id: str | None = None
    display_at: str | None = None


@dataclass
class ChangePage:
    items: list[ChangeEvent]
    next_cursor: str | None
    head_seq: int | None = None
    has_more: bool = False
    next_seq: int | None = None


@dataclass
class Detail:
    cert_no: str
    revision: int
    status: str
    data: dict[str, Any]
    updated_at: str | None
    revoked_at: str | None = None
    correction_id: str | None = None
    correction_members: list[str] = field(default_factory=list)
    correction_supersedes: list[str] = field(default_factory=list)
    historical: bool = False


# ---------------------------------------------------------------------------
# transports
class Transport(Protocol):
    def request(self, method: str, url: str, body: bytes | None = None) -> tuple[int, bytes, dict[str, str]]: ...


class UrllibTransport:
    def __init__(self, timeout: float = 20.0):
        self.timeout = timeout

    def request(self, method: str, url: str, body: bytes | None = None) -> tuple[int, bytes, dict[str, str]]:
        req = urllib.request.Request(url, data=body, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, resp.read(), dict(resp.headers)
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(), dict(exc.headers or {})
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise SourceUnavailable(f"upstream request failed: {exc}") from exc


class LoopbackTransport:
    """Routes requests straight into an in-process simulator handler."""

    def __init__(self, handler: Callable[[dict[str, Any]], tuple[int, Any, dict[str, str]]], base_url: str):
        self.handler = handler
        self.base_url = base_url.rstrip("/")

    def request(self, method: str, url: str, body: bytes | None = None) -> tuple[int, bytes, dict[str, str]]:
        if not url.startswith(self.base_url):
            raise SourceUnavailable(f"loopback cannot reach {url}")
        raw = url[len(self.base_url) :] or "/"
        split = urllib.parse.urlsplit(raw)
        query = {k: v[-1] for k, v in urllib.parse.parse_qs(split.query).items()}
        status, payload, headers = self.handler(
            {
                "method": method,
                "path": split.path,
                "query": query,
                "body": body.decode("utf-8") if body else None,
            }
        )
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        return status, payload, headers


class _HttpClient:
    def __init__(self, base_url: str, transport: Transport):
        self.base_url = base_url.rstrip("/")
        self.transport = transport

    def get(self, path: str, params: dict[str, Any] | None = None) -> tuple[int, bytes, dict[str, str]]:
        url = self.base_url + path
        if params:
            clean = {k: v for k, v in params.items() if v is not None}
            if clean:
                url += "?" + urllib.parse.urlencode(clean)
        return self.transport.request("GET", url)

    def call(self, path: str, params: dict[str, Any] | None = None) -> Any:
        status, raw, headers = self.get(path, params)
        self._raise_for(status, raw, headers)
        try:
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise UpstreamError("upstream returned malformed JSON") from exc

    def call_html(self, path: str, params: dict[str, Any] | None = None) -> tuple[str, str]:
        status, raw, headers = self.get(path, params)
        self._raise_for(status, raw, headers)
        return raw.decode("utf-8", errors="replace"), headers.get("Content-Type", "")

    @staticmethod
    def _raise_for(status: int, raw: bytes, headers: dict[str, str]) -> None:
        if status < 400:
            return
        retry = headers.get("Retry-After") or headers.get("retry-after")
        retry_after: float | None = None
        if retry:
            try:
                retry_after = float(str(retry).strip())
            except ValueError:
                retry_after = None
        message = raw.decode("utf-8", errors="replace")[:300]
        if status == 429:
            raise RateLimited("upstream rate limit", details={"retry_after": retry_after or 0.5})
        if status == 410:
            if b"history_expired" in raw:
                raise HistoryExpired(
                    "historical revision is no longer retained", details={"body": message}
                )
            raise ChannelExpired("upstream position expired", details={"body": message})
        if status == 404:
            raise NotFound("upstream object not found", details={"body": message})
        if status in (408, 425, 500, 502, 503, 504):
            raise SourceUnavailable(
                "upstream temporarily unavailable",
                details={"status": status, "retry_after": retry_after},
            )
        raise UpstreamError("upstream rejected request", details={"status": status, "body": message})


# ---------------------------------------------------------------------------
# HTML parsing helpers
class _CatalogTableParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.rows: list[dict[str, str]] = []
        self.meta: dict[str, str] = {}
        self.next_href: str | None = None
        self.prev_href: str | None = None
        self._in_tbody = False
        self._in_row = False
        self._in_cell = False
        self._cell_text: list[str] = []
        self._cells: list[str] = []
        self._cell_link: str | None = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "p" and attrs.get("class") == "snapshot":
            self.meta.update({k: v for k, v in attrs.items() if v is not None})
        elif tag == "tbody":
            self._in_tbody = True
        elif tag == "tr" and self._in_tbody:
            self._in_row = True
            self._cells = []
        elif tag == "td" and self._in_row:
            self._in_cell = True
            self._cell_text = []
            self._cell_link = None
        elif tag == "a" and self._in_cell:
            self._cell_link = attrs.get("href")
            if attrs.get("rel") == "next":
                self.next_href = attrs.get("href")
            elif attrs.get("rel") == "prev":
                self.prev_href = attrs.get("href")
        elif tag == "a" and attrs.get("rel") == "next":
            self.next_href = attrs.get("href")
        elif tag == "a" and attrs.get("rel") == "prev":
            self.prev_href = attrs.get("href")

    def handle_endtag(self, tag):
        if tag == "td" and self._in_cell:
            self._in_cell = False
            text = "".join(self._cell_text).strip()
            if self._cell_link and not text:
                text = urllib.parse.unquote(urllib.parse.urlsplit(self._cell_link).path.rsplit("/", 1)[-1])
            self._cells.append(text)
        elif tag == "tr" and self._in_row:
            self._in_row = False
            if len(self._cells) >= 4:
                self.rows.append(
                    {
                        "cert_no": self._cells[0],
                        "revision": self._cells[1],
                        "status": self._cells[2],
                        "updated_at": self._cells[3],
                    }
                )
        elif tag == "tbody":
            self._in_tbody = False

    def handle_data(self, data):
        if self._in_cell:
            self._cell_text.append(data)


class _DetailParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root: dict[str, str] = {}
        self.updated: str | None = None
        self.pairs: dict[str, str] = {}
        self.correction: dict[str, Any] | None = None
        self._in_table = False
        self._in_row = False
        self._in_cell = False
        self._cell_text: list[str] = []
        self._cells: list[str] = []
        self._in_updated = False
        self._in_correction = False
        self._correction_depth = 0
        self._in_members = False
        self._correction_id: str | None = None
        self._members: list[str] = []
        self._supersedes: list[str] = []
        self._pending_text: list[str] | None = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "h1":
            self.root.update({k: v for k, v in attrs.items() if v is not None})
        elif tag == "p":
            if "data-revision" in attrs:
                self.root.update({k: v for k, v in attrs.items() if v is not None})
            if attrs.get("class") == "updated":
                self._in_updated = True
            elif self._in_correction:
                self._pending_text = []
        elif tag == "section" and attrs.get("id") == "correction":
            self._in_correction = True
            self._correction_id = attrs.get("data-correction-id")
        elif tag == "table" and not self._in_correction:
            self._in_table = True
        elif tag == "tr" and self._in_table:
            self._in_row = True
            self._cells = []
        elif tag == "td" and self._in_row:
            self._in_cell = True
            self._cell_text = []
        elif tag == "a":
            if attrs.get("class") == "correction-member":
                href = attrs.get("href") or ""
                self._members.append(urllib.parse.unquote(href.rsplit("/", 1)[-1]))

    def handle_endtag(self, tag):
        if tag == "p":
            self._in_updated = False
            if getattr(self, "_pending_text", None) is not None:
                text = "".join(self._pending_text).strip()
                if text.startswith("supersedes:"):
                    suffix = text[len("supersedes:") :].strip()
                    self._supersedes = [s.strip() for s in suffix.split(",") if s.strip()]
                self._pending_text = None
        elif tag == "td" and self._in_cell:
            self._in_cell = False
            self._cells.append("".join(self._cell_text).strip())
        elif tag == "tr" and self._in_row:
            self._in_row = False
            if len(self._cells) == 2:
                self.pairs[self._cells[0]] = self._cells[1]
        elif tag == "table" and self._in_table:
            self._in_table = False
        elif tag == "section" and self._in_correction:
            self._in_correction = False

    def handle_data(self, data):
        if self._in_cell:
            self._cell_text.append(data)
        if self._in_updated:
            text = data.strip()
            if text.startswith("updated"):
                self.updated = text[len("updated") :].strip()
            elif text:
                self.updated = text
        pending = getattr(self, "_pending_text", None)
        if pending is not None:
            pending.append(data)

    def finish(self) -> None:
        if self._correction_id:
            self.correction = {
                "id": self._correction_id,
                "members": self._members,
                "supersedes": self._supersedes,
            }


# ---------------------------------------------------------------------------
# adapters
class _BaseAdapter:
    default_page_size = 10

    def __init__(self, client: _HttpClient, config: dict[str, Any] | None = None):
        self.client = client
        config = config or {}
        try:
            self.page_size = max(1, int(config.get("page_size") or self.default_page_size))
        except (TypeError, ValueError):
            self.page_size = self.default_page_size

    def _detail_urls(self, cert_no: str) -> list[str]:
        raise NotImplementedError

    def open_catalog(self) -> CatalogPage:
        raise NotImplementedError

    def catalog_page(self, token: str) -> CatalogPage:
        raise NotImplementedError

    def detail(self, cert_no: str, revision: int | None = None) -> Detail:
        raise NotImplementedError

    def changes(self, cursor: str, limit: int = 100) -> ChangePage:
        raise NotImplementedError


class HtmlAdapter(_BaseAdapter):
    default_page_size = 10

    def open_catalog(self) -> CatalogPage:
        body, _ = self.client.call_html("/catalog", {"page": 1, "page_size": self.page_size})
        return self._parse(body)

    def catalog_page(self, token: str) -> CatalogPage:
        # token is the page URL produced by the previous page
        body, _ = self.client.call_html(token)
        return self._parse(body)

    def _parse(self, body: str) -> CatalogPage:
        parser = _CatalogTableParser()
        parser.feed(body)
        items = [
            CatalogItem(
                cert_no=row["cert_no"],
                revision=int(row["revision"] or 0),
                status=row["status"] or "active",
                updated_at=row["updated_at"] or None,
            )
            for row in parser.rows
        ]
        return CatalogPage(
            items=items,
            snapshot_id=parser.meta.get("data-snapshot-id"),
            change_position=parser.meta.get("data-change-position"),
            next_token=parser.next_href,
            total=int(parser.meta["data-total"]) if parser.meta.get("data-total") else None,
        )

    def detail(self, cert_no: str, revision: int | None = None) -> Detail:
        body = None
        last_error: Exception | None = None
        for path, params in (
            ("/cert/" + urllib.parse.quote(cert_no), {"rev": revision}),
            ("/certificate", {"no": cert_no, "rev": revision}),
        ):
            status, raw, headers = self.client.get(path, params)
            if status == 404:
                # the alternate entry point may be the only one that knows it
                last_error = NotFound("certificate not found", details={"cert_no": cert_no})
                continue
            self.client._raise_for(status, raw, headers)
            body = raw.decode("utf-8", errors="replace")
            break
        if body is None:
            raise last_error or NotFound("certificate not found")
        parser = _DetailParser()
        parser.feed(body)
        parser.finish()
        root = parser.root
        correction = parser.correction or {}
        data = dict(parser.pairs)
        data.setdefault("cert_no", root.get("data-cert-no", cert_no))
        return Detail(
            cert_no=root.get("data-cert-no", cert_no),
            revision=int(root.get("data-revision", "0") or 0),
            status=root.get("data-status", "active"),
            data=data,
            updated_at=parser.updated,
            revoked_at=root.get("data-revoked-at") or None,
            correction_id=correction.get("id"),
            correction_members=correction.get("members", []),
            correction_supersedes=correction.get("supersedes", []),
        )

    def changes(self, cursor: str, limit: int = 100) -> ChangePage:
        body = self.client.call("/changes", {"since": cursor, "limit": limit})
        return ChangePage(
            items=[
                ChangeEvent(
                    seq=item.get("seq"),
                    kind=item.get("kind") or "upsert",
                    cert_no=item.get("cert_no"),
                    event_id=item.get("event_id"),
                    correction_id=item.get("correction_id"),
                    display_at=item.get("display_at"),
                )
                for item in body.get("items", [])
            ],
            next_cursor=body.get("next_cursor"),
            head_seq=body.get("head_seq"),
            has_more=bool(body.get("has_more")),
            next_seq=body.get("next_seq"),
        )


class JsonAdapter(_BaseAdapter):
    default_page_size = 100

    def open_catalog(self) -> CatalogPage:
        body = self.client.call("/api/v1/items", {"limit": self.page_size})
        return self._parse(body)

    def catalog_page(self, token: str) -> CatalogPage:
        body = self.client.call("/api/v1/items", {"cursor": token})
        return self._parse(body)

    def _parse(self, body: dict[str, Any]) -> CatalogPage:
        return CatalogPage(
            items=[
                CatalogItem(
                    cert_no=item["cert_no"],
                    revision=int(item.get("revision") or 0),
                    status=item.get("status") or "active",
                    updated_at=item.get("updated_at"),
                )
                for item in body.get("items", [])
            ],
            snapshot_id=body.get("snapshot_id"),
            change_position=body.get("change_position"),
            next_token=body.get("next_cursor"),
            total=body.get("total"),
            expires_at=body.get("expires_at"),
        )

    def detail(self, cert_no: str, revision: int | None = None) -> Detail:
        body = None
        last_error: Exception | None = None
        for path, params in (
            ("/api/v1/items/" + urllib.parse.quote(cert_no), {"revision": revision}),
            ("/api/v1/certificate", {"no": cert_no, "revision": revision}),
        ):
            status, raw, headers = self.client.get(path, params)
            if status == 404:
                last_error = NotFound("certificate not found", details={"cert_no": cert_no})
                continue
            self.client._raise_for(status, raw, headers)
            try:
                body = json.loads(raw.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise UpstreamError("upstream returned malformed JSON") from exc
            break
        if body is None:
            raise last_error or NotFound("certificate not found")
        correction = body.get("correction") or {}
        return Detail(
            cert_no=body.get("cert_no", cert_no),
            revision=int(body.get("revision") or 0),
            status=body.get("status") or "active",
            data=dict(body.get("data") or {}),
            updated_at=body.get("updated_at"),
            revoked_at=body.get("revoked_at"),
            correction_id=correction.get("id"),
            correction_members=list(correction.get("members") or []),
            correction_supersedes=list(correction.get("supersedes") or []),
            historical=bool(body.get("historical")),
        )

    def changes(self, cursor: str, limit: int = 100) -> ChangePage:
        body = self.client.call("/api/v1/changes", {"cursor": cursor, "limit": limit})
        return ChangePage(
            items=[
                ChangeEvent(
                    seq=item.get("seq"),
                    kind=item.get("kind") or "upsert",
                    cert_no=item.get("cert_no"),
                    event_id=item.get("event_id"),
                    correction_id=item.get("correction_id"),
                    display_at=item.get("display_at"),
                )
                for item in body.get("items", [])
            ],
            next_cursor=body.get("next_cursor"),
            head_seq=body.get("head_seq"),
            has_more=bool(body.get("has_more")),
            next_seq=body.get("next_seq"),
        )


ADAPTERS = {"html": HtmlAdapter, "json": JsonAdapter}


def build_adapter(config: dict[str, Any], transport: Transport | None = None) -> _BaseAdapter:
    base_url = config.get("base_url")
    kind = config.get("kind")
    if not base_url:
        raise ValidationError("source.base_url is required")
    if kind not in ADAPTERS:
        raise ValidationError(
            "source.kind must be one of html, json", details={"kind": kind}
        )
    if config.get("detail_url") is not None and not isinstance(config["detail_url"], str):
        raise ValidationError("source.detail_url must be a string")
    client = _HttpClient(base_url, transport or UrllibTransport(timeout=float(config.get("timeout", 20))))
    return ADAPTERS[kind](client, config)
