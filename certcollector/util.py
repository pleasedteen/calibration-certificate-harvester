"""Shared error types and small helpers."""

from __future__ import annotations

import datetime as _dt
import json
import re
from typing import Any


class CertCollectorError(Exception):
    status = 500
    code = "internal_error"

    def __init__(self, message: str, *, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def as_dict(self) -> dict[str, Any]:
        return {"error": self.code, "message": self.message, "details": self.details}


class ValidationError(CertCollectorError):
    status = 400
    code = "validation_error"


class NotFound(CertCollectorError):
    status = 404
    code = "not_found"


class Conflict(CertCollectorError):
    status = 409
    code = "conflict"


class Gone(CertCollectorError):
    status = 410
    code = "gone"


class HistoryExpired(Gone):
    status = 410
    code = "history_expired"


class UpstreamError(CertCollectorError):
    status = 502
    code = "upstream_error"


class RateLimited(UpstreamError):
    status = 429
    code = "rate_limited"


class SourceUnavailable(UpstreamError):
    status = 503
    code = "source_unavailable"


class ChannelExpired(UpstreamError):
    status = 502
    code = "channel_expired"


UTC = _dt.timezone.utc


def utcnow() -> _dt.datetime:
    return _dt.datetime.now(UTC)


def iso(dt: _dt.datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


def parse_iso(value: str | None) -> _dt.datetime | None:
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = _dt.datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def loads(text: str | bytes | None, default: Any = None) -> Any:
    if text is None:
        return default
    if isinstance(text, bytes):
        text = text.decode("utf-8")
    if text == "":
        return default
    return json.loads(text)


_ORG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


def validate_org_id(org_id: str) -> str:
    if not isinstance(org_id, str) or not _ORG_RE.match(org_id):
        raise ValidationError(
            "org_id must match ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$", details={"org_id": org_id}
        )
    return org_id


def chunked(items: list[Any], size: int):
    for i in range(0, len(items), size):
        yield items[i : i + size]
