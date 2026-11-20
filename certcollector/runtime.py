"""Runtime wiring: database selection, simulated upstreams and the HTTP server."""

from __future__ import annotations

import logging
import os
import tempfile
from typing import Any

from .api import ApiServer, DEFAULT_LIMITS, DEFAULT_OPTIONS, make_api
from .db import make_database
from .engine import Engine
from .sim_sites import HtmlSite, JsonSite
from .sim_world import World
from .source import LoopbackTransport
from .store import Store

log = logging.getLogger("certcollector.runtime")


def default_db_url() -> str:
    raw = os.environ.get("CERTCOLLECTOR_DATABASE_URL")
    if raw:
        # accept the common "sqlite:///path" spelling as well as a bare path
        if raw.startswith("sqlite:///"):
            return raw[len("sqlite:///") :]
        return raw
    return _embedded_url()


def _embedded_url() -> str:
    directory = os.environ.get("CERTCOLLECTOR_DATA_DIR")
    if not directory:
        directory = os.path.join(tempfile.gettempdir(), "certcollector")
    os.makedirs(directory, exist_ok=True)
    return os.path.join(directory, "certcollector.db")


class Simulator:
    """Both simulated bodies served through one loopback router."""

    def __init__(self, seed: int = 7, count: int = 20):
        self.html_world = World("html", count=count, seed=seed)
        self.json_world = World("json", count=count, seed=seed + 1)
        self.html_site = HtmlSite(self.html_world)
        self.json_site = JsonSite(self.json_world)

    def handler(self, request: dict[str, Any]):
        path = request["path"]
        if path.startswith("/json"):
            inner = dict(request)
            inner["path"] = path[len("/json") :] or "/"
            return self.json_site.handle(inner)
        return self.html_site.handle(request)

    def base_urls(self) -> dict[str, str]:
        return {"html": "http://sim.local", "json": "http://sim.local/json"}

    def transport(self, config: dict[str, Any]):
        base_url = str(config.get("base_url") or "")
        kind = config.get("kind")
        expected = self.base_urls().get(kind or "html")
        if expected and base_url.rstrip("/") == expected.rstrip("/"):
            return LoopbackTransport(self.handler, "http://sim.local")
        return None


class Runtime:
    """Everything needed to run the service in one process."""

    def __init__(
        self,
        db_url: str | None = None,
        *,
        simulate: bool = True,
        use_loopback: bool = True,
        seed: int = 7,
        count: int = 20,
        poll_interval_ms: int = 500,
        full_retry_delay: float = 0.5,
        owner_id: str | None = None,
        lease_ttl: float = 3.0,
        lease_renew_interval: float = 0.5,
    ):
        self.db_url = db_url or default_db_url()
        self.db = make_database(self.db_url)
        self.store = Store(self.db)
        self.simulator = Simulator(seed=seed, count=count) if simulate else None
        transport_factory = self.simulator.transport if (simulate and use_loopback) else None
        self.engine = Engine(
            self.store,
            transport_factory,
            poll_interval_ms=poll_interval_ms,
            full_retry_delay=full_retry_delay,
            owner_id=owner_id,
            lease_ttl=lease_ttl,
            lease_renew_interval=lease_renew_interval,
        )
        self.api = make_api(self.store, self.engine, {"db_url": self.db_url})
        self._server: ApiServer | None = None

    # ------------------------------------------------------------------
    def start(self, host: str = "127.0.0.1", port: int = 0) -> "Runtime":
        self.engine.start()
        self._server = ApiServer(self.api, host=host, port=port).start()
        return self

    @property
    def base_url(self) -> str:
        assert self._server is not None
        return self._server.base_url

    def stop(self) -> None:
        if self._server:
            self._server.stop()
            self._server = None
        self.engine.stop()
        self.db.close()

    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()

    # ------------------------------------------------------------------
    def register_simulated_org(
        self,
        org_id: str,
        kind: str = "html",
        *,
        limits: dict[str, Any] | None = None,
        options: dict[str, Any] | None = None,
        start: bool = True,
        name: str | None = None,
    ) -> dict[str, Any]:
        urls = self.simulator.base_urls() if self.simulator else {}
        base_url = urls.get(kind, "http://127.0.0.1:8801")
        source = {"kind": kind, "base_url": base_url, "timeout": 20}
        merged_limits = {**DEFAULT_LIMITS, **(limits or {})}
        merged_options = {**DEFAULT_OPTIONS, **(options or {})}
        org = self.store.upsert_org(org_id, name or org_id, source, merged_limits, merged_options)
        self.engine.runtime(org_id)
        self.engine.claim_now(org_id)
        self.engine._ensure_lanes(org_id)
        if start:
            state = self.store.get_state(org_id)
            if not state["ready"]:
                self.engine.request_full(org_id, "initial")
        return org


def create_runtime_from_env() -> Runtime:
    return Runtime(default_db_url())
