"""Standalone HTTP server for the two simulated bodies.

Useful for demos and for crash tests where the collector runs in a separate
process from its (simulated) upstream::

    python3 -m certcollector.sim_server --port 8801

Site A  -> http://127.0.0.1:8801            (HTML pagination)
Site B  -> http://127.0.0.1:8801/json       (cursor based JSON)
"""

from __future__ import annotations

import argparse
import json
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .sim_sites import HtmlSite, JsonSite
from .sim_world import World


class SimServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 0, seed: int = 7, count: int = 20):
        self.html_world = World("html", count=count, seed=seed)
        self.json_world = World("json", count=count, seed=seed + 1)
        self.html_site = HtmlSite(self.html_world)
        self.json_site = JsonSite(self.json_world)
        self.httpd = ThreadingHTTPServer((host, port), self._handler_class())
        self.httpd.daemon_threads = True
        self.host, self.port = self.httpd.server_address[:2]
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def urls(self) -> dict[str, str]:
        return {"html": self.base_url, "json": self.base_url + "/json"}

    def route(self, request: dict[str, Any]):
        path = request["path"]
        if path.startswith("/json"):
            inner = dict(request)
            inner["path"] = path[len("/json") :] or "/"
            return self.json_site.handle(inner)
        return self.html_site.handle(request)

    def _handler_class(self):
        router = self.route

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt, *args):
                pass

            def _do(self, method: str):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else None
                split = urllib.parse.urlsplit(self.path)
                query = {k: v[-1] for k, v in urllib.parse.parse_qs(split.query).items()}
                status, payload, headers = router(
                    {
                        "method": method,
                        "path": split.path,
                        "query": query,
                        "body": raw.decode("utf-8") if raw else None,
                    }
                )
                if isinstance(payload, str):
                    payload = payload.encode("utf-8")
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_GET(self):
                self._do("GET")

            def do_POST(self):
                self._do("POST")

        return Handler

    def start(self) -> "SimServer":
        self._thread = threading.Thread(
            target=self.httpd.serve_forever,
            kwargs={"poll_interval": 0.05},
            name="sim-http",
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="certcollector.sim_server", description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8801)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--count", type=int, default=20)
    args = parser.parse_args(argv)
    server = SimServer(args.host, args.port, args.seed, args.count).start()
    print(json.dumps({"simulator": server.base_url, "urls": server.urls()}), flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.stop()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
