"""Shared pytest fixtures: isolated runtime per test, fast polling, HTTP helpers."""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from certcollector.runtime import Runtime  # noqa: E402


def wait_until(predicate, timeout: float = 15.0, interval: float = 0.05, message: str = "condition"):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            value = predicate()
            if value:
                return value
            last = value
        except Exception as exc:  # pragma: no cover - surfaced on timeout
            last = exc
        time.sleep(interval)
    raise AssertionError(f"timed out waiting for {message}; last={last!r}")


def wait_ready(runtime: Runtime, org_id: str, count: int | None = None, timeout: float = 20.0):
    def ready():
        state = runtime.store.get_state(org_id)
        if not state["ready"]:
            return False
        if count is not None and state["cert_count"] != count:
            return False
        return state["caught_up"]

    return wait_until(ready, timeout=timeout, message=f"{org_id} catalog ready")


class Client:
    def __init__(self, base_url: str):
        self.base_url = base_url

    def request(self, method: str, path: str, body=None):
        data = None
        headers = {}
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.base_url + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                raw = resp.read()
                return resp.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            return exc.code, json.loads(raw) if raw else None

    def get(self, path):
        return self.request("GET", path)

    def post(self, path, body=None):
        return self.request("POST", path, body)


@pytest.fixture()
def runtime(tmp_path):
    rt = Runtime(
        str(tmp_path / "collector.db"),
        seed=11,
        count=12,
        poll_interval_ms=80,
        full_retry_delay=0.1,
    )
    rt.start()
    try:
        yield rt
    finally:
        rt.stop()


@pytest.fixture()
def client(runtime):
    return Client(runtime.base_url)


@pytest.fixture()
def sim(runtime):
    return runtime.simulator
