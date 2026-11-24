"""Minimal pytest-compatible runner for environments without pytest.

Supports the small subset used by this repository: module-level ``fixture``
functions, ``parametrize`` markers, ``raises`` and plain ``assert``.  It is a
verification aid only; the project's real runner remains ``pytest``.
"""

from __future__ import annotations

import importlib
import inspect
import os
import sys
import tempfile
import time
import traceback
from types import SimpleNamespace

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ACCEPTANCE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ACCEPTANCE_DIR)
sys.path.insert(0, ROOT)

import pytest_compat as pc  # noqa: E402

sys.modules.setdefault("pytest", pc)

from certcollector.runtime import Runtime  # noqa: E402


class _Client:
    def __init__(self, base_url):
        import json
        import urllib.error
        import urllib.request

        self._json = json
        self._ue = urllib.error
        self._ur = urllib.request
        self.base_url = base_url

    def request(self, method, path, body=None):
        data = None
        headers = {}
        if body is not None:
            data = self._json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = self._ur.Request(self.base_url + path, data=data, method=method, headers=headers)
        try:
            with self._ur.urlopen(req, timeout=30) as resp:
                raw = resp.read()
                return resp.status, self._json.loads(raw) if raw else None
        except self._ue.HTTPError as exc:
            raw = exc.read()
            return exc.code, self._json.loads(raw) if raw else None

    def get(self, path):
        return self.request("GET", path)

    def post(self, path, body=None):
        return self.request("POST", path, body)


def wait_until(predicate, timeout=15.0, interval=0.05, message="condition"):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            value = predicate()
            if value:
                return value
            last = value
        except Exception as exc:
            last = exc
        time.sleep(interval)
    raise AssertionError(f"timed out waiting for {message}; last={last!r}")


def wait_ready(runtime, org_id, count=None, timeout=30.0):
    def ready():
        state = runtime.store.get_state(org_id)
        if not state["ready"]:
            return False
        if count is not None and state["cert_count"] != count:
            return False
        return state["caught_up"]

    return wait_until(ready, timeout=timeout, message=f"{org_id} ready")


def make_fixtures(tmp_path):
    rt = Runtime(
        str(tmp_path / "collector.db"),
        seed=11,
        count=12,
        poll_interval_ms=80,
        full_retry_delay=0.1,
    )
    rt.start()
    fixtures = {
        "runtime": rt,
        "client": _Client(rt.base_url),
        "sim": rt.simulator,
    }
    return rt, fixtures


def main():
    test_dir = os.path.join(ROOT, "tests")
    modules = sorted(
        f[:-3] for f in os.listdir(test_dir) if f.startswith("test_") and f.endswith(".py")
    )
    tmp_root = tempfile.mkdtemp(prefix="cc-pytest-compat-")
    passed = failed = 0
    failures = []
    for mod_name in modules:
        mod = importlib.import_module(f"tests.{mod_name}")
        # inject the names tests import from conftest
        mod.wait_ready = wait_ready
        mod.wait_until = wait_until
        for name, fn in sorted(vars(mod).items()):
            if not name.startswith("test_") or not callable(fn):
                continue
            cases = pc.cases(fn)
            for case_id, kwargs in cases:
                label = f"{mod_name}.{name}" + (f"[{case_id}]" if case_id else "")
                tmp_path = pc.Path(tempfile.mkdtemp(dir=tmp_root))
                rt = None
                try:
                    sig = inspect.signature(fn)
                    needed = set(sig.parameters)
                    if needed:
                        rt, fixtures = make_fixtures(tmp_path)
                        kwargs = {**kwargs, **{k: fixtures[k] for k in needed if k in fixtures}}
                        if "tmp_path" in needed:
                            kwargs["tmp_path"] = tmp_path
                        if set(kwargs) != needed:
                            raise AssertionError(f"unresolved fixtures: {needed - set(kwargs)}")
                    fn(**kwargs)
                    passed += 1
                    print(f"PASS {label}")
                except Exception as exc:  # noqa: BLE001
                    failed += 1
                    failures.append((label, exc, traceback.format_exc(limit=5)))
                    print(f"FAIL {label}: {exc}")
                finally:
                    if rt is not None:
                        rt.stop()
    print("\n" + "=" * 70)
    for label, exc, tb in failures:
        print(f"FAILED {label}\n{tb}")
    print(f"{passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
