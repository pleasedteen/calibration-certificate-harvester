"""Process-level source-switch recovery.

The simulated bodies run in a separate process (``certcollector.sim_server``),
so killing the collector mid-switch is a genuine interruption.  Two scenarios
are exercised against the two simulated bodies:

* a switch started against a temporarily unavailable body completes by itself
  once that body is brought back online;
* the collector is hard-killed while a switch is in flight; after restart the
  durable pending switch resumes and cuts over without any new request.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
import urllib.request

from .conftest import Client, wait_until

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _start_sim(port: int = 0) -> tuple[subprocess.Popen, dict]:
    code = (
        "import sys\n"
        f"sys.path.insert(0, {ROOT!r})\n"
        "from certcollector.sim_server import SimServer\n"
        "import json, time\n"
        f"s = SimServer('127.0.0.1', {port}, seed=7, count=24).start()\n"
        "print(json.dumps({'urls': s.urls()}), flush=True)\n"
        "time.sleep(3600)\n"
    )
    proc = subprocess.Popen(
        [sys.executable, "-I", "-c", code],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    line = proc.stdout.readline()
    if not line.strip():
        err = proc.stderr.read(4000)
        raise AssertionError(f"simulator failed to start: {err}")
    return proc, json.loads(line)


def _start_collector(db_path: str, port: int) -> subprocess.Popen:
    code = (
        "import sys\n"
        f"sys.path.insert(0, {ROOT!r})\n"
        "import json,time\n"
        "from certcollector.runtime import Runtime\n"
        f"rt = Runtime({db_path!r}, simulate=False, poll_interval_ms=100)\n"
        f"rt.start(port={port})\n"
        "print(json.dumps({'listening': rt.base_url}), flush=True)\n"
        "time.sleep(3600)\n"
    )
    return subprocess.Popen(
        [sys.executable, "-I", "-c", code],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _await_line(proc: subprocess.Popen, timeout: float = 20.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = proc.stdout.readline()
        if line:
            return json.loads(line)
    raise AssertionError("process did not report readiness")


def _kill(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.send_signal(signal.SIGKILL)
    proc.wait(timeout=10)


def _admin(base_url: str, action: str) -> None:
    req = urllib.request.Request(base_url + "/__admin/" + action, method="GET")
    with urllib.request.urlopen(req, timeout=10) as resp:
        assert resp.status == 200


def _start_and_ready(client: Client, org_id: str, source_url: str, kind: str):
    status, body = client.post(
        "/api/orgs",
        {"org_id": org_id, "source": {"kind": kind, "base_url": source_url}},
    )
    assert status == 201, body
    wait_until(
        lambda: client.get(f"/api/orgs/{org_id}/status")[1].get("ready") is True,
        timeout=40,
        message="initial catalog",
    )


def test_switch_auto_recovers_when_new_body_comes_back(tmp_path):
    sim_proc, info = _start_sim()
    try:
        urls = info["urls"]
        db_path = str(tmp_path / "auto.db")
        port = 19011
        collector = _start_collector(db_path, port)
        try:
            _await_line(collector)
            c = Client(f"http://127.0.0.1:{port}")
            _start_and_ready(c, "auto-switch", urls["json"], "json")
            before = c.get("/api/orgs/auto-switch/status")[1]["catalog"]

            # take the target body offline, then request the switch
            _admin(urls["alt"], "disable")
            status, body = c.post(
                "/api/orgs",
                {"org_id": "auto-switch", "source": {"kind": "json", "base_url": urls["alt"]}},
            )
            assert status == 202
            switch_id = body["source_switch"]["switch_id"]

            # the old catalog keeps serving while the target is unreachable
            deadline = time.time() + 3.0
            while time.time() < deadline:
                status, detail = c.get("/api/orgs/auto-switch")
                assert detail["catalog"]["ready"] is True
                assert detail["catalog"]["version"] == before["version"]
                assert detail["pending_switch"]["switch_id"] == switch_id
                assert detail["source"]["base_url"] == urls["json"]
                time.sleep(0.1)

            # bring the body back: no further API call, the switch self-heals
            _admin(urls["alt"], "enable")
            wait_until(
                lambda: c.get("/api/orgs/auto-switch")[1]["pending_switch"] is None,
                timeout=60,
                message="automatic switch completion",
            )
            status, detail = c.get("/api/orgs/auto-switch")
            assert detail["source"]["base_url"] == urls["alt"]
            assert detail["catalog"]["ready"] is True
            assert detail["catalog"]["cert_count"] > 0
            status, switches = c.get("/api/orgs/auto-switch/switches")
            assert switches["items"][0]["status"] == "completed"
        finally:
            _kill(collector)
    finally:
        _kill(sim_proc)


def test_switch_survives_hard_kill_and_resumes_after_restart(tmp_path):
    sim_proc, info = _start_sim()
    try:
        urls = info["urls"]
        db_path = str(tmp_path / "kill.db")
        port = 19012
        collector = _start_collector(db_path, port)
        try:
            _await_line(collector)
            c = Client(f"http://127.0.0.1:{port}")
            _start_and_ready(c, "kill-switch", urls["html"], "html")

            # make the target body slow so the kill lands mid-collection
            req = urllib.request.Request(
                urls["alt"] + "/__admin/config",
                data=json.dumps({"slow_ms": 40}).encode(),
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                assert resp.status == 200

            status, body = c.post(
                "/api/orgs",
                {"org_id": "kill-switch", "source": {"kind": "json", "base_url": urls["alt"]}},
            )
            assert status == 202
            switch_id = body["source_switch"]["switch_id"]
            time.sleep(0.4)
            status, detail = c.get("/api/orgs/kill-switch")
            assert detail["pending_switch"] is not None
            _kill(collector)
        finally:
            _kill(collector)

        # durable state must still show the pending cutover
        from certcollector.db import make_database
        from certcollector.store import Store

        leftover = Store(make_database(db_path))
        pending = leftover.get_pending_switch("kill-switch")
        assert pending is not None and pending["switch_id"] == switch_id
        assert leftover.get_org("kill-switch")["source"]["base_url"] == urls["html"]
        leftover.db.close()

        # restore target speed, restart the collector without any new request
        req = urllib.request.Request(
            urls["alt"] + "/__admin/config",
            data=json.dumps({"slow_ms": 0}).encode(),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            assert resp.status == 200

        collector = _start_collector(db_path, port)
        try:
            _await_line(collector)
            c = Client(f"http://127.0.0.1:{port}")
            wait_until(
                lambda: c.get("/api/orgs/kill-switch")[1]["pending_switch"] is None,
                timeout=60,
                message="resumed switch to complete",
            )
            status, detail = c.get("/api/orgs/kill-switch")
            assert detail["source"]["base_url"] == urls["alt"]
            assert detail["catalog"]["ready"] is True
            assert detail["catalog"]["caught_up"] is True
            status, page = c.get("/api/orgs/kill-switch/certs?page=1&page_size=500")
            assert page["total"] == detail["catalog"]["cert_count"]
            status, switches = c.get("/api/orgs/kill-switch/switches")
            assert any(s["switch_id"] == switch_id and s["status"] == "completed" for s in switches["items"])
        finally:
            _kill(collector)
    finally:
        _kill(sim_proc)
