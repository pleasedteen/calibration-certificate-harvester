"""Hard-kill recovery: the service restarts after its whole process is killed.

The simulated sources run in a separate process (``certcollector.sim_server``),
so killing the collector is a genuine interruption of the network conversation
rather than a same-process re-entrancy check.  Restarting must resume work, be
allowed to repeat requests, and converge to the same catalog as an
uninterrupted run.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time

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
    info = json.loads(line)
    return proc, info


def _start_collector(db_path: str, port: int, sim_urls: dict, org_id: str, kind: str) -> subprocess.Popen:
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
        time.sleep(0.01)
    raise AssertionError("process did not report readiness")


def _kill(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.send_signal(signal.SIGKILL)
    proc.wait(timeout=10)


def test_forced_kill_and_restart_converges(tmp_path):
    sim_proc, sim_info = _start_sim()
    try:
        urls = sim_info["urls"]
        db_path = str(tmp_path / "crash.db")
        port = 18901
        # baseline: an uninterrupted run against the same upstream
        base_db = str(tmp_path / "baseline.db")
        base_port = 18902
        base = _start_collector(base_db, base_port, urls, "crash-lab", "json")
        try:
            _await_line(base)
            c = Client(f"http://127.0.0.1:{base_port}")
            c.post(
                "/api/orgs",
                {"org_id": "crash-lab", "source": {"kind": "json", "base_url": urls["json"]}},
            )
            wait_until(
                lambda: c.get("/api/orgs/crash-lab/status")[1]["ready"] is True,
                timeout=40,
                message="baseline catalog",
            )
            _, baseline_export = c.post("/api/orgs/crash-lab/exports", {"page_size": 7})
            baseline = []
            page = 1
            while page:
                _, body = c.get(f"/api/exports/{baseline_export['token']}/pages/{page}")
                baseline.extend(item["cert_no"] for item in body["items"])
                page = body["next_page"]
        finally:
            _kill(base)

        # the actual run: kill mid-collection, restart, assert convergence
        collector = _start_collector(db_path, port, urls, "crash-lab", "json")
        try:
            _await_line(collector)
            c = Client(f"http://127.0.0.1:{port}")
            c.post(
                "/api/orgs",
                {
                    "org_id": "crash-lab",
                    "source": {"kind": "json", "base_url": urls["json"]},
                    "limits": {"max_concurrency": 1, "min_interval_ms": 120},
                    "options": {"poll_interval_ms": 80},
                },
            )
            # let a few requests through, then hard-kill the collector
            time.sleep(0.5)
            _, mid_status = c.get("/api/orgs/crash-lab/status")
            assert mid_status["ready"] is False, "kill must happen before the catalog is ready"
            assert mid_status["catalog"]["cert_count"] == 0
            _kill(collector)
        finally:
            _kill(collector)
        # inspect the durable state left behind by the hard kill
        from certcollector.db import make_database
        from certcollector.store import Store

        leftover = Store(make_database(db_path))
        assert leftover.get_state("crash-lab")["ready"] is False
        interrupted = [
            r for r in leftover.list_runs("crash-lab", limit=50)
            if r["status"] in ("queued", "running", "interrupted")
        ]
        assert interrupted, "a killed run must be recoverable from storage"
        leftover.db.close()

        collector = _start_collector(db_path, port, urls, "crash-lab", "json")
        try:
            _await_line(collector)
            c = Client(f"http://127.0.0.1:{port}")
            # no explicit rebuild: the service resumes interrupted work by itself
            # (duplicate/repeated requests after a crash are allowed)
            first = c.post("/api/orgs/crash-lab/collect", {"mode": "full", "request_key": "resume-1"})
            second = c.post("/api/orgs/crash-lab/collect", {"mode": "full", "request_key": "resume-1"})
            assert first[1]["run_id"] == second[1]["run_id"]
            wait_until(
                lambda: c.get("/api/orgs/crash-lab/status")[1].get("ready") is True,
                timeout=60,
                message="restarted catalog",
            )
            wait_until(
                lambda: c.get("/api/orgs/crash-lab/status")[1]["catalog"]["caught_up"] is True,
                timeout=60,
                message="restarted catalog caught up",
            )
            _, export = c.post("/api/orgs/crash-lab/exports", {"page_size": 7})
            seen = []
            page = 1
            while page:
                _, body = c.get(f"/api/exports/{export['token']}/pages/{page}")
                seen.extend(item["cert_no"] for item in body["items"])
                page = body["next_page"]
            assert seen == baseline
            _, status = c.get("/api/orgs/crash-lab/status")
            assert status["ready"] is True
            assert status["catalog"]["caught_up"] is True
        finally:
            _kill(collector)
    finally:
        _kill(sim_proc)
