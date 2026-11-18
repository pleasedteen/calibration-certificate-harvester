"""Online source switching: no downtime, independent per-body state, resumability."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time

from .conftest import Client, wait_ready, wait_until

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _json(client, org_id, **extra):
    status, body = client.post(
        "/api/orgs",
        {
            "org_id": org_id,
            "source": {"kind": "json", "base_url": "http://sim.local/json"},
            "options": {"poll_interval_ms": 80, **extra.pop("options", {})},
            **extra,
        },
    )
    assert status == 201, body
    return body


def _switch(client, org_id, kind="html", **body):
    status, response = client.post(
        "/api/orgs/%s/source" % org_id,
        {"source": {"kind": kind, "base_url": "http://sim.local" if kind == "html" else "http://sim.local/json"}, **body},
    )
    assert status == 202, response
    return response


def _wait_switch(client, org_id, statuses=("succeeded",), timeout=30):
    return wait_until(
        lambda: client.get(f"/api/orgs/{org_id}/source")[1].get("status") in statuses
        and client.get(f"/api/orgs/{org_id}/source")[1],
        timeout=timeout,
        message=f"{org_id} switch to finish",
    )


def test_switch_keeps_old_body_serving_queries_and_exports(client, runtime, sim):
    _json(client, "swap-lab")
    wait_ready(runtime, "swap-lab")
    world = sim.json_world
    before = runtime.store.get_state("swap-lab")
    assert before["source_generation"] == 0
    status, export = client.post("/api/orgs/swap-lab/exports", {"page_size": 3})
    assert status == 201

    # the new body is slow, so the old one is visibly still serving
    sim.html_world.update_config({"slow_ms": 8})
    switch = _switch(client, "swap-lab", kind="html")
    assert switch["target_generation"] == before["source_generation"] + 1

    served_during = 0
    exported_during = 0
    deadline = time.time() + 15
    while time.time() < deadline:
        state = runtime.store.get_state("swap-lab")
        assert state["ready"] is True
        assert state["cert_count"] == len(world.state()["certs"])
        served_during += 1
        if served_during % 3 == 0:
            status, page = client.get(f"/api/exports/{export['token']}/pages/1")
            assert status == 200
            exported_during += 1
        if runtime.store.get_source_switch("swap-lab")["status"] == "succeeded":
            break
        time.sleep(0.02)
    sim.html_world.update_config({"slow_ms": 0})
    _wait_switch(client, "swap-lab")
    assert served_during > 0
    assert exported_during > 0, "an existing export must stay usable during the switch"

    after = runtime.store.get_state("swap-lab")
    assert after["source_generation"] == 1
    assert after["ready"] is True and after["caught_up"] is True
    assert after["cert_count"] == len(sim.html_world.state()["certs"])
    # certificate content now comes from the new body
    cert = runtime.store.get_cert("swap-lab", "C-1001")
    assert cert["data"]["model"].startswith("HTML")

    # the pre-switch export still serves the version it was frozen on
    status, page = client.get(f"/api/exports/{export['token']}/pages/1")
    assert status == 200
    assert page["catalog_version"] == export["catalog_version"]


def test_switch_status_reports_progress_and_failure_reason(client, runtime, sim):
    _json(client, "watch-lab")
    wait_ready(runtime, "watch-lab")

    # the target body refuses everything for now
    sim.html_world.update_config({"failure_rate": 1.0})
    _switch(client, "watch-lab", kind="html")
    failure = wait_until(
        lambda: (lambda s: s if s and s["error"] else None)(
            client.get("/api/orgs/watch-lab/source")[1]
        ),
        timeout=20,
        message="switch failure to be reported",
    )
    assert failure["status"] in ("retrying", "pending", "running")
    assert failure["failure_reason"]
    status, body = client.get("/api/orgs/watch-lab/status")
    assert status == 200
    switch = body["source_switch"]
    assert switch["active"] is True
    assert switch["error"]["code"]
    assert body["phase"] == "switching_source"
    assert any(r["scope"] == "source_switch" for r in body["reasons"])
    # the old catalog is untouched while the target body fails
    assert body["ready"] is True
    assert body["catalog"]["source_generation"] == 0
    assert runtime.store.get_org("watch-lab")["source"]["kind"] == "json"

    sim.html_world.update_config({"failure_rate": 0.0})
    _wait_switch(client, "watch-lab")
    state = runtime.store.get_state("watch-lab")
    assert state["source_generation"] == 1
    assert state["cert_count"] == len(sim.html_world.state()["certs"])


def test_late_old_body_results_are_discarded_after_switch(client, runtime, sim):
    _json(client, "late-lab")
    wait_ready(runtime, "late-lab")
    json_world = sim.json_world
    html_world = sim.html_world
    # both bodies publish the same numbers with different revisions
    json_world.revise_cert("C-1002", {"temperature": "json-2"})
    html_world.revise_cert("C-1002", {"temperature": "html-2"})
    wait_until(
        lambda: runtime.store.get_cert("late-lab", "C-1002")["data"]["temperature"] == "json-2",
        message="old body revision to land",
    )

    # keep the old body busy so it returns results after the switch committed
    json_world.update_config({"slow_ms": 15})
    json_world.add_cert("C-9500", {"instrument": "old body only"})
    _switch(client, "late-lab", kind="html")
    _wait_switch(client, "late-lab")
    json_world.update_config({"slow_ms": 0})
    state = runtime.store.get_state("late-lab")
    assert state["source_generation"] == 1

    # the new body's revisions are authoritative even when they are lower
    wait_until(
        lambda: runtime.store.get_cert("late-lab", "C-1002")["data"]["temperature"] == "html-2",
        message="new body revision",
    )
    assert runtime.store.get_cert("late-lab", "C-1002")["revision"] == 2
    # a number that only exists on the old body must not survive the switch
    try:
        runtime.store.get_cert("late-lab", "C-9500")
        raise AssertionError("old body certificate leaked into the new catalog")
    except Exception as exc:
        assert exc.__class__.__name__ == "NotFound"
    time.sleep(0.4)
    stored = {
        c["cert_no"]: c["data"].get("temperature")
        for c in runtime.store.list_certs("late-lab", page=1, page_size=500)["items"]
    }
    assert "C-9500" not in stored
    assert runtime.store.get_state("late-lab")["source_generation"] == 1


def test_both_bodies_keep_independent_positions(client, runtime, sim):
    _json(client, "pos-lab")
    wait_ready(runtime, "pos-lab")
    json_world = sim.json_world
    html_world = sim.html_world
    json_world.revise_cert("C-1003", {"temperature": "json-new"})
    wait_until(
        lambda: runtime.store.get_state("pos-lab")["caught_up"]
        and runtime.store.get_cert("pos-lab", "C-1003")["data"]["temperature"] == "json-new",
        message="json position",
    )
    first = runtime.store.get_state("pos-lab")

    _switch(client, "pos-lab", kind="html")
    _wait_switch(client, "pos-lab")
    second = runtime.store.get_state("pos-lab")
    assert second["source_generation"] == 1
    assert second["watermark_seq"] == html_world.seq
    # the JSON body's position is remembered separately
    json_position = runtime.store.get_position("pos-lab", 0)
    assert json_position is not None
    assert json_position["watermark_seq"] == first["watermark_seq"]
    html_position = runtime.store.get_position("pos-lab", 1)
    assert html_position is not None
    assert html_position["watermark_seq"] == second["watermark_seq"]

    # switching back to the JSON body resumes from what it already knows
    _switch(client, "pos-lab", kind="json")
    _wait_switch(client, "pos-lab")
    third = runtime.store.get_state("pos-lab")
    assert third["source_generation"] == 2
    assert runtime.store.get_cert("pos-lab", "C-1003")["data"]["temperature"] == "json-new"
    assert third["cert_count"] == len(json_world.state()["certs"])


def test_repeated_switch_requests_are_not_reapplied(client, runtime, sim):
    _json(client, "repeat-lab")
    wait_ready(runtime, "repeat-lab")
    first = _switch(client, "repeat-lab", kind="html", request_key="move-1")
    second = _switch(client, "repeat-lab", kind="html", request_key="move-1")
    assert second["switch_id"] == first["switch_id"]
    _wait_switch(client, "repeat-lab")
    state = runtime.store.get_state("repeat-lab")
    assert state["source_generation"] == 1

    # re-posting /api/orgs with the same source must not start another switch
    status, body = client.post(
        "/api/orgs",
        {
            "org_id": "repeat-lab",
            "source": {"kind": "html", "base_url": "http://sim.local"},
        },
    )
    assert status == 200, body
    assert runtime.store.get_state("repeat-lab")["source_generation"] == 1
    assert runtime.store.get_source_switch("repeat-lab")["status"] == "succeeded"


def test_switch_resumes_after_engine_restart(client, runtime, sim):
    _json(client, "resume-lab")
    wait_ready(runtime, "resume-lab")
    sim.html_world.update_config({"slow_ms": 12})
    _switch(client, "resume-lab", kind="html")
    time.sleep(0.08)
    runtime.engine.stop()
    sim.html_world.update_config({"slow_ms": 0})
    runtime.engine.start()
    # no re-submission: the durable switch row is enough
    _wait_switch(client, "resume-lab", timeout=40)
    state = runtime.store.get_state("resume-lab")
    assert state["source_generation"] == 1
    assert state["cert_count"] == len(sim.html_world.state()["certs"])
    assert state["caught_up"] is True
    runs = runtime.store.list_runs("resume-lab", limit=30)
    assert any(r["kind"] == "switch" and r["status"] == "succeeded" for r in runs)


def test_rebuild_requested_during_switch_does_not_corrupt_the_new_catalog(client, runtime, sim):
    _json(client, "defer-lab")
    wait_ready(runtime, "defer-lab")
    sim.html_world.update_config({"slow_ms": 10})
    _switch(client, "defer-lab", kind="html")
    status, run = client.post("/api/orgs/defer-lab/rebuild")
    assert status == 202
    _wait_switch(client, "defer-lab")
    sim.html_world.update_config({"slow_ms": 0})
    # the switch scan already rebuilt the catalog, so a rebuild aimed at the
    # previous body is closed out instead of publishing stale content
    wait_until(
        lambda: runtime.store.get_run(run["run_id"])["status"] in ("succeeded", "superseded"),
        timeout=30,
        message="rebuild requested during switch to settle",
    )
    state = runtime.store.get_state("defer-lab")
    assert state["source_generation"] == 1
    assert state["cert_count"] == len(sim.html_world.state()["certs"])
    assert state["caught_up"] is True
    assert runtime.store.get_org("defer-lab")["source"]["kind"] == "html"
    # a rebuild of the *new* body still works normally afterwards
    status, later = client.post("/api/orgs/defer-lab/rebuild")
    assert status == 202
    wait_until(
        lambda: runtime.store.get_run(later["run_id"])["status"] == "succeeded",
        timeout=30,
        message="rebuild of the new body",
    )
    assert runtime.store.get_state("defer-lab")["source_generation"] == 1
    assert runtime.store.get_state("defer-lab")["cert_count"] == len(
        sim.html_world.state()["certs"]
    )


def test_incremental_collection_continues_on_new_body_after_switch(client, runtime, sim):
    _json(client, "post-lab")
    wait_ready(runtime, "post-lab")
    _switch(client, "post-lab", kind="html")
    _wait_switch(client, "post-lab")
    world = sim.html_world
    world.revise_cert("C-1004", {"temperature": "99.0 C"})
    world.add_cert("C-9400", {"instrument": "after switch"})
    wait_until(
        lambda: runtime.store.get_cert("post-lab", "C-1004")["revision"] == 2
        and runtime.store.get_cert("post-lab", "C-9400")["status"] == "active"
        and runtime.store.get_state("post-lab")["caught_up"],
        timeout=25,
        message="incremental collection on the new body",
    )
    assert runtime.store.get_state("post-lab")["cert_count"] == len(world.state()["certs"])


def test_switching_an_uninitialized_org_builds_the_new_catalog(client, runtime, sim):
    status, _ = client.post(
        "/api/orgs",
        {"org_id": "fresh-lab", "source": {"kind": "json", "base_url": "http://sim.local/json"}, "start": False},
    )
    assert status == 201
    state = runtime.store.get_state("fresh-lab")
    assert state["ready"] is False
    _switch(client, "fresh-lab", kind="html")
    _wait_switch(client, "fresh-lab")
    state = runtime.store.get_state("fresh-lab")
    assert state["ready"] is True
    assert state["source_generation"] == 1
    assert state["cert_count"] == len(sim.html_world.state()["certs"])


def test_late_old_body_window_is_rejected_after_commit(client, runtime, sim):
    """Even a window that is already staged cannot touch the new catalog."""
    from certcollector.source import ChangeEvent, ChangePage

    _json(client, "late-win-lab")
    wait_ready(runtime, "late-win-lab")
    stale_run, _ = runtime.store.create_run(
        "late-win-lab", "incremental", "manual", source_generation=0
    )
    runtime.store.update_run(stale_run["run_id"], status="running")
    _switch(client, "late-win-lab", kind="html")
    _wait_switch(client, "late-win-lab")
    assert runtime.store.get_run(stale_run["run_id"])["status"] == "superseded"

    state = runtime.store.get_state("late-win-lab")
    page = ChangePage(
        items=[ChangeEvent(seq=999, kind="upsert", cert_no="C-1001")],
        next_cursor=state["watermark_cursor"],
        head_seq=999,
        has_more=False,
    )
    stale_run = runtime.store.get_run(stale_run["run_id"])
    try:
        runtime.engine._apply_change_window(
            runtime.engine.runtime("late-win-lab"), stale_run, page
        )
        raise AssertionError("a window from the previous body was applied")
    except Exception as exc:
        assert exc.__class__.__name__ == "SourceChanged"
    cert = runtime.store.get_cert("late-win-lab", "C-1001")
    assert cert["data"]["model"].startswith("HTML")
    assert runtime.store.get_state("late-win-lab")["source_generation"] == 1


# ---------------------------------------------------------------------------
# hard-kill recovery across a real process boundary
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
        [sys.executable, "-I", "-c", code], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    line = proc.stdout.readline()
    if not line.strip():
        raise AssertionError(f"simulator failed to start: {proc.stderr.read(4000)}")
    return proc, json.loads(line)


def _start_collector(db_path: str, port: int) -> subprocess.Popen:
    code = (
        "import sys\n"
        f"sys.path.insert(0, {ROOT!r})\n"
        "import json,time\n"
        "from certcollector.runtime import Runtime\n"
        f"rt = Runtime({db_path!r}, simulate=False, poll_interval_ms=80)\n"
        f"rt.start(port={port})\n"
        "print(json.dumps({'listening': rt.base_url}), flush=True)\n"
        "time.sleep(3600)\n"
    )
    return subprocess.Popen(
        [sys.executable, "-I", "-c", code], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )


def _await(proc: subprocess.Popen, timeout: float = 20.0) -> dict:
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


def test_forced_kill_during_switch_resumes_without_resubmission(tmp_path):
    sim_proc, sim_info = _start_sim()
    urls = sim_info["urls"]
    db_path = str(tmp_path / "switch.db")
    port = 18911
    collector = _start_collector(db_path, port)
    try:
        _await(collector)
        c = Client(f"http://127.0.0.1:{port}")
        c.post(
            "/api/orgs",
            {"org_id": "kill-lab", "source": {"kind": "json", "base_url": urls["json"]}},
        )
        wait_until(
            lambda: c.get("/api/orgs/kill-lab/status")[1]["ready"] is True,
            timeout=40,
            message="initial catalog",
        )
        c.post(
            "/api/orgs",
            {
                "org_id": "kill-lab",
                "source": {"kind": "html", "base_url": urls["html"]},
                "limits": {"max_concurrency": 1, "min_interval_ms": 60},
            },
        )
        wait_until(
            lambda: c.get("/api/orgs/kill-lab/source")[1]["status"] == "running",
            timeout=20,
            message="switch to start",
        )
        _kill(collector)
    finally:
        _kill(collector)

    from certcollector.db import make_database
    from certcollector.store import Store

    leftover = Store(make_database(db_path))
    switch = leftover.get_source_switch("kill-lab")
    assert switch["status"] in ("pending", "running", "retrying")
    assert leftover.get_state("kill-lab")["source_generation"] == 0
    leftover.db.close()

    collector = _start_collector(db_path, port)
    try:
        _await(collector)
        c = Client(f"http://127.0.0.1:{port}")
        # no explicit switch request: the recorded intent is resumed
        wait_until(
            lambda: c.get("/api/orgs/kill-lab/source")[1]["status"] == "succeeded",
            timeout=60,
            message="resumed switch",
        )
        _, status = c.get("/api/orgs/kill-lab/status")
        assert status["source_generation"] == 1
        assert status["source"]["kind"] == "html"
        assert status["catalog"]["caught_up"] is True
        _, page = c.get("/api/orgs/kill-lab/certs?page=1&page_size=1")
        assert page["total"] == 24
    finally:
        _kill(collector)
        _kill(sim_proc)
