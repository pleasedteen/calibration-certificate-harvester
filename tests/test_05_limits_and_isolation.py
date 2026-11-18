"""Shared upstream limits, Retry-After handling and organization isolation."""

from __future__ import annotations

import time

from .conftest import wait_ready, wait_until


def _site(kind: str) -> str:
    return "http://sim.local" if kind == "html" else "http://sim.local/json"


def test_retry_after_is_honoured_and_reported(client, runtime, sim):
    world = sim.json_world
    world.update_config({"min_interval_ms": 120, "retry_after": 0.05})
    client.post(
        "/api/orgs",
        {
            "org_id": "limit-lab",
            "source": {"kind": "json", "base_url": _site("json")},
            "limits": {"max_concurrency": 1, "min_interval_ms": 0},
            "options": {"poll_interval_ms": 80, "request_attempts": 5},
        },
    )
    wait_until(
        lambda: world.counters["rate_limited"] > 0,
        timeout=20,
        message="upstream to rate limit the collector",
    )
    wait_ready(runtime, "limit-lab")
    status, body = client.get("/api/orgs/limit-lab/status")
    assert status == 200
    upstream = body["upstream"]
    assert upstream["stats"]["rate_limit_hits"] > 0
    assert upstream["stats"]["last_retry_after"] is not None
    assert body["catalog"]["cert_count"] == len(world.state()["certs"])
    world.update_config({"min_interval_ms": 0})


def test_concurrency_limit_is_not_exceeded(client, runtime, sim):
    world = sim.html_world
    world.update_config({"max_concurrency": 1, "slow_ms": 40})
    client.post(
        "/api/orgs",
        {
            "org_id": "conc-lab",
            "source": {"kind": "html", "base_url": _site("html")},
            "limits": {"max_concurrency": 1},
            "options": {"poll_interval_ms": 60, "request_attempts": 5},
        },
    )
    wait_ready(runtime, "conc-lab", timeout=30)
    # the simulator rejects overlapping requests with 429 + Retry-After
    status, body = client.get("/api/orgs/conc-lab/status")
    assert status == 200
    assert body["upstream"]["stats"]["requests"] > 0
    assert body["catalog"]["cert_count"] == len(world.state()["certs"])
    world.update_config({"max_concurrency": 4, "slow_ms": 0})


def test_one_organization_waiting_does_not_block_another(client, runtime, sim):
    slow = sim.json_world
    fast = sim.html_world
    slow.update_config({"min_interval_ms": 300, "retry_after": 0.05, "slow_ms": 20})
    fast.update_config({"min_interval_ms": 0, "slow_ms": 0})
    client.post(
        "/api/orgs",
        {
            "org_id": "blocked-lab",
            "source": {"kind": "json", "base_url": _site("json")},
            "limits": {"max_concurrency": 1},
            "options": {"poll_interval_ms": 50},
        },
    )
    client.post(
        "/api/orgs",
        {
            "org_id": "free-lab",
            "source": {"kind": "html", "base_url": _site("html")},
            "limits": {"max_concurrency": 1},
            "options": {"poll_interval_ms": 50},
        },
    )
    started = time.time()
    wait_ready(runtime, "free-lab", timeout=20)
    free_elapsed = time.time() - started
    # the throttled body is still busy (or has been waiting) while the other finished
    status, slow_state = client.get("/api/orgs/blocked-lab/status")
    assert status == 200
    assert free_elapsed < 5, f"unrelated organization was blocked for {free_elapsed:.1f}s"
    status, free_state = client.get("/api/orgs/free-lab/status")
    assert free_state["catalog"]["caught_up"] is True
    # the blocked organization eventually catches up as well
    wait_ready(runtime, "blocked-lab", timeout=40)
    assert slow.counters["rate_limited"] > 0
    slow.update_config({"min_interval_ms": 0})
    fast.update_config({"min_interval_ms": 0})


def test_status_explains_waiting_and_failure_reasons(client, runtime, sim):
    world = sim.json_world
    world.update_config({"min_interval_ms": 200, "retry_after": 0.05})
    client.post(
        "/api/orgs",
        {
            "org_id": "explain-lab",
            "source": {"kind": "json", "base_url": _site("json")},
            "limits": {"max_concurrency": 1},
            "options": {"poll_interval_ms": 50, "request_attempts": 5},
        },
    )
    found = None
    deadline = time.time() + 20
    while time.time() < deadline:
        status, body = client.get("/api/orgs/explain-lab/status")
        assert status == 200
        if body["upstream"]["wait"]:
            found = body["upstream"]["wait"]
            break
        time.sleep(0.05)
    assert found is not None, "status never reported a wait reason"
    assert found["reason"] in {"rate_limited", "pacing", "concurrency", "source_unavailable"}
    wait_ready(runtime, "explain-lab", timeout=30)
    world.update_config({"min_interval_ms": 0})


def test_transient_source_failures_are_retried(client, runtime, sim):
    world = sim.json_world
    world.update_config({"failure_rate": 0.45, "retry_after": 1})
    client.post(
        "/api/orgs",
        {
            "org_id": "flaky-lab",
            "source": {"kind": "json", "base_url": _site("json")},
            "options": {"poll_interval_ms": 100, "request_attempts": 6},
        },
    )
    wait_ready(runtime, "flaky-lab", timeout=40)
    assert world.counters["failures_injected"] > 0
    assert runtime.store.get_state("flaky-lab")["cert_count"] == len(world.state()["certs"])
    world.update_config({"failure_rate": 0.0})


def test_pause_and_resume(client, runtime, sim):
    client.post(
        "/api/orgs",
        {
            "org_id": "pause-lab",
            "source": {"kind": "html", "base_url": _site("html")},
            "options": {"poll_interval_ms": 80},
        },
    )
    wait_ready(runtime, "pause-lab")
    status, org = client.post("/api/orgs/pause-lab/pause")
    assert status == 200 and org["paused"] is True
    status, body = client.get("/api/orgs/pause-lab/status")
    assert body["phase"] == "paused"
    time.sleep(0.3)
    status, org = client.post("/api/orgs/pause-lab/resume")
    assert status == 200 and org["paused"] is False
    status, body = client.get("/api/orgs/pause-lab/status")
    assert body["phase"] != "paused"
