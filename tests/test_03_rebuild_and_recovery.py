"""Online rebuilds, catalog replacement, retention and expiry recovery."""

from __future__ import annotations

import time

from .conftest import wait_ready, wait_until


def _setup(client, org_id, kind="json", **extra):
    payload = {
        "org_id": org_id,
        "source": {
            "kind": kind,
            "base_url": "http://sim.local" if kind == "html" else "http://sim.local/json",
        },
        "options": {"poll_interval_ms": 100, **extra.pop("options", {})},
        **extra,
    }
    status, body = client.post("/api/orgs", payload)
    assert status == 201, body
    return body


def test_rebuild_keeps_incremental_channel_serving(client, runtime, sim):
    _setup(client, "build-lab")
    wait_ready(runtime, "build-lab")
    world = sim.json_world
    # make the rebuild slow enough to observe the catalog while it runs
    world.update_config({"slow_ms": 15})
    status, run = client.post("/api/orgs/build-lab/rebuild")
    assert status == 202
    assert run["kind"] == "full"

    saw_version_during_rebuild = False
    for _ in range(12):
        time.sleep(0.03)
        state = runtime.store.get_state("build-lab")
        assert state["ready"] is True
        assert state["cert_count"] == len(world.state()["certs"])
        if state["version"] >= 1:
            saw_version_during_rebuild = True
    assert saw_version_during_rebuild
    world.update_config({"slow_ms": 0})
    wait_until(
        lambda: runtime.store.get_run(run["run_id"])["status"] == "succeeded",
        timeout=25,
        message="rebuild to complete",
    )
    state = runtime.store.get_state("build-lab")
    assert state["ready"] and state["caught_up"]
    assert state["cert_count"] == len(world.state()["certs"])


def test_rebuild_does_not_regress_or_resurrect(client, runtime, sim):
    _setup(client, "regress-lab", kind="html")
    wait_ready(runtime, "regress-lab")
    world = sim.html_world
    world.correction("C-1010", [{"cert_no": "C-8401", "data": {"instrument": "new"}}])
    wait_until(
        lambda: runtime.store.get_cert("regress-lab", "C-8401")["status"] == "active"
        and runtime.store.get_cert("regress-lab", "C-1010")["status"] == "revoked",
        message="correction to land",
    )
    before = runtime.store.get_state("regress-lab")
    status, run = client.post("/api/orgs/regress-lab/rebuild")
    assert status == 202
    wait_until(
        lambda: runtime.store.get_run(run["run_id"])["status"] in ("succeeded", "failed"),
        timeout=25,
        message="rebuild to finish",
    )
    after = runtime.store.get_state("regress-lab")
    assert after["version"] > before["version"]
    assert runtime.store.get_cert("regress-lab", "C-1010")["status"] == "revoked"
    assert runtime.store.get_cert("regress-lab", "C-8401")["status"] == "active"
    assert after["cert_count"] == len(world.state()["certs"])


def test_snapshot_missing_certificates_leave_catalog(client, runtime, sim):
    _setup(client, "shrink-lab")
    wait_ready(runtime, "shrink-lab")
    world = sim.json_world
    before = runtime.store.get_state("shrink-lab")["cert_count"]
    world.purge_cert("C-1008")
    world.purge_cert("C-1009")
    wait_until(
        lambda: runtime.store.get_state("shrink-lab")["cert_count"] == before - 2,
        message="purges to cascade",
    )
    status, run = client.post("/api/orgs/shrink-lab/rebuild")
    wait_until(
        lambda: runtime.store.get_run(run["run_id"])["status"] == "succeeded",
        timeout=25,
        message="rebuild after purge",
    )
    state = runtime.store.get_state("shrink-lab")
    assert state["cert_count"] == before - 2
    for no in ("C-1008", "C-1009"):
        assert client.get(f"/api/orgs/shrink-lab/certs/{no}")[0] == 404


def test_expired_snapshot_triggers_restart_and_recovers(client, runtime, sim):
    _setup(client, "expire-lab", options={"poll_interval_ms": 100})
    wait_ready(runtime, "expire-lab")
    world = sim.json_world
    world.update_config({"slow_ms": 10})
    status, run = client.post("/api/orgs/expire-lab/rebuild")
    time.sleep(0.05)
    world.expire_all()
    wait_until(
        lambda: runtime.store.get_run(run["run_id"])["status"] in ("succeeded", "failed", "queued"),
        timeout=25,
        message="rebuild to observe expiry",
    )
    world.update_config({"slow_ms": 0})
    wait_until(
        lambda: runtime.store.get_state("expire-lab")["caught_up"],
        timeout=30,
        message="catalog to recover after expiry",
    )
    state = runtime.store.get_state("expire-lab")
    assert state["ready"] is True
    assert state["cert_count"] == len(world.state()["certs"])


def test_expired_history_is_reported_by_source(client, runtime, sim):
    status, body = client.post(
        "/api/orgs",
        {"org_id": "history-lab", "source": {"kind": "json", "base_url": "http://sim.local/json"}},
    )
    assert status == 201
    wait_ready(runtime, "history-lab")
    world = sim.json_world
    world.update_config({"history_retention": 0.3})
    world.revise_cert("C-1011", {"temperature": "30.0 C"})
    world.revise_cert("C-1011", {"temperature": "31.0 C"})
    from certcollector.source import build_adapter

    adapter = build_adapter(
        {"kind": "json", "base_url": "http://sim.local/json"},
        runtime.simulator.transport({"kind": "json", "base_url": "http://sim.local/json"}),
    )
    detail = adapter.detail("C-1011", revision=2)
    assert detail.revision == 2
    time.sleep(0.6)
    import pytest

    from certcollector.util import HistoryExpired

    with pytest.raises(HistoryExpired):
        adapter.detail("C-1011", revision=2)


def test_interrupted_run_is_recovered_and_converges(client, runtime, sim):
    _setup(client, "recover-lab")
    wait_ready(runtime, "recover-lab")
    world = sim.json_world
    world.update_config({"slow_ms": 8})
    status, run = client.post("/api/orgs/recover-lab/rebuild")
    time.sleep(0.05)
    # simulate an unclean stop: the run and its scan are left behind in storage
    runtime.engine.stop()
    world.update_config({"slow_ms": 0})
    runtime.engine.start()
    wait_until(
        lambda: runtime.store.get_state("recover-lab")["caught_up"],
        timeout=30,
        message="catalog to converge after restart",
    )
    state = runtime.store.get_state("recover-lab")
    assert state["ready"] is True
    assert state["cert_count"] == len(world.state()["certs"])
    runs = runtime.store.list_runs("recover-lab", limit=30)
    assert any(r["status"] == "succeeded" for r in runs)


def test_repeated_rebuilds_with_continuous_updates_converge(client, runtime, sim):
    """A rebuild storm while the source keeps changing must converge exactly."""
    client.post(
        "/api/orgs",
        {
            "org_id": "storm-lab",
            "source": {"kind": "html", "base_url": "http://sim.local"},
            "options": {"poll_interval_ms": 40},
        },
    )
    wait_ready(runtime, "storm-lab")
    world = sim.html_world
    world.start_auto_updates(15)
    try:
        for _ in range(3):
            status, run = client.post("/api/orgs/storm-lab/rebuild")
            assert status == 202
            time.sleep(0.3)
    finally:
        world.stop_auto_updates()
    # "caught up" is as-of-last-observation, so require the collector to have
    # actually read past the final source position.
    wait_until(
        lambda: runtime.store.get_state("storm-lab")["source_head_seq"] >= world.seq
        and runtime.store.get_state("storm-lab")["caught_up"],
        timeout=40,
        message="catalog to converge after rebuild storm",
    )
    source = {c["cert_no"]: (c["revision"], c["status"]) for c in world.state()["certs"]}
    stored = {
        c["cert_no"]: (c["revision"], c["status"])
        for c in runtime.store.list_certs("storm-lab", page=1, page_size=500)["items"]
    }
    assert stored == source
    # no revoked certificate may come back as active
    assert all(v[1] == "active" for v in stored.values())
