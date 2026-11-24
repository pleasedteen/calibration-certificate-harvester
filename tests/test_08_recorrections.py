"""Re-corrections with temporarily unreadable detail pages.

A correction member that the upstream directory still lists while its detail
page answers 404 must hold *that* correction back without blocking unrelated
revisions, be visible through the status endpoints, and converge automatically
once the member is readable again or confirmed removed from the directory.
The same guarantees hold for full rebuilds, for re-correction chains and after
a restart with expired continuation positions.  Both simulated bodies are
exercised.
"""

from __future__ import annotations

import time

import pytest

from .conftest import wait_ready, wait_until


def _setup(client, org_id, kind):
    status, body = client.post(
        "/api/orgs",
        {
            "org_id": org_id,
            "source": {
                "kind": kind,
                "base_url": "http://sim.local" if kind == "html" else "http://sim.local/json",
            },
            "options": {"poll_interval_ms": 80},
        },
    )
    assert status == 201, body
    return body


@pytest.mark.parametrize("kind", ["html", "json"])
def test_listed_404_holds_correction_but_keeps_unrelated_revisions(client, runtime, sim, kind):
    org = f"hold-{kind}"
    _setup(client, org, kind)
    wait_ready(runtime, org)
    world = sim.html_world if kind == "html" else sim.json_world
    baseline = runtime.store.get_state(org)["cert_count"]

    world.revise_cert("C-1001", {"temperature": "23.0 C"})
    result = world.correction(
        "C-1002",
        [
            {"cert_no": "C-9101", "data": {"instrument": "Balance"}},
            {"cert_no": "C-9102", "data": {"instrument": "Gauge"}},
        ],
    )
    cid = result["correction_id"]
    world.hide_detail(["C-9102"])

    # unrelated revision keeps applying
    wait_until(
        lambda: runtime.store.get_cert(org, "C-1001")["revision"] == 2,
        message="unrelated revision applies while the correction waits",
    )

    # the correction is tracked as pending and never appears partially
    wait_until(
        lambda: any(p["correction_id"] == cid for p in runtime.store.list_pending_corrections(org)),
        message="blocked correction registered",
    )
    deadline = time.time() + 3.0
    while time.time() < deadline:
        assert runtime.store.get_cert(org, "C-1002")["status"] == "active"
        with pytest.raises(Exception):
            runtime.store.get_cert(org, "C-9102")
        time.sleep(0.05)
    assert any(p["cert_no"] == "C-9102" for p in runtime.store.list_pending_reads(org))

    # status explains the pending work explicitly
    status, body = client.get(f"/api/orgs/{org}/status")
    assert status == 200
    assert body["corrections_pending"] is True
    assert {r["scope"] for r in body["reasons"]} & {"correction", "detail"}
    assert body["pending_reads"][0]["cert_no"] == "C-9102"
    # catalog size is unchanged by the held correction
    assert runtime.store.get_state(org)["cert_count"] == baseline

    # healing the detail page converges the whole group atomically
    world.show_detail(["C-9102"])
    wait_until(
        lambda: runtime.store.get_state(org)["caught_up"]
        and runtime.store.get_cert(org, "C-1002")["status"] == "revoked"
        and runtime.store.get_cert(org, "C-9101")["status"] == "active"
        and runtime.store.get_cert(org, "C-9102")["status"] == "active",
        timeout=30,
        message="correction converges after the member becomes readable",
    )
    wait_until(
        lambda: not runtime.store.list_pending_corrections(org)
        and not runtime.store.list_pending_reads(org),
        message="pending bookkeeping clears",
    )
    status, body = client.get(f"/api/orgs/{org}/status")
    assert body["corrections_pending"] is False


@pytest.mark.parametrize("kind", ["html", "json"])
def test_rebuild_waits_on_listed_404_and_publishes_complete_result(client, runtime, sim, kind):
    org = f"rebuild-{kind}"
    _setup(client, org, kind)
    wait_ready(runtime, org)
    world = sim.html_world if kind == "html" else sim.json_world
    baseline = runtime.store.get_state(org)["cert_count"]

    world.correction(
        "C-1003",
        [
            {"cert_no": "C-9201", "data": {"instrument": "A"}},
            {"cert_no": "C-9202", "data": {"instrument": "B"}},
        ],
    )
    wait_until(
        lambda: runtime.store.get_cert(org, "C-1003")["status"] == "revoked"
        and runtime.store.get_cert(org, "C-9202")["status"] == "active",
        message="initial correction lands",
    )
    world.hide_detail(["C-9201"])
    status, run = client.post(f"/api/orgs/{org}/rebuild")
    assert status == 202

    wait_until(
        lambda: runtime.store.get_run(run["run_id"])["phase"] == "awaiting_correction"
        or runtime.store.get_run(run["run_id"])["status"] == "succeeded",
        timeout=20,
        message="rebuild enters the waiting state",
    )
    time.sleep(0.4)
    current = runtime.store.get_run(run["run_id"])
    assert current["status"] in ("queued", "running"), current
    # previously published catalog keeps serving in full
    state = runtime.store.get_state(org)
    assert state["ready"] and state["cert_count"] == baseline + 2

    world.show_detail(["C-9201"])
    wait_until(
        lambda: runtime.store.get_run(run["run_id"])["status"] == "succeeded",
        timeout=30,
        message="blocked rebuild finishes after heal",
    )
    state = runtime.store.get_state(org)
    assert state["caught_up"]
    assert state["cert_count"] == len(world.state()["certs"])
    assert runtime.store.get_cert(org, "C-9201")["status"] == "active"
    assert not runtime.store.list_pending_reads(org)


@pytest.mark.parametrize("kind", ["html", "json"])
def test_member_removed_from_directory_converges_remaining_group(client, runtime, sim, kind):
    org = f"removed-{kind}"
    _setup(client, org, kind)
    wait_ready(runtime, org)
    world = sim.html_world if kind == "html" else sim.json_world

    world.correction(
        "C-1004",
        [
            {"cert_no": "C-9301", "data": {"instrument": "A"}},
            {"cert_no": "C-9302", "data": {"instrument": "B"}},
        ],
    )
    world.hide_detail(["C-9302"])
    wait_until(
        lambda: any(p["cert_no"] == "C-9302" for p in runtime.store.list_pending_reads(org)),
        message="blocked member registered",
    )
    world.show_detail(["C-9302"])
    world.purge_cert("C-9302")
    wait_until(
        lambda: runtime.store.get_cert(org, "C-1004")["status"] == "revoked"
        and runtime.store.get_cert(org, "C-9301")["status"] == "active"
        and runtime.store.get_state(org)["caught_up"],
        timeout=30,
        message="group converges after member leaves the directory",
    )
    stored = {c["cert_no"] for c in runtime.store.list_certs(org, page=1, page_size=500)["items"]}
    assert stored == {c["cert_no"] for c in world.state()["certs"]}
    assert not runtime.store.list_pending_reads(org)


@pytest.mark.parametrize("kind", ["html", "json"])
def test_recorrection_chain_publishes_fully_on_both_lanes(client, runtime, sim, kind):
    org = f"chain-{kind}"
    _setup(client, org, kind)
    wait_ready(runtime, org)
    world = sim.html_world if kind == "html" else sim.json_world

    world.correction(
        "C-1005",
        [
            {"cert_no": "C-9401", "data": {"instrument": "A"}},
            {"cert_no": "C-9402", "data": {"instrument": "B"}},
        ],
    )
    wait_until(
        lambda: runtime.store.get_cert(org, "C-1005")["status"] == "revoked"
        and runtime.store.get_cert(org, "C-9402")["status"] == "active",
        message="first correction lands",
    )
    first_cid = runtime.store.get_cert(org, "C-9401")["correction"]["id"]

    second = world.correction(
        "C-9401",
        [
            {"cert_no": "C-9501", "data": {"instrument": "A2"}},
            {"cert_no": "C-9502", "data": {"instrument": "A3"}},
        ],
    )
    assert second["correction_id"] != first_cid
    wait_until(
        lambda: runtime.store.get_state(org)["caught_up"]
        and runtime.store.get_cert(org, "C-9401")["status"] == "revoked"
        and runtime.store.get_cert(org, "C-9501")["status"] == "active"
        and runtime.store.get_cert(org, "C-9502")["status"] == "active"
        and runtime.store.get_cert(org, "C-9402")["status"] == "active",
        timeout=30,
        message="re-correction applies incrementally",
    )
    assert not runtime.store.list_pending_corrections(org)

    # the same chain must not block or fail a full rebuild
    status, run = client.post(f"/api/orgs/{org}/rebuild")
    assert status == 202
    wait_until(
        lambda: runtime.store.get_run(run["run_id"])["status"] == "succeeded",
        timeout=30,
        message="rebuild over the chain succeeds",
    )
    stored = {
        c["cert_no"]: (c["revision"], c["status"])
        for c in runtime.store.list_certs(org, page=1, page_size=500)["items"]
    }
    source = {c["cert_no"]: (c["revision"], c["status"]) for c in world.state()["certs"]}
    assert stored == source


def test_initial_collection_waits_for_hidden_member_then_converges(client, runtime, sim):
    # hide a seed member before the org exists: even the first full scan must
    # wait rather than publish a catalog missing a listed certificate
    sim.json_world.hide_detail(["C-1005"])
    _setup(client, "initial-hold", "json")
    time.sleep(1.5)
    state = runtime.store.get_state("initial-hold")
    assert state["ready"] is False
    full = [r for r in runtime.store.list_runs("initial-hold", limit=5) if r["kind"] == "full"][0]
    assert full["status"] in ("queued", "running")
    assert any(p["cert_no"] == "C-1005" for p in runtime.store.list_pending_reads("initial-hold"))
    status, body = client.get("/api/orgs/initial-hold/status")
    assert body["phase"] == "awaiting_correction"

    sim.json_world.show_detail(["C-1005"])
    wait_ready(runtime, "initial-hold", timeout=30)
    state = runtime.store.get_state("initial-hold")
    assert state["cert_count"] == len(sim.json_world.state()["certs"])
    assert not runtime.store.list_pending_reads("initial-hold")


def test_hidden_plain_revision_is_held_then_published_without_blocking_others(client, runtime, sim):
    org = "plain-hold"
    _setup(client, org, "json")
    wait_ready(runtime, org)
    world = sim.json_world
    # an unrelated ordinary revision and a hidden ordinary revision
    world.revise_cert("C-1001", {"temperature": "24.0 C"})
    world.revise_cert("C-1007", {"temperature": "25.0 C"})
    world.hide_detail(["C-1007"])
    wait_until(
        lambda: runtime.store.get_cert(org, "C-1001")["revision"] == 2,
        message="unrelated plain revision applies",
    )
    wait_until(
        lambda: any(p["cert_no"] == "C-1007" for p in runtime.store.list_pending_reads(org)),
        message="hidden plain revision registered as pending",
    )
    # the stale revision 1 stays published; revision 2 never half-appears
    assert runtime.store.get_cert(org, "C-1007")["revision"] == 1
    world.show_detail(["C-1007"])
    wait_until(
        lambda: runtime.store.get_cert(org, "C-1007")["revision"] == 2
        and runtime.store.get_state(org)["caught_up"],
        timeout=30,
        message="held plain revision converges",
    )
    assert not runtime.store.list_pending_reads(org)


def test_pending_correction_survives_restart_and_converges_after_expiry(client, runtime, sim):
    org = "restart-hold"
    _setup(client, org, "json")
    wait_ready(runtime, org)
    world = sim.json_world

    world.correction(
        "C-1006",
        [
            {"cert_no": "C-9601", "data": {"instrument": "A"}},
            {"cert_no": "C-9602", "data": {"instrument": "B"}},
        ],
    )
    world.hide_detail(["C-9602"])
    wait_until(
        lambda: any(p["cert_no"] == "C-9602" for p in runtime.store.list_pending_reads(org)),
        message="blocked member registered",
    )

    runtime.engine.stop()
    runtime.engine.start()
    assert any(p["cert_no"] == "C-9602" for p in runtime.store.list_pending_reads(org))
    # every retained position is now stale and the blocked member is healed
    world.expire_all()
    world.show_detail(["C-9602"])
    wait_until(
        lambda: runtime.store.get_state(org)["caught_up"]
        and runtime.store.get_cert(org, "C-1006")["status"] == "revoked"
        and runtime.store.get_cert(org, "C-9601")["status"] == "active"
        and runtime.store.get_cert(org, "C-9602")["status"] == "active",
        timeout=45,
        message="convergence after restart with expired positions",
    )
    wait_until(
        lambda: not runtime.store.list_pending_reads(org)
        and not runtime.store.list_pending_corrections(org),
        message="pending state clears",
    )
    assert runtime.store.get_state(org)["cert_count"] == len(world.state()["certs"])
