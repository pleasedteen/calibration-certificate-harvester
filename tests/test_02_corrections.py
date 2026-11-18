"""Corrections: multi-certificate atomicity, revisions and revocations."""

from __future__ import annotations

import time

from .conftest import wait_ready, wait_until


def _setup(client, org_id="corr-lab", kind="json"):
    status, _ = client.post(
        "/api/orgs",
        {
            "org_id": org_id,
            "source": {
                "kind": kind,
                "base_url": "http://sim.local" if kind == "html" else "http://sim.local/json",
            },
            "options": {"poll_interval_ms": 100},
        },
    )
    assert status == 201


def test_multi_certificate_correction_is_atomic(client, runtime, sim):
    _setup(client)
    wait_ready(runtime, "corr-lab")
    world = sim.json_world
    baseline = runtime.store.get_state("corr-lab")["cert_count"]

    result = world.correction(
        "C-1002",
        [
            {"cert_no": "C-8001", "data": {"instrument": "Balance", "result": "pass"}},
            {"cert_no": "C-8002", "data": {"instrument": "Gauge", "result": "pass"}},
            {"cert_no": "C-8003", "data": {"instrument": "Oven", "result": "pass"}},
        ],
    )
    assert result["correction_id"]

    wait_until(
        lambda: runtime.store.get_state("corr-lab")["cert_count"] == baseline + 3
        and runtime.store.get_state("corr-lab")["caught_up"],
        timeout=20,
        message="correction to be fully applied",
    )
    old = runtime.store.get_cert("corr-lab", "C-1002")
    assert old["status"] == "revoked"
    members = old["correction"]["members"]
    assert set(members) == {"C-1002", "C-8001", "C-8002", "C-8003"}
    for member in ("C-8001", "C-8002", "C-8003"):
        cert = runtime.store.get_cert("corr-lab", member)
        assert cert["status"] == "active"
        assert cert["correction"]["id"] == old["correction"]["id"]
    assert runtime.store.list_pending_corrections("corr-lab") == []


def test_correction_never_exposes_partial_state(client, runtime, sim):
    """While the change feed is delayed, the old cert must stay active until
    every replacement can be resolved in the same publication."""
    _setup(client, "atomic-lab")
    wait_ready(runtime, "atomic-lab")
    world = sim.json_world
    baseline = runtime.store.get_state("atomic-lab")["cert_count"]
    world.correction(
        "C-1003",
        [
            {"cert_no": "C-8101", "data": {"instrument": "Balance"}},
            {"cert_no": "C-8102", "data": {"instrument": "Gauge"}},
        ],
    )
    seen_partial = False
    deadline = time.time() + 15
    while time.time() < deadline:
        old = runtime.store.get_cert("atomic-lab", "C-1003")
        try:
            new_a = runtime.store.get_cert("atomic-lab", "C-8101")
            new_b = runtime.store.get_cert("atomic-lab", "C-8102")
            if old["status"] == "revoked":
                assert new_a["status"] == "active" and new_b["status"] == "active"
        except Exception:
            if old["status"] == "revoked":
                seen_partial = True
        st = runtime.store.get_state("atomic-lab")
        if st["caught_up"] and st["cert_count"] == baseline + 2:
            break
        time.sleep(0.02)
    assert not seen_partial


def test_revision_updates_and_revocation_propagate(client, runtime, sim):
    _setup(client, "rev-lab", kind="html")
    wait_ready(runtime, "rev-lab")
    world = sim.html_world
    world.revise_cert("C-1004", {"temperature": "21.5 C"})
    world.revise_cert("C-1004", {"temperature": "22.0 C"})
    world.revoke_cert("C-1005")
    wait_until(
        lambda: runtime.store.get_cert("rev-lab", "C-1004")["revision"] == 3
        and runtime.store.get_cert("rev-lab", "C-1005")["status"] == "revoked",
        message="revision and revocation to propagate",
    )
    cert = runtime.store.get_cert("rev-lab", "C-1004")
    assert cert["data"]["temperature"] == "22.0 C"
    assert cert["status"] == "active"
    revoked = runtime.store.get_cert("rev-lab", "C-1005")
    assert revoked["revoked_at"] is not None


def test_duplicate_and_reordered_changes_are_idempotent(client, runtime, sim):
    _setup(client, "noisy-lab")
    wait_ready(runtime, "noisy-lab")
    world = sim.json_world
    world.update_config({"duplicate_events": True, "shuffle_events": True})
    for idx in range(5):
        world.revise_cert("C-1006", {"temperature": f"{20 + idx}.0 C"})
    world.add_cert("C-8301", {"instrument": "Noisy"})
    wait_until(
        lambda: runtime.store.get_cert("noisy-lab", "C-1006")["revision"] == 6
        and runtime.store.get_state("noisy-lab")["caught_up"],
        timeout=25,
        message="noisy changes to converge",
    )
    assert runtime.store.get_cert("noisy-lab", "C-8301")["status"] == "active"
    assert runtime.store.get_state("noisy-lab")["cert_count"] == len(
        world.state()["certs"]
    )


def test_deleted_certificate_leaves_catalog(client, runtime, sim):
    _setup(client, "delete-lab")
    wait_ready(runtime, "delete-lab")
    world = sim.json_world
    baseline = runtime.store.get_state("delete-lab")["cert_count"]
    world.purge_cert("C-1007")
    wait_until(
        lambda: runtime.store.get_state("delete-lab")["cert_count"] == baseline - 1
        and runtime.store.get_state("delete-lab")["caught_up"],
        message="deletion to propagate",
    )
    status, body = client.get("/api/orgs/delete-lab/certs/C-1007")
    assert status == 404
