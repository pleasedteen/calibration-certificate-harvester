"""Noisy upstreams: duplicates, reordering, expiry, torn corrections, entry points."""

from __future__ import annotations

import time

import pytest

from .conftest import wait_ready, wait_until


def _post_org(client, org_id, kind="json", **options):
    status, body = client.post(
        "/api/orgs",
        {
            "org_id": org_id,
            "source": {
                "kind": kind,
                "base_url": "http://sim.local" if kind == "html" else "http://sim.local/json",
            },
            "options": {"poll_interval_ms": 80, **options},
        },
    )
    assert status == 201, body
    return body


def test_reordered_change_feed_does_not_lose_updates(client, runtime, sim):
    _post_org(client, "reorder-lab")
    wait_ready(runtime, "reorder-lab")
    world = sim.json_world
    world.update_config({"shuffle_events": True, "duplicate_events": True})
    for idx in range(6):
        world.revise_cert(f"C-100{idx + 1}", {"temperature": f"{26 + idx}.0 C"})
    world.correction(
        "C-1008",
        [{"cert_no": f"C-88{idx:02d}", "data": {"instrument": f"replacement {idx}"}} for idx in range(4)],
    )
    wait_until(
        lambda: runtime.store.get_state("reorder-lab")["caught_up"]
        and runtime.store.get_state("reorder-lab")["cert_count"] == len(world.state()["certs"]),
        timeout=30,
        message="reordered feed to converge",
    )
    for idx in range(6):
        assert runtime.store.get_cert("reorder-lab", f"C-100{idx + 1}")["revision"] == 2
    old = runtime.store.get_cert("reorder-lab", "C-1008")
    assert old["status"] == "revoked"
    for idx in range(4):
        assert runtime.store.get_cert("reorder-lab", f"C-88{idx:02d}")["status"] == "active"
    world.update_config({"shuffle_events": False, "duplicate_events": False})


def test_stale_upsert_does_not_resurrect_deleted_cert(client, runtime, sim):
    _post_org(client, "stale-lab")
    wait_ready(runtime, "stale-lab")
    world = sim.json_world
    baseline = runtime.store.get_state("stale-lab")["cert_count"]
    # queue an upsert and a delete for the same certificate, then deliver them
    # out of order (delete first)
    world.revise_cert("C-1011", {"temperature": "33.0 C"})
    world.purge_cert("C-1011")
    wait_until(
        lambda: runtime.store.get_state("stale-lab")["cert_count"] == baseline - 1
        and runtime.store.get_state("stale-lab")["caught_up"],
        timeout=25,
        message="delete to win over stale upsert",
    )
    with pytest.raises(Exception):
        runtime.store.get_cert("stale-lab", "C-1011")


def test_catalog_recovers_after_cursor_and_snapshot_expiry(client, runtime, sim):
    _post_org(client, "expire2-lab", kind="html")
    wait_ready(runtime, "expire2-lab")
    world = sim.html_world
    baseline = runtime.store.get_state("expire2-lab")
    world.update_config({"cursor_ttl": 0.2, "snapshot_ttl": 0.2})
    world.add_cert("C-8701", {"instrument": "New"})
    # let the cursor die before the next incremental poll
    time.sleep(0.4)
    wait_until(
        lambda: runtime.store.get_state("expire2-lab")["caught_up"]
        and runtime.store.get_cert("expire2-lab", "C-8701")["status"] == "active",
        timeout=30,
        message="collector to self-heal from expired positions",
    )
    state = runtime.store.get_state("expire2-lab")
    assert state["version"] > baseline["version"]
    assert state["cert_count"] == len(world.state()["certs"])
    triggers = [r["trigger"] for r in runtime.store.list_runs("expire2-lab", limit=30)]
    assert any(t.startswith("recovery:") for t in triggers)
    world.update_config({"cursor_ttl": 300, "snapshot_ttl": 300})


def test_correction_never_applies_with_only_part_of_live_members(client, runtime, sim):
    """While a multi-certificate correction propagates, the catalog may not show
    the old certificate revoked unless every replacement that the source still
    publishes is in the catalog as well."""
    _post_org(client, "torn-lab")
    wait_ready(runtime, "torn-lab")
    world = sim.json_world
    replacements = [f"C-88{idx:02d}" for idx in range(0, 5)]
    # 4 of the 5 members exist from the start, so the group is resolvable
    sources = {no: {"instrument": f"replacement {no}"} for no in replacements[:4]}
    world.correction(
        "C-1003",
        [{"cert_no": no, "data": data} for no, data in sources.items()],
    )
    old_no = "C-1003"
    violations = []
    deadline = time.time() + 12
    while time.time() < deadline:
        old = runtime.store.get_cert("torn-lab", old_no)
        if old["status"] == "revoked":
            live = {c["cert_no"] for c in world.state()["certs"] if c["status"] == "active"}
            stored = {
                c["cert_no"]
                for c in runtime.store.list_certs("torn-lab", page=1, page_size=500)["items"]
            }
            missing = (set(sources) & live) - stored
            if missing:
                violations.append(sorted(missing))
        state = runtime.store.get_state("torn-lab")
        if state["caught_up"]:
            try:
                if runtime.store.get_cert("torn-lab", replacements[0])["status"] == "active":
                    break
            except Exception:
                pass
        time.sleep(0.01)
    assert not violations, f"old revoked while replacements absent: {violations[:3]}"
    for no in replacements[:4]:
        assert runtime.store.get_cert("torn-lab", no)["status"] == "active"
        assert runtime.store.get_cert("torn-lab", no)["correction"]["id"]
    assert runtime.store.get_cert("torn-lab", old_no)["status"] == "revoked"


def test_member_removed_after_correction_converges_to_source(client, runtime, sim):
    _post_org(client, "torn2-lab", kind="html")
    wait_ready(runtime, "torn2-lab")
    world = sim.html_world
    world.correction(
        "C-1004",
        [
            {"cert_no": "C-8901", "data": {"instrument": "A"}},
            {"cert_no": "C-8902", "data": {"instrument": "B"}},
        ],
    )
    world.purge_cert("C-8902")
    wait_until(
        lambda: runtime.store.get_cert("torn2-lab", "C-1004")["status"] == "revoked"
        and runtime.store.get_state("torn2-lab")["caught_up"],
        timeout=25,
        message="correction to converge after member removal",
    )
    stored = {
        c["cert_no"]
        for c in runtime.store.list_certs("torn2-lab", page=1, page_size=500)["items"]
    }
    live = {c["cert_no"] for c in world.state()["certs"]}
    assert stored == live
    assert "C-8902" not in stored
    assert runtime.store.get_cert("torn2-lab", "C-8901")["status"] == "active"


def test_correction_under_transient_failures_stays_atomic(client, runtime, sim):
    _post_org(client, "torn3-lab", request_attempts=6)
    wait_ready(runtime, "torn3-lab")
    world = sim.json_world
    world.update_config({"failure_rate": 0.35, "retry_after": 0.05})
    world.correction(
        "C-1005",
        [
            {"cert_no": "C-8911", "data": {"instrument": "A"}},
            {"cert_no": "C-8912", "data": {"instrument": "B"}},
        ],
    )
    violations = []
    deadline = time.time() + 20
    while time.time() < deadline:
        old = runtime.store.get_cert("torn3-lab", "C-1005")
        if old["status"] == "revoked":
            stored = {
                c["cert_no"]
                for c in runtime.store.list_certs("torn3-lab", page=1, page_size=500)["items"]
            }
            if not {"C-8911", "C-8912"} <= stored:
                violations.append(sorted(stored))
        state = runtime.store.get_state("torn3-lab")
        if state["caught_up"]:
            try:
                if runtime.store.get_cert("torn3-lab", "C-8911")["status"] == "active":
                    break
            except Exception:
                pass
        time.sleep(0.01)
    assert not violations
    world.update_config({"failure_rate": 0.0})
    assert runtime.store.get_cert("torn3-lab", "C-1005")["status"] == "revoked"
    assert runtime.store.get_cert("torn3-lab", "C-8912")["status"] == "active"


def test_certificate_numbers_are_scoped_per_organization(client, runtime, sim):
    _post_org(client, "scope-a", kind="html")
    world = sim.html_world
    world.add_cert("C-9000", {"instrument": "shared number A"})
    _post_org(client, "scope-b", kind="json")
    wait_ready(runtime, "scope-a")
    wait_ready(runtime, "scope-b")
    # the same number exists in both bodies but must be independent
    sim.json_world.add_cert("C-9000", {"instrument": "shared number B"})
    wait_until(
        lambda: runtime.store.get_cert("scope-b", "C-9000")["data"]["instrument"]
        == "shared number B",
        message="second body's number to arrive",
    )
    a = runtime.store.get_cert("scope-a", "C-9000")
    b = runtime.store.get_cert("scope-b", "C-9000")
    assert a["data"]["instrument"] == "shared number A"
    assert b["data"]["instrument"] == "shared number B"


def test_sites_support_alternate_detail_entry_points():
    """Details are reachable through more than one URL on both bodies."""
    from certcollector.runtime import Simulator
    from certcollector.source import LoopbackTransport, build_adapter

    sim = Simulator(seed=2, count=4)
    # drive the raw sites: path based and query based entry points must agree
    for kind, site, base in (
        ("html", sim.html_site, "http://sim.local"),
        ("json", sim.json_site, "http://sim.local/json"),
    ):
        transport = LoopbackTransport(sim.handler, "http://sim.local")
        adapter = build_adapter({"kind": kind, "base_url": base}, transport)
        detail = adapter.detail("C-1002")
        assert detail.cert_no == "C-1002"
        if kind == "html":
            path = "/cert/C-1002"
            alt = "/certificate"
        else:
            path = "/api/v1/items/C-1002"
            alt = "/api/v1/certificate"
        status_a, body_a, _ = transport.request("GET", base + path)
        status_b, body_b, _ = transport.request("GET", base + alt + "?no=C-1002")
        assert status_a == 200 and status_b == 200
        assert body_a and body_b
