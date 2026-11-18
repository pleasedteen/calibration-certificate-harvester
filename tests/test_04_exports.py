"""Paged, resumable exports over one frozen catalog version."""

from __future__ import annotations

import time

from .conftest import wait_ready, wait_until


def _setup(client, org_id="export-lab", kind="json", options=None):
    status, body = client.post(
        "/api/orgs",
        {
            "org_id": org_id,
            "source": {
                "kind": kind,
                "base_url": "http://sim.local" if kind == "html" else "http://sim.local/json",
            },
            "options": {"poll_interval_ms": 100, **(options or {})},
        },
    )
    assert status == 201, body
    return body


def test_export_pages_cover_one_catalog_version(client, runtime, sim):
    _setup(client)
    wait_ready(runtime, "export-lab")
    world = sim.json_world
    status, export = client.post("/api/orgs/export-lab/exports", {"page_size": 4})
    assert status == 201, export
    assert export["catalog_version"] == runtime.store.get_state("export-lab")["version"]
    total = export["total"]
    assert total == len(world.state()["certs"])

    seen: list[str] = []
    page = 1
    while page:
        status, body = client.get(f"/api/exports/{export['token']}/pages/{page}")
        assert status == 200, body
        assert body["catalog_version"] == export["catalog_version"]
        seen.extend(item["cert_no"] for item in body["items"])
        page = body["next_page"]
    assert len(seen) == total
    assert len(set(seen)) == total


def test_export_stays_stable_while_collection_and_rebuild_run(client, runtime, sim):
    _setup(client, "stable-lab")
    wait_ready(runtime, "stable-lab")
    world = sim.json_world
    status, export = client.post("/api/orgs/stable-lab/exports", {"page_size": 3})
    assert status == 201
    snapshot_total = export["total"]

    # mutate the source heavily and start a rebuild mid-export
    for idx in range(4):
        world.revise_cert(f"C-100{idx + 1}", {"temperature": f"{25 + idx}.0 C"})
    world.add_cert("C-8601", {"instrument": "During export"})
    client.post("/api/orgs/stable-lab/rebuild")

    seen = []
    page = 1
    while page:
        status, body = client.get(f"/api/exports/{export['token']}/pages/{page}")
        assert status == 200
        assert body["total"] == snapshot_total
        assert body["catalog_version"] == export["catalog_version"]
        seen.extend(item["cert_no"] for item in body["items"])
        page = body["next_page"]
    assert len(seen) == snapshot_total
    # the frozen snapshot must not contain the certificate added afterwards
    assert "C-8601" not in seen
    wait_until(
        lambda: runtime.store.get_cert("stable-lab", "C-8601")["status"] == "active",
        message="new certificate to reach the live catalog",
    )


def test_export_resumes_after_service_restart(tmp_path, sim):
    from certcollector.runtime import Runtime

    db_path = str(tmp_path / "restart.db")
    rt = Runtime(db_path, seed=5, count=10, poll_interval_ms=100)
    rt.start()
    try:
        from .conftest import Client

        c = Client(rt.base_url)
        c.post(
            "/api/orgs",
            {"org_id": "restart-lab", "source": {"kind": "html", "base_url": "http://sim.local"}},
        )
        wait_ready(rt, "restart-lab")
        status, export = c.post("/api/orgs/restart-lab/exports", {"page_size": 4, "ttl_seconds": 300})
        assert status == 201
        status, first = c.get(f"/api/exports/{export['token']}/pages/1")
        assert status == 200
        token = export["token"]
        baseline_version = export["catalog_version"]
        baseline_total = export["total"]
    finally:
        rt.stop()

    rt2 = Runtime(db_path, seed=5, count=10, poll_interval_ms=100)
    rt2.start()
    try:
        from .conftest import Client

        c2 = Client(rt2.base_url)
        status, info = c2.get(f"/api/exports/{token}")
        assert status == 200, info
        assert info["catalog_version"] == baseline_version
        status, second = c2.get(f"/api/exports/{token}/pages/2")
        assert status == 200
        assert second["catalog_version"] == baseline_version
        assert second["total"] == baseline_total
        assert second["page"] == 2
    finally:
        rt2.stop()


def test_export_expiry_is_explicit(client, runtime, sim):
    _setup(client, "expiry-lab")
    wait_ready(runtime, "expiry-lab")
    status, export = client.post("/api/orgs/expiry-lab/exports", {"page_size": 5, "ttl_seconds": 1})
    assert status == 201
    assert client.get(f"/api/exports/{export['token']}/pages/1")[0] == 200
    time.sleep(1.2)
    status, body = client.get(f"/api/exports/{export['token']}")
    assert status == 410
    assert body["error"] == "gone"
    status, body = client.get(f"/api/exports/{export['token']}/pages/2")
    assert status == 410
    status, body = client.get("/api/exports/does-not-exist")
    assert status == 404


def test_export_validation(client, runtime, sim):
    _setup(client, "export-val")
    wait_ready(runtime, "export-val")
    status, body = client.post("/api/orgs/export-val/exports", {"page_size": 0})
    assert status == 400
    status, export = client.post("/api/orgs/export-val/exports", {"page_size": 2})
    assert status == 201
    token = export["token"]
    status, body = client.get(f"/api/exports/{token}/pages/999")
    assert status == 404
    status, body = client.get(f"/api/exports/{token}/pages/0")
    assert status == 404


def test_finished_runs_and_exports_are_pruned(client, runtime, sim):
    _setup(
        client,
        "retention-lab",
        options={
            "keep_runs": 3,
            "poll_interval_ms": 60,
            "export_tombstone_seconds": 1,
        },
    )
    wait_ready(runtime, "retention-lab")
    for _ in range(8):
        client.post("/api/orgs/retention-lab/collect", {"mode": "incremental"})
        time.sleep(0.05)
    client.post("/api/orgs/retention-lab/exports", {"page_size": 5, "ttl_seconds": 1})
    # materialized rows are dropped as soon as the credential expires, so the
    # historical storage cannot grow with finished exports
    wait_until(
        lambda: runtime.store.storage_counts()["export_items"] == 0,
        timeout=20,
        message="expired export rows to be pruned",
    )
    # the small tombstone (which keeps the expiry answer explicit) goes too
    wait_until(
        lambda: runtime.store.storage_counts()["exports"] == 0,
        timeout=25,
        message="expired export tombstones to be pruned",
    )
    wait_until(
        lambda: len(runtime.store.list_runs("retention-lab", limit=100)) <= 3,
        timeout=25,
        message="finished runs to be pruned",
    )
    counts = runtime.store.storage_counts()
    assert counts["runs"] <= 3
    assert counts["exports"] == 0
    assert counts["export_items"] == 0
