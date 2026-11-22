"""End-to-end online rebuilds against a large local source fixture.

The simulator runs in-process (loopback transport) and is seeded with 2,000
certificates so a rebuild genuinely pages through many catalog pages and
streams thousands of details through ``scan_items``.  The tests pin the
behavioural guarantees of the scalable rebuild path:

* incremental publications keep landing while the rebuild is preparing;
* a hard engine restart mid-rebuild resumes and converges to the source;
* certificates removed at the source leave the catalog after the switch;
* updates applied before the switch stay visible afterwards;
* an export opened before the rebuild remains readable on its frozen version.
"""

from __future__ import annotations

import time

import pytest

from certcollector.runtime import Runtime

from .conftest import Client, wait_ready, wait_until

LARGE_COUNT = 2_000


@pytest.fixture()
def large_runtime(tmp_path):
    rt = Runtime(
        str(tmp_path / "large-collector.db"),
        seed=31,
        count=LARGE_COUNT,
        poll_interval_ms=80,
        full_retry_delay=0.1,
    )
    rt.start()
    try:
        yield rt
    finally:
        rt.stop()


@pytest.fixture()
def large_client(large_runtime):
    return Client(large_runtime.base_url)


def _register_json(client, org_id="large-lab", **options):
    payload = {
        "org_id": org_id,
        "source": {"kind": "json", "base_url": "http://sim.local/json"},
        "options": {
            "poll_interval_ms": 60,
            "batch_size": 200,
            "page_size": 200,
            # rapid polling creates many small incremental runs; keep history
            # long enough that an in-flight rebuild run is never pruned
            "keep_runs": 5_000,
            **options,
        },
    }
    status, body = client.post("/api/orgs", payload)
    assert status == 201, body
    return body


def _source_view(world):
    return {c["cert_no"]: (c["revision"], c["status"]) for c in world.state()["certs"]}


def _stored_view(runtime, org_id="large-lab", page_size=1_000):
    out = {}
    page = 1
    while True:
        result = runtime.store.list_certs(org_id, page=page, page_size=page_size)
        for item in result["items"]:
            out[item["cert_no"]] = (item["revision"], item["status"])
        if page >= result["pages"]:
            return out
        page += 1


def test_large_rebuild_converges_exactly(large_runtime, large_client):
    _register_json(large_client)
    wait_ready(large_runtime, "large-lab", count=LARGE_COUNT, timeout=60)
    world = large_runtime.simulator.json_world
    status, run = large_client.post("/api/orgs/large-lab/rebuild")
    assert status == 202
    wait_until(
        lambda: large_runtime.store.get_run(run["run_id"])["status"] == "succeeded",
        timeout=90,
        message="large rebuild to finish",
    )
    state = large_runtime.store.get_state("large-lab")
    assert state["ready"] and state["caught_up"]
    assert state["cert_count"] == LARGE_COUNT
    assert _stored_view(large_runtime) == _source_view(world)
    # the run record reports the bounded write footprint (nothing changed:
    # the swap must not have rewritten the whole directory)
    finished = large_runtime.store.get_run(run["run_id"])
    assert finished["progress"].get("changed_rows") == 0
    assert finished["progress"].get("deleted_rows") == 0


def test_incremental_updates_land_while_rebuild_prepares(large_runtime, large_client):
    _register_json(large_client)
    wait_ready(large_runtime, "large-lab", count=LARGE_COUNT, timeout=60)
    world = large_runtime.simulator.json_world
    # stretch listing/fetching so the rebuild stays in its preparation window
    world.update_config({"slow_ms": 2})
    status, run = large_client.post("/api/orgs/large-lab/rebuild")
    assert status == 202

    target = f"C-{1001 + 500:04d}"
    revisions_seen = []
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            current_run = large_runtime.store.get_run(run["run_id"])
        except Exception:
            break
        if current_run["status"] not in ("queued", "running", "paused"):
            break
        world.revise_cert(target, {"temperature": "23.0 C"})
        try:
            cert = large_runtime.store.get_cert("large-lab", target)
            revisions_seen.append(cert["revision"])
        except Exception:
            pass
        # the published catalog must stay ready and queryable throughout
        assert large_runtime.store.get_state("large-lab")["ready"] is True
        time.sleep(0.05)
    world.update_config({"slow_ms": 0})

    wait_until(
        lambda: large_runtime.store.get_run(run["run_id"])["status"] == "succeeded",
        timeout=90,
        message="rebuild after concurrent updates",
    )
    assert len(set(revisions_seen)) >= 2, "incremental revisions must publish during preparation"
    # revisions may keep landing while the rebuild finishes; wait for the
    # incremental lane to drain the whole feed before comparing catalogs
    wait_until(
        lambda: large_runtime.store.get_state("large-lab")["caught_up"]
        and large_runtime.store.get_state("large-lab")["source_head_seq"] >= world.seq,
        timeout=60,
        message="catalog to fully catch up after the switch",
    )
    state = large_runtime.store.get_state("large-lab")
    assert state["ready"] and state["caught_up"]
    # every revision applied before the switch remains visible afterwards
    # (later windows may advance it further, so the final value is >=)
    assert large_runtime.store.get_cert("large-lab", target)["revision"] >= max(revisions_seen)
    assert _stored_view(large_runtime) == _source_view(world)


def test_rebuild_restart_midway_converges(large_runtime, large_client):
    _register_json(large_client)
    wait_ready(large_runtime, "large-lab", count=LARGE_COUNT, timeout=60)
    world = large_runtime.simulator.json_world
    world.update_config({"slow_ms": 2})
    status, run = large_client.post("/api/orgs/large-lab/rebuild")
    assert status == 202
    # let the scan get partway through its detail fetching, then stop the
    # engine abruptly (the durable scan/run rows are left behind)
    time.sleep(0.4)
    large_runtime.engine.stop()
    world.update_config({"slow_ms": 0})
    large_runtime.engine.start()
    wait_until(
        lambda: large_runtime.store.get_state("large-lab")["caught_up"]
        and large_runtime.store.get_state("large-lab")["cert_count"] == LARGE_COUNT,
        timeout=120,
        message="catalog to converge after mid-rebuild restart",
    )
    runs = large_runtime.store.list_runs("large-lab", limit=20)
    assert any(r["status"] == "succeeded" and r["kind"] == "full" for r in runs)
    assert _stored_view(large_runtime) == _source_view(world)


def test_removed_certs_leave_and_updates_survive_the_switch(large_runtime, large_client):
    _register_json(large_client)
    wait_ready(large_runtime, "large-lab", count=LARGE_COUNT, timeout=60)
    world = large_runtime.simulator.json_world
    purged = [f"C-{1001 + i:04d}" for i in (10, 20, 30)]
    revised = f"C-{1001 + 7:04d}"
    for no in purged:
        world.purge_cert(no)
    world.revise_cert(revised, {"temperature": "24.5 C"})
    # let the incremental channel drain first so the changes are live before
    # the rebuild even starts
    wait_until(
        lambda: large_runtime.store.get_state("large-lab")["cert_count"]
        == LARGE_COUNT - len(purged),
        timeout=30,
        message="incremental purges to land",
    )
    status, run = large_client.post("/api/orgs/large-lab/rebuild")
    assert status == 202
    wait_until(
        lambda: large_runtime.store.get_run(run["run_id"])["status"] == "succeeded",
        timeout=90,
        message="rebuild after removals",
    )
    state = large_runtime.store.get_state("large-lab")
    assert state["cert_count"] == LARGE_COUNT - len(purged)
    for no in purged:
        with pytest.raises(Exception):
            large_runtime.store.get_cert("large-lab", no)
    assert large_runtime.store.get_cert("large-lab", revised)["revision"] == 2
    assert _stored_view(large_runtime) == _source_view(world)


def test_old_export_remains_readable_across_rebuild(large_runtime, large_client):
    _register_json(large_client)
    wait_ready(large_runtime, "large-lab", count=LARGE_COUNT, timeout=60)
    world = large_runtime.simulator.json_world
    status, export = large_client.post(
        "/api/orgs/large-lab/exports", {"page_size": 250, "ttl_seconds": 600}
    )
    assert status == 201
    frozen_version = export["catalog_version"]
    frozen_total = export["total"]

    # mutate the source and rebuild while the export is being read
    for i in range(25):
        world.revise_cert(f"C-{1001 + i:04d}", {"temperature": f"{20 + i % 5}.0 C"})
    status, run = large_client.post("/api/orgs/large-lab/rebuild")
    assert status == 202

    seen = []
    page = 1
    while page:
        status, body = large_client.get(
            f"/api/exports/{export['token']}/pages/{page}"
        )
        assert status == 200, body
        assert body["catalog_version"] == frozen_version
        assert body["total"] == frozen_total
        seen.extend(item["cert_no"] for item in body["items"])
        page = body["next_page"]
    assert len(seen) == frozen_total == LARGE_COUNT

    wait_until(
        lambda: large_runtime.store.get_run(run["run_id"])["status"] == "succeeded",
        timeout=90,
        message="rebuild during paged export",
    )
    # live catalog moved on; the frozen export did not
    assert large_runtime.store.get_state("large-lab")["version"] > frozen_version
    assert _stored_view(large_runtime) == _source_view(world)


def test_publish_progress_reports_change_scaled_write_footprint(large_runtime, large_client):
    _register_json(large_client)
    wait_ready(large_runtime, "large-lab", count=LARGE_COUNT, timeout=60)
    world = large_runtime.simulator.json_world
    # Pause the incremental lane so the pending changes cannot be absorbed
    # before the rebuild's swap transaction runs; the rebuild lane itself is
    # started explicitly and resumed for the duration of the run.
    large_runtime.engine.pause("large-lab")
    world.update_config({"slow_ms": 2})
    status, run = large_client.post("/api/orgs/large-lab/rebuild")
    assert status == 202
    large_runtime.engine.resume("large-lab")
    # revise only a handful of certificates while the rebuild is preparing, so
    # the changes are still pending when the swap transaction runs
    for i in range(12):
        world.revise_cert(f"C-{1001 + i:04d}", {"temperature": "26.0 C"})
    world.update_config({"slow_ms": 0})

    # Count certificate rows written by the *swap transaction alone*.  The
    # rebuild's own catch-up may already have merged some of the twelve
    # revisions; whatever remains must be written as a small, bounded delta
    # rather than as 2,000 full-row rewrites.
    traced: list[tuple] = []
    large_runtime.db.sql_trace = traced
    try:
        wait_until(
            lambda: large_runtime.store.get_run(run["run_id"])["status"] == "succeeded",
            timeout=90,
            message="rebuild with a few changes",
        )
    finally:
        large_runtime.db.sql_trace = None
    cert_writes = sum(
        rowcount
        for verb, sql, rowcount in traced
        if verb in ("INSERT", "DELETE") and "certs" in sql.lower()
    )
    # at most the twelve pending revisions plus their deletions, never 2,000
    assert cert_writes <= 12
    progress = large_runtime.store.get_run(run["run_id"])["progress"]
    assert progress["cert_count"] == LARGE_COUNT
    # the catalog converges once the incremental lane drains the residual feed
    wait_until(
        lambda: large_runtime.store.get_state("large-lab")["caught_up"],
        timeout=30,
        message="catalog to catch up after the swap",
    )
    assert _stored_view(large_runtime) == _source_view(world)
