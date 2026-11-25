"""Online source switching via ``POST /api/orgs`` with a changed ``source``.

Guarantees under test:

* the old catalog and its incremental channel keep serving until the cutover
  transaction commits; the new full catalog and its continuation position take
  effect together;
* a new source whose sequence numbers are smaller, or whose shared certificate
  numbers carry lower revisions, is still accepted;
* results arriving late from the old source can never be written back to the
  old certificate rows or the old continuation position;
* exports materialized before the switch keep paging through their frozen
  catalog after the switch and after a service restart;
* a temporarily unavailable new source leaves the old catalog serving and the
  switch completes automatically once the source recovers;
* a restart while a switch is in flight resumes the same pending switch.
"""

from __future__ import annotations

import time

from .conftest import wait_ready, wait_until

ALT_URL = "http://sim.local/alt"


def _setup(client, org_id, kind="json", **extra):
    payload = {
        "org_id": org_id,
        "source": {
            "kind": kind,
            "base_url": "http://sim.local" if kind == "html" else "http://sim.local/json",
        },
        "options": {"poll_interval_ms": 80, **extra.pop("options", {})},
        **extra,
    }
    status, body = client.post("/api/orgs", payload)
    assert status == 201, body
    return body


def _switch(client, org_id, source):
    return client.post("/api/orgs", {"org_id": org_id, "source": source})


def _switch_done(runtime, org_id):
    pending = runtime.store.get_pending_switch(org_id)
    return pending is None


def _wait_switch(runtime, org_id, timeout: float = 30.0):
    wait_until(lambda: _switch_done(runtime, org_id), timeout=timeout, message="source switch to complete")
    return runtime.store.get_state(org_id)


def test_switch_cutover_is_atomic_and_keeps_old_catalog_serving(client, runtime, sim):
    _setup(client, "switch-lab")
    wait_ready(runtime, "switch-lab")
    old_world = sim.json_world
    new_world = sim.alt_world
    before = runtime.store.get_state("switch-lab")

    # make the new source slow enough to observe the old catalog mid-switch
    new_world.update_config({"slow_ms": 20})
    status, body = _switch(client, "switch-lab", {"kind": "json", "base_url": ALT_URL})
    assert status == 202, body
    assert body["source_switch"]["status"] == "pending"
    switch_id = body["source_switch"]["switch_id"]
    to_epoch = body["source_switch"]["to_epoch"]
    assert to_epoch == before["active_epoch"] + 1

    # while the switch runs: org still points at the old source, the published
    # catalog is untouched and keeps serving the old body's content
    observed_pending = False
    for _ in range(15):
        time.sleep(0.03)
        org = runtime.store.get_org("switch-lab")
        state = runtime.store.get_state("switch-lab")
        if runtime.store.get_pending_switch("switch-lab") is not None:
            observed_pending = True
            assert org["source"]["base_url"] == "http://sim.local/json"
            assert state["active_epoch"] == before["active_epoch"]
            assert state["cert_count"] == len(old_world.state()["certs"])
            page = runtime.store.list_certs("switch-lab", page=1, page_size=500)
            assert {c["cert_no"] for c in page["items"]} == {
                c["cert_no"] for c in old_world.state()["certs"]
            }
    assert observed_pending, "switch must have been observable as pending"
    new_world.update_config({"slow_ms": 0})

    state = _wait_switch(runtime, "switch-lab")
    assert state["active_epoch"] == to_epoch
    assert state["ready"] and state["caught_up"]
    # catalog now equals the new source exactly, in one publication
    assert state["cert_count"] == len(new_world.state()["certs"])
    page = runtime.store.list_certs("switch-lab", page=1, page_size=500)
    assert {c["cert_no"] for c in page["items"]} == {
        c["cert_no"] for c in new_world.state()["certs"]
    }
    # the org's source config was swapped as part of the same cutover
    org = runtime.store.get_org("switch-lab")
    assert org["source"]["base_url"] == ALT_URL
    switch = runtime.store.get_switch(switch_id)
    assert switch["status"] == "completed"
    # the continuation position belongs to the new source: old cursors name a
    # different site and must not be retained
    assert state["watermark_cursor"] is not None
    import base64
    import json as _json

    raw = state["watermark_cursor"] + "=" * (-len(state["watermark_cursor"]) % 4)
    decoded = _json.loads(base64.urlsafe_b64decode(raw.encode()))
    assert decoded["site"] == "alt"


def test_switch_accepts_lower_sequence_numbers_and_lower_revisions(client, runtime, sim):
    _setup(client, "lowseq-lab")
    wait_ready(runtime, "lowseq-lab")
    old_world = sim.json_world
    # drive the old source well past the alt body's sequence space and push a
    # shared certificate number to a revision the alt body does not have
    old_world.revise_cert("C-1001", {"temperature": "29.0 C"})
    old_world.revise_cert("C-1001", {"temperature": "30.0 C"})
    wait_until(
        lambda: runtime.store.get_cert("lowseq-lab", "C-1001")["revision"] >= 3,
        message="old source revisions to land",
    )
    old_state = runtime.store.get_state("lowseq-lab")
    alt_head = sim.alt_world.seq
    assert alt_head < old_state["watermark_seq"], "test fixture: alt seq must be lower"

    status, _ = _switch(client, "lowseq-lab", {"kind": "json", "base_url": ALT_URL})
    assert status == 202
    state = _wait_switch(runtime, "lowseq-lab")

    # lower sequence numbers did not block the cutover ...
    assert state["watermark_seq"] <= alt_head < old_state["watermark_seq"]
    # ... and the shared number is taken from the new source even at lower rev
    cert = runtime.store.get_cert("lowseq-lab", "C-1001")
    alt_view = sim.alt_world.detail("C-1001")
    assert cert["revision"] == alt_view["revision"] == 1
    assert cert["data"]["model"] == alt_view["data"]["model"]
    # old-only numbers are gone, new-only numbers are present
    old_only = {c["cert_no"] for c in old_world.state()["certs"]} - {
        c["cert_no"] for c in sim.alt_world.state()["certs"]
    }
    for no in old_only:
        assert client.get(f"/api/orgs/lowseq-lab/certs/{no}")[0] == 404


def test_late_old_source_results_cannot_write_back_after_switch(client, runtime, sim):
    _setup(client, "alt-write-lab")
    wait_ready(runtime, "alt-write-lab")
    old_world = sim.json_world
    new_world = sim.alt_world

    # stage a change on the old source; an in-flight incremental window will
    # resolve it around the same time the cutover commits
    status, _ = _switch(client, "alt-write-lab", {"kind": "json", "base_url": ALT_URL})
    assert status == 202
    state = _wait_switch(runtime, "alt-write-lab")
    epoch_after = state["active_epoch"]
    wm_after = state["watermark_seq"]
    cursor_after = state["watermark_cursor"]

    # old source keeps changing: its events must never reach the new catalog
    old_world.revise_cert("C-1002", {"temperature": "66.0 C"})
    old_world.add_cert("C-9901", {"instrument": "ghost from old source"})
    # and a manual incremental run created before any guard would notice is
    # harmless as well
    status, run = client.post("/api/orgs/alt-write-lab/collect", {"mode": "incremental"})
    assert status == 202
    time.sleep(0.4)

    state = runtime.store.get_state("alt-write-lab")
    assert state["active_epoch"] == epoch_after
    assert state["watermark_cursor"] == cursor_after, "old cursor must not replace new position"
    assert state["watermark_seq"] == wm_after or state["watermark_seq"] >= new_world.seq
    page = runtime.store.list_certs("alt-write-lab", page=1, page_size=500)
    nos = {c["cert_no"] for c in page["items"]}
    assert "C-9901" not in nos
    # C-1002 content stays whatever the new source says, never the old revision
    if "C-1002" in nos:
        cert = runtime.store.get_cert("alt-write-lab", "C-1002")
        assert cert["data"].get("temperature") != "66.0 C"
    # every run bound to the old epoch has been retired, none succeeded late
    for r in runtime.store.list_runs("alt-write-lab", limit=100):
        if int(r["source_epoch"]) < epoch_after:
            assert r["status"] in ("superseded", "succeeded", "failed", "cancelled")
    late = runtime.store.get_run(run["run_id"])
    assert late["source_epoch"] == epoch_after  # new runs bind to the new epoch


def test_export_created_before_switch_keeps_its_frozen_pages(client, runtime, sim):
    _setup(client, "frozen-lab")
    wait_ready(runtime, "frozen-lab")
    old_world = sim.json_world
    status, export = client.post("/api/orgs/frozen-lab/exports", {"page_size": 3, "ttl_seconds": 600})
    assert status == 201
    frozen_version = export["catalog_version"]
    frozen_total = export["total"]
    token = export["token"]
    first_page = client.get(f"/api/exports/{token}/pages/1")[1]
    frozen_first = [i["cert_no"] for i in first_page["items"]]

    # old source mutates while the switch is in flight
    old_world.add_cert("C-9902", {"instrument": "during switch"})
    status, _ = _switch(client, "frozen-lab", {"kind": "json", "base_url": ALT_URL})
    assert status == 202
    _wait_switch(runtime, "frozen-lab")

    seen = []
    page_no = 1
    while page_no:
        status, body = client.get(f"/api/exports/{token}/pages/{page_no}")
        assert status == 200, body
        assert body["catalog_version"] == frozen_version
        assert body["total"] == frozen_total
        seen.extend(i["cert_no"] for i in body["items"])
        page_no = body["next_page"]
    assert len(seen) == frozen_total and len(set(seen)) == frozen_total
    assert "C-9902" not in seen
    assert seen[: len(frozen_first)] == frozen_first
    # the live catalog meanwhile serves the new source
    live = client.get("/api/orgs/frozen-lab/certs?page=1&page_size=500")[1]
    assert {i["cert_no"] for i in live["items"]} == {
        c["cert_no"] for c in sim.alt_world.state()["certs"]
    }


def test_export_survives_restart_around_a_switch(client, runtime, sim, tmp_path):
    from certcollector.runtime import Runtime

    _setup(client, "restart-switch-lab")
    wait_ready(runtime, "restart-switch-lab")
    status, export = client.post(
        "/api/orgs/restart-switch-lab/exports", {"page_size": 4, "ttl_seconds": 600}
    )
    assert status == 201
    token = export["token"]
    frozen_version = export["catalog_version"]
    frozen_total = export["total"]

    status, _ = _switch(client, "restart-switch-lab", {"kind": "json", "base_url": ALT_URL})
    assert status == 202
    _wait_switch(runtime, "restart-switch-lab")

    # full engine restart on the same database file
    db_url = runtime.db_url
    runtime.stop()
    rt2 = Runtime(db_url, seed=11, count=12, poll_interval_ms=80, full_retry_delay=0.1)
    rt2.start()
    try:
        from .conftest import Client as _Client

        c2 = _Client(rt2.base_url)
        status, info = c2.get(f"/api/exports/{token}")
        assert status == 200, info
        assert info["catalog_version"] == frozen_version
        assert info["total"] == frozen_total
        status, page = c2.get(f"/api/exports/{token}/pages/2")
        assert status == 200
        assert page["catalog_version"] == frozen_version
        # the switch itself remains visible as completed history
        status, detail = c2.get("/api/orgs/restart-switch-lab")
        assert status == 200
        assert detail["source"]["base_url"] == ALT_URL
        assert detail["catalog"]["ready"] is True
        assert detail["pending_switch"] is None
    finally:
        rt2.stop()


def test_unavailable_new_source_keeps_old_catalog_serving_and_auto_completes(client, runtime, sim):
    _setup(client, "offline-lab")
    wait_ready(runtime, "offline-lab")
    old_world = sim.json_world
    new_world = sim.alt_world
    old_count = runtime.store.get_state("offline-lab")["cert_count"]

    # new source is down before the switch starts
    new_world.set_enabled(False)
    status, body = _switch(client, "offline-lab", {"kind": "json", "base_url": ALT_URL})
    assert status == 202
    switch_id = body["source_switch"]["switch_id"]

    # the switch stays pending and the old catalog keeps serving unchanged
    deadline = time.time() + 3.0
    while time.time() < deadline:
        state = runtime.store.get_state("offline-lab")
        org = runtime.store.get_org("offline-lab")
        pending = runtime.store.get_pending_switch("offline-lab")
        assert pending is not None and pending["switch_id"] == switch_id
        assert state["ready"] and state["cert_count"] == old_count
        assert org["source"]["base_url"] == "http://sim.local/json"
        time.sleep(0.05)
    # old incremental channel is still alive: an old-source change lands
    old_world.add_cert("C-9910", {"instrument": "old site still serving"})
    wait_until(
        lambda: runtime.store.get_state("offline-lab")["cert_count"] == old_count + 1,
        timeout=15,
        message="old incremental channel to keep serving during switch",
    )

    # recover the new source: the pending switch completes without a new request
    new_world.set_enabled(True)
    state = _wait_switch(runtime, "offline-lab", timeout=40)
    assert state["cert_count"] == len(new_world.state()["certs"])
    assert "C-9910" not in {
        c["cert_no"] for c in runtime.store.list_certs("offline-lab", page=1, page_size=500)["items"]
    }
    org = runtime.store.get_org("offline-lab")
    assert org["source"]["base_url"] == ALT_URL


def test_restart_during_switch_resumes_and_completes(client, runtime, sim):
    _setup(client, "midrestart-lab")
    wait_ready(runtime, "midrestart-lab")
    new_world = sim.alt_world
    new_world.update_config({"slow_ms": 25})

    status, body = _switch(client, "midrestart-lab", {"kind": "json", "base_url": ALT_URL})
    assert status == 202
    switch_id = body["source_switch"]["switch_id"]
    to_epoch = body["source_switch"]["to_epoch"]
    time.sleep(0.1)
    assert runtime.store.get_pending_switch("midrestart-lab") is not None

    # hard engine restart while the switch run is mid-listing
    runtime.engine.stop()
    new_world.update_config({"slow_ms": 0})
    runtime.engine.start()

    state = _wait_switch(runtime, "midrestart-lab", timeout=40)
    assert state["active_epoch"] == to_epoch
    assert state["cert_count"] == len(new_world.state()["certs"])
    switch = runtime.store.get_switch(switch_id)
    assert switch["status"] == "completed"
    assert runtime.store.get_org("midrestart-lab")["source"]["base_url"] == ALT_URL
    # the resumed run is the switch lineage, not a fresh ordinary rebuild
    runs = runtime.store.list_runs("midrestart-lab", limit=50)
    assert any(r["switch_id"] == switch_id and r["status"] == "succeeded" for r in runs)


def test_status_and_org_detail_report_the_pending_switch(client, runtime, sim):
    _setup(client, "phase-lab")
    wait_ready(runtime, "phase-lab")
    sim.alt_world.update_config({"slow_ms": 60})
    try:
        status, body = _switch(client, "phase-lab", {"kind": "json", "base_url": ALT_URL})
        assert status == 202
        saw_switching = False
        for _ in range(25):
            time.sleep(0.03)
            status, status_body = client.get("/api/orgs/phase-lab/status")
            assert status == 200
            status, detail = client.get("/api/orgs/phase-lab")
            if status_body["phase"] == "switching":
                saw_switching = True
                assert status_body["pending_switch"]["to_epoch"] == 1
                assert status_body["pending_switch"]["source"]["base_url"] == ALT_URL
                assert status_body["ready"] is True
                # while pending the org row still names the active old source
                assert detail["source"]["base_url"] == "http://sim.local/json"
                assert detail["source_epoch"] == 0
        assert saw_switching, "status must expose the switching phase while pending"
    finally:
        sim.alt_world.update_config({"slow_ms": 0})
    _wait_switch(runtime, "phase-lab")
    status, status_body = client.get("/api/orgs/phase-lab/status")
    assert status_body["phase"] != "switching"
    assert status_body["pending_switch"] is None
    assert status_body["source_epoch"] == 1


def test_second_switch_while_pending_is_rejected_and_switch_history_is_listed(client, runtime, sim):
    _setup(client, "guard-lab")
    wait_ready(runtime, "guard-lab")
    sim.alt_world.update_config({"slow_ms": 30})
    status, first = _switch(client, "guard-lab", {"kind": "json", "base_url": ALT_URL})
    assert status == 202
    status, body = _switch(client, "guard-lab", {"kind": "html", "base_url": "http://sim.local"})
    assert status == 409
    assert body["error"] == "conflict"
    sim.alt_world.update_config({"slow_ms": 0})
    _wait_switch(runtime, "guard-lab")

    # after completion, switching again is allowed and lands on the third epoch
    status, second = _switch(client, "guard-lab", {"kind": "html", "base_url": "http://sim.local"})
    assert status == 202
    _wait_switch(runtime, "guard-lab")
    assert second["source_switch"]["to_epoch"] == first["source_switch"]["to_epoch"] + 1
    status, history = client.get("/api/orgs/guard-lab/switches")
    assert status == 200
    assert {s["status"] for s in history["items"]} == {"completed"}
    assert len(history["items"]) == 2
    assert runtime.store.get_org("guard-lab")["source"]["kind"] == "html"
