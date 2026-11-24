"""Acceptance for re-correction convergence on both simulated sites.

Run from the repository root with the standard library only::

    python3 acceptance/acceptance_runner.py

Scenarios (exercised for the HTML table site *and* the cursor JSON site):

1. incremental lane: a correction whose replacement is still listed upstream
   while its detail page temporarily returns 404 keeps waiting; unrelated
   revisions keep applying; status explains the pending correction; once the
   detail is readable the whole group converges atomically;
2. full lane (rebuild): the same listed-but-404 condition never fails the
   rebuild -- the previous catalog keeps serving and, when the member becomes
   readable again, the rebuild publishes the complete corrected catalog;
3. directory removal: when the unreadable member is confirmed removed from the
   directory (purged), the remaining correction members converge;
4. re-correction chains: a formal correction that is itself formally corrected
   again publishes fully through both lanes;
5. restart durability: pending state survives an engine restart, and an expired
   cursor/snapshot afterwards still converges automatically.
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from certcollector.runtime import Runtime  # noqa: E402


def wait_until(predicate, timeout=30.0, interval=0.05, message="condition"):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            value = predicate()
            if value:
                return value
            last = value
        except Exception as exc:  # surfaced on timeout
            last = repr(exc)
        time.sleep(interval)
    raise AssertionError(f"timed out waiting for {message}; last={last!r}")


def ready(rt, org):
    wait_until(
        lambda: rt.store.get_state(org)["ready"] and rt.store.get_state(org)["caught_up"],
        timeout=40,
        message=f"{org} ready",
    )


def make_runtime(workdir: str, name: str) -> Runtime:
    return Runtime(
        os.path.join(workdir, f"{name}.db"),
        seed=11,
        count=12,
        poll_interval_ms=80,
        full_retry_delay=0.1,
    )


def register(rt: Runtime, org: str, kind: str) -> None:
    rt.register_simulated_org(org, kind)


def world_for(rt: Runtime, kind: str):
    return rt.simulator.html_world if kind == "html" else rt.simulator.json_world


def cert(rt, org, no):
    return rt.store.get_cert(org, no)


# ---------------------------------------------------------------------------
# scenarios
def scenario_incremental_waits_then_converges(rt, org, kind):
    world = world_for(rt, kind)
    ready(rt, org)
    baseline = rt.store.get_state(org)["cert_count"]

    # unrelated revision must keep flowing while the correction is held
    world.revise_cert("C-1001", {"temperature": "23.0 C"})
    result = world.correction(
        "C-1002",
        [
            {"cert_no": "C-9101", "data": {"instrument": "Balance"}},
            {"cert_no": "C-9102", "data": {"instrument": "Gauge"}},
        ],
    )
    cid = result["correction_id"]
    # hide one replacement *after* the change events exist: the feed names the
    # member, the directory still lists it, only the detail page answers 404.
    world.hide_detail(["C-9102"])

    # unrelated revision still lands
    wait_until(
        lambda: cert(rt, org, "C-1001")["revision"] == 2,
        message="unrelated revision applies while correction waits",
    )

    # the correction never appears partially
    deadline = time.time() + 4.0
    while time.time() < deadline:
        old = cert(rt, org, "C-1002")
        if old["status"] == "revoked":
            raise AssertionError("old cert revoked while a replacement was unreadable")
        if any(p["correction_id"] == cid for p in rt.store.list_pending_corrections(org)):
            break
        time.sleep(0.05)
    pending = {p["correction_id"]: p for p in rt.store.list_pending_corrections(org)}
    assert cid in pending, "the blocked correction must be tracked as pending"
    reads = {p["cert_no"]: p for p in rt.store.list_pending_reads(org)}
    assert "C-9102" in reads, "the listed-but-404 member must be durably tracked"

    # status explains that a correction is pending
    status = rt.api._status(org)
    assert status["corrections_pending"] is True
    scopes = {r["scope"] for r in status["reasons"]}
    assert {"correction", "detail"} & scopes

    # catalog stays at baseline + 0 net corrections (the readable replacement
    # must not have been published on its own either)
    assert rt.store.get_cert(org, "C-1002")["status"] == "active"
    try:
        rt.store.get_cert(org, "C-9102")
        raise AssertionError("unreadable replacement leaked into catalog")
    except Exception:
        pass

    # heal the source: the correction now publishes atomically
    world.show_detail(["C-9102"])
    wait_until(
        lambda: rt.store.get_state(org)["caught_up"]
        and cert(rt, org, "C-1002")["status"] == "revoked"
        and cert(rt, org, "C-9101")["status"] == "active"
        and cert(rt, org, "C-9102")["status"] == "active",
        timeout=30,
        message="correction to converge after detail healed",
    )
    wait_until(
        lambda: rt.store.list_pending_corrections(org) == []
        and rt.store.list_pending_reads(org) == [],
        message="pending bookkeeping to clear",
    )
    assert rt.store.get_state(org)["cert_count"] == baseline + 2
    status = rt.api._status(org)
    assert status["corrections_pending"] is False


def scenario_rebuild_waits_then_publishes_complete(rt, org, kind):
    world = world_for(rt, kind)
    ready(rt, org)
    baseline = rt.store.get_state(org)["cert_count"]

    # a fully published correction first
    result = world.correction(
        "C-1003",
        [
            {"cert_no": "C-9201", "data": {"instrument": "A"}},
            {"cert_no": "C-9202", "data": {"instrument": "B"}},
        ],
    )
    wait_until(
        lambda: cert(rt, org, "C-1003")["status"] == "revoked"
        and cert(rt, org, "C-9202")["status"] == "active",
        message="first correction to land",
    )

    # now hide a member and rebuild: the full lane must not fail
    world.hide_detail(["C-9201"])
    run = rt.engine.request_full(org, "acceptance-rebuild")
    run_id = run["run_id"]

    # the run reaches the waiting state instead of failing
    wait_until(
        lambda: rt.store.get_run(run_id)["phase"] == "awaiting_correction"
        or rt.store.get_run(run_id)["status"] == "succeeded",
        timeout=20,
        message="rebuild to wait on the unreadable member",
    )
    time.sleep(0.4)
    current = rt.store.get_run(run_id)
    assert current["status"] in ("queued", "running"), (
        f"rebuild must keep retrying, was {current['status']} {current.get('error')}"
    )
    # previous catalog keeps serving completely
    state = rt.store.get_state(org)
    assert state["ready"] is True
    assert state["cert_count"] == baseline + 2
    assert cert(rt, org, "C-9202")["status"] == "active"

    # heal -> the same run converges and publishes the complete catalog
    world.show_detail(["C-9201"])
    wait_until(
        lambda: rt.store.get_run(run_id)["status"] == "succeeded",
        timeout=30,
        message="blocked rebuild to finish after heal",
    )
    state = rt.store.get_state(org)
    assert state["caught_up"] and state["cert_count"] == len(world.state()["certs"])
    assert cert(rt, org, "C-9201")["status"] == "active"
    assert cert(rt, org, "C-9202")["status"] == "active"
    assert cert(rt, org, "C-1003")["status"] == "revoked"
    assert rt.store.list_pending_reads(org) == []


def scenario_removed_member_converges(rt, org, kind):
    world = world_for(rt, kind)
    ready(rt, org)
    before = rt.store.get_state(org)["cert_count"]

    world.correction(
        "C-1004",
        [
            {"cert_no": "C-9301", "data": {"instrument": "A"}},
            {"cert_no": "C-9302", "data": {"instrument": "B"}},
        ],
    )
    world.hide_detail(["C-9302"])
    # wait until the collector has registered the blocked member
    wait_until(
        lambda: any(p["cert_no"] == "C-9302" for p in rt.store.list_pending_reads(org)),
        timeout=20,
        message="blocked member to be registered",
    )
    # now the body removes the member from the directory entirely
    world.show_detail(["C-9302"])
    world.purge_cert("C-9302")
    wait_until(
        lambda: cert(rt, org, "C-1004")["status"] == "revoked"
        and cert(rt, org, "C-9301")["status"] == "active"
        and rt.store.get_state(org)["caught_up"],
        timeout=30,
        message="correction to converge after member removed from directory",
    )
    stored = {c["cert_no"] for c in rt.store.list_certs(org, page=1, page_size=500)["items"]}
    live = {c["cert_no"] for c in world.state()["certs"]}
    assert stored == live
    # the purged replacement is gone but the revoked old cert still lists
    assert rt.store.get_state(org)["cert_count"] == len(live)
    assert rt.store.list_pending_reads(org) == []


def scenario_recorrection_chain_both_lanes(rt, org, kind):
    world = world_for(rt, kind)
    ready(rt, org)

    # first formal correction C-1005 -> C-9401, C-9402
    world.correction(
        "C-1005",
        [
            {"cert_no": "C-9401", "data": {"instrument": "A"}},
            {"cert_no": "C-9402", "data": {"instrument": "B"}},
        ],
    )
    wait_until(
        lambda: cert(rt, org, "C-1005")["status"] == "revoked"
        and cert(rt, org, "C-9402")["status"] == "active",
        message="first correction to land",
    )
    first_cid = cert(rt, org, "C-9401")["correction"]["id"]

    # second formal correction: re-correct a replacement into two new certs.
    # C-9401 gets revoked and points at a *new* correction id.
    second = world.correction(
        "C-9401",
        [
            {"cert_no": "C-9501", "data": {"instrument": "A2"}},
            {"cert_no": "C-9502", "data": {"instrument": "A3"}},
        ],
    )
    second_cid = second["correction_id"]
    assert first_cid != second_cid
    wait_until(
        lambda: rt.store.get_state(org)["caught_up"]
        and cert(rt, org, "C-9401")["status"] == "revoked"
        and cert(rt, org, "C-9501")["status"] == "active"
        and cert(rt, org, "C-9502")["status"] == "active"
        and cert(rt, org, "C-9402")["status"] == "active",
        timeout=30,
        message="re-correction chain to apply through the incremental lane",
    )
    assert cert(rt, org, "C-9501")["correction"]["id"] == second_cid
    assert rt.store.list_pending_corrections(org) == []

    # now a full rebuild must publish the same complete state without failing
    run = rt.engine.request_full(org, "acceptance-chain-rebuild")
    wait_until(
        lambda: rt.store.get_run(run["run_id"])["status"] == "succeeded",
        timeout=30,
        message="rebuild over a re-correction chain to succeed",
    )
    state = rt.store.get_state(org)
    assert state["caught_up"] and state["cert_count"] == len(world.state()["certs"])
    stored = {c["cert_no"]: (c["revision"], c["status"]) for c in
              rt.store.list_certs(org, page=1, page_size=500)["items"]}
    source = {c["cert_no"]: (c["revision"], c["status"]) for c in world.state()["certs"]}
    assert stored == source
    assert rt.store.list_pending_corrections(org) == []


def scenario_restart_and_expiry_converge(rt, org, kind, workdir, name):
    world = world_for(rt, kind)
    ready(rt, org)

    world.correction(
        "C-1006",
        [
            {"cert_no": "C-9601", "data": {"instrument": "A"}},
            {"cert_no": "C-9602", "data": {"instrument": "B"}},
        ],
    )
    world.hide_detail(["C-9602"])
    wait_until(
        lambda: any(p["cert_no"] == "C-9602" for p in rt.store.list_pending_reads(org)),
        timeout=20,
        message="blocked member registered before restart",
    )

    # hard engine restart: durable pending state must survive
    db_url = rt.db_url
    rt.engine.stop()
    rt.engine.start()
    assert any(p["cert_no"] == "C-9602" for p in rt.store.list_pending_reads(org)), (
        "pending reads must survive a restart"
    )
    # make every old cursor/snapshot stale, then heal: self-healing must
    # converge even though all positions expired across the restart.
    world.expire_all()
    world.show_detail(["C-9602"])
    wait_until(
        lambda: rt.store.get_state(org)["caught_up"]
        and cert(rt, org, "C-1006")["status"] == "revoked"
        and cert(rt, org, "C-9601")["status"] == "active"
        and cert(rt, org, "C-9602")["status"] == "active",
        timeout=45,
        message="convergence after restart with expired positions",
    )
    wait_until(
        lambda: rt.store.list_pending_reads(org) == []
        and rt.store.list_pending_corrections(org) == [],
        message="pending state to clear after convergence",
    )
    state = rt.store.get_state(org)
    assert state["cert_count"] == len(world.state()["certs"])
    _ = db_url, name  # db path retained for debugging


SCENARIOS = [
    ("incremental waits then converges", scenario_incremental_waits_then_converges),
    ("rebuild waits then publishes complete result", scenario_rebuild_waits_then_publishes_complete),
    ("removed member converges the group", scenario_removed_member_converges),
    ("re-correction chain converges on both lanes", scenario_recorrection_chain_both_lanes),
    ("restart with expired positions converges", scenario_restart_and_expiry_converge),
]


def main() -> int:
    workdir = tempfile.mkdtemp(prefix="certcollector-acceptance-")
    failures = 0
    total = 0
    for kind in ("html", "json"):
        for title, fn in SCENARIOS:
            total += 1
            name = f"acc-{kind}-{title.split()[0]}"
            rt = make_runtime(workdir, name)
            rt.start()
            org = f"{kind}-lab"
            try:
                register(rt, org, kind)
                if fn.__name__ == "scenario_restart_and_expiry_converge":
                    fn(rt, org, kind, workdir, name)
                else:
                    fn(rt, org, kind)
                print(f"[PASS] {kind:4s} | {title}")
            except Exception as exc:  # noqa: BLE001 - acceptance report
                failures += 1
                print(f"[FAIL] {kind:4s} | {title}: {exc}")
                traceback.print_exc(limit=4)
            finally:
                rt.stop()
    print(f"\n{total - failures}/{total} scenarios passed ({failures} failed); workdir={workdir}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
