"""Several collector processes sharing one database.

These scenarios run two real collector processes against one SQLite file and a
separate simulator process, and check that

* different organizations are collected in parallel, each process owning its
  own organization and neither touching the other's;
* starting the second process never interrupts work already running in the
  first one;
* the full and incremental lanes of one organization still run in parallel;
* when a process exits or is killed the other takes over automatically;
* the last-observed organization access limits survive the hand-over;
* a late result from a process that lost ownership cannot rewrite task state
  or the published catalog.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time

import pytest

from .conftest import Client, wait_until

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ---------------------------------------------------------------------------
# process helpers (each collector is a genuine separate OS process)
def _start_sim(port: int = 0, count: int = 24) -> tuple[subprocess.Popen, dict]:
    code = (
        "import sys\n"
        f"sys.path.insert(0, {ROOT!r})\n"
        "from certcollector.sim_server import SimServer\n"
        "import json, time\n"
        f"s = SimServer('127.0.0.1', {port}, seed=7, count={count}).start()\n"
        "print(json.dumps({'urls': s.urls()}), flush=True)\n"
        "time.sleep(3600)\n"
    )
    proc = subprocess.Popen(
        [sys.executable, "-I", "-c", code],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    line = proc.stdout.readline()
    if not line.strip():
        raise AssertionError(f"simulator failed to start: {proc.stderr.read(4000)}")
    return proc, json.loads(line)


class Collector:
    """A collector process plus the base URL of its HTTP API."""

    def __init__(self, db_path: str, *, owner_id: str, lease_ttl: float = 1.2,
                 lease_renew: float = 0.2, poll_ms: int = 100):
        code = (
            "import sys\n"
            f"sys.path.insert(0, {ROOT!r})\n"
            "import json, time\n"
            "from certcollector.runtime import Runtime\n"
            f"rt = Runtime({db_path!r}, simulate=False, poll_interval_ms={poll_ms},\n"
            f"             owner_id={owner_id!r}, lease_ttl={lease_ttl},\n"
            f"             lease_renew_interval={lease_renew})\n"
            "rt.start(port=0)\n"
            "print(json.dumps({'listening': rt.base_url}), flush=True)\n"
            "time.sleep(3600)\n"
        )
        self.owner_id = owner_id
        self.proc = subprocess.Popen(
            [sys.executable, "-I", "-c", code],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        line = self.proc.stdout.readline()
        if not line.strip():
            raise AssertionError(f"collector failed to start: {self.proc.stderr.read(6000)}")
        self.base_url = json.loads(line)["listening"]
        self.client = Client(self.base_url)

    def kill(self) -> None:
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGKILL)
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover - defensive
            self.proc.kill()

    def stop(self) -> None:
        """Graceful shutdown (leases are released on exit)."""
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover - defensive
            self.kill()


def _kill(*collectors: Collector) -> None:
    for c in collectors:
        try:
            c.kill()
        except Exception:  # pragma: no cover - defensive
            pass


def _register(client: Client, org_id: str, kind: str, urls: dict, **options):
    status, body = client.post(
        "/api/orgs",
        {
            "org_id": org_id,
            "source": {"kind": kind, "base_url": urls[kind]},
            "limits": {
                "max_concurrency": options.pop("max_concurrency", 2),
                "min_interval_ms": options.pop("min_interval_ms", 0),
            },
            "options": {
                "poll_interval_ms": options.pop("poll_interval_ms", 80),
                **options,
            },
        },
    )
    assert status == 201, body
    return body


def _status(client: Client, org_id: str) -> dict:
    status, body = client.get(f"/api/orgs/{org_id}/status")
    assert status == 200, body
    return body


def _lease_view(client: Client) -> dict:
    status, body = client.get("/api/admin/collectors")
    assert status == 200, body
    return {entry["org_id"]: entry for entry in body["org_leases"]}


def _wait_caught_up(client: Client, org_id: str, source_count: int, timeout: float = 60.0):
    def done():
        body = _status(client, org_id)
        return (
            body["ready"]
            and body["catalog"]["caught_up"]
            and body["catalog"]["cert_count"] == source_count
        )

    return wait_until(done, timeout=timeout, message=f"{org_id} caught up on the shared db")


def _sim_get(urls: dict, kind: str, path: str) -> dict:
    """Admin reads share the body's rate limit with the collectors; retry."""
    import urllib.error
    import urllib.request

    deadline = time.time() + 15
    while True:
        try:
            with urllib.request.urlopen(urls[kind] + path, timeout=10) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            if exc.code != 429 or time.time() > deadline:
                raise
            time.sleep(0.1)


def _sim_state(urls: dict, kind: str) -> dict:
    return _sim_get(urls, kind, "/__admin/state")


def _sim_config(urls: dict, kind: str, changes: dict) -> None:
    import urllib.error
    import urllib.request

    req = urllib.request.Request(
        urls[kind] + "/__admin/config",
        data=json.dumps(changes).encode(),
        method="GET",
    )
    deadline = time.time() + 15
    while True:
        try:
            urllib.request.urlopen(req, timeout=10).read()
            return
        except urllib.error.HTTPError as exc:
            if exc.code != 429 or time.time() > deadline:
                raise
            time.sleep(0.1)


def _export_certs(client: Client, org_id: str) -> dict[str, list]:
    status, export = client.post(f"/api/orgs/{org_id}/exports", {"page_size": 50})
    assert status == 201, export
    seen: dict[str, list] = {}
    page = 1
    while page:
        status, body = client.get(f"/api/exports/{export['token']}/pages/{page}")
        assert status == 200, body
        for item in body["items"]:
            seen[item["cert_no"]] = [item["revision"], item["status"]]
        page = body["next_page"]
    return seen


# ---------------------------------------------------------------------------
def test_second_process_does_not_interrupt_first_and_they_share_work(tmp_path):
    """Starting a second collector on the same database leaves the first one's
    in-flight work alone; different organizations are collected in parallel and
    each process owns exactly its own organization."""
    sim_proc, sim = _start_sim()
    urls = sim["urls"]
    db = str(tmp_path / "shared.db")
    first = second = None
    try:
        first = Collector(db, owner_id="proc-a")
        # make the first body slow enough that its collection is still running
        # when the second process starts
        _sim_config(urls, "json", {"slow_ms": 25})
        _register(first.client, "org-a", "json", urls, poll_interval_ms=60)
        wait_until(
            lambda: _lease_view(first.client)["org-a"]["owned_here"],
            timeout=15,
            message="first process to own org-a",
        )
        # record the in-flight run of the first process
        runs_a = first.client.get("/api/orgs/org-a/runs?limit=5")[1]["items"]
        running_a = [r for r in runs_a if r["status"] == "running"]
        assert running_a, "org-a must be mid-collection before the second starts"
        in_flight = running_a[0]["run_id"]

        second = Collector(db, owner_id="proc-b")
        # the second process must register in the shared database but must not
        # claim the first process's organization
        wait_until(
            lambda: any(
                c["owner_id"] == "proc-b" and c["alive"]
                for c in second.client.get("/api/admin/collectors")[1]["items"]
            ),
            timeout=15,
            message="second process to register",
        )
        time.sleep(1.0)
        view = _lease_view(second.client)
        assert view["org-a"]["owner"] == "proc-a"
        assert view["org-a"]["owned_here"] is False

        # the first process's run was not requeued/interrupted by the start-up
        still = first.client.get(f"/api/orgs/org-a/runs/{in_flight}")[1]
        assert still["status"] in ("running", "succeeded"), still
        assert still["reason"] != "resumed_after_restart"

        # now let the second process collect a different organization
        _register(second.client, "org-b", "html", urls, poll_interval_ms=60)
        wait_until(
            lambda: _lease_view(second.client)["org-b"]["owner"] == "proc-b",
            timeout=15,
            message="second process to own org-b",
        )
        # both organizations converge; each on its own body
        source_a = _sim_state(urls, "json")["cert_count"]
        source_b = _sim_state(urls, "html")["cert_count"]
        _wait_caught_up(first.client, "org-a", source_a)
        _wait_caught_up(second.client, "org-b", source_b)

        view = _lease_view(second.client)
        assert view["org-a"]["owner"] == "proc-a"
        assert view["org-b"]["owner"] == "proc-b"

        # the certificate sets are independent and match their own bodies
        assert set(_export_certs(first.client, "org-a")) == {
            c["cert_no"] for c in _sim_state(urls, "json")["certs"]
        }
        assert set(_export_certs(second.client, "org-b")) == {
            c["cert_no"] for c in _sim_state(urls, "html")["certs"]
        }
    finally:
        if first:
            _kill(first)
        if second:
            _kill(second)
        _kill_sim(sim_proc)


def _kill_sim(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.send_signal(signal.SIGKILL)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:  # pragma: no cover - defensive
        proc.kill()


def test_full_and_incremental_lanes_of_one_org_run_in_parallel(tmp_path):
    """Within one organization, a rebuild and an incremental catch-up may run
    at the same time (two lanes), even when two processes share the database."""
    sim_proc, sim = _start_sim()
    urls = sim["urls"]
    db = str(tmp_path / "lanes.db")
    owner = other = None
    try:
        owner = Collector(db, owner_id="lane-a", poll_ms=60)
        _register(owner.client, "lane-lab", "json", urls, poll_interval_ms=60)
        _wait_caught_up(owner.client, "lane-lab", _sim_state(urls, "json")["cert_count"])

        other = Collector(db, owner_id="lane-b", poll_ms=60)
        wait_until(
            lambda: _lease_view(other.client)["lane-lab"]["owned_here"] is False,
            timeout=15,
            message="second process to stay passive",
        )

        _sim_config(urls, "json", {"slow_ms": 20})
        status, full_run = owner.client.post("/api/orgs/lane-lab/rebuild")
        assert status == 202
        status, inc_run = owner.client.post("/api/orgs/lane-lab/collect", {"mode": "incremental"})
        assert status == 202
        assert full_run["kind"] == "full"

        def both_started():
            runs = owner.client.get("/api/orgs/lane-lab/runs?limit=20")[1]["items"]
            kinds = {r["kind"] for r in runs if r["status"] == "running"}
            return {"full", "incremental"} <= kinds

        # A rebuild and a catch-up are independent lanes; the incremental run
        # may finish its single empty window before we look, so keep asking
        # for a fresh incremental run while the rebuild is still staging.
        def observe_parallel():
            for _ in range(40):
                try:
                    owner.client.post("/api/orgs/lane-lab/collect", {"mode": "incremental"})
                except Exception:
                    pass
                if both_started():
                    return True
                time.sleep(0.05)
            return False

        wait_until(observe_parallel, timeout=25, message="both lanes to run at once")
        wait_until(
            lambda: owner.client.get(f"/api/orgs/lane-lab/runs/{full_run['run_id']}")[1]["status"]
            in ("succeeded", "failed"),
            timeout=40,
            message="rebuild to finish",
        )
        # the second process stayed passive the whole time
        assert _lease_view(other.client)["lane-lab"]["owned_here"] is False
        state = _status(owner.client, "lane-lab")["catalog"]
        assert state["caught_up"] is True
    finally:
        _kill(owner, other) if owner and other else _kill(*(c for c in (owner, other) if c))
        _kill_sim(sim_proc)


def test_surviving_process_takes_over_after_peer_exit(tmp_path):
    """When the owning process exits gracefully the other one takes over its
    work and converges without an API call, and the access budget carries
    over (the upstream still sees respectful pacing)."""
    sim_proc, sim = _start_sim()
    urls = sim["urls"]
    db = str(tmp_path / "takeover.db")
    first = second = None
    try:
        first = Collector(db, owner_id="take-a", lease_ttl=1.2, lease_renew=0.2)
        second = Collector(db, owner_id="take-b", lease_ttl=1.2, lease_renew=0.2)
        # upstream is strict: 1 concurrent request, 80ms spacing
        _sim_config(urls, "json", {"max_concurrency": 1, "min_interval_ms": 60,
                                  "retry_after": 0.05, "slow_ms": 10})
        _register(first.client, "take-lab", "json", urls,
                  max_concurrency=1, min_interval_ms=0, poll_interval_ms=50)
        wait_until(
            lambda: _lease_view(first.client)["take-lab"]["owner"] == "take-a",
            timeout=15,
            message="first process to own the organization",
        )
        _wait_caught_up(first.client, "take-lab", _sim_state(urls, "json")["cert_count"])

        # hand over while the peer keeps running
        first.stop()

        # the second process takes over by itself - no API request is made
        wait_until(
            lambda: _lease_view(second.client)["take-lab"]["owned_here"],
            timeout=20,
            message="survivor to take over",
        )
        source_count = _sim_state(urls, "json")["cert_count"]
        _wait_caught_up(second.client, "take-lab", source_count, timeout=90)
        view = _lease_view(second.client)
        assert view["take-lab"]["owner"] == "take-b"
        # pacing survived: the body was never overwhelmed
        counters = _sim_state(urls, "json")["counters"]
        assert counters["peak_active"] <= 1
    finally:
        _kill(*(c for c in (first, second) if c))
        _kill_sim(sim_proc)


def test_killed_process_is_replaced_and_late_writer_is_fenced(tmp_path):
    """A hard-killed owner is taken over automatically, and task state / the
    catalog written by the old epoch can never be applied afterwards."""
    sim_proc, sim = _start_sim(count=18)
    urls = sim["urls"]
    db = str(tmp_path / "fencing.db")
    first = second = None
    try:
        first = Collector(db, owner_id="fence-a", lease_ttl=1.0, lease_renew=0.15)
        second = Collector(db, owner_id="fence-b", lease_ttl=1.0, lease_renew=0.15)
        _sim_config(urls, "html", {"slow_ms": 30, "max_concurrency": 2})
        _register(first.client, "fence-lab", "html", urls, poll_interval_ms=60)
        wait_until(
            lambda: _lease_view(first.client)["fence-lab"]["owner"] == "fence-a",
            timeout=15,
            message="first process to own the organization",
        )
        # it must be mid-collection when killed
        runs = first.client.get("/api/orgs/fence-lab/runs?limit=5")[1]["items"]
        assert any(r["status"] in ("running", "queued") for r in runs)

        first.kill()

        wait_until(
            lambda: _lease_view(second.client)["fence-lab"]["owned_here"],
            timeout=25,
            message="survivor to take over a killed peer",
        )
        source = _sim_state(urls, "html")["cert_count"]
        _wait_caught_up(second.client, "fence-lab", source, timeout=90)
        good = _export_certs(second.client, "fence-lab")
        state_after = _status(second.client, "fence-lab")
        assert state_after["ready"] is True

        # ---- late writer simulation -------------------------------------
        # A process believing it still owns the old epoch tries to publish a
        # bogus catalog, finish a task and fill staging.  Every write must be
        # rejected, so neither the catalog nor the task state can change.
        from certcollector.db import make_database
        from certcollector.store import Lease, Store
        from certcollector.util import LeaseLost

        late = Store(make_database(db))
        try:
            epoch = late.db.query_one(
                "SELECT epoch FROM org_leases WHERE org_id=?", ("fence-lab",)
            )["epoch"]
            stale = Lease("fence-lab", "fence-a", int(epoch) - 1)
            bogus = [{
                "cert_no": "C-9999",
                "revision": 9,
                "status": "active",
                "data": {"instrument": "late writer"},
            }]
            with late.fence(stale):
                with pytest.raises(LeaseLost):
                    late.publish_full(
                        "fence-lab", bogus,
                        watermark_cursor="late", watermark_seq=10_000,
                        head_cursor="late", head_seq=10_000,
                    )
                with pytest.raises(LeaseLost):
                    late.publish_incremental(
                        "fence-lab", bogus, [],
                        watermark_cursor="late", watermark_seq=10_000,
                        head_cursor="late", head_seq=10_000,
                    )
                with pytest.raises(LeaseLost):
                    late.finish_run(runs[0]["run_id"], "succeeded", cursor_after="late")
                with pytest.raises(LeaseLost):
                    late.update_run(runs[0]["run_id"], phase="published", status="succeeded")
                scan = late.db.query_one(
                    "SELECT scan_id FROM scans WHERE org_id=? ORDER BY created_at DESC LIMIT 1",
                    ("fence-lab",),
                )
                if scan is not None:
                    with pytest.raises(LeaseLost):
                        late.update_scan(scan["scan_id"], pages_done=999)
                    with pytest.raises(LeaseLost):
                        late.set_scan_item(
                            scan["scan_id"], "C-9999", status="ok", payload=bogus[0]
                        )
            # nothing changed
            after = _export_certs(second.client, "fence-lab")
            assert after == good
            assert "C-9999" not in after
            task = second.client.get(f"/api/orgs/fence-lab/runs/{runs[0]['run_id']}")[1]
            assert task["cursor_after"] != "late"
            assert task["phase"] != "published"
        finally:
            late.db.close()
    finally:
        _kill(*(c for c in (first, second) if c))
        _kill_sim(sim_proc)


def test_access_limits_are_respected_across_takeover(tmp_path):
    """Pacing/Retry-After state learned by one owner is honoured by the next:
    the upstream never sees overlapping requests across the hand-over."""
    sim_proc, sim = _start_sim(count=20)
    urls = sim["urls"]
    db = str(tmp_path / "limits.db")
    first = second = None
    try:
        _sim_config(urls, "json", {"max_concurrency": 1, "min_interval_ms": 120,
                                  "retry_after": 0.1, "slow_ms": 15})
        first = Collector(db, owner_id="limit-a", lease_ttl=1.0, lease_renew=0.15)
        second = Collector(db, owner_id="limit-b", lease_ttl=1.0, lease_renew=0.15)
        _register(first.client, "limit-lab", "json", urls,
                  max_concurrency=1, min_interval_ms=0, poll_interval_ms=50)
        wait_until(
            lambda: _lease_view(first.client)["limit-lab"]["owned_here"],
            timeout=15,
            message="first owner",
        )
        # let it collect for a while and learn the pacing
        time.sleep(0.8)
        first.kill()
        wait_until(
            lambda: _lease_view(second.client)["limit-lab"]["owned_here"],
            timeout=20,
            message="takeover",
        )
        _wait_caught_up(second.client, "limit-lab",
                        _sim_state(urls, "json")["cert_count"], timeout=90)
        counters = _sim_state(urls, "json")["counters"]
        assert counters["peak_active"] <= 1, counters
        # the persisted budget shows a real minimum spacing was learned
        from certcollector.db import make_database
        from certcollector.store import Store

        store = Store(make_database(db))
        try:
            access = store.load_access("limit-lab")
        finally:
            store.db.close()
        assert access["adaptive_interval"] > 0 or access["next_allowed_at"] > 0
    finally:
        _kill(*(c for c in (first, second) if c))
        _kill_sim(sim_proc)


# ---------------------------------------------------------------------------
def test_existing_database_is_migrated_for_sharing(tmp_path):
    """An older database file (written before multi-process support) gains the
    lease/ownership bookkeeping on start instead of failing."""
    import sqlite3

    path = str(tmp_path / "legacy.db")
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE orgs (org_id TEXT PRIMARY KEY, name TEXT NOT NULL,
          source_config TEXT NOT NULL, limits TEXT NOT NULL, options TEXT NOT NULL,
          enabled INTEGER NOT NULL DEFAULT 1, paused INTEGER NOT NULL DEFAULT 0,
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE runs (run_id TEXT PRIMARY KEY, org_id TEXT NOT NULL,
          kind TEXT NOT NULL, trigger TEXT NOT NULL, status TEXT NOT NULL, phase TEXT,
          progress TEXT, error TEXT, reason TEXT, cursor_before TEXT, cursor_after TEXT,
          requested_at TEXT NOT NULL, started_at TEXT, finished_at TEXT,
          updated_at TEXT NOT NULL, heartbeat_at TEXT, request_key TEXT);
        CREATE TABLE scans (scan_id TEXT PRIMARY KEY, org_id TEXT NOT NULL, run_id TEXT,
          kind TEXT NOT NULL, status TEXT NOT NULL, snapshot_id TEXT, change_position TEXT,
          catchup_cursor TEXT, page_cursor TEXT, pages_done INTEGER NOT NULL DEFAULT 0,
          entries_done INTEGER NOT NULL DEFAULT 0, total_hint INTEGER,
          head_seq BIGINT NOT NULL DEFAULT -1, head_cursor TEXT, expires_at TEXT,
          error TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        """
    )
    conn.commit()
    conn.close()

    from certcollector.db import make_database

    db = make_database(path)
    try:
        runs_cols = {row["name"] for row in db.query("PRAGMA table_info(runs)")}
        scans_cols = {row["name"] for row in db.query("PRAGMA table_info(scans)")}
        assert {"owner_id", "owner_epoch"} <= runs_cols
        assert {"owner_id", "owner_epoch"} <= scans_cols
        for table in ("org_leases", "org_access", "collectors"):
            assert db.query_one(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)
            ), table
    finally:
        db.close()


# ---------------------------------------------------------------------------
# In-process equivalents: two runtimes on one database file.  They exercise the
# same coordination without child-process timing, so the core guarantees stay
# covered even on slow machines.
def test_in_process_second_owner_is_passive_and_does_not_requeue(tmp_path):
    from certcollector.runtime import Runtime

    db = str(tmp_path / "inproc.db")
    sim = Runtime(db, seed=5, count=10, simulate=True, poll_interval_ms=60,
                  owner_id="a", lease_ttl=1.5, lease_renew_interval=0.2)
    sim.start()
    peer = None
    try:
        sim.register_simulated_org("share-a", "json")
        wait_until(
            lambda: sim.engine.org_owned("share-a"), timeout=10,
            message="first runtime to own the org",
        )
        # second runtime on the same file, without a simulator (passive)
        peer = Runtime(db, simulate=False, poll_interval_ms=60,
                       owner_id="b", lease_ttl=1.5, lease_renew_interval=0.2)
        peer.start()
        time.sleep(0.8)
        assert not peer.engine.org_owned("share-a")
        # the owner's work was not disturbed
        runs = sim.store.list_runs("share-a", limit=5)
        assert not any(r["reason"] == "resumed_after_restart" for r in runs)
        wait_ready_here(sim, "share-a", 10)
        # ... and the peer kept its hands off the catalog
        assert peer.store.get_state("share-a")["ready"] is True
    finally:
        if peer:
            peer.stop()
        sim.stop()


def wait_ready_here(runtime, org_id: str, count: int | None = None, timeout: float = 30.0):
    def done():
        state = runtime.store.get_state(org_id)
        return state["ready"] and state["caught_up"] and (
            count is None or state["cert_count"] == count
        )

    return wait_until(done, timeout=timeout, message=f"{org_id} ready")


def test_in_process_takeover_when_owner_stops(tmp_path):
    from certcollector.runtime import Runtime

    db = str(tmp_path / "takeover-inproc.db")
    first = Runtime(db, seed=9, count=8, simulate=True, poll_interval_ms=60,
                    owner_id="first", lease_ttl=1.0, lease_renew_interval=0.15)
    # the peer needs a transport for the same simulated body; share the first's
    # simulator through a loopback factory
    first.start()
    peer = None
    try:
        first.register_simulated_org("handover", "html")
        wait_ready_here(first, "handover", 8)
        world = first.simulator.html_world
        peer = Runtime(db, simulate=True, seed=9, count=8, poll_interval_ms=60,
                       owner_id="second", lease_ttl=1.0, lease_renew_interval=0.15)
        # point the peer at the same simulated state
        peer.simulator = first.simulator
        peer.engine.transport_factory = first.simulator.transport
        peer.engine.runtime("handover").invalidate()
        peer.start()
        assert not peer.engine.org_owned("handover")
        first.engine.stop()
        wait_until(
            lambda: peer.engine.org_owned("handover"), timeout=15,
            message="peer to take over",
        )
        # a change after the hand-over is collected by the new owner
        world.add_cert("C-7701", {"instrument": "after handover"})
        wait_until(
            lambda: peer.store.get_state("handover")["caught_up"]
            and peer.store.get_state("handover")["cert_count"] == 9,
            timeout=30,
            message="peer to converge after takeover",
        )
    finally:
        if peer:
            peer.stop()
        first.stop()
