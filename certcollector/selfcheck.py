"""Embedded, dependency-free verification path.

Runs the whole pipeline in-process (SQLite + both simulated bodies) and prints
one line per checked behaviour::

    python3 -I -m certcollector.selfcheck
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import traceback

from .runtime import Runtime
from .util import CertCollectorError


def _wait(fn, timeout=20.0, interval=0.02):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            value = fn()
            if value:
                return value
        except CertCollectorError:
            pass
        time.sleep(interval)
    raise AssertionError("timed out")


def _check(name, fn, results):
    started = time.time()
    try:
        detail = fn()
        results.append((name, True, detail, time.time() - started))
    except Exception as exc:  # pragma: no cover - diagnostic path
        results.append((name, False, f"{exc}\n{traceback.format_exc(limit=3)}", time.time() - started))


def run() -> int:
    workdir = tempfile.mkdtemp(prefix="certcollector-selfcheck-")
    results: list[tuple[str, bool, str, float]] = []
    rt = Runtime(os.path.join(workdir, "selfcheck.db"), seed=21, count=16, poll_interval_ms=80)
    rt.start()
    try:
        rt.register_simulated_org("html-lab", "html")
        rt.register_simulated_org("json-lab", "json")

        def first_catalog():
            _wait(lambda: rt.store.get_state("html-lab")["ready"])
            _wait(lambda: rt.store.get_state("json-lab")["ready"])
            a = rt.store.get_state("html-lab")
            b = rt.store.get_state("json-lab")
            return f"html={a['cert_count']} json={b['cert_count']}"

        _check("initial full catalog for HTML and JSON bodies", first_catalog, results)

        world = rt.simulator.json_world
        baseline = rt.store.get_state("json-lab")["cert_count"]

        def corrections():
            world.correction(
                "C-1002",
                [
                    {"cert_no": "C-7001", "data": {"instrument": "Balance"}},
                    {"cert_no": "C-7002", "data": {"instrument": "Gauge"}},
                ],
            )
            # old cert stays listed (revoked) and two replacements are added
            _wait(
                lambda: rt.store.get_state("json-lab")["cert_count"] == baseline + 2
                and rt.store.get_state("json-lab")["caught_up"]
            )
            old = rt.store.get_cert("json-lab", "C-1002")
            assert old["status"] == "revoked"
            assert rt.store.get_cert("json-lab", "C-7001")["status"] == "active"
            return "old revoked with both replacements in one publication"

        _check("multi-certificate correction applied atomically", corrections, results)

        def online_rebuild():
            before = rt.store.get_state("html-lab")
            rt.simulator.html_world.update_config({"slow_ms": 5})
            rt.engine.request_full("html-lab", "selfcheck")
            seen_ready = []
            for _ in range(20):
                state = rt.store.get_state("html-lab")
                seen_ready.append(state["ready"])
                time.sleep(0.01)
            rt.simulator.html_world.update_config({"slow_ms": 0})
            _wait(lambda: rt.store.get_state("html-lab")["caught_up"])
            after = rt.store.get_state("html-lab")
            assert all(seen_ready)
            assert after["version"] >= before["version"]
            return f"version {before['version']} -> {after['version']}, catalog kept serving"

        _check("online rebuild keeps the published catalog serving", online_rebuild, results)

        def source_switch():
            alt = rt.simulator.alt_world
            old_state = rt.store.get_state("json-lab")
            # push the old source past the alt body's seq space and a shared
            # number past its revision: the switch must still be accepted
            world.revise_cert("C-1001", {"temperature": "33.0 C"})
            _wait(
                lambda: rt.store.get_cert("json-lab", "C-1001")["revision"] >= 2
                and rt.store.get_state("json-lab")["caught_up"]
            )
            assert alt.seq < rt.store.get_state("json-lab")["watermark_seq"]
            export = rt.store.create_export("json-lab", 5, 300)
            frozen_total = export["total"]
            frozen_version = export["catalog_version"]

            alt.set_enabled(False)
            switch = rt.engine.request_switch(
                "json-lab", {"kind": "json", "base_url": "http://sim.local/alt", "timeout": 20}
            )
            assert switch["status"] == "pending"
            time.sleep(0.4)
            # the old catalog keeps serving while the new body is unavailable
            mid = rt.store.get_state("json-lab")
            assert mid["ready"] and mid["active_epoch"] == old_state["active_epoch"]
            assert mid["cert_count"] == old_state["cert_count"]
            alt.set_enabled(True)
            _wait(lambda rt=rt: rt.store.get_pending_switch("json-lab") is None, timeout=30)
            after = rt.store.get_state("json-lab")
            assert after["active_epoch"] == old_state["active_epoch"] + 1
            assert after["cert_count"] == len(alt.state()["certs"])
            assert after["watermark_seq"] <= alt.seq < old_state["watermark_seq"]
            # shared number is taken from the new source despite lower revision
            assert rt.store.get_cert("json-lab", "C-1001")["revision"] == 1
            # late old-source writes cannot land on the new catalog
            world.add_cert("C-9977", {"instrument": "old ghost"})
            time.sleep(0.3)
            assert all(
                c["cert_no"] != "C-9977"
                for c in rt.store.list_certs("json-lab", page=1, page_size=500)["items"]
            )
            # the pre-switch export keeps its frozen pages
            page = rt.store.export_page(export["token"], 1)
            assert page["catalog_version"] == frozen_version and page["total"] == frozen_total
            # incremental collection resumes against the new source
            alt.add_cert("C-A001", {"instrument": "post switch"})
            _wait(
                lambda: rt.store.get_state("json-lab")["cert_count"] == len(alt.state()["certs"])
                and rt.store.get_state("json-lab")["caught_up"],
                timeout=20,
            )
            # switch back so later checks keep exercising the JSON body
            rt.engine.request_switch(
                "json-lab", {"kind": "json", "base_url": "http://sim.local/json", "timeout": 20}
            )
            _wait(
                lambda: rt.store.get_state("json-lab")["cert_count"] == len(world.state()["certs"])
                and rt.store.get_state("json-lab")["caught_up"],
                timeout=30,
            )
            return (
                f"epoch {old_state['active_epoch']} -> {after['active_epoch']}, "
                f"{after['cert_count']} certs, frozen export intact, switched back"
            )

        _check("online source switch cuts over atomically and rejects late old writes", source_switch, results)

        def history_expiry():
            from .source import build_adapter

            world.update_config({"history_retention": 0.2})
            world.revise_cert("C-1003", {"temperature": "40.0 C"})
            world.revise_cert("C-1003", {"temperature": "41.0 C"})
            adapter = build_adapter(
                {"kind": "json", "base_url": "http://sim.local/json"},
                rt.simulator.transport({"kind": "json", "base_url": "http://sim.local/json"}),
            )
            adapter.detail("C-1003", revision=2)
            time.sleep(0.4)
            from .util import HistoryExpired

            try:
                adapter.detail("C-1003", revision=2)
            except HistoryExpired:
                world.update_config({"history_retention": 120})
                return "old revision rejected after retention period"
            raise AssertionError("historical revision was still served")

        _check("historical revisions expire at the source", history_expiry, results)

        def export_resume():
            from .db import make_database
            from .store import Store

            export = rt.store.create_export("html-lab", 5, 300)
            first = rt.store.export_page(export["token"], 1)
            # a fresh store on the same database stands in for a restarted
            # service: the credential and its pages must still be there
            other = Store(make_database(rt.db_url))
            try:
                page = other.export_page(export["token"], 2)
                assert page["catalog_version"] == export["catalog_version"]
                assert first["page"] == 1
                return f"pages={export['pages']} version={export['catalog_version']}"
            finally:
                other.db.close()

        _check("export resumes after a service restart", export_resume, results)

        def export_expiry():
            export = rt.store.create_export("html-lab", 5, 1)
            time.sleep(1.1)
            from .util import Gone

            try:
                rt.store.get_export(export["token"])
            except Gone:
                return "expired credential rejected explicitly"
            raise AssertionError("expired export was accepted")

        _check("expired export credentials are rejected", export_expiry, results)

        _burst_counter = {"n": 0}

        def _burst(n=25):
            for _ in range(n):
                _burst_counter["n"] += 1
                no = f"C-B{_burst_counter['n']:04d}"
                world.add_cert(no, {"instrument": f"burst {_burst_counter['n']}"})

        def access_limits():
            # a burst of changes makes the collector issue requests faster than
            # the body's minimum spacing, so the 429/Retry-After path is used
            _burst()
            # Tighten the body's spacing *and* give the collector a matching
            # concurrency budget so the limit is what slows it down, exactly
            # like a real body.
            world.update_config({"min_interval_ms": 120, "retry_after": 0.05})
            org = rt.store.get_org("json-lab")
            rt.store.upsert_org(
                "json-lab",
                org["name"],
                org["source"],
                {"max_concurrency": 3, "min_interval_ms": 0},
                {**org["options"], "batch_size": 8, "poll_interval_ms": 10},
            )
            rt.engine.runtime("json-lab").invalidate()
            rt.engine.request_incremental("json-lab", "selfcheck")
            _wait(lambda: world.counters["rate_limited"] > 0, timeout=20)
            _wait(
                lambda: rt.store.get_state("json-lab")["caught_up"]
                and rt.store.get_state("json-lab")["cert_count"] == len(world.state()["certs"]),
                timeout=25,
            )
            stats = rt.engine.runtime_state("json-lab")["stats"]
            assert stats["rate_limit_hits"] > 0
            _wait(lambda: rt.engine.runtime_state("json-lab")["wait"] is None, timeout=5)
            world.update_config({"min_interval_ms": 0})
            rt.store.upsert_org(
                "json-lab", org["name"], org["source"], org["limits"],
                {**org["options"], "batch_size": 4},
            )
            return f"rate limit hits={stats['rate_limit_hits']}"

        _check("upstream rate limits and Retry-After are honoured", access_limits, results)

        def isolation():
            _burst(20)
            world.update_config({"min_interval_ms": 300, "retry_after": 0.05})
            rt.engine.request_incremental("json-lab", "selfcheck")
            started = time.time()
            # the other body must keep answering its own queries immediately
            for _ in range(3):
                rt.store.list_certs("html-lab", page=1, page_size=5)
                rt.store.get_cert("html-lab", "C-1001")
            elapsed = time.time() - started
            assert elapsed < 0.5, f"unrelated body was blocked for {elapsed:.2f}s"
            world.update_config({"min_interval_ms": 0})
            _wait(
                lambda: rt.store.get_state("json-lab")["caught_up"]
                and rt.store.get_state("json-lab")["cert_count"] == len(world.state()["certs"]),
                timeout=30,
            )
            return f"unrelated body unaffected ({elapsed * 1000:.0f}ms)"

        _check("one organization waiting does not block another", isolation, results)

        def paused():
            rt.engine.pause("html-lab")
            status = rt.api._status("html-lab")
            assert status["phase"] == "paused"
            rt.engine.resume("html-lab")
            assert rt.api._status("html-lab")["phase"] != "paused"
            return "pause and resume"

        _check("pause/resume", paused, results)

        def crash_recovery():
            rt.engine.stop()
            rt.engine.start()
            _wait(
                lambda: rt.store.get_state("html-lab")["caught_up"]
                and rt.store.get_state("json-lab")["caught_up"],
                timeout=20,
            )
            return "engine restarted and both catalogs converged"

        _check("restart after interruption", crash_recovery, results)
    finally:
        rt.stop()

    width = max(len(name) for name, *_ in results)
    failures = 0
    for name, ok, detail, elapsed in results:
        mark = "PASS" if ok else "FAIL"
        print(f"[{mark}] {name:<{width}}  {elapsed:5.2f}s  {detail.splitlines()[0] if detail else ''}")
        if not ok:
            failures += 1
            for line in str(detail).splitlines()[1:]:
                print("       " + line)
    print(json.dumps({"checks": len(results), "failures": failures, "workdir": workdir}))
    return 1 if failures else 0


def main() -> int:
    return run()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
