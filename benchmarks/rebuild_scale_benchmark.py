"""Scale benchmark for the streaming online-rebuild swap (SQLite, stdlib only).

Run from the repository root with an isolated interpreter::

    python3 -I benchmarks/rebuild_scale_benchmark.py

It builds local source-sized SQLite fixtures at two directory scales (2,000
and 20,000 equal-sized certificate details) and compares, for each scale:

* the peak Python heap memory used by the swap publication (tracemalloc);
* how many certificate rows the single swap transaction actually writes, both
  when nothing changed and when only a small delta is pending;
* how long the write lock / swap transaction is held.

The legacy behaviour -- materializing every staged detail and rewriting the
whole directory in one transaction -- is reproduced inline as ``legacy_publish``
purely for the comparison; production code only contains the streaming path.
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
import tracemalloc

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from certcollector.db import make_database  # noqa: E402
from certcollector.store import PUBLISH_CHUNK_SIZE, Store  # noqa: E402
from certcollector.util import dumps, iso, utcnow  # noqa: E402

SCALES = (2_000, 20_000)
DELTA_CHANGES = 20
ORG = "bench-lab"


def make_entry(no: int, *, revision: int = 1) -> dict:
    return {
        "cert_no": f"C-{no:06d}",
        "revision": revision,
        "status": "active",
        "data": {
            "instrument": f"instrument-{no}",
            "manufacturer": f"maker-{no % 50}",
            "serial_no": f"SN-{no:08d}",
            "notes": "x" * 200,
        },
        "source_updated_at": "2026-01-01T00:00:00Z",
        "revoked_at": None,
        "correction_id": None,
        "correction": None,
    }


def build_fixture(workdir: str, n: int, *, pending_changes: int) -> tuple[Store, str]:
    db = make_database(os.path.join(workdir, f"fixture-{n}.db"))
    store = Store(db)
    store.upsert_org(
        ORG,
        ORG,
        {"kind": "json", "base_url": "http://sim.local/json"},
        {"max_concurrency": 2, "min_interval_ms": 0},
        {"poll_interval_ms": 1_000_000},
    )
    store.bulk_upsert_certs(ORG, [make_entry(i) for i in range(1, n + 1)], source_seq=100)
    store.execute_checked(
        "UPDATE catalog_state SET ready=1, watermark_seq=100, source_head_seq=100, "
        "cert_count=?, watermark_cursor='cur-100', source_head_cursor='cur-100' "
        "WHERE org_id=?",
        (n, ORG),
    )
    scan = store.create_scan(ORG, "bench-run", "full")
    scan_id = scan["scan_id"]
    items = []
    for no in range(1, n + 1):
        entry = make_entry(no, revision=2 if no <= pending_changes else 1)
        items.append(
            {
                "cert_no": entry["cert_no"],
                "revision": entry["revision"],
                "status": "ok",
                "payload": {
                    "cert_no": entry["cert_no"],
                    "revision": entry["revision"],
                    "status": entry["status"],
                    "data": entry["data"],
                    "source_updated_at": entry["source_updated_at"],
                    "revoked_at": entry["revoked_at"],
                    "correction_id": entry["correction_id"],
                    "correction": entry["correction"],
                },
                "ordinal": no,
            }
        )
    for idx in range(0, len(items), PUBLISH_CHUNK_SIZE):
        store.add_scan_items(scan_id, items[idx : idx + PUBLISH_CHUNK_SIZE])
    return store, scan_id


def legacy_publish(store: Store, scan_id: str, n: int, watermark_seq: int) -> None:
    """Reproduction of the pre-refactor whole-directory materialization."""
    entries = []
    for chunk in store.iter_scan_entries(scan_id):
        entries.extend(chunk)
    with store.db.transaction(write=True) as tx:
        state = tx.fetchone(
            store.db._translate("SELECT * FROM catalog_state WHERE org_id=?"), (ORG,)
        )
        rows = [store._cert_row_tuple(ORG, e, watermark_seq) for e in entries]
        tx.executemany(store.db._translate(Store.CERT_INSERT), rows)
        tx.execute(
            store.db._translate(
                "UPDATE catalog_state SET version=version+1, watermark_seq=?, "
                "cert_count=?, updated_at=? WHERE org_id=?"
            ),
            (watermark_seq, len(entries), iso(utcnow()), ORG),
        )


def measure(label: str, fn) -> dict:
    tracemalloc.start()
    tracemalloc.reset_peak()
    started = time.perf_counter()
    fn()
    elapsed = time.perf_counter() - started
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {"label": label, "peak_kb": peak // 1024, "elapsed_ms": round(elapsed * 1000, 1)}


def run_case(workdir: str, n: int, pending_changes: int) -> dict:
    store, scan_id = build_fixture(workdir, n, pending_changes=pending_changes)
    store.db.sql_trace = []
    streaming = measure(
        "streaming",
        lambda: store.publish_full_from_scan(
            ORG,
            scan_id,
            watermark_cursor="cur-101",
            watermark_seq=101,
            head_cursor="cur-101",
            head_seq=101,
        ),
    )
    cert_writes = sum(
        rowcount
        for verb, sql, rowcount in store.db.sql_trace
        if verb in ("INSERT", "DELETE") and "certs" in sql.lower()
    )
    store.db.sql_trace = None
    store.db.close()

    # fresh fixture for the legacy comparison, same pending delta
    legacy_store, legacy_scan = build_fixture(workdir, n, pending_changes=pending_changes)
    legacy = measure("legacy", lambda: legacy_publish(legacy_store, legacy_scan, n, 101))
    legacy_store.db.close()
    return {
        "n": n,
        "pending_changes": pending_changes,
        "streaming": streaming,
        "legacy": legacy,
        "streaming_cert_rows_written": cert_writes,
        "peak_ratio_legacy_over_streaming": round(
            legacy["peak_kb"] / max(1, streaming["peak_kb"]), 2
        ),
    }


def main() -> int:
    workdir = tempfile.mkdtemp(prefix="rebuild-bench-")
    print(f"workdir={workdir} chunk_size={PUBLISH_CHUNK_SIZE}\n")
    results = []
    for n in SCALES:
        for pending in (0, DELTA_CHANGES):
            result = run_case(workdir, n, pending)
            results.append(result)
            print(f"n={n:>6} pending={pending:>3}")
            print(
                f"  streaming: peak={result['streaming']['peak_kb']:>7} KB "
                f"swap={result['streaming']['elapsed_ms']:>8} ms "
                f"cert_rows_written={result['streaming_cert_rows_written']}"
            )
            print(
                f"  legacy   : peak={result['legacy']['peak_kb']:>7} KB "
                f"swap={result['legacy']['elapsed_ms']:>8} ms "
                f"cert_rows_written={n}"
            )
            ratio = result["peak_ratio_legacy_over_streaming"]
            print(f"  legacy/streaming peak ratio: {ratio}x\n")
    # summary assertions of the design goals
    no_delta = [r for r in results if r["pending_changes"] == 0]
    small, large = no_delta
    growth = large["streaming"]["peak_kb"] / max(1, small["streaming"]["peak_kb"])
    print(f"streaming peak growth 2k -> 20k (no delta): {growth:.2f}x (target <= 2.0x)")
    delta_cases = [r for r in results if r["pending_changes"] == DELTA_CHANGES]
    for case in delta_cases:
        print(
            f"n={case['n']}: swap writes {case['streaming_cert_rows_written']} rows "
            f"for {DELTA_CHANGES} pending changes (legacy would write {case['n']})"
        )
    return 0 if growth <= 2.0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
