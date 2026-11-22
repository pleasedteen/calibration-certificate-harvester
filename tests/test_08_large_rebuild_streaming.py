"""Streaming full-publication semantics on large local SQLite fixtures.

These tests pin down the two scalability properties of an online rebuild swap:

* the staged catalog is streamed out of ``scan_items`` in bounded chunks, so
  the publication peak does not grow with the directory size;
* the swap transaction only writes rows that actually changed, so its write
  footprint grows with the number of pending merges rather than the total
  number of certificates.

Everything here uses in-process fixtures and SQLite; no network is involved.
"""

from __future__ import annotations

import tracemalloc

import pytest

from certcollector.db import make_database
from certcollector.store import PUBLISH_CHUNK_SIZE, Store

SMALL = 2_000
LARGE = 20_000


def _entry(no: int, *, revision: int = 1, status: str = "active", **over) -> dict:
    return {
        "cert_no": f"C-{no:06d}",
        "revision": revision,
        "status": status,
        "data": {
            "instrument": f"instrument-{no}",
            "manufacturer": f"maker-{no % 50}",
            "serial_no": f"SN-{no:08d}",
            # a payload sized like a real detail document
            "notes": "x" * 200,
            **over.pop("data", {}),
        },
        "source_updated_at": "2026-01-01T00:00:00Z",
        "revoked_at": None,
        "correction_id": None,
        "correction": None,
        **over,
    }


def _entry_payload(no: int, **over) -> dict:
    """The JSON document stored inside scan_items.payload."""
    entry = _entry(no, **over)
    return {
        "cert_no": entry["cert_no"],
        "revision": entry["revision"],
        "status": entry["status"],
        "data": entry["data"],
        "source_updated_at": entry["source_updated_at"],
        "revoked_at": entry["revoked_at"],
        "correction_id": entry["correction_id"],
        "correction": entry["correction"],
    }


@pytest.fixture()
def store(tmp_path):
    db = make_database(str(tmp_path / "large.db"))
    s = Store(db)
    s.upsert_org(
        "big-lab",
        "Big lab",
        {"kind": "json", "base_url": "http://sim.local/json"},
        {"max_concurrency": 2, "min_interval_ms": 0},
        {"poll_interval_ms": 1000},
    )
    yield s
    db.close()


def _fresh_store(tmp_path, name: str) -> Store:
    """An isolated store/database so scale comparisons start from zero state."""
    db = make_database(str(tmp_path / name))
    s = Store(db)
    s.upsert_org(
        "big-lab",
        "Big lab",
        {"kind": "json", "base_url": "http://sim.local/json"},
        {"max_concurrency": 2, "min_interval_ms": 0},
        {"poll_interval_ms": 1000},
    )
    return s


def _stage_scan(
    store: Store, n: int, *, changed: dict | None = None, removed: set[int] | None = None
):
    """Create a scan with ``n`` visible staged certs.

    ``changed`` maps cert number to keyword overrides applied on top of the
    baseline entry; numbers in ``removed`` are staged as deleted instead.
    """
    changed = changed or {}
    removed = removed or set()
    scan = store.create_scan("big-lab", "run-fixture", "full")
    scan_id = scan["scan_id"]
    items = []
    for no in range(1, n + 1):
        if no in removed:
            continue
        payload = _entry_payload(no, **changed.get(no, {}))
        items.append(
            {
                "cert_no": payload["cert_no"],
                "revision": payload["revision"],
                "status": "ok",
                "payload": payload,
                "ordinal": no,
            }
        )
    # load staging in chunks, mirroring how the engine persists details
    for idx in range(0, len(items), PUBLISH_CHUNK_SIZE):
        store.add_scan_items(scan_id, items[idx : idx + PUBLISH_CHUNK_SIZE])
    for no in sorted(removed):
        store.set_scan_item(scan_id, f"C-{no:06d}", status="deleted")
    return scan_id


def _seed_published(store: Store, n: int, *, source_seq: int = 100):
    store.bulk_upsert_certs(
        "big-lab", [_entry(no) for no in range(1, n + 1)], source_seq=source_seq
    )
    store.execute_checked(
        "UPDATE catalog_state SET ready=1, watermark_seq=?, source_head_seq=?, cert_count=?, "
        "watermark_cursor='cur-100', source_head_cursor='cur-100' WHERE org_id='big-lab'",
        (source_seq, source_seq, n),
    )


def _swap_traces(store: Store):
    """Return the write statements executed inside the next swap transaction."""
    store.db.sql_trace = []
    return store.db.sql_trace


def _swap_writes(trace) -> dict[str, int]:
    verbs = {"INSERT": 0, "UPDATE": 0, "DELETE": 0}
    rows = {"INSERT": 0, "UPDATE": 0, "DELETE": 0}
    for verb, _sql, rowcount in trace:
        if verb in verbs:
            verbs[verb] += 1
            rows[verb] += rowcount
    return {"statements": verbs, "rows": rows}


def test_unchanged_rebuild_writes_no_certificate_rows(store):
    n = LARGE
    _seed_published(store, n)
    scan_id = _stage_scan(store, n)
    trace = _swap_traces(store)
    result = store.publish_full_from_scan(
        "big-lab", scan_id, watermark_cursor="cur-100", watermark_seq=100,
        head_cursor="cur-100", head_seq=100,
    )
    assert result is not None
    writes = _swap_writes(trace)
    # only the catalog_state version row changes; certs are untouched
    cert_rows = writes["rows"]["INSERT"] + writes["rows"]["DELETE"]
    assert cert_rows == 0
    state = store.get_state("big-lab")
    assert state["cert_count"] == n
    assert state["version"] == 1
    assert result["changed_rows"] == 0
    assert result["deleted_rows"] == 0


def test_swap_writes_only_changed_and_removed_rows(store):
    n = LARGE
    _seed_published(store, n)
    changed = {
        42: {"revision": 2, "data": {"temperature": "22.0 C"}},
        1337: {"revision": 3, "status": "revoked", "revoked_at": "2026-02-02T00:00:00Z"},
        LARGE - 5: {"revision": 2},
    }
    removed = {7, 8, 999}
    scan_id = _stage_scan(store, n, changed=changed, removed=removed)
    trace = _swap_traces(store)
    result = store.publish_full_from_scan(
        "big-lab", scan_id, watermark_cursor="cur-101", watermark_seq=101,
        head_cursor="cur-101", head_seq=101,
    )
    writes = _swap_writes(trace)
    assert writes["rows"]["INSERT"] == len(changed)
    assert writes["rows"]["DELETE"] == len(removed)
    assert result["changed_rows"] == len(changed)
    assert result["deleted_rows"] == len(removed)
    state = store.get_state("big-lab")
    assert state["cert_count"] == n - len(removed)
    # a modified row carries the new content
    revised = store.get_cert("big-lab", "C-000042")
    assert revised["revision"] == 2
    assert revised["data"]["temperature"] == "22.0 C"
    assert store.get_cert("big-lab", "C-001337")["status"] == "revoked"
    # removed numbers leave the catalog
    for no in removed:
        with pytest.raises(Exception):
            store.get_cert("big-lab", f"C-{no:06d}")
    # untouched rows are byte-for-byte the same
    sample = store.get_cert("big-lab", "C-000001")
    assert sample["revision"] == 1 and sample["status"] == "active"


def test_write_footprint_does_not_grow_with_directory_size(tmp_path):
    """Same number of changes on a 10x larger directory => same write count."""

    def measure(n, name):
        store = _fresh_store(tmp_path, name)
        _seed_published(store, n)
        changed = {10 + i: {"revision": 2} for i in range(10)}
        removed = {20 + i for i in range(5)}
        scan_id = _stage_scan(store, n, changed=changed, removed=removed)
        trace = _swap_traces(store)
        result = store.publish_full_from_scan(
            "big-lab", scan_id, watermark_cursor="cur-101", watermark_seq=101,
            head_cursor="cur-101", head_seq=101,
        )
        footprint = result["changed_rows"] + result["deleted_rows"]
        return footprint, _swap_writes(trace)

    small_footprint, small_writes = measure(SMALL, "small.db")
    large_footprint, large_writes = measure(LARGE, "large.db")
    assert small_footprint == large_footprint == 15
    assert small_writes["rows"] == large_writes["rows"]


def test_publication_peak_memory_is_bounded_across_scales(tmp_path):
    """Streaming publication keeps peak memory within ~2x between 2k and 20k."""

    def peak_for(n, name):
        store = _fresh_store(tmp_path, name)
        _seed_published(store, n)
        # change a handful of rows so the swap has real work to do
        changed = {i + 1: {"revision": 2} for i in range(20)}
        scan_id = _stage_scan(store, n, changed=changed)
        tracemalloc.start()
        tracemalloc.reset_peak()
        result = store.publish_full_from_scan(
            "big-lab", scan_id, watermark_cursor="cur-101", watermark_seq=101,
            head_cursor="cur-101", head_seq=101,
        )
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        assert result is not None
        store.db.close()
        return peak

    small_peak = peak_for(SMALL, "peak-small.db")
    large_peak = peak_for(LARGE, "peak-large.db")
    # The legacy path materialized all N entries plus the full existing set;
    # streaming holds one scan chunk and one chunk-sized published-row page at
    # a time, so a 10x directory must not produce anywhere near a 10x peak.
    assert large_peak < small_peak * 2.0, (small_peak, large_peak)
    # and the absolute peak stays in the two-chunk order of magnitude
    assert large_peak < PUBLISH_CHUNK_SIZE * 4_096


def test_iter_scan_entries_is_chunked_and_excludes_deleted(store):
    n = PUBLISH_CHUNK_SIZE * 2 + 7
    _seed_published(store, min(n, 10))
    removed = {3, 55}
    scan_id = _stage_scan(store, n, removed=removed)
    chunks = list(store.iter_scan_entries(scan_id))
    # deleted rows are filtered inside SQL, so only visible rows are paged:
    # two full chunks and the remaining seven minus the two deleted numbers
    assert len(chunks) == 3
    assert [len(c) for c in chunks] == [PUBLISH_CHUNK_SIZE, PUBLISH_CHUNK_SIZE, 5]
    seen = [e["cert_no"] for chunk in chunks for e in chunk]
    assert len(seen) == n - len(removed)
    assert "C-000003" not in seen and "C-000055" not in seen
    # every chunk stays well under the whole-directory size
    assert all(len(c) <= PUBLISH_CHUNK_SIZE for c in chunks)


def test_backward_watermark_swap_writes_nothing(store):
    _seed_published(store, 500, source_seq=200)
    scan_id = _stage_scan(store, 500)
    trace = _swap_traces(store)
    result = store.publish_full_from_scan(
        "big-lab", scan_id, watermark_cursor="cur-100", watermark_seq=150,
        head_cursor="cur-100", head_seq=150,
    )
    assert result is None
    writes = _swap_writes(trace)
    assert sum(writes["rows"].values()) == 0
    assert store.get_state("big-lab")["watermark_seq"] == 200


def test_newer_incremental_rows_survive_the_swap(store):
    # incremental wrote cert 5 at seq 300; rebuild snapshot only reaches 200
    _seed_published(store, 20, source_seq=100)
    store.bulk_upsert_certs("big-lab", [_entry(5, revision=9)], source_seq=300)
    scan_id = _stage_scan(store, 20, changed={5: {"revision": 2}}, removed={6})
    result = store.publish_full_from_scan(
        "big-lab", scan_id, watermark_cursor="cur-200", watermark_seq=200,
        head_cursor="cur-200", head_seq=200,
    )
    assert result is not None
    # the newer incremental revision is neither overwritten nor deleted
    kept = store.get_cert("big-lab", "C-000005")
    assert kept["revision"] == 9
    # the removed cert (seq 100 <= watermark 200) still leaves the catalog
    with pytest.raises(Exception):
        store.get_cert("big-lab", "C-000006")
