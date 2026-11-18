# Calibration certificate collector

A small service that mirrors the certificate catalogs of external calibration
bodies into a local, queryable catalog. It supports organization configuration,
full and incremental collection, online rebuilds, pause/resume, certificate
queries, paged exports and progress reporting.

The repository ships two simulated upstream bodies, so nothing here ever talks
to a real external site.

```
certcollector/
    api.py         HTTP API (standard library ThreadingHTTPServer)
    db.py          SQLite / PostgreSQL access layer + schema
    store.py       persistence operations, atomic publication, exports
    engine.py      collection lanes (full rebuild + incremental) per org
    source.py      upstream adapters (HTML table site, cursor JSON site)
    sim_world.py   in-memory state of the two simulated bodies
    sim_sites.py   HTTP faces of the simulated bodies (also: loopback)
    sim_server.py  standalone simulator process
    runtime.py     wiring: db + simulator + engine + HTTP server
```

## Quick start (embedded, no external database)

Requires Python 3.10+ and nothing else (the test suite needs `pytest`).

```bash
python3 -m certcollector --port 8000 --demo
```

`--demo` registers `lab-html` (HTML paginated site) and `lab-json` (cursor JSON
site) against built-in simulators and starts their initial collection. A SQLite
file under `$TMPDIR/certcollector/` is used unless `--database-url` is given.
Then:

```bash
curl localhost:8000/api/orgs/lab-html/status
curl 'localhost:8000/api/orgs/lab-html/certs?page=1&page_size=10'
curl -X POST localhost:8000/api/orgs/lab-html/rebuild
```

Add your own organization (the `base_url` must be reachable by the service):

```bash
curl -X POST localhost:8000/api/orgs -d '{
  "org_id": "lab-x",
  "source": {"kind": "json", "base_url": "http://127.0.0.1:8801/json"},
  "limits": {"max_concurrency": 2, "min_interval_ms": 100},
  "options": {"poll_interval_ms": 1000}
}'
```

To run the simulated sources as a separate process (used by the crash test and
handy for a multi-process demo):

```bash
python3 -m certcollector.sim_server --port 8801
# site A: http://127.0.0.1:8801/           (HTML pagination)
# site B: http://127.0.0.1:8801/json      (cursor based JSON)
```

## PostgreSQL deployment

Install the optional driver and point the service at the database; the schema is
created on start. `CERTCOLLECTOR_DATABASE_URL` accepts `postgresql://`,
`sqlite:///path` or a bare file path.

```bash
python3 -m pip install "psycopg[binary]"
export CERTCOLLECTOR_DATABASE_URL=postgresql://user:pass@localhost:5432/certs
python3 -m certcollector --port 8000 --host 0.0.0.0
```

The embedded SQLite path requires no extra services; both backends share the
same SQL through a thin translation layer (placeholder translation, portable
`ON CONFLICT` upserts, explicit transactions). A `Dockerfile` is included for
the container deployment.

Any number of organizations can share one database: all state is keyed by
`org_id`, and each organization's lanes and rate budget are independent.

## Configuration

Organization payload (`POST /api/orgs`):

| field | meaning |
| --- | --- |
| `org_id` | `[A-Za-z0-9][A-Za-z0-9_.-]{0,63}`, certificate numbers are only unique inside an organization |
| `source.kind` | `html` (table pagination) or `json` (cursor list) |
| `source.base_url` | site root |
| `limits.max_concurrency` | max in-flight requests to this body |
| `limits.min_interval_ms` | minimum spacing between requests |
| `options.poll_interval_ms` | how often to poll the change feed once ready |
| `options.batch_size` | change-feed window size |
| `options.request_attempts` | attempts per upstream request (`Retry-After` respected) |
| `options.export_ttl_seconds` | default export credential lifetime |
| `options.keep_runs`, `keep_scans`, `keep_exports`, `export_tombstone_seconds` | retention bounds |

Limits are per organization and are shared by the full and incremental lanes of
that organization; different organizations never share a queue, a worker or a
rate budget.

## API

| method | path | purpose |
| --- | --- | --- |
| `POST` | `/api/orgs` | create/update organization |
| `GET` | `/api/orgs` | list organizations |
| `GET` | `/api/orgs/{org}` | organization + catalog state |
| `POST` | `/api/orgs/{org}/collect` | `{"mode":"auto\|full\|incremental"}` |
| `POST` | `/api/orgs/{org}/rebuild` | online rebuild (full) |
| `POST` | `/api/orgs/{org}/pause` / `resume` | pause / resume |
| `GET` | `/api/orgs/{org}/status` | phase, progress, wait and failure reasons |
| `GET` | `/api/orgs/{org}/runs[/{run}]` | run history and detail |
| `GET` | `/api/orgs/{org}/certs?page=&page_size=&status=` | paged certificates |
| `GET` | `/api/orgs/{org}/certs/{cert}` | certificate detail (incl. correction) |
| `GET` | `/api/orgs/{org}/corrections` | corrections not yet fully applied |
| `POST` | `/api/orgs/{org}/exports` | `{"page_size":n,"ttl_seconds":s}` |
| `GET` | `/api/exports/{token}` | export metadata |
| `GET` | `/api/exports/{token}/pages/{page}` | one frozen-catalog page |
| `GET` | `/api/health`, `/api/admin/storage`, `/api/admin/config` | diagnostics |

## Behavioural guarantees

* **Not ready before the first catalog.** Until the initial full scan finishes
  and is published, `status.ready` is `false` and certificate queries return an
  empty catalog.
* **Rebuilds are online.** The previously published catalog (and the
  incremental channel) keep serving during a rebuild; the new catalog replaces
  it in one transaction only after listing, detail fetching and catch-up have
  all succeeded. A failed scan never touches the published catalog, and
  certificates missing from the new snapshot leave the catalog.
* **Corrections are all-or-nothing.** A formal correction that revokes an old
  certificate and publishes several replacements is only applied once every
  member is resolvable; the group (from the detail pages) is published in one
  transaction, so a query can never observe the old revoked with only part of
  the replacements present.
* **Monotonic catch-up.** Published watermarks only move forward, so neither a
  rebuild nor a late incremental window can regress the catalog or resurrect a
  revoked certificate. Once caught up, the stored catalog equals the source.
* **Expired positions self-heal.** An expired snapshot or change cursor
  restarts the affected scan automatically (bounded retries) and the catalog
  converges again.
* **Consistent exports.** An export materializes one published catalog version;
  every page of that token stays on that version while collection and rebuilds
  continue. Credentials survive a service restart, resume by page, and are
  rejected with `410` after expiry.
* **Bounded history.** Expired export rows are pruned immediately and finished
  runs are pruned beyond the configured keep count; a small export tombstone is
  retained only long enough to keep the expiry answer explicit.
* **Crash safe.** Runs are durable; after a forced kill and restart the service
  resumes interrupted work, tolerates repeated requests, and converges to the
  same catalog as an uninterrupted run.
* **Respectful to sources.** Per-organization concurrency, request spacing and
  `Retry-After` are obeyed (the collector also adapts its pacing when it is
  throttled). Waiting for one body never blocks another, and `status` reports
  the current progress plus the reason for waiting or failing.

## Tests

```bash
python3 -m pip install pytest
python3 -m pytest -q
```

The suite runs entirely against the built-in simulators (embedded SQLite) and
covers corrections, online rebuilds, history expiry, export resumption, access
limits and forced-kill recovery. It finishes well under 80 seconds.

## Embedded self-check (no pytest needed)

```bash
python3 -m certcollector.selfcheck
```

It exercises the same invariants in-process and prints one readable line per
check (`[PASS]` / `[FAIL]`), ending with a small JSON summary. No third-party
package and no external database or network access is required.
