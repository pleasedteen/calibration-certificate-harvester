"""Command line entry point.

Examples
--------
Embedded verification mode (no external database, built-in simulated bodies)::

    python3 -m certcollector --port 8000 --demo

PostgreSQL deployment::

    export CERTCOLLECTOR_DATABASE_URL=postgresql://user:pass@localhost:5432/certs
    python3 -m certcollector --port 8000
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

from . import __version__
from .runtime import Runtime, default_db_url


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="certcollector", description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument(
        "--database-url",
        default=None,
        help="SQLite file path or postgresql:// URL (default: env or embedded file)",
    )
    parser.add_argument("--demo", action="store_true", help="register the two simulated bodies")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--count", type=int, default=20, help="certificates per simulated body")
    parser.add_argument("--poll-interval-ms", type=int, default=1000)
    parser.add_argument("--no-simulator", action="store_true", help="do not start simulated bodies")
    parser.add_argument("--log-level", default="INFO")
    parser.add_argument("--version", action="version", version=__version__)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    db_url = args.database_url or default_db_url()
    runtime = Runtime(
        db_url,
        simulate=not args.no_simulator,
        seed=args.seed,
        count=args.count,
        poll_interval_ms=args.poll_interval_ms,
    )
    if args.demo and runtime.simulator:
        runtime.register_simulated_org("lab-html", "html")
        runtime.register_simulated_org("lab-json", "json")
    runtime.start(host=args.host, port=args.port)
    print(
        json.dumps(
            {
                "service": "certcollector",
                "listening": runtime.base_url,
                "database": "postgresql" if runtime.db.is_postgres else db_url,
                "simulated_orgs": ["lab-html", "lab-json"] if args.demo else [],
                "demo": args.demo,
            }
        ),
        flush=True,
    )
    try:
        while True:
            import time

            time.sleep(3600)
    except KeyboardInterrupt:
        runtime.stop()
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
