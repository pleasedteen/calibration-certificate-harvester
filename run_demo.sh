#!/bin/sh
# Embedded verification mode: built-in simulated bodies, SQLite storage.
set -eu
exec python3 -m certcollector --port "${PORT:-8000}" --demo "$@"
