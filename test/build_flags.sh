#!/usr/bin/env bash
# 0.20.0: the default build adds no CPU-specific flag to what PGXS compiles with (a build tuned with
# -march=native on one host can die with SIGILL on another); PHASEVEC_NATIVE=1 adds -march=native.
#   PG=~/pg19/bin test/build_flags.sh
set -euo pipefail
cd "$(dirname "$0")/.."
PG=${PG:-$HOME/pg19/bin}
line() { make -s -n -B PG_CONFIG="$PG/pg_config" "$@" src/phasevec_truth.o; }
count() { { grep -o -- '-march=native' || true; } | wc -l; }
server=$(line PG_CFLAGS= | count)        # what PGXS itself passes, without this Makefile's flags
dflt=$(line | count)
native=$(line PHASEVEC_NATIVE=1 | count)
[ "$dflt" -eq "$server" ] || { echo "not ok - the default build adds -march=native"; exit 1; }
[ "$native" -eq $((server + 1)) ] || { echo "not ok - PHASEVEC_NATIVE=1 does not add -march=native"; exit 1; }
echo "ok - the default build adds no -march=native; PHASEVEC_NATIVE=1 adds it"
