#!/usr/bin/env bash
# installcheck against a throwaway cluster (default .testcluster, :5491, socket in /tmp), with the
# extension SQL linked from this repo (extension_control_path), so nothing is installed into the
# PostgreSQL tree. The cluster is created if it does not exist.
#   PG=~/pg19/bin test/installcheck.sh
#   PV_DATA=/dev/shm/pv PV_PORT=62010 PV_SOCK=/dev/shm/pv test/installcheck.sh   (elsewhere)
#   REGRESS="truth truth_binding" test/installcheck.sh                           (some tests only)
set -uo pipefail
cd "$(dirname "$0")/.."
PG=${PG:-$HOME/pg19/bin}
DATA=${PV_DATA:-$PWD/.testcluster}
PORT=${PV_PORT:-5491}
SOCK=${PV_SOCK:-/tmp}
[ -f "$DATA/PG_VERSION" ] || "$PG/initdb" -D "$DATA" -A trust -U "$(id -un)" >/dev/null
mkdir -p "$DATA/ext/extension"
for f in pg_phasevec.control sql/*.sql; do ln -sfn "$PWD/$f" "$DATA/ext/extension/$(basename "$f")"; done
make -s PG_CONFIG="$PG/pg_config" >/dev/null
mkdir -p "$DATA/ext/lib" && ln -sfn "$PWD/pg_phasevec.so" "$DATA/ext/lib/pg_phasevec.so"
grep -q "^dynamic_library_path" "$DATA/postgresql.conf" || echo "dynamic_library_path = '$DATA/ext/lib:\$libdir'" >> "$DATA/postgresql.conf"
# Without this a fresh .testcluster reads the control file and scripts INSTALLED in the PostgreSQL
# tree, not the ones of this checkout, and every test passes against the previous version (seen on
# 2026-11-05: 23 "ok" that never loaded the new upgrade script).
grep -q "^extension_control_path" "$DATA/postgresql.conf" || echo "extension_control_path = '$DATA/ext:\$system'" >> "$DATA/postgresql.conf"
"$PG/pg_ctl" -D "$DATA" -o "-p $PORT -k $SOCK" -l "$DATA/server.log" -w start >/dev/null
PGHOST=$SOCK PGPORT=$PORT make installcheck PG_CONFIG="$PG/pg_config" ${REGRESS:+REGRESS="$REGRESS"} 2>&1 | grep -E '^(ok|not ok|#)'
rc=${PIPESTATUS[0]}
"$PG/pg_ctl" -D "$DATA" -w stop >/dev/null
exit "$rc"
