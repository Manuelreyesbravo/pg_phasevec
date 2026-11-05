#!/usr/bin/env bash
# installcheck against the throwaway cluster in .testcluster (:5491), with the extension SQL linked
# from this repo (extension_control_path), so nothing is installed into the PostgreSQL tree.
#   PG=~/pg19/bin test/installcheck.sh
set -uo pipefail
cd "$(dirname "$0")/.."
PG=${PG:-$HOME/pg19/bin}
mkdir -p .testcluster/ext/extension
for f in pg_phasevec.control sql/*.sql; do ln -sfn "$PWD/$f" ".testcluster/ext/extension/$(basename "$f")"; done
make -s PG_CONFIG="$PG/pg_config" >/dev/null
mkdir -p .testcluster/ext/lib && ln -sfn "$PWD/pg_phasevec.so" .testcluster/ext/lib/pg_phasevec.so
grep -q "^dynamic_library_path" .testcluster/postgresql.conf || echo "dynamic_library_path = '$PWD/.testcluster/ext/lib:\$libdir'" >> .testcluster/postgresql.conf
# Without this a fresh .testcluster reads the control file and scripts INSTALLED in the PostgreSQL
# tree, not the ones of this checkout, and every test passes against the previous version (seen on
# 2026-11-05: 23 "ok" that never loaded the new upgrade script).
grep -q "^extension_control_path" .testcluster/postgresql.conf || echo "extension_control_path = '$PWD/.testcluster/ext:\$system'" >> .testcluster/postgresql.conf
"$PG/pg_ctl" -D .testcluster -o "-p 5491 -k /tmp" -l .testcluster/server.log -w start >/dev/null
PGHOST=/tmp PGPORT=5491 make installcheck PG_CONFIG="$PG/pg_config" 2>&1 | grep -E '^(ok|not ok|#)'
rc=${PIPESTATUS[0]}
"$PG/pg_ctl" -D .testcluster -w stop >/dev/null
exit "$rc"
