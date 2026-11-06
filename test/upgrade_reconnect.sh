#!/usr/bin/env bash
# 0.20.0: a session that loaded the library of 0.19.0 and writes to a watched table after ALTER EXTENSION UPDATE to
# 0.20.0. The watch trigger is C from 0.20.0, and the older library loaded in that session has no such function: the
# third cut failed every such write with "could not find function". The trigger now lives in a library of its own
# (src/pg_phasevec_observe.c), which tells that session to reconnect and lets nothing through unrecorded; a new
# session writes. Against the throwaway cluster of installcheck.sh (run that first), with the same
# PV_DATA/PV_PORT/PV_SOCK. Builds 0.19.0 (commit 65ae00d) aside, in a temporary directory.
#   PG=~/pg19/bin test/upgrade_reconnect.sh
set -uo pipefail
cd "$(dirname "$0")/.."
PG=${PG:-$HOME/pg19/bin}
DATA=${PV_DATA:-$PWD/.testcluster}
PORT=${PV_PORT:-5491}
SOCK=${PV_SOCK:-/tmp}
V019=65ae00d
W=$(mktemp -d "${TMPDIR:-/tmp}/pv-up.XXXXXX")
P=(-h "$SOCK" -p "$PORT" -X -q -At -d pv_up)
export PGOPTIONS="-c client_min_messages=warning"

mkdir -p "$W/v019" "$W/lib"
GIT_INDEX_FILE="$W/index" git read-tree "$V019" && GIT_INDEX_FILE="$W/index" git --work-tree="$W/v019" checkout-index -a
make -s -C "$W/v019" PG_CONFIG="$PG/pg_config" >/dev/null 2>&1 || { echo "not ok - 0.19.0 does not build"; exit 1; }
ln -sfn "$W/v019/pg_phasevec.so" "$W/lib/pg_phasevec.so"
ln -sfn "$PWD/src/pg_phasevec_observe.so" "$W/lib/pg_phasevec_observe.so"
LIBPATH="$W/lib:\$libdir"

"$PG/pg_ctl" -D "$DATA" -o "-p $PORT -k $SOCK" -l "$DATA/server.log" -w start >/dev/null
trap 'exec 3>&- 4<&- 2>/dev/null; "$PG/pg_ctl" -D "$DATA" -w stop >/dev/null; rm -rf "$W"' EXIT
"$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists pv_up 2>/dev/null
"$PG/createdb" -h "$SOCK" -p "$PORT" pv_up

# Session A stays open across the update: commands in through a fifo, answers out through another.
mkfifo "$W/in" "$W/out"
"$PG/psql" "${P[@]}" -v ON_ERROR_STOP=0 <"$W/in" >"$W/out" 2>&1 &
exec 3>"$W/in" 4<"$W/out"
a() {  # one command in session A; its output (errors included) on stdout
    printf '%s\n\\echo __done\n' "$1" >&3
    while IFS= read -r line <&4; do [ "$line" = "__done" ] && break; echo "$line"; done
}
a "SET dynamic_library_path = '$LIBPATH';" >/dev/null
a "CREATE EXTENSION pg_phasevec VERSION '0.19.0';" >/dev/null
a "SELECT phasevec.reader_register('r1', repeat('a', 64), 4) > 0;" >/dev/null
a "CREATE TABLE notes (id int PRIMARY KEY, body text); INSERT INTO notes VALUES (1, 'one');" >/dev/null
a "SELECT phasevec.watch('notes', 'notes'::regclass, 'id', 'r.body', 'r1') > 0;" >/dev/null
a "LOAD 'pg_phasevec';" >/dev/null
echo "session A runs $(a "SELECT extversion FROM pg_extension WHERE extname = 'pg_phasevec';"), with its library loaded"

# The new library takes the old one's place on disk, and another session updates the extension.
ln -sfn "$PWD/pg_phasevec.so" "$W/lib/pg_phasevec.so"
"$PG/psql" "${P[@]}" -v ON_ERROR_STOP=1 >/dev/null <<SQL || { echo "not ok - the update failed"; exit 1; }
SET dynamic_library_path = '$LIBPATH';
ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0';
SQL
fallas=0
said=$(a "INSERT INTO notes VALUES (2, 'two');")
echo "session A writes after the update: $said"
case "$said" in
    *"econnect"*) echo "ok - the session that loaded the older library is told to reconnect" ;;
    *) echo "not ok - the session that loaded the older library is not told why its write fails"; fallas=1 ;;
esac
n=$(a "SELECT count(*) FROM notes WHERE id = 2;")
[ "$n" = "0" ] && echo "ok - its write is refused, not let through unrecorded" || { echo "not ok - a write went through unrecorded"; fallas=1; }
exec 3>&-
new=$("$PG/psql" "${P[@]}" -v ON_ERROR_STOP=1 2>&1 <<SQL
SET dynamic_library_path = '$LIBPATH';
INSERT INTO notes VALUES (2, 'two');
SELECT string_agg(key, ',' ORDER BY key) FROM phasevec.sources;
SQL
)
echo "a new session writes: noted keys $new"
[ "$new" = "1,2" ] && echo "ok - a new session writes, and the row is noted" || { echo "not ok - a new session cannot write"; fallas=1; }
"$PG/psql" "${P[@]}" -c "DROP TABLE notes; DROP EXTENSION pg_phasevec;" >/dev/null
"$PG/dropdb" -h "$SOCK" -p "$PORT" pv_up
exit $fallas
