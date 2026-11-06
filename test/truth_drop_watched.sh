#!/usr/bin/env bash
# 0.20.0 (seventeenth review): DROP TABLE of a watched table while verify() runs does not deadlock: the proof's session
# locks the table before the claim's row, the order DROP TABLE takes them in. Against the throwaway cluster of
# installcheck.sh (run that first), with the same PV_DATA/PV_PORT/PV_SOCK.
#   PG=~/pg19/bin test/truth_drop_watched.sh
# In the sixteenth cut the proof's session took the claim's row, ran the proof, and then read the table: a DROP TABLE
# that came while the proof ran held the table and waited for the row, and the deadlock detector aborted the DROP.
set -uo pipefail
cd "$(dirname "$0")/.."
PG=${PG:-$HOME/pg19/bin}
DATA=${PV_DATA:-$PWD/.testcluster}
PORT=${PV_PORT:-5491}
SOCK=${PV_SOCK:-/tmp}
P=(-h "$SOCK" -p "$PORT" -X -q -At -d pv_dropw)
export PGOPTIONS="-c client_min_messages=warning"
q() { "$PG/psql" "${P[@]}" "$@"; }
fallas=0
"$PG/pg_ctl" -D "$DATA" -o "-p $PORT -k $SOCK" -l "$DATA/server.log" -w start >/dev/null
"$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists pv_dropw 2>/dev/null
"$PG/createdb" -h "$SOCK" -p "$PORT" pv_dropw
q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register('r1', repeat('a', 64), 4);
SQL
out=$(mktemp -d /dev/shm/pv_dropw.XXXXXX)
for run in 1 2 3; do
    q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE TABLE notes (id int PRIMARY KEY, body text);
INSERT INTO notes SELECT g, 'claim ' || g FROM generate_series(1, 4) g;
SELECT phasevec.watch('w', 'notes'::regclass, 'id', 'r.body', 'r1');
SELECT count(phasevec.assert('w', g::text, 'pg_sleep(1) IS NOT NULL')) FROM generate_series(1, 4) g;
SQL
    q -c "SELECT count(*) FROM phasevec.verify('w', 10, '0', p_timeout_ms => 5000)" > "$out/verify" 2>&1 &
    vpid=$!
    sleep 0.6
    q -c "DROP TABLE notes" > "$out/drop" 2>&1
    drc=$?
    wait $vpid
    echo "run $run: DROP TABLE -> rc $drc $(tr '\n' ' ' < "$out/drop"); verify -> $(tr '\n' ' ' < "$out/verify")"
    if [ $drc -ne 0 ] || grep -q -i deadlock "$out/drop" "$out/verify"; then
        echo "not ok - run $run: DROP TABLE of a watched table failed while verify() ran"; fallas=1
        q -c "DROP TABLE IF EXISTS notes" >/dev/null 2>&1
    fi
    left=$(q -c "SELECT count(*) FROM phasevec.watches")
    [ "$left" = "0" ] || { echo "not ok - run $run: the watch is left"; fallas=1; q -c "SELECT phasevec.unwatch('w')" >/dev/null 2>&1; }
done
[ $fallas -eq 0 ] && echo "ok - DROP TABLE of a watched table does not deadlock with verify()"
left=$(q -c "SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'pg_phasevec proof'")
[ "$left" = "0" ] || { echo "not ok - $left proof workers are left"; fallas=1; }
rm -rf "$out"
"$PG/pg_ctl" -D "$DATA" -w stop >/dev/null
exit $fallas
