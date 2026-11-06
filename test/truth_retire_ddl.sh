#!/usr/bin/env bash
# 0.20.0 (eighteenth review): an owner's transaction that takes a claim's row (refute(), assert()) and then alters the
# watched table does not deadlock with a verify_one() waiting for that row. Against the throwaway cluster of
# installcheck.sh (run that first), with the same PV_DATA/PV_PORT/PV_SOCK.
#   PG=~/pg19/bin test/truth_retire_ddl.sh
# In the seventeenth cut the proof's session waited for the claim's row holding the watched table (taken first, the
# order DROP TABLE takes them in), and the owner's ALTER TABLE waited for that table: the deadlock detector aborted
# one of them after deadlock_timeout.
set -uo pipefail
cd "$(dirname "$0")/.."
PG=${PG:-$HOME/pg19/bin}
DATA=${PV_DATA:-$PWD/.testcluster}
PORT=${PV_PORT:-5491}
SOCK=${PV_SOCK:-/tmp}
P=(-h "$SOCK" -p "$PORT" -X -q -At -d pv_retddl)
export PGOPTIONS="-c client_min_messages=warning"
q() { "$PG/psql" "${P[@]}" "$@"; }
fallas=0
"$PG/pg_ctl" -D "$DATA" -o "-p $PORT -k $SOCK" -l "$DATA/server.log" -w start >/dev/null
"$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists pv_retddl 2>/dev/null
"$PG/createdb" -h "$SOCK" -p "$PORT" pv_retddl
q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register('r1', repeat('a', 64), 4);
SQL
out=$(mktemp -d /dev/shm/pv_retddl.XXXXXX)
for what in "phasevec.refute('w', '1', 'deleted')" "phasevec.assert('w', '1', 'pg_sleep(0.1) IS NOT NULL AND true')"; do
    q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
DROP TABLE IF EXISTS mem;
CREATE TABLE mem (id int PRIMARY KEY, body text);
INSERT INTO mem SELECT g, 'memory ' || g FROM generate_series(1, 3) g;
SELECT phasevec.watch('w', 'mem'::regclass, 'id', 'r.body', 'r1');
SELECT phasevec.assert('w', '1', 'pg_sleep(0.1) IS NOT NULL');
SQL
    logfrom=$(stat -c %s "$DATA/server.log")
    q > "$out/owner" 2>&1 <<SQL &
BEGIN;
SELECT $what;
SELECT pg_sleep(1.6);
ALTER TABLE mem ADD COLUMN extra int;
COMMIT;
SELECT 'committed';
SQL
    opid=$!
    sleep 0.3
    q -c "SELECT phasevec.verify_one('w', '1', 5000)" > "$out/one" 2>&1
    wait $opid
    dead=$(tail -c +"$((logfrom + 1))" "$DATA/server.log" | grep -c "deadlock detected")
    echo "$what then ALTER TABLE: owner -> $(tr '\n' ' ' < "$out/owner"); verify_one -> $(tr '\n' ' ' < "$out/one"); deadlocks in the log: $dead"
    state=$(q -c "SELECT phasevec._claim_state(t) || ' ' || phasevec._verdict(t) FROM phasevec.truth t WHERE key = '1'")
    echo "  claim 1 is now: $state"
    if [ "$dead" != 0 ] || ! grep -q committed "$out/owner" || grep -qi deadlock "$out/owner" "$out/one"; then
        echo "not ok - $what, then DDL in one transaction, deadlocked with verify_one()"; fallas=1
    fi
    case "$what" in
        *refute*) [ "$state" = "retired refuted" ] && [ ! -s "$out/one" -o "$(tr -d '\n' < "$out/one")" = "" ] \
                      || { echo "not ok - the claim retired while verify_one() waited for it: $state, $(cat "$out/one")"; fallas=1; } ;;
    esac
done
[ $fallas -eq 0 ] && echo "ok - an owner's refute() or assert() and then DDL do not deadlock with a waiting verify_one()"
left=$(q -c "SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'pg_phasevec proof'")
[ "$left" = "0" ] || { echo "not ok - $left proof workers are left"; fallas=1; }
rm -rf "$out"
"$PG/dropdb" -h "$SOCK" -p "$PORT" pv_retddl 2>/dev/null
"$PG/pg_ctl" -D "$DATA" -w stop >/dev/null
exit $fallas
