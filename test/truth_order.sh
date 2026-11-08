#!/usr/bin/env bash
# 0.20.0 (tenth review): a verdict is never replaced by one about an older state.
# Against the throwaway cluster of installcheck.sh (run that first), with the same PV_DATA/PV_PORT/PV_SOCK.
#   PG=~/pg19/bin test/truth_order.sh
# The reviewer's timeline. verify() B's worker took the claim and sleeps 3 s in the proof before it reads inv;
# verify_one() A's worker judged right away (inv not overdue: verified) and then waited for the row B's worker held;
# inv became overdue and committed; B recorded 'refuted'; A then wrote its older 'verified' over it, brief() served it
# and verify() left the claim alone for p_every. Now every worker takes the claim's row before it judges (A waits for B,
# then judges what is committed then: refuted), and _truth_set does not replace a verdict read later than the one it
# records (test/sql/truth_order.sql).
set -uo pipefail
cd "$(dirname "$0")/.."
PG=${PG:-$HOME/pg19/bin}
DATA=${PV_DATA:-$PWD/.testcluster}
PORT=${PV_PORT:-5491}
SOCK=${PV_SOCK:-/tmp}
P=(-h "$SOCK" -p "$PORT" -X -q -At -d pv_order)
export PGOPTIONS="-c client_min_messages=warning"
"$PG/pg_ctl" -D "$DATA" -o "-p $PORT -k $SOCK" -l "$DATA/server.log" -w start >/dev/null
W=$(mktemp -d "${TMPDIR:-/tmp}/pv-order.XXXXXX")
trap '"$PG/pg_ctl" -D "$DATA" -w stop >/dev/null; rm -rf "$W"' EXIT
"$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists pv_order 2>/dev/null
"$PG/createdb" -h "$SOCK" -p "$PORT" pv_order
q() { "$PG/psql" "${P[@]}" "$@"; }
q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
DROP ROLE IF EXISTS pv_o_a; DROP ROLE IF EXISTS pv_o_v;
CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register('r1', repeat('a', 64), 4);
CREATE ROLE pv_o_a LOGIN;
CREATE ROLE pv_o_v LOGIN;
GRANT pv_o_a TO pv_o_v;
GRANT USAGE ON SCHEMA phasevec TO pv_o_a, pv_o_v;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz) TO pv_o_a;
GRANT EXECUTE ON FUNCTION phasevec.verify(text, int, interval, interval, int, float8),
                          phasevec.verify_one(text, text, int, float8), phasevec.brief(text, int) TO pv_o_v;
CREATE TABLE ctl (s float8);
INSERT INTO ctl VALUES (3);
CREATE TABLE inv (id int, overdue boolean);
INSERT INTO inv VALUES (1, false);
CREATE TABLE notes (id int PRIMARY KEY, body text);
INSERT INTO notes VALUES (1, 'no invoice is overdue');
GRANT SELECT ON ctl, inv, notes TO pv_o_a, pv_o_v;
GRANT UPDATE ON ctl, inv, notes TO pv_o_a, pv_o_v;
-- each statement in a new snapshot: ctl only sets how long this run sleeps before it reads inv
CREATE FUNCTION public.no_overdue() RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE s float8;
BEGIN
    SELECT c.s INTO s FROM public.ctl c;
    PERFORM pg_sleep(s);
    RETURN NOT EXISTS (SELECT 1 FROM public.inv WHERE overdue);
END $$;
SELECT phasevec.watch('inv', 'notes'::regclass, 'id', 'r.body', 'r1');
SET ROLE pv_o_a;
SELECT phasevec.assert('inv', '1', 'public.no_overdue()');
RESET ROLE;
SQL
until_q() {  # until the query returns a count above 0
    for _ in $(seq 1 200); do
        [ "$(q -c "$1")" -gt 0 ] && return 0
        sleep 0.05
    done
    echo "not ok - timed out waiting for: $1"; return 1
}
fallas=0
q -c "SET ROLE pv_o_v" -c "SELECT key || ' ' || verdict FROM phasevec.verify('inv', p_timeout_ms => 10000, p_budget => '20 s')" >"$W/b" 2>&1 &
b=$!
until_q "SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'pg_phasevec proof' AND wait_event = 'PgSleep'" || fallas=1
q -c "UPDATE ctl SET s = 0"
q -c "SET ROLE pv_o_v" -c "SELECT phasevec.verify_one('inv', '1', 10000)" >"$W/a" 2>&1 &
a=$!
until_q "SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'pg_phasevec proof' AND wait_event_type = 'Lock'" || fallas=1
q -c "UPDATE inv SET overdue = true"
wait $b; wait $a
echo "verify() said: $(tr '\n' ' ' <"$W/b"); verify_one() said: $(tr '\n' ' ' <"$W/a")"
stored=$(q -c "SELECT phasevec._verdict(t) FROM phasevec.truth t WHERE key = '1'")
served=$(q -c "SET ROLE pv_o_v" -c "SELECT count(*) FROM phasevec.brief('inv') WHERE verdict = 'verified'")
echo "the claim reads: $stored; brief() serves it as verified: $served"
[ "$stored|$served" = "refuted|0" ] && echo "ok - a verdict about an older state does not replace a newer refutation" \
    || { echo "not ok - an older 'verified' was written over a newer 'refuted'"; fallas=1; }
[ "$(cat "$W/a")" = "refuted" ] && echo "ok - verify_one() waited for the other judgment, then judged what was committed" \
    || { echo "not ok - verify_one() judged before it took the claim"; fallas=1; }
left=$(q -c "SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'pg_phasevec proof'")
[ "$left" = "0" ] || { echo "not ok - $left proof workers are left"; fallas=1; }
exit $fallas
