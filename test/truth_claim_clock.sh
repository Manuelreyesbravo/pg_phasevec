#!/usr/bin/env bash
# 0.20.0 (fourteenth review): a judgment's clock, snapshot and stamp are one instant. Against the throwaway cluster of
# installcheck.sh (run that first), with the same PV_DATA/PV_PORT/PV_SOCK.
#   PG=~/pg19/bin test/truth_claim_clock.sh
# verify_one() waits for its claim's row when another verifier is judging it. In the thirteenth cut its worker began
# the transaction that judges (the proof's now()) and then waited for the row in it: the proof read a clock from before
# the wait, a snapshot from after it, and its verdict was stamped after it. Two verifiers of one claim were enough:
#  1. an invoice that fell due while the second one waited was not past due by its now(): 'verified', stamped after
#     the due date, and served fresh for a whole max_age;
#  2. a heartbeat written while it waited was 'in the future' by its now(): a true claim stored 'refuted'.
# Now the claim is taken without a wait in the transaction that judges it (a wait for it happens in a transaction of
# its own, then the take is tried again in a new one), and verified_at is the proof's own now().
set -uo pipefail
cd "$(dirname "$0")/.."
PG=${PG:-$HOME/pg19/bin}
DATA=${PV_DATA:-$PWD/.testcluster}
PORT=${PV_PORT:-5491}
SOCK=${PV_SOCK:-/tmp}
P=(-h "$SOCK" -p "$PORT" -X -q -At -d pv_clock)
export PGOPTIONS="-c client_min_messages=warning"
"$PG/pg_ctl" -D "$DATA" -o "-p $PORT -k $SOCK" -l "$DATA/server.log" -w start >/dev/null
trap '"$PG/pg_ctl" -D "$DATA" -w stop >/dev/null' EXIT
"$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists pv_clock 2>/dev/null
"$PG/createdb" -h "$SOCK" -p "$PORT" pv_clock
q() { "$PG/psql" "${P[@]}" "$@"; }
pause() { python3 -I -c "import time, sys; time.sleep(float(sys.argv[1]))" "$1"; }
q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
DROP ROLE IF EXISTS pv_cc_a; DROP ROLE IF EXISTS pv_cc_v;
CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register('r1', repeat('a', 64), 4);
CREATE ROLE pv_cc_a LOGIN; CREATE ROLE pv_cc_v LOGIN; GRANT pv_cc_a TO pv_cc_v;
GRANT USAGE ON SCHEMA phasevec TO pv_cc_a, pv_cc_v;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz) TO pv_cc_a;
GRANT EXECUTE ON FUNCTION phasevec.verify_one(text, text, int, float8), phasevec.brief(text, int) TO pv_cc_v;
CREATE TABLE ctl (s float8); INSERT INTO ctl VALUES (0);
CREATE TABLE inv (id text, due timestamptz, paid boolean);
CREATE TABLE beats (at timestamptz);
CREATE TABLE notes (id int PRIMARY KEY, body text);
INSERT INTO notes VALUES (1, 'no unpaid invoice is past due'), (2, 'no heartbeat is stamped in the future');
GRANT SELECT ON ctl, inv, beats, notes TO pv_cc_a, pv_cc_v;
-- ctl.s makes the first judgment slow (the one the second verifier waits behind); the second reads s = 0
CREATE FUNCTION public.no_overdue() RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN PERFORM pg_sleep((SELECT c.s FROM public.ctl c)); RETURN NOT EXISTS (SELECT 1 FROM public.inv WHERE due < now() AND NOT paid); END $$;
CREATE FUNCTION public.no_future_beat() RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN PERFORM pg_sleep((SELECT c.s FROM public.ctl c)); RETURN NOT EXISTS (SELECT 1 FROM public.beats WHERE at > now()); END $$;
SELECT phasevec.watch('w', 'notes'::regclass, 'id', 'r.body', 'r1');
SET ROLE pv_cc_a;
SELECT phasevec.assert('w', '1', 'public.no_overdue()');
SELECT phasevec.assert('w', '2', 'public.no_future_beat()');
RESET ROLE;
SQL
fallas=0
# Two verify_one() of one claim: the first sleeps 3 s in its proof, the second waits for its row; `during` runs while
# the second waits.
two() {
    local key=$1 during=$2
    q -c "UPDATE ctl SET s = 3"
    "$PG/psql" "${P[@]}" -U pv_cc_v -c "SELECT phasevec.verify_one('w', '$key', 10000)" >/dev/null 2>&1 &
    local a=$!
    for _ in $(seq 1 200); do
        [ "$(q -c "SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'pg_phasevec proof' AND wait_event = 'PgSleep'")" -gt 0 ] && break
        pause 0.02
    done
    q -c "UPDATE ctl SET s = 0"
    "$PG/psql" "${P[@]}" -U pv_cc_v -c "SELECT phasevec.verify_one('w', '$key', 10000)" >"$DATA/clock_b.out" 2>&1 &
    local b=$!
    for _ in $(seq 1 200); do
        [ "$(q -c "SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'pg_phasevec proof' AND wait_event_type = 'Lock'")" -gt 0 ] && break
        pause 0.02
    done
    [ -n "$during" ] && q -c "$during"
    wait $a; wait $b
    echo "  second verify_one(): $(tr '\n' ' ' < "$DATA/clock_b.out")"
    rm -f "$DATA/clock_b.out"
}
# 1. An invoice falls due 1.5 s from now, while the second verifier waits; the first one's proof takes 3 s.
q -c "INSERT INTO inv VALUES ('X', clock_timestamp() + interval '1.5 s', false)"
two 1 ""
row=$(q -c "SELECT phasevec._verdict(t) || ' ' || (verified_at > (SELECT due FROM inv)) FROM phasevec.truth t JOIN phasevec.watches w ON w.id = t.watch WHERE w.name = 'w' AND t.key = '1'")
served=$(q -c "SET ROLE pv_cc_v" -c "SELECT verdict FROM phasevec.brief('w') WHERE key = '1'")
now=$(q -c "SET ROLE pv_cc_a" -c "SELECT public.no_overdue()")
echo "claim 1: recorded '$row' (verdict, stamped after the due date), brief() serves '$served', the proof now: $now"
case "$row" in
    "verified true") echo "not ok - a claim false at its stamp is recorded 'verified' and served fresh"; fallas=1 ;;
    "refuted true") echo "ok - the second judgment read the clock of its own instant: refuted" ;;
    *) echo "not ok - unexpected: $row"; fallas=1 ;;
esac
# 2. A heartbeat is written while the second verifier waits.
two 2 "INSERT INTO beats VALUES (clock_timestamp())"
row=$(q -c "SELECT phasevec._verdict(t) FROM phasevec.truth t JOIN phasevec.watches w ON w.id = t.watch WHERE w.name = 'w' AND t.key = '2'")
now=$(q -c "SET ROLE pv_cc_a" -c "SELECT public.no_future_beat()")
echo "claim 2: recorded '$row', the proof now: $now"
[ "$row" = "verified" ] && [ "$now" = "t" ] && echo "ok - a row written before the proof's instant is not in its future" \
    || { echo "not ok - a true claim is recorded '$row'"; fallas=1; }
# 3. The stamp is the proof's own now() (it writes it to the server's log: what a proof writes is rolled back).
q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE FUNCTION public.saw_now() RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN RAISE LOG 'pv_clock_now=%', now(); RETURN true; END $$;
INSERT INTO notes VALUES (3, 'it sees its now');
SET ROLE pv_cc_a;
SELECT phasevec.assert('w', '3', 'public.saw_now()');
RESET ROLE;
SQL
q -c "SET ROLE pv_cc_v" -c "SELECT phasevec.verify_one('w', '3', 10000)" >/dev/null
saw=$(grep -o "pv_clock_now=[^\"]*" "$DATA/server.log" | tail -1 | cut -d= -f2)
stamp=$(q -c "SELECT t.verified_at = '$saw'::timestamptz FROM phasevec.truth t JOIN phasevec.watches w ON w.id = t.watch WHERE w.name = 'w' AND t.key = '3'")
echo "claim 3: the proof's now() $saw; verified_at is it: $stamp"
[ "$stamp" = "t" ] && echo "ok - verified_at is the proof's own now()" || { echo "not ok - verified_at is not the clock the proof read"; fallas=1; }
left=$(q -c "SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'pg_phasevec proof'")
[ "$left" = "0" ] || { echo "not ok - $left proof workers are left"; fallas=1; }
exit $fallas
