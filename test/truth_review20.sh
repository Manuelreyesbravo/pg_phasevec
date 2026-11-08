#!/usr/bin/env bash
# 0.20.0 (twentieth review): the races of that review, and a caller's DateStyle from its role's settings. Against the
# throwaway cluster of installcheck.sh (run that first), with the same PV_DATA/PV_PORT/PV_SOCK.
#   PG=~/pg19/bin test/truth_review20.sh
# 1. (RT20M-1) A claim asserted again, in a transaction that began before its proof did, while the proof's session
#    ended itself: the new claim is not halted. In the nineteenth review's cut _truth_halted compared the assert's
#    changed_at (its transaction's start) with when the proof began: the new claim was halted, and verify() never ran
#    it again.
# 2. (RT20M-4) adopt() while a transaction that took the watched table drops it: no deadlock. In the nineteenth
#    review's cut adopt() held the orphans' rows before it took the table, and one side was aborted.
# 3. (RT20M-5) verify_one() that waited for a supersede() of its claim: NULL (no claim to run), and the proof did not
#    run. In the nineteenth review's cut it ran the replaced claim's proof and answered 'replaced'.
# 4. (RT20M-2) A caller whose DateStyle order (DMY) comes from its role's own settings calls the author's wrapper
#    with SET DateStyle = ISO: nothing of DateStyle is recorded, and the proof reads the date as its author does. In
#    the nineteenth review's cut 'ISO, DMY' was recorded as the author's, and the claim was refuted.
set -uo pipefail
cd "$(dirname "$0")/.."
PG=${PG:-$HOME/pg19/bin}
DATA=${PV_DATA:-$PWD/.testcluster}
PORT=${PV_PORT:-5491}
SOCK=${PV_SOCK:-/tmp}
P=(-h "$SOCK" -p "$PORT" -X -q -At -d pv_r20)
unset PGDATESTYLE PGTZ PGOPTIONS
export PGOPTIONS="-c client_min_messages=warning"
q() { "$PG/psql" "${P[@]}" "$@"; }
as() { local r=$1; shift; "$PG/psql" "${P[@]}" -U "$r" "$@"; }
pause() { python3 -I -c "import time, sys; time.sleep(float(sys.argv[1]))" "$1"; }
fallas=0
ok() { echo "ok - $1"; }
nok() { echo "not ok - $1"; fallas=1; }
W=$(mktemp -d /dev/shm/pv_r20.XXXXXX)
"$PG/pg_ctl" -D "$DATA" -o "-p $PORT -k $SOCK" -l "$DATA/server.log" -w start >/dev/null
trap '"$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists pv_r20 2>/dev/null; "$PG/pg_ctl" -D "$DATA" -w stop >/dev/null; rm -rf "$W"' EXIT
"$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists pv_r20 2>/dev/null
"$PG/createdb" -h "$SOCK" -p "$PORT" pv_r20
q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
DO $d$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pv_r20_au') THEN
        EXECUTE 'DROP OWNED BY pv_r20_au, pv_r20_other'; DROP ROLE pv_r20_au, pv_r20_other;
    END IF;
END $d$;
CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register('r1', repeat('a', 64), 4);
CREATE ROLE pv_r20_au LOGIN;
CREATE ROLE pv_r20_other LOGIN;
CREATE TABLE notes (id int PRIMARY KEY, body text);
INSERT INTO notes VALUES (1, 'one'), (2, 'two'), (3, 'three'), (4, '03/04/2026');
SELECT phasevec.watch('notes', 'notes'::regclass, 'id', 'r.body', 'r1');
GRANT USAGE ON SCHEMA phasevec TO pv_r20_au, pv_r20_other;
GRANT SELECT ON notes TO pv_r20_au;
GRANT UPDATE ON notes TO pv_r20_au;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz),
    phasevec.supersede(text, text, text, text), phasevec.verify(text, int, interval, interval, int, float8),
    phasevec.verify_one(text, text, int, float8), phasevec.adopt(text, regrole, text[], text[]) TO pv_r20_au;
CREATE FUNCTION public.end_my_session(pid int, timeout bigint DEFAULT 0) RETURNS boolean
    LANGUAGE internal STRICT VOLATILE AS 'pg_terminate_backend';
CREATE FUNCTION public.gate_or_end(k int) RETURNS boolean LANGUAGE plpgsql AS $f$
BEGIN
    IF pg_try_advisory_xact_lock_shared(k) THEN RETURN true; END IF;
    PERFORM pg_advisory_xact_lock_shared(k);
    PERFORM public.end_my_session(pg_backend_pid());
    RETURN true;
END $f$;
SQL

# 1. RT20M-1
as pv_r20_au -c "SELECT phasevec.assert('notes', '1', 'public.gate_or_end(91)')" >/dev/null
q -c "SELECT pg_advisory_lock(91), pg_sleep(3.5)" >/dev/null &
g=$!
pause 0.3
as pv_r20_au >"$W/h.out" 2>&1 <<'SQL' &
BEGIN;
SELECT pg_sleep(2);
SELECT phasevec.assert('notes', '1', 'public.gate_or_end(91)');
SELECT pg_sleep(1);
COMMIT;
SQL
h=$!
pause 0.5
as pv_r20_au -c "SELECT phasevec.verify_one('notes', '1', 10000)" >"$W/v.out" 2>&1
wait $g $h
halted=$(q -c "SELECT halted FROM phasevec.truth WHERE key = '1'")
after=$(as pv_r20_au -c "SELECT verdict FROM phasevec.verify('notes', 10, interval '0') WHERE key = '1'" 2>&1)
if [ "$halted" = "f" ] && [ "$after" = "verified" ]; then
    ok "a claim asserted again while its proof's session ended itself is not halted, and verify() runs it"
else
    nok "RT20M-1: halted '$halted', verify() then '$after' (verify_one: $(tr '\n' ' ' <"$W/v.out"))"
fi

# 2. RT20M-4
q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE TABLE gone (id int PRIMARY KEY, body text);
INSERT INTO gone VALUES (1, 'a'), (2, 'b');
SELECT phasevec.watch('gone', 'gone'::regclass, 'id', 'r.body', 'r1');
GRANT SELECT ON gone TO pv_r20_other;
GRANT UPDATE ON gone TO pv_r20_other;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz) TO pv_r20_other;
GRANT SELECT ON gone TO pv_r20_au;
GRANT UPDATE ON gone TO pv_r20_au;
SQL
as pv_r20_other -c "SELECT phasevec.assert('gone', '1', 'SELECT true'), phasevec.assert('gone', '2', 'SELECT true')" >/dev/null
q -c "UPDATE phasevec.truth SET asserted_by = 'nobody_now' WHERE watch = (SELECT id FROM phasevec.watches WHERE name = 'gone')" >/dev/null
q >"$W/x.out" 2>&1 <<'SQL' &
BEGIN;
LOCK TABLE public.gone IN ACCESS EXCLUSIVE MODE;
SELECT pg_sleep(1.5);
DROP TABLE public.gone;
COMMIT;
SQL
x=$!
pause 0.5
as pv_r20_au -c "SELECT key, adopted FROM phasevec.adopt('gone', 'pv_r20_au')" >"$W/a.out" 2>&1
wait $x
dropped=$(q -c "SELECT to_regclass('public.gone') IS NULL")
if ! grep -q "deadlock" "$W/x.out" "$W/a.out" && [ "$dropped" = "t" ]; then
    ok "adopt() and a DROP TABLE that holds the table: no deadlock ($(tr '\n' ' ' <"$W/a.out" | cut -c1-90))"
else
    nok "RT20M-4: drop '$(tr '\n' ' ' <"$W/x.out")', adopt '$(tr '\n' ' ' <"$W/a.out")', table dropped: $dropped"
fi

# 3. RT20M-5
as pv_r20_au -c "SELECT phasevec.assert('notes', '2', 'SELECT pg_sleep(0) IS NOT NULL')" >/dev/null
as pv_r20_au >/dev/null 2>&1 <<'SQL' &
BEGIN; SELECT phasevec.supersede('notes', '2', '3', 'newer'); SELECT pg_sleep(2); COMMIT;
SQL
s=$!
pause 0.5
vo=$(as pv_r20_au -c "SELECT coalesce(phasevec.verify_one('notes', '2'), '<NULL>')" 2>&1)
wait $s
row=$(q -c "SELECT verdict || '|' || coalesce(a.attempted_at::text, 'never tried') FROM phasevec.truth t
            LEFT JOIN phasevec.attempts a USING (watch, key) WHERE t.key = '2'")
if [ "$vo" = "<NULL>" ] && [ "${row%%|*}" = "replaced" ]; then
    ok "verify_one() that waited for a supersede() answers NULL"
else
    nok "RT20M-5: verify_one answered '$vo', row '$row'"
fi

# 4. RT20M-2 through the caller's role settings
q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE SCHEMA app20 AUTHORIZATION pv_r20_au;
GRANT USAGE ON SCHEMA app20 TO pv_r20_other;
ALTER ROLE pv_r20_other SET DateStyle = 'SQL, DMY';
SQL
as pv_r20_au -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE FUNCTION app20.afirmar(k int) RETURNS void LANGUAGE sql SECURITY DEFINER
    SET search_path = pg_catalog, public SET DateStyle = ISO AS $f$
    SELECT phasevec.assert('notes', k::text,
                           format('SELECT (SELECT body FROM public.notes WHERE id = %s)::date = date ''2026-03-04''', k))
$f$;
REVOKE ALL ON FUNCTION app20.afirmar(int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app20.afirmar(int) TO pv_r20_other;
SQL
ds=$(as pv_r20_other -c "SHOW DateStyle" -c "SELECT app20.afirmar(4)" 2>&1 | tr '\n' ' ')
env=$(q -c "SELECT array(SELECT e FROM unnest(proof_env) e WHERE e ~ '^DateStyle') FROM phasevec.truth WHERE key = '4'")
v4=$(as pv_r20_au -c "SELECT verdict FROM phasevec.verify('notes', 10, interval '0') WHERE key = '4'" 2>&1)
q -c "ALTER ROLE pv_r20_other RESET DateStyle" >/dev/null
if [ "$env" = "{}" ] && [ "$v4" = "verified" ]; then
    ok "a caller's DateStyle order from its role's settings is not recorded as the author's ($ds)"
else
    nok "RT20M-2 (role settings): caller '$ds', recorded '$env', verify() '$v4'"
fi

q >/dev/null 2>&1 <<'SQL'
DROP EXTENSION pg_phasevec CASCADE;
DROP SCHEMA app20 CASCADE;
DROP OWNED BY pv_r20_au, pv_r20_other;
DROP ROLE pv_r20_au, pv_r20_other;
SQL
exit $fallas
