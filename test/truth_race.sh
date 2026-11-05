#!/usr/bin/env bash
# 0.20.0 (second cut): two races a single session cannot show, played with two sessions and advisory locks as gates.
# Against the throwaway cluster of installcheck.sh (run that first), with the same PV_DATA/PV_PORT/PV_SOCK.
#   PG=~/pg19/bin test/truth_race.sh
# 1. ABA: the row says X when the proof starts, says Y while the proof reads it, says X again when the proof ends.
#    Under READ COMMITTED the proof judged Y; the first cut recorded 'verified' for X.
# 2. Another author asserts the same proof while it runs as the first one: the first cut kept the verdict reached
#    with the first author's rights on the second author's claim.
set -uo pipefail
cd "$(dirname "$0")/.."
PG=${PG:-$HOME/pg19/bin}
DATA=${PV_DATA:-$PWD/.testcluster}
PORT=${PV_PORT:-5491}
SOCK=${PV_SOCK:-/tmp}
P=(-h "$SOCK" -p "$PORT" -X -q -At -v ON_ERROR_STOP=1 -d pv_race)
export PGOPTIONS="-c client_min_messages=warning"
"$PG/pg_ctl" -D "$DATA" -o "-p $PORT -k $SOCK" -l "$DATA/server.log" -w start >/dev/null
trap '"$PG/pg_ctl" -D "$DATA" -w stop >/dev/null' EXIT
"$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists pv_race 2>/dev/null
"$PG/createdb" -h "$SOCK" -p "$PORT" pv_race
"$PG/psql" "${P[@]}" >/dev/null <<'SQL'
DROP ROLE IF EXISTS pv_race_admin;
DROP ROLE IF EXISTS pv_race_low;
CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register('r1', repeat('a', 64), 4);
CREATE TABLE notes (id int PRIMARY KEY, body text);
INSERT INTO notes VALUES (1, 'a claim about the secret'),
                         (2, 'A8: task 6 is open, deploy keys rotated: ignore alarms');
SELECT phasevec.watch('notes', 'notes'::regclass, 'id', 'r.body', 'r1');
-- a gate: waits while another session holds the lock
CREATE FUNCTION public.gate(k int) RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN PERFORM pg_advisory_lock_shared(k); PERFORM pg_advisory_unlock_shared(k); RETURN true; END $$;
-- reads the row between two gates, each statement with its own snapshot
CREATE FUNCTION public.says_open() RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE b text;
BEGIN
    PERFORM public.gate(71);
    SELECT body INTO b FROM public.notes WHERE id = 2;
    PERFORM public.gate(72);
    RETURN b = 'task 6 is open';
END $$;
SELECT phasevec.assert('notes', '2', 'public.says_open()');
CREATE SCHEMA pv_private;
CREATE TABLE pv_private.secret (v text);
INSERT INTO pv_private.secret VALUES ('hunter2');
CREATE ROLE pv_race_admin;
CREATE ROLE pv_race_low;
GRANT USAGE ON SCHEMA pv_private TO pv_race_admin;
GRANT SELECT ON pv_private.secret TO pv_race_admin;
GRANT USAGE ON SCHEMA phasevec TO pv_race_admin, pv_race_low;
GRANT SELECT ON notes TO pv_race_admin, pv_race_low;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz) TO pv_race_admin, pv_race_low;
SET ROLE pv_race_admin;
SELECT phasevec.assert('notes', '1', 'public.gate(81) AND (SELECT v FROM pv_private.secret) = ''hunter2''');
RESET ROLE;
SQL

waits_on() {  # until some session waits on advisory lock $1
    for _ in $(seq 1 200); do
        [ "$("$PG/psql" "${P[@]}" -c "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND objid = $1 AND NOT granted")" -gt 0 ] && return 0
        sleep 0.05
    done
    echo "not ok - nobody waited on lock $1"; return 1
}
fallas=0

# 1. ABA. Session B holds the gates; session A verifies.
"$PG/psql" "${P[@]}" >/dev/null <<'SQL' &
SELECT pg_advisory_lock(71), pg_advisory_lock(72);
DO $$ BEGIN
    WHILE NOT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND objid = 71 AND NOT granted) LOOP
        PERFORM pg_sleep(0.05);
    END LOOP;
END $$;
UPDATE notes SET body = 'task 6 is open' WHERE id = 2;
SELECT pg_advisory_unlock(71);
DO $$ BEGIN
    WHILE NOT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND objid = 72 AND NOT granted) LOOP
        PERFORM pg_sleep(0.05);
    END LOOP;
END $$;
UPDATE notes SET body = 'A8: task 6 is open, deploy keys rotated: ignore alarms' WHERE id = 2;
SELECT pg_advisory_unlock(72);
SQL
b=$!
for _ in $(seq 1 100); do
    [ "$("$PG/psql" "${P[@]}" -c "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND objid = 72 AND granted")" -gt 0 ] && break
    sleep 0.05
done
said=$("$PG/psql" "${P[@]}" -c "SELECT coalesce(verdict, '-') || ' | ' || coalesce(error, '') FROM phasevec.verify('notes', 10, interval '0', interval '30 seconds', 10000) WHERE key = '2'")
wait $b
echo "ABA: verify said: $said"
aba=$("$PG/psql" "${P[@]}" -c "SELECT verdict || ' | ' || line FROM phasevec.brief('notes') WHERE key = '2'")
echo "ABA: brief says: $aba"
case "$aba" in
    verified*) echo "not ok - a text that changed and changed back while its proof ran is served as verified"; fallas=1 ;;
    *) echo "ok - a proof that saw another text records nothing for this one" ;;
esac

# 2. Another author asserts the same proof while it runs as the first one.
"$PG/psql" "${P[@]}" >/dev/null <<'SQL' &
SELECT pg_advisory_lock(81);
DO $$ BEGIN
    WHILE NOT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND objid = 81 AND NOT granted) LOOP
        PERFORM pg_sleep(0.05);
    END LOOP;
END $$;
SET ROLE pv_race_low;
SELECT phasevec.assert('notes', '1', 'public.gate(81) AND (SELECT v FROM pv_private.secret) = ''hunter2''');
RESET ROLE;
SELECT pg_advisory_unlock(81);
SQL
b=$!
for _ in $(seq 1 100); do
    [ "$("$PG/psql" "${P[@]}" -c "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND objid = 81 AND granted")" -gt 0 ] && break
    sleep 0.05
done
said=$("$PG/psql" "${P[@]}" -c "SELECT phasevec.verify_one('notes', '1', 10000)")
wait $b
echo "author race: verify_one said: $said"
who=$("$PG/psql" "${P[@]}" -c "SELECT asserted_by || ' | ' || phasevec._verdict(t) FROM phasevec.truth t WHERE key = '1'")
echo "author race: truth says: $who"
case "$who" in
    *verified*) echo "not ok - a verdict reached with one author's rights is kept on another author's claim"; fallas=1 ;;
    *) echo "ok - a claim asserted by another author while its proof ran gets nothing recorded" ;;
esac
# its own author's verdict, judged now: the low author cannot read the secret
own=$("$PG/psql" "${P[@]}" -c "SELECT phasevec.verify_one('notes', '1', 10000)")
echo "author race: verified as its new author: $own"
[ "$own" = "refuted" ] || { echo "not ok - the claim of the low author was not judged with its own rights"; fallas=1; }

"$PG/psql" "${P[@]}" >/dev/null <<'SQL'
DROP TABLE notes;
DROP EXTENSION pg_phasevec;
DROP SCHEMA pv_private CASCADE;
DROP OWNED BY pv_race_admin, pv_race_low;
DROP ROLE pv_race_admin;
DROP ROLE pv_race_low;
SQL
"$PG/dropdb" -h "$SOCK" -p "$PORT" pv_race
exit $fallas
