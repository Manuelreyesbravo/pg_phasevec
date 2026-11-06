#!/usr/bin/env bash
# 0.20.0 (second cut): two races a single session cannot show, played with two sessions and advisory locks as gates.
# Against the throwaway cluster of installcheck.sh (run that first), with the same PV_DATA/PV_PORT/PV_SOCK.
#   PG=~/pg19/bin test/truth_race.sh
# 1. ABA: the row says X when the proof starts, says Y while the proof reads it, says X again when the proof ends.
#    Under READ COMMITTED the proof judged Y; the first cut recorded 'verified' for X.
# 2. Another author asserts the same proof while it runs as the first one: the first cut kept the verdict reached
#    with the first author's rights on the second author's claim.
# 3. The verifier's session ends while a proof runs (here it is terminated; a proof that set transaction_timeout did
#    it with a FATAL in the second cut): nothing of that verify() is written, and in the second cut the same claim
#    came first again and ended every later verify() too. Now the next verify() records it refuted and runs the rest.
# 4. (third cut) Only that claim: not every claim of the watch with the same text, proof and author.
# 5. (third cut) Every such mark is taken: with ten sessions ended, the ninth was dropped and its claim ran again.
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
-- a gate: waits while another session holds the lock (transaction-level: a proof cannot take a session lock)
CREATE FUNCTION public.gate(k int) RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN PERFORM pg_advisory_xact_lock_shared(k); RETURN true; END $$;
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
CREATE TABLE jobs (id int PRIMARY KEY, body text);
INSERT INTO jobs VALUES (1, 'waits at the gate'), (2, 'plain'), (3, 'plain too');
SELECT phasevec.watch('jobs', 'jobs'::regclass, 'id', 'r.body', 'r1');
SELECT phasevec.assert('jobs', '1', 'public.gate(91)');
SELECT phasevec.assert('jobs', '2', 'true');
SELECT phasevec.assert('jobs', '3', 'true');
-- three claims that read alike (same text, proof and author), and ten claims behind one gate
CREATE TABLE twins (id int PRIMARY KEY, body text);
INSERT INTO twins VALUES (1, 'status: approved'), (2, 'status: approved'), (3, 'status: approved');
SELECT phasevec.watch('twins', 'twins'::regclass, 'id', 'r.body', 'r1');
SELECT phasevec.assert('twins', k::text, 'public.gate(95)') FROM generate_series(1, 3) k;
CREATE TABLE pool (id int PRIMARY KEY, body text);
INSERT INTO pool SELECT g, 'job ' || g FROM generate_series(1, 10) g;
SELECT phasevec.watch('pool', 'pool'::regclass, 'id', 'r.body', 'r1');
SELECT phasevec.assert('pool', k::text, 'public.gate(96)') FROM generate_series(1, 10) k;
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
who=$("$PG/psql" "${P[@]}" -c "SELECT asserted_by || ' | ' || phasevec._verdict(t) FROM phasevec.truth t WHERE key = '1' AND watch = (SELECT id FROM phasevec.watches WHERE name = 'notes')")
echo "author race: truth says: $who"
case "$who" in
    *verified*) echo "not ok - a verdict reached with one author's rights is kept on another author's claim"; fallas=1 ;;
    *) echo "ok - a claim asserted by another author while its proof ran gets nothing recorded" ;;
esac
# its own author's verdict, judged now: the low author cannot read the secret
own=$("$PG/psql" "${P[@]}" -c "SELECT phasevec.verify_one('notes', '1', 10000)")
echo "author race: verified as its new author: $own"
[ "$own" = "refuted" ] || { echo "not ok - the claim of the low author was not judged with its own rights"; fallas=1; }

# 3. Session B holds the gate; session A verifies and is terminated inside the proof.
"$PG/psql" "${P[@]}" >/dev/null <<'SQL' &
SELECT pg_advisory_lock(91);
DO $$ BEGIN
    WHILE NOT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND objid = 91 AND NOT granted) LOOP
        PERFORM pg_sleep(0.05);
    END LOOP;
    PERFORM pg_terminate_backend(pid) FROM pg_locks WHERE locktype = 'advisory' AND objid = 91 AND NOT granted;
    PERFORM pg_sleep(0.2);
END $$;
SELECT pg_advisory_unlock(91);
SQL
b=$!
for _ in $(seq 1 100); do
    [ "$("$PG/psql" "${P[@]}" -c "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND objid = 91 AND granted")" -gt 0 ] && break
    sleep 0.05
done
"$PG/psql" "${P[@]}" -c "SELECT key, verdict FROM phasevec.verify('jobs', 10, interval '0', interval '30 seconds', 20000)" >/dev/null 2>&1
wait $b
next=$("$PG/psql" "${P[@]}" -c "SELECT string_agg(key || ' ' || verdict, ', ' ORDER BY key) FROM phasevec.verify('jobs', 10, interval '0', interval '30 seconds', 20000)")
echo "ended session: the next verify said: $next"
halted=$("$PG/psql" "${P[@]}" -c "SELECT verdict || ' | ' || halted || ' | ' || last_error FROM phasevec.truth WHERE key = '1' AND watch = (SELECT id FROM phasevec.watches WHERE name = 'jobs')")
echo "ended session: key 1 is: $halted"
case "$next|$halted" in
    "2 verified, 3 verified|refuted | true | "*) echo "ok - the claim whose verifier's session ended is refuted, and the others are judged" ;;
    *) echo "not ok - a claim that ended its verifier's session still blocks the watch"; fallas=1 ;;
esac
again=$("$PG/psql" "${P[@]}" -c "SELECT count(*) FROM phasevec.verify('jobs', 10, interval '0', interval '30 seconds', 20000) WHERE key = '1'")
[ "$again" = "0" ] && echo "ok - it is not run again until asserted again" || { echo "not ok - a halted claim runs again"; fallas=1; }
"$PG/psql" "${P[@]}" -c "SELECT phasevec.assert('jobs', '1', 'public.gate(91)')" >/dev/null
back=$("$PG/psql" "${P[@]}" -c "SELECT verdict FROM phasevec.verify('jobs', 10, interval '0', interval '30 seconds', 20000) WHERE key = '1'")
[ "$back" = "verified" ] && echo "ok - asserted again, it runs" || { echo "not ok - asserted again, it does not run ($back)"; fallas=1; }

# 4. Three claims read alike (same text, proof and author); the session verifying the first one ends inside it.
# In the third cut the mark named the claim and not its key, and all three were halted.
"$PG/psql" "${P[@]}" -c "SELECT count(*) FROM phasevec.verify('twins', 10, interval '0', interval '30 seconds', 20000)" >/dev/null
"$PG/psql" "${P[@]}" >/dev/null <<'SQL' &
SELECT pg_advisory_lock(95);
DO $$ BEGIN
    WHILE NOT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND objid = 95 AND NOT granted) LOOP
        PERFORM pg_sleep(0.05);
    END LOOP;
    PERFORM pg_terminate_backend(pid) FROM pg_locks WHERE locktype = 'advisory' AND objid = 95 AND NOT granted;
    PERFORM pg_sleep(0.2);
END $$;
SELECT pg_advisory_unlock(95);
SQL
b=$!
for _ in $(seq 1 100); do
    [ "$("$PG/psql" "${P[@]}" -c "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND objid = 95 AND granted")" -gt 0 ] && break
    sleep 0.05
done
"$PG/psql" "${P[@]}" -c "SELECT phasevec.verify_one('twins', '1', 20000)" >/dev/null 2>&1
wait $b
"$PG/psql" "${P[@]}" -c "SELECT count(*) FROM phasevec.verify('twins', 0)" >/dev/null
twins=$("$PG/psql" "${P[@]}" -c "SELECT string_agg(key || ' ' || verdict || CASE WHEN halted THEN ' halted' ELSE '' END, ', ' ORDER BY key) FROM phasevec.truth WHERE watch = (SELECT id FROM phasevec.watches WHERE name = 'twins')")
echo "claims alike: $twins"
[ "$twins" = "1 refuted halted, 2 verified, 3 verified" ] && echo "ok - only the claim whose verifier's session ended is halted" || { echo "not ok - a session that ended halted claims it never ran"; fallas=1; }

# 5. Ten sessions verifying ten claims of one watch end inside them. In the third cut the first verify() after took
# eight marks and dropped the ninth, whose claim then ran again.
pids=()
"$PG/psql" "${P[@]}" -c "SELECT pg_advisory_lock(96), pg_sleep(30)" >/dev/null 2>&1 &
holder=$!
for _ in $(seq 1 100); do
    [ "$("$PG/psql" "${P[@]}" -c "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND objid = 96 AND granted")" -gt 0 ] && break
    sleep 0.05
done
for k in $(seq 1 10); do
    "$PG/psql" "${P[@]}" -c "SELECT phasevec.verify_one('pool', '$k', 30000)" >/dev/null 2>&1 &
    pids+=($!)
done
for _ in $(seq 1 200); do
    [ "$("$PG/psql" "${P[@]}" -c "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND objid = 96 AND NOT granted")" -ge 10 ] && break
    sleep 0.05
done
"$PG/psql" "${P[@]}" -c "SELECT count(pg_terminate_backend(pid)) FROM pg_locks WHERE locktype = 'advisory' AND objid = 96 AND NOT granted" >/dev/null
for p in "${pids[@]}"; do wait "$p"; done
"$PG/psql" "${P[@]}" -c "SELECT count(pg_terminate_backend(pid)) FROM pg_locks WHERE locktype = 'advisory' AND objid = 96 AND granted" >/dev/null
wait $holder
"$PG/psql" "${P[@]}" -c "SELECT count(*) FROM phasevec.verify('pool', 0)" >/dev/null
pool=$("$PG/psql" "${P[@]}" -c "SELECT count(*) FILTER (WHERE halted) || ' halted of ' || count(*) FROM phasevec.truth WHERE watch = (SELECT id FROM phasevec.watches WHERE name = 'pool')")
echo "ten ended sessions: $pool"
[ "$pool" = "10 halted of 10" ] && echo "ok - every mark is taken, none is lost past the eighth" || { echo "not ok - a mark of an ended session was lost"; fallas=1; }

"$PG/psql" "${P[@]}" >/dev/null <<'SQL'
DROP TABLE notes, jobs, twins, pool;
DROP EXTENSION pg_phasevec;
DROP SCHEMA pv_private CASCADE;
DROP OWNED BY pv_race_admin, pv_race_low;
DROP ROLE pv_race_admin;
DROP ROLE pv_race_low;
SQL
"$PG/dropdb" -h "$SOCK" -p "$PORT" pv_race
exit $fallas
