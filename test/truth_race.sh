#!/usr/bin/env bash
# 0.20.0 (second cut): two races a single session cannot show, played with two sessions and advisory locks as gates.
# Against the throwaway cluster of installcheck.sh (run that first), with the same PV_DATA/PV_PORT/PV_SOCK.
#   PG=~/pg19/bin test/truth_race.sh
# 1. ABA: the row says X when the proof starts, says Y while the proof reads it, says X again when the proof ends.
#    Under READ COMMITTED the proof judged Y; the first cut recorded 'verified' for X.
# 2. Another author asserts the same proof while it runs as the first one: the first cut kept the verdict reached
#    with the first author's rights on the second author's claim.
# 3. The session a proof runs in ends while it runs (here by its author's transaction_timeout, while the proof waits
#    at a gate; a proof that set transaction_timeout did it with a FATAL in the second cut): in the second cut that
#    session was the verifier's, nothing of that verify() was written, and the same claim came first again and ended
#    every later verify() too. Since the eighth review a proof runs in a session of its own (a background worker): that
#    one ends, the claim is recorded refuted and halted (not run again until asserted again), and the rest are judged
#    in the same call. (Until the ninth review these sessions were terminated from outside, and that halted the claim
#    too; a session another process ends is interrupted now, not halted: test/truth_worker.sh.)
# 4. (third cut) Only that claim: not every claim of the watch with the same text, proof and author.
# 5. Each verify_one() halts the claim whose session ended; one that finds no background worker free records
#    nothing, and its claim stays due (the third cut dropped a mark past the eighth ended session).
# 6. (sixth review) A halt is recorded only by a verifier that may act as the claim's author, and only when its record
#    commits; a role that may not act as the author holds none of its claims (the author's assert() of that key
#    waited on its open transaction). A claim asserted again since its proof began is not the one that ran: it runs.
# 7. (eighth review) A verifier canceled or terminated while its proof runs: the proof's session ends with it.
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
DROP ROLE IF EXISTS pv_race_mal;
DROP ROLE IF EXISTS pv_race_end;
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
-- an author every session of which ends a transaction after 1.5 s: its proof that waits at a gate ends its session
CREATE ROLE pv_race_end;
ALTER ROLE pv_race_end SET transaction_timeout = '1500ms';
GRANT USAGE ON SCHEMA phasevec TO pv_race_end;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz) TO pv_race_end;
CREATE TABLE jobs (id int PRIMARY KEY, body text);
INSERT INTO jobs VALUES (1, 'waits at the gate'), (2, 'plain'), (3, 'plain too');
SELECT phasevec.watch('jobs', 'jobs'::regclass, 'id', 'r.body', 'r1');
GRANT SELECT ON jobs TO pv_race_end;
SET ROLE pv_race_end;
SELECT phasevec.assert('jobs', '1', 'public.gate(91)');
SELECT phasevec.assert('jobs', '2', 'true');
SELECT phasevec.assert('jobs', '3', 'true');
RESET ROLE;
-- three claims that read alike (same text, proof and author), and ten claims behind one gate
CREATE TABLE twins (id int PRIMARY KEY, body text);
INSERT INTO twins VALUES (1, 'status: approved'), (2, 'status: approved'), (3, 'status: approved');
SELECT phasevec.watch('twins', 'twins'::regclass, 'id', 'r.body', 'r1');
GRANT SELECT ON twins TO pv_race_end;
SET ROLE pv_race_end;
SELECT phasevec.assert('twins', k::text, 'public.gate(95)') FROM generate_series(1, 3) k;
RESET ROLE;
CREATE TABLE pool (id int PRIMARY KEY, body text);
INSERT INTO pool SELECT g, 'job ' || g FROM generate_series(1, 10) g;
SELECT phasevec.watch('pool', 'pool'::regclass, 'id', 'r.body', 'r1');
GRANT SELECT ON pool TO pv_race_end;
SET ROLE pv_race_end;
SELECT phasevec.assert('pool', k::text, 'public.gate(96)') FROM generate_series(1, 10) k;
RESET ROLE;
CREATE TABLE halts (id int PRIMARY KEY, body text);
INSERT INTO halts VALUES (1, 'waits at the gate'), (2, 'plain');
SELECT phasevec.watch('halts', 'halts'::regclass, 'id', 'r.body', 'r1');
GRANT SELECT ON halts TO pv_race_end;
SET ROLE pv_race_end;
SELECT phasevec.assert('halts', '1', 'public.gate(97)');
SELECT phasevec.assert('halts', '2', 'true');
RESET ROLE;
CREATE ROLE pv_race_mal LOGIN;
GRANT USAGE ON SCHEMA phasevec TO pv_race_mal;
GRANT EXECUTE ON FUNCTION phasevec.verify(text, int, interval, interval, int, float8),
                          phasevec.verify_one(text, text, int, float8) TO pv_race_mal;
SQL

waits_on() {  # until some session waits on advisory lock $1
    for _ in $(seq 1 200); do
        [ "$("$PG/psql" "${P[@]}" -c "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND objid = $1 AND NOT granted")" -gt 0 ] && return 0
        sleep 0.05
    done
    echo "not ok - nobody waited on lock $1"; return 1
}
fallas=0
# hold gate $1 until a proof has waited at it and its session has ended (by its author's transaction_timeout)
hold_until_ended() {
    cat <<SQL
SELECT pg_advisory_lock($1);
DO \$\$ BEGIN
    WHILE NOT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND objid = $1 AND NOT granted) LOOP
        PERFORM pg_sleep(0.05);
    END LOOP;
    WHILE EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND objid = $1 AND NOT granted) LOOP
        PERFORM pg_sleep(0.05);
    END LOOP;
    PERFORM pg_sleep(0.2);
END \$\$;
SELECT pg_advisory_unlock($1);
SQL
}

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

# 3. Session B holds the gate; session A verifies, and the session its proof runs in ends inside it.
hold_until_ended 91 | "$PG/psql" "${P[@]}" >/dev/null &
b=$!
for _ in $(seq 1 100); do
    [ "$("$PG/psql" "${P[@]}" -c "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND objid = 91 AND granted")" -gt 0 ] && break
    sleep 0.05
done
first=$("$PG/psql" "${P[@]}" -c "SELECT string_agg(key || ' ' || verdict, ', ' ORDER BY key) FROM phasevec.verify('jobs', 10, interval '0', interval '30 seconds', 20000)" 2>&1)
wait $b
echo "ended session: that verify said: $first"
[ "$first" = "1 refuted, 2 verified, 3 verified" ] && echo "ok - the verifier outlives the session its proof ended, and judges the rest" || { echo "not ok - the verifier did not outlive the session its proof ended"; fallas=1; }
next=$("$PG/psql" "${P[@]}" -c "SELECT string_agg(key || ' ' || verdict, ', ' ORDER BY key) FROM phasevec.verify('jobs', 10, interval '0', interval '30 seconds', 20000)")
echo "ended session: the next verify said: $next"
halted=$("$PG/psql" "${P[@]}" -c "SELECT verdict || ' | ' || halted || ' | ' || last_error FROM phasevec.truth WHERE key = '1' AND watch = (SELECT id FROM phasevec.watches WHERE name = 'jobs')")
echo "ended session: key 1 is: $halted"
case "$next|$halted" in
    "2 verified, 3 verified|refuted | true | "*) echo "ok - the claim whose proof's session ended is refuted and halted, and the others are judged" ;;
    *) echo "not ok - a claim that ended its verifier's session still blocks the watch"; fallas=1 ;;
esac
again=$("$PG/psql" "${P[@]}" -c "SELECT count(*) FROM phasevec.verify('jobs', 10, interval '0', interval '30 seconds', 20000) WHERE key = '1'")
[ "$again" = "0" ] && echo "ok - it is not run again until asserted again" || { echo "not ok - a halted claim runs again"; fallas=1; }
"$PG/psql" "${P[@]}" -c "SET ROLE pv_race_end" -c "SELECT phasevec.assert('jobs', '1', 'public.gate(91)')" >/dev/null
back=$("$PG/psql" "${P[@]}" -c "SELECT verdict FROM phasevec.verify('jobs', 10, interval '0', interval '30 seconds', 20000) WHERE key = '1'")
[ "$back" = "verified" ] && echo "ok - asserted again, it runs" || { echo "not ok - asserted again, it does not run ($back)"; fallas=1; }

# 4. Three claims read alike (same text, proof and author); the session verifying the first one ends inside it.
# In the third cut the mark named the claim and not its key, and all three were halted.
"$PG/psql" "${P[@]}" -c "SELECT count(*) FROM phasevec.verify('twins', 10, interval '0', interval '30 seconds', 20000)" >/dev/null
hold_until_ended 95 | "$PG/psql" "${P[@]}" >/dev/null &
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
[ "$twins" = "1 refuted halted, 2 verified, 3 verified" ] && echo "ok - only the claim whose proof's session ended is halted" || { echo "not ok - a session that ended halted claims it never ran"; fallas=1; }

# 5. Ten verify_one() calls of ten claims, each in a session of its own: as many as there are background workers
# free wait at the gate, and the rest are told that none is free (nothing recorded: their claims stay due). The
# waiting ones end inside their proofs (their author's transaction_timeout): each of those claims is halted, by the
# verify_one() that ran it, which goes on. In the third cut a mark of a verifier's ended session was dropped past the
# eighth, and its claim ran again.
W5=$(mktemp -d "${TMPDIR:-/tmp}/pv-race.XXXXXX")
pids=()
"$PG/psql" "${P[@]}" -c "SELECT pg_advisory_lock(96), pg_sleep(30)" >/dev/null 2>&1 &
holder=$!
for _ in $(seq 1 100); do
    [ "$("$PG/psql" "${P[@]}" -c "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND objid = 96 AND granted")" -gt 0 ] && break
    sleep 0.05
done
for k in $(seq 1 10); do
    "$PG/psql" "${P[@]}" -c "SELECT phasevec.verify_one('pool', '$k', 30000)" >"$W5/$k" 2>&1 &
    pids+=($!)
done
for p in "${pids[@]}"; do wait "$p"; done
waiting=$(grep -lx "refuted" "$W5"/* 2>/dev/null | wc -l)
nofree=$(grep -l "no background worker is free" "$W5"/* 2>/dev/null | wc -l)
echo "ten verify_one(): $waiting ended in their own sessions, $nofree found no background worker free"
[ $((waiting + nofree)) -eq 10 ] || { echo "not ok - $((10 - waiting - nofree)) verify_one() calls said something else: $(cat "$W5"/* | sort | uniq -c | tr '\n' ' ')"; fallas=1; }
"$PG/psql" "${P[@]}" -c "SELECT count(pg_terminate_backend(pid)) FROM pg_locks WHERE locktype = 'advisory' AND objid = 96 AND granted" >/dev/null
wait $holder
pool=$("$PG/psql" "${P[@]}" -c "SELECT count(*) FILTER (WHERE halted) || ' halted, ' || count(*) FILTER (WHERE NOT halted AND verdict = 'unproven') || ' due' FROM phasevec.truth WHERE watch = (SELECT id FROM phasevec.watches WHERE name = 'pool')")
said=$(cat "$W5"/* | grep -c "^refuted$")
echo "ten ended or refused: $pool; verify_one() said refuted $said times"
[ "$pool" = "$waiting halted, $nofree due" ] && [ "$said" = "$waiting" ] && [ "$waiting" -gt 0 ] \
    && echo "ok - every claim whose session ended is halted by its own verifier; one with no worker free stays due" \
    || { echo "not ok - a claim whose session ended was not halted, or one not judged was recorded"; fallas=1; }
rest=$("$PG/psql" "${P[@]}" -c "SELECT count(*) FROM phasevec.verify('pool', 10, interval '0', interval '30 seconds', 20000) WHERE verdict = 'verified'")
[ "$rest" = "$nofree" ] && echo "ok - the claims that stayed due are judged by the next verify()" || { echo "not ok - the claims that stayed due were not judged ($rest)"; fallas=1; }
rm -rf "$W5"

# 6. The session of claim 1 of 'halts' is terminated inside its proof (its verifier records it halted); then a role
# that may not act as its author calls verify_one() in a transaction it rolls back, and is refused it for that key,
# and runs verify(): the halt stays.
end_in_gate() {  # $1 gate, $2 the verify that waits at it (its session ends there)
    hold_until_ended "$1" | "$PG/psql" "${P[@]}" >/dev/null &
    local g=$!
    for _ in $(seq 1 100); do
        [ "$("$PG/psql" "${P[@]}" -c "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND objid = $1 AND granted")" -gt 0 ] && break
        sleep 0.05
    done
    "$PG/psql" "${P[@]}" -c "$2" >/dev/null 2>&1
    wait $g
}
M=(-h "$SOCK" -p "$PORT" -X -q -At -d pv_race -U pv_race_mal)
end_in_gate 97 "SELECT count(*) FROM phasevec.verify('halts', 10, interval '0', interval '30 seconds', 20000)"
"$PG/psql" "${M[@]}" -c "BEGIN" -c "SELECT phasevec.verify_one('halts', 'nokey')" -c "ROLLBACK" >/dev/null 2>&1
"$PG/psql" "${M[@]}" -c "SELECT phasevec.verify_one('halts', '1')" >/dev/null 2>&1
"$PG/psql" "${M[@]}" -c "SELECT count(*) FROM phasevec.verify('halts', 10, interval '0')" >/dev/null 2>&1
"$PG/psql" "${P[@]}" -c "SELECT count(*) FROM phasevec.verify('halts', 10, interval '0', interval '30 seconds', 20000)" >/dev/null
h1=$("$PG/psql" "${P[@]}" -c "SELECT verdict || ' | ' || halted FROM phasevec.truth WHERE key = '1' AND watch = (SELECT id FROM phasevec.watches WHERE name = 'halts')")
echo "halt after a rollback and a refusal: key 1 is: $h1"
[ "$h1" = "refuted | true" ] && echo "ok - a halt outlives a rollback and a verifier that may not act as its author" || { echo "not ok - a halt was erased, and its claim ran again"; fallas=1; }
# the author asserts it again: a new mark, and that role's open transaction while the author asserts again
"$PG/psql" "${P[@]}" -c "SET ROLE pv_race_end" -c "SELECT phasevec.assert('halts', '1', 'public.gate(97)')" >/dev/null
end_in_gate 97 "SELECT count(*) FROM phasevec.verify('halts', 10, interval '0', interval '30 seconds', 20000)"
"$PG/psql" "${M[@]}" -c "BEGIN" -c "SELECT phasevec.verify_one('halts', 'nokey')" -c "SELECT pg_sleep(4)" -c "COMMIT" >/dev/null 2>&1 &
mal=$!
for _ in $(seq 1 100); do
    [ "$("$PG/psql" "${P[@]}" -c "SELECT count(*) FROM pg_stat_activity WHERE usename = 'pv_race_mal' AND query LIKE 'SELECT pg_sleep(4)%'")" -gt 0 ] && break
    sleep 0.05
done
re=$("$PG/psql" "${P[@]}" -c "SET lock_timeout = '2s'" -c "SELECT 'asserted' FROM phasevec.assert('halts', '1', 'public.gate(97)')" 2>&1)
wait $mal
echo "assert while that role's transaction is open: $re"
[ "$re" = "asserted" ] && echo "ok - a verifier that may not act as the author holds none of its claims" || { echo "not ok - the author's assert() waited on a role with no rights over its claim"; fallas=1; }
back=$("$PG/psql" "${P[@]}" -c "SELECT verdict FROM phasevec.verify('halts', 10, interval '0', interval '30 seconds', 20000) WHERE key = '1'")
[ "$back" = "verified" ] && echo "ok - asserted again after its proof began, it runs" || { echo "not ok - a claim asserted again was halted by its old mark ($back)"; fallas=1; }

# 7. (eighth review) A verifier canceled (its statement_timeout) while its proof waits at a gate, and one terminated
# there: the session of each one's proof ends with it, and nothing is recorded (the claim is not halted: its proof did
# not end anything).
"$PG/psql" "${P[@]}" >/dev/null <<'SQL'
CREATE TABLE gated (id int PRIMARY KEY, body text);
INSERT INTO gated VALUES (1, 'waits at the gate');
SELECT phasevec.watch('gated', 'gated'::regclass, 'id', 'r.body', 'r1');
SELECT phasevec.assert('gated', '1', 'public.gate(98)');
SQL
"$PG/psql" "${P[@]}" -c "SELECT pg_advisory_lock(98), pg_sleep(30)" >/dev/null 2>&1 &
holder=$!
for _ in $(seq 1 100); do
    [ "$("$PG/psql" "${P[@]}" -c "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND objid = 98 AND granted")" -gt 0 ] && break
    sleep 0.05
done
proofs() { "$PG/psql" "${P[@]}" -c "SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'pg_phasevec proof'"; }
gone() { for _ in $(seq 1 60); do [ "$(proofs)" = "0" ] && return 0; sleep 0.05; done; return 1; }
canceled=$("$PG/psql" "${P[@]}" -c "SET statement_timeout = '1s'" -c "SELECT phasevec.verify_one('gated', '1', 20000)" 2>&1)
echo "canceled verifier: $canceled"
case "$canceled" in *"statement timeout"*) gone && echo "ok - a canceled verifier's proof session ends with it" || { echo "not ok - a canceled verifier left its proof's session running"; fallas=1; } ;;
    *) echo "not ok - the verifier's statement_timeout did not cancel it"; fallas=1 ;; esac
"$PG/psql" "${P[@]}" -c "SELECT phasevec.verify_one('gated', '1', 20000)" >/dev/null 2>&1 &
v=$!
for _ in $(seq 1 100); do
    [ "$("$PG/psql" "${P[@]}" -c "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND objid = 98 AND NOT granted")" -gt 0 ] && break
    sleep 0.05
done
"$PG/psql" "${P[@]}" -c "SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE query LIKE 'SELECT phasevec.verify_one(''gated''%' AND backend_type = 'client backend'" >/dev/null
wait $v
gone && echo "ok - a terminated verifier's proof session ends with it" || { echo "not ok - a terminated verifier left its proof's session running"; fallas=1; }
"$PG/psql" "${P[@]}" -c "SELECT count(pg_terminate_backend(pid)) FROM pg_locks WHERE locktype = 'advisory' AND objid = 98 AND granted" >/dev/null
wait $holder
g=$("$PG/psql" "${P[@]}" -c "SELECT verdict || ' | ' || halted FROM phasevec.truth WHERE key = '1' AND watch = (SELECT id FROM phasevec.watches WHERE name = 'gated')")
[ "$g" = "unproven | false" ] && echo "ok - nothing is recorded for the claim of a verifier that ended" || { echo "not ok - a verifier that ended recorded or halted its claim ($g)"; fallas=1; }

"$PG/psql" "${P[@]}" >/dev/null <<'SQL'
DROP TABLE notes, jobs, twins, pool, halts, gated;
DROP EXTENSION pg_phasevec;
DROP SCHEMA pv_private CASCADE;
DROP OWNED BY pv_race_admin, pv_race_low;
DROP ROLE pv_race_admin;
DROP ROLE pv_race_low;
DROP OWNED BY pv_race_mal;
DROP ROLE pv_race_mal;
DROP OWNED BY pv_race_end;
DROP ROLE pv_race_end;
SQL
"$PG/dropdb" -h "$SOCK" -p "$PORT" pv_race
exit $fallas
