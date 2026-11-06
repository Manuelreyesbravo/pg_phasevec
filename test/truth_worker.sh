#!/usr/bin/env bash
# 0.20.0 (ninth review): a proof's own session and the sessions around it, played with several sessions.
# Against the throwaway cluster of installcheck.sh (run that first), with the same PV_DATA/PV_PORT/PV_SOCK.
#   PG=~/pg19/bin test/truth_worker.sh
# 1. A session that ends is the proof's failure only when the proof ended it. A role with only pg_signal_backend (or
#    the verifier, from another session of its own) terminated a proof's worker, and a true claim was recorded refuted
#    and halted for good (it left brief()). Now a worker ended by another process leaves the claim due, with the reason
#    ('interrupted'); one the proof ends itself (here it terminates its own session) is still refuted and halted.
#    (Until the tenth review the author's transaction_timeout did it here; a worker no longer takes its author's
#    session timeouts: test/truth_unjudged.sh.)
# 2. A proof that waits for a lock the verifier holds through a third session (an ALTER TABLE queued behind the
#    verifier's lock): the check saw only a direct wait, the proof waited for its clock and was recorded refuted, and
#    the ALTER and every reader of the table waited n times the clock. The verifier walks the waits now: an error.
# 3. A proof that waits for a lock held by a third session that does not wait on the verifier: refuted for its time
#    then; not judged now (a lock wait is not the proof's answer): verify_one() says so, the verdict stays as it was
#    (until the eleventh review it was recorded 'unproven'), and it is judged once the lock is gone.
# 4. A claim larger than the queue, whose worker waits for a lock at its start: the verifier waited inside the send
#    for as long as the lock was held. Now it waits under its deadlines and says the claim was not judged.
set -uo pipefail
cd "$(dirname "$0")/.."
PG=${PG:-$HOME/pg19/bin}
DATA=${PV_DATA:-$PWD/.testcluster}
PORT=${PV_PORT:-5491}
SOCK=${PV_SOCK:-/tmp}
P=(-h "$SOCK" -p "$PORT" -X -q -At -d pv_worker)
export PGOPTIONS="-c client_min_messages=warning"
"$PG/pg_ctl" -D "$DATA" -o "-p $PORT -k $SOCK" -l "$DATA/server.log" -w start >/dev/null
W=$(mktemp -d "${TMPDIR:-/tmp}/pv-worker.XXXXXX")
trap '"$PG/pg_ctl" -D "$DATA" -w stop >/dev/null; rm -rf "$W"' EXIT
"$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists pv_worker 2>/dev/null
"$PG/createdb" -h "$SOCK" -p "$PORT" pv_worker
"$PG/psql" "${P[@]}" -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
DROP ROLE IF EXISTS pv_w_a; DROP ROLE IF EXISTS pv_w_b; DROP ROLE IF EXISTS pv_w_v; DROP ROLE IF EXISTS pv_w_mon;
CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register('r1', repeat('a', 64), 4);
CREATE ROLE pv_w_a LOGIN;
CREATE ROLE pv_w_b LOGIN;
CREATE ROLE pv_w_v LOGIN;
CREATE ROLE pv_w_mon LOGIN;
GRANT pg_signal_backend TO pv_w_mon;
GRANT pv_w_a, pv_w_b TO pv_w_v;
GRANT USAGE ON SCHEMA phasevec TO pv_w_a, pv_w_b, pv_w_v;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz) TO pv_w_a, pv_w_b;
GRANT EXECUTE ON FUNCTION phasevec.verify(text, int, interval, interval, int, float8),
                          phasevec.verify_one(text, text, int, float8), phasevec.brief(text, int) TO pv_w_v;
CREATE FUNCTION public.gate(k int) RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN PERFORM pg_advisory_xact_lock_shared(k); RETURN true; END $$;
-- a proof's own way to end its session (in practice a C function's FATAL): pg_terminate_backend of itself, under a
-- name the guard does not know
CREATE FUNCTION public.end_my_session(pid int, timeout bigint DEFAULT 0) RETURNS boolean
    LANGUAGE internal STRICT VOLATILE AS 'pg_terminate_backend';
CREATE TABLE jobs (id int PRIMARY KEY, body text);
INSERT INTO jobs VALUES (1, 'waits at the gate'), (2, 'plain'), (3, 'sleeps');
CREATE TABLE inv (id int, overdue boolean);
INSERT INTO inv VALUES (1, false);
CREATE TABLE notes (id int PRIMARY KEY, body text);
INSERT INTO notes SELECT g, 'note ' || g FROM generate_series(1, 4) g;
GRANT SELECT ON jobs, inv, notes TO pv_w_a, pv_w_b, pv_w_v;
SELECT phasevec.watch('jobs', 'jobs'::regclass, 'id', 'r.body', 'r1');
SELECT phasevec.watch('inv', 'notes'::regclass, 'id', 'r.body', 'r1');
SELECT phasevec.watch('big', 'notes'::regclass, 'id', 'r.body', 'r1');
SET ROLE pv_w_a;
SELECT phasevec.assert('jobs', '1', 'public.gate(61)');
SELECT phasevec.assert('jobs', '2', 'true');
SELECT phasevec.assert('inv', k::text, 'NOT EXISTS (SELECT 1 FROM public.inv WHERE overdue)') FROM generate_series(1, 3) k;
SELECT phasevec.assert('big', '1', format('length(%L) = 70000', repeat('x', 70000)));
RESET ROLE;
SQL
fallas=0
q() { "$PG/psql" "${P[@]}" "$@"; }
waits_on() {  # until some session waits on advisory lock $1
    for _ in $(seq 1 200); do
        [ "$(q -c "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND objid = $1 AND NOT granted")" -gt 0 ] && return 0
        sleep 0.05
    done
    echo "not ok - nobody waited on lock $1"; return 1
}
verdicts() { q -c "SELECT string_agg(key || ' ' || verdict || CASE WHEN halted THEN ' halted' ELSE '' END, ', ' ORDER BY key) FROM phasevec.truth WHERE watch = (SELECT id FROM phasevec.watches WHERE name = '$1')"; }

# 1. Every claim judged once; then the worker judging key 1 (behind gate 61) is terminated by $killer.
first=$(q -c "SET ROLE pv_w_v" -c "SELECT string_agg(key || ' ' || verdict, ', ' ORDER BY key) FROM phasevec.verify('jobs', 10, interval '0', interval '30 seconds', 20000)")
echo "first verify: $first"
for killer in pv_w_mon pv_w_v; do
    # asserted (again) and judged: verified
    q -c "SET ROLE pv_w_a" -c "SELECT phasevec.assert('jobs', '1', 'public.gate(61)')" >/dev/null
    q -c "SET ROLE pv_w_v" -c "SELECT count(*) FROM phasevec.verify('jobs', 10, interval '0', interval '30 seconds', 20000)" >/dev/null
    q -c "SELECT pg_advisory_lock(61), pg_sleep(30)" >/dev/null 2>&1 &
    holder=$!
    for _ in $(seq 1 100); do
        [ "$(q -c "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND objid = 61 AND granted")" -gt 0 ] && break
        sleep 0.05
    done
    q -c "SET ROLE pv_w_v" -c "SELECT key || ' ' || coalesce(verdict, '-') || ' | ' || coalesce(error, '') FROM phasevec.verify('jobs', 10, interval '0', interval '30 seconds', 20000) WHERE key = '1'" >"$W/said" 2>&1 &
    v=$!
    waits_on 61 || fallas=1
    "$PG/psql" -h "$SOCK" -p "$PORT" -X -q -At -d pv_worker -U "$killer" -c "SELECT count(pg_terminate_backend(pid)) FROM pg_locks WHERE locktype = 'advisory' AND objid = 61 AND NOT granted" >/dev/null
    wait $v
    kill $holder 2>/dev/null; q -c "SELECT count(pg_terminate_backend(pid)) FROM pg_locks WHERE locktype = 'advisory' AND objid = 61 AND granted" >/dev/null; wait $holder 2>/dev/null
    echo "terminated by $killer: verify said: $(cat "$W/said")"
    now=$(verdicts jobs)
    brief=$(q -c "SET ROLE pv_w_v" -c "SELECT count(*) FROM phasevec.brief('jobs') WHERE key = '1'")
    echo "terminated by $killer: the claims are: $now; brief lists key 1: $brief"
    case "$now|$brief" in
        "1 verified, 2 verified|1") echo "ok - a worker terminated by $killer leaves the true claim as it was, in brief()" ;;
        *) echo "not ok - a worker terminated by $killer refuted or halted a true claim"; fallas=1 ;;
    esac
    grep -q "interrupted" "$W/said" && echo "ok - verify() says the claim was interrupted" || { echo "not ok - verify() does not say the claim was interrupted"; fallas=1; }
    next=$(q -c "SET ROLE pv_w_v" -c "SELECT string_agg(key || ' ' || verdict, ', ' ORDER BY key) FROM phasevec.verify('jobs', 10, interval '0', interval '30 seconds', 20000) WHERE key = '1'")
    [ "$next" = "1 verified" ] && echo "ok - it is due, and the next verify() judges it" || { echo "not ok - the next verify() did not judge it ($next)"; fallas=1; }
done
# the proof that ends its own session
q -c "SET ROLE pv_w_b" -c "SELECT phasevec.assert('jobs', '3', 'public.end_my_session(pg_backend_pid())')" >/dev/null
ended=$(q -c "SET ROLE pv_w_v" -c "SELECT key || ' ' || verdict FROM phasevec.verify('jobs', 10, interval '0', interval '30 seconds', 20000) WHERE key = '3'" 2>&1)
halted=$(q -c "SELECT verdict || ' ' || halted FROM phasevec.truth WHERE key = '3' AND watch = (SELECT id FROM phasevec.watches WHERE name = 'jobs')")
echo "a proof that ends its own session: verify said: $ended; it is: $halted"
[ "$ended|$halted" = "3 refuted|refuted true" ] && echo "ok - a proof that ends its own session is refuted and halted" || { echo "not ok - a proof that ends its own session was not halted"; fallas=1; }

# 2. The verifier read inv in its transaction; an ALTER TABLE queues behind that read; the proofs read inv.
q -c "SELECT count(*) FROM phasevec.verify('inv', 10, interval '0')" >/dev/null
cat >"$W/v2.sql" <<'SQL'
\set ON_ERROR_STOP 0
BEGIN;
SELECT count(*) FROM inv;
DO $$ BEGIN
    WHILE NOT EXISTS (SELECT 1 FROM pg_locks WHERE relation = 'inv'::regclass AND mode = 'AccessExclusiveLock' AND NOT granted) LOOP
        PERFORM pg_sleep(0.05);
    END LOOP;
END $$;
SELECT extract(epoch FROM clock_timestamp()) AS t0 \gset
SELECT string_agg(key || ' ' || verdict, ', ') FROM phasevec.verify('inv', 10, interval '0', interval '60 seconds', 2000);
COMMIT;
SELECT 'took ' || round((extract(epoch FROM clock_timestamp()) - :t0) * 1000) || ' ms';
SQL
q -f "$W/v2.sql" >"$W/v2.out" 2>&1 &
v=$!
for _ in $(seq 1 100); do
    [ "$(q -c "SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a USING (pid) WHERE l.relation = 'inv'::regclass AND l.granted AND a.query LIKE 'DO%'")" -gt 0 ] && break
    sleep 0.05
done
t0=$(date +%s%N)
q -c "SET lock_timeout = '60s'" -c "ALTER TABLE inv ADD COLUMN z int" >/dev/null 2>&1
alter_ms=$(( ($(date +%s%N) - t0) / 1000000 ))
wait $v
echo "a lock through a third session: verify said: $(tr '\n' ' ' <"$W/v2.out")"
echo "the ALTER TABLE waited $alter_ms ms"
now=$(verdicts inv)
echo "the claims are: $now"
took=$(grep -o 'took [0-9]*' "$W/v2.out" | grep -o '[0-9]*')
grep -q "waits.*for a lock this transaction holds" "$W/v2.out" && [ "${took:-99999}" -lt 3000 ] \
    && echo "ok - a proof that waits for the verifier through another session is an error at once" \
    || { echo "not ok - the verifier waited for its proofs through another session"; fallas=1; }
[ "$now" = "1 verified, 2 verified, 3 verified" ] && echo "ok - nothing was refuted for it" || { echo "not ok - claims were refuted for a lock wait"; fallas=1; }
q -c "ALTER TABLE inv DROP COLUMN z" >/dev/null

# 3. A third session holds inv for 4 s; the proof waits for it past its clock (1 s).
q -c "BEGIN" -c "LOCK TABLE inv IN ACCESS EXCLUSIVE MODE" -c "SELECT pg_sleep(4)" -c "COMMIT" >/dev/null 2>&1 &
x=$!
for _ in $(seq 1 100); do
    [ "$(q -c "SELECT count(*) FROM pg_locks WHERE relation = 'inv'::regclass AND mode = 'AccessExclusiveLock' AND granted")" -gt 0 ] && break
    sleep 0.05
done
during=$(q -c "SELECT phasevec.verify_one('inv', '1', 1000)" 2>&1 | grep -c "could not judge")
why=$(q -c "SELECT phasevec._verdict(t) || ': ' || coalesce(a.why, '') FROM phasevec.truth t JOIN phasevec.attempts a USING (watch, key) WHERE key = '1' AND watch = (SELECT id FROM phasevec.watches WHERE name = 'inv')")
wait $x
after=$(q -c "SELECT phasevec.verify_one('inv', '1', 1000)" 2>&1)
echo "a lock held by a third session: verify_one said $during ($why), and once it is gone: $after"
case "$why" in "verified: not judged: the proof was still waiting for a lock"*) ;; *) during="$during, $why" ;; esac
[ "$during|$after" = "1|verified" ] && echo "ok - a lock wait past the clock is not a refutation" || { echo "not ok - a lock wait past the clock was judged"; fallas=1; }

# 4. A third session holds the watched table; the 70 kB claim's worker waits for it as it starts.
q -c "BEGIN" -c "LOCK TABLE notes IN ACCESS EXCLUSIVE MODE" -c "SELECT pg_sleep(20)" -c "COMMIT" >/dev/null 2>&1 &
x=$!
for _ in $(seq 1 100); do
    [ "$(q -c "SELECT count(*) FROM pg_locks WHERE relation = 'notes'::regclass AND mode = 'AccessExclusiveLock' AND granted")" -gt 0 ] && break
    sleep 0.05
done
t0=$(date +%s%N)
big=$(q -c "SET statement_timeout = '15s'" -c "SELECT phasevec.verify_one('big', '1', 500)" 2>&1)
big_ms=$(( ($(date +%s%N) - t0) / 1000000 ))
q -c "SELECT count(pg_terminate_backend(pid)) FROM pg_locks WHERE relation = 'notes'::regclass AND mode = 'AccessExclusiveLock' AND granted" >/dev/null
wait $x 2>/dev/null
echo "a 70 kB claim whose worker waits at its start: verify_one said, after $big_ms ms: $big"
case "$big" in
    *"not judged"*) [ "$big_ms" -lt 9000 ] && echo "ok - the verifier waited under its deadlines" || { echo "not ok - the verifier waited too long ($big_ms ms)"; fallas=1; } ;;
    *) echo "not ok - the verifier waited inside its send"; fallas=1 ;;
esac
after=$(q -c "SELECT phasevec.verify_one('big', '1', 2000)" 2>&1)
[ "$after" = "verified" ] && echo "ok - judged once the lock is gone" || { echo "not ok - not judged after ($after)"; fallas=1; }
left=$(q -c "SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'pg_phasevec proof'")
[ "$left" = "0" ] && echo "ok - no proof's worker is left" || { echo "not ok - $left proof workers are left"; fallas=1; }
exit $fallas
