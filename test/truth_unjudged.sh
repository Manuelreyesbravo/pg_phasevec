#!/usr/bin/env bash
# 0.20.0 (tenth review): an author cannot keep its claims from being judged, nor keep them 'verified' that way.
# Against the throwaway cluster of installcheck.sh (run that first), with the same PV_DATA/PV_PORT/PV_SOCK.
#   PG=~/pg19/bin test/truth_unjudged.sh
# 1. An ordinary author set its own role's transaction_timeout (and the other session timeouts) to 1 ms: its proofs'
#    workers ended before they judged, every verify() said 'not judged', and a claim that had turned false kept reading
#    'verified' in verify(), verify_one() and brief(). The worker is phasevec's session, not the author's: it pins those
#    timeouts before it connects, over the database's and the role's defaults; the proof's clock is its only time
#    limit (a proof waiting for a lock is 'unproven' at its clock, as before, not at the author's lock_timeout).
# 2. A claim that still cannot be judged for its author's sake (here the author's local_preload_libraries names a
#    library that does not exist: a new session of the author fails as it starts) is recorded as such
#    (truth.unjudged_at, unjudged_why). It keeps its verdict while that is fresh (p_every of the verify() that found it),
#    then reads 'unproven', in brief() too. And it waits behind the claims judged since (truth.tried_at): with p_n, an
#    author's claims that cannot be judged held the head of the queue, and another author's false claims were never
#    refuted.
set -uo pipefail
cd "$(dirname "$0")/.."
PG=${PG:-$HOME/pg19/bin}
DATA=${PV_DATA:-$PWD/.testcluster}
PORT=${PV_PORT:-5491}
SOCK=${PV_SOCK:-/tmp}
P=(-h "$SOCK" -p "$PORT" -X -q -At -d pv_unjudged)
export PGOPTIONS="-c client_min_messages=warning"
"$PG/pg_ctl" -D "$DATA" -o "-p $PORT -k $SOCK" -l "$DATA/server.log" -w start >/dev/null
trap '"$PG/pg_ctl" -D "$DATA" -w stop >/dev/null' EXIT
"$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists pv_unjudged 2>/dev/null
"$PG/createdb" -h "$SOCK" -p "$PORT" pv_unjudged
q() { "$PG/psql" "${P[@]}" "$@"; }
v() { q -c "SET ROLE pv_u_v" "$@"; }
q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
DROP ROLE IF EXISTS pv_u_a; DROP ROLE IF EXISTS pv_u_b; DROP ROLE IF EXISTS pv_u_v;
CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register('r1', repeat('a', 64), 4);
CREATE ROLE pv_u_a LOGIN;
CREATE ROLE pv_u_b LOGIN;
CREATE ROLE pv_u_v LOGIN;
GRANT pv_u_a, pv_u_b TO pv_u_v;
GRANT USAGE ON SCHEMA phasevec TO pv_u_a, pv_u_b, pv_u_v;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz) TO pv_u_a, pv_u_b;
GRANT EXECUTE ON FUNCTION phasevec.verify(text, int, interval, interval, int, float8),
                          phasevec.verify_one(text, text, int, float8), phasevec.brief(text, int) TO pv_u_v;
CREATE FUNCTION public.gate(k int) RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN PERFORM pg_advisory_xact_lock_shared(k); RETURN true; END $$;
CREATE TABLE inv (id int, overdue boolean);
INSERT INTO inv VALUES (1, false);
CREATE TABLE notes (id int PRIMARY KEY, body text);
INSERT INTO notes SELECT g, 'note ' || g FROM generate_series(1, 30) g;
GRANT SELECT ON inv, notes TO pv_u_a, pv_u_b, pv_u_v;
SELECT phasevec.watch('inv', 'notes'::regclass, 'id', 'r.body', 'r1');
SET ROLE pv_u_a;
SELECT phasevec.assert('inv', '1', 'NOT EXISTS (SELECT 1 FROM public.inv WHERE overdue)');
SELECT phasevec.assert('inv', '2', 'public.gate(51)');
RESET ROLE;
SQL
fallas=0
verdicts() { q -c "SELECT string_agg(key || ' ' || phasevec._verdict(t), ', ' ORDER BY key::int) FROM phasevec.truth t WHERE key::int BETWEEN $1 AND $2"; }

# 1. The author sets its own session timeouts to 1 ms, connected as itself (no superuser, no CREATEROLE).
v -c "SELECT count(*) FROM phasevec.verify('inv', 10, interval '0', interval '30 seconds', 5000)" >/dev/null
q -c "UPDATE inv SET overdue = true"
"$PG/psql" -h "$SOCK" -p "$PORT" -X -q -At -d pv_unjudged -U pv_u_a -v ON_ERROR_STOP=1 \
    -c "ALTER ROLE pv_u_a SET transaction_timeout = '1ms'" -c "ALTER ROLE pv_u_a SET statement_timeout = '1ms'" \
    -c "ALTER ROLE pv_u_a SET lock_timeout = '1ms'" -c "ALTER ROLE pv_u_a SET idle_in_transaction_session_timeout = '1ms'" \
    -c "ALTER ROLE pv_u_a SET idle_session_timeout = '1ms'" || { echo "not ok - the author could not set its own timeouts"; fallas=1; }
said=$(v -c "SELECT key || ' ' || verdict || coalesce(' ' || error, '') FROM phasevec.verify('inv', 10, interval '0', interval '30 seconds', 5000) WHERE key = '1'" 2>&1)
one=$(v -c "SELECT phasevec.verify_one('inv', '1', 5000)" 2>&1)
served=$(v -c "SELECT count(*) FROM phasevec.brief('inv') WHERE key = '1' AND verdict = 'verified'" 2>&1)
echo "the author's timeouts at 1 ms: verify() said: $said; verify_one() said: $one; brief() serves it as verified: $served"
[ "$said|$one|$served" = "1 refuted|refuted|0" ] && echo "ok - an author's own session timeouts do not keep its claims from being judged" \
    || { echo "not ok - an author's own session timeouts kept a false claim verified"; fallas=1; }
# the proof waits 0.5 s for a lock: past the author's lock_timeout of 1 ms, well within its clock
q -c "SELECT pg_advisory_lock(51), pg_sleep(0.5)" >/dev/null &
h=$!
for _ in $(seq 1 100); do
    [ "$(q -c "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND objid = 51 AND granted")" -gt 0 ] && break
    sleep 0.02
done
gated=$(v -c "SELECT phasevec.verify_one('inv', '2', 5000)" 2>&1)
wait $h
echo "a proof that waits 0.5 s for a lock, its author's lock_timeout 1 ms: $gated"
[ "$gated" = "verified" ] && echo "ok - the proof's clock is its only time limit" || { echo "not ok - the author's lock_timeout decided it"; fallas=1; }
q -c "ALTER ROLE pv_u_a RESET ALL" >/dev/null

# 2. Nine claims of pv_u_a, judged first (the oldest verdicts), then ten of pv_u_b; all true, then all false.
q -c "UPDATE inv SET overdue = false" >/dev/null
q -c "SET ROLE pv_u_a" -c "SELECT count(phasevec.assert('inv', k::text, 'NOT EXISTS (SELECT 1 FROM public.inv WHERE overdue)')) FROM generate_series(3, 11) k" >/dev/null
v -c "SELECT count(*) FROM phasevec.verify('inv', 100, interval '0', interval '30 seconds', 5000)" >/dev/null
sleep 0.1
q -c "SET ROLE pv_u_b" -c "SELECT count(phasevec.assert('inv', k::text, 'NOT EXISTS (SELECT 1 FROM public.inv WHERE overdue)')) FROM generate_series(12, 21) k" >/dev/null
v -c "SELECT count(*) FROM phasevec.verify('inv', 100, interval '1 hour', interval '30 seconds', 5000)" >/dev/null
echo "before: $(verdicts 3 21)"
q -c "UPDATE inv SET overdue = true" >/dev/null
# a new session of pv_u_a now fails as it starts, whatever phasevec pins
"$PG/psql" -h "$SOCK" -p "$PORT" -X -q -At -d pv_unjudged -U pv_u_a -c "ALTER ROLE pv_u_a SET local_preload_libraries = 'pv_no_such_library'"
sleep 2.2
# p_every 2 s: due (verified more than 2 s ago); not judged now, it keeps its verdict while that is fresh
first=$(v -c "SELECT count(*) FILTER (WHERE verdict = 'verified' AND error LIKE 'not judged%') || ' of ' || count(*) || ' still verified, not judged' FROM phasevec.verify('inv', 9, interval '2 seconds', interval '30 seconds', 5000)" 2>&1)
fresh=$(q -c "SELECT phasevec._verdict(t) || ' ' || (unjudged_at IS NOT NULL) FROM phasevec.truth t WHERE key = '3'")
echo "an author whose sessions cannot start: verify() said: $first; key 3 reads: $fresh"
sleep 2.2
stale=$(q -c "SELECT phasevec._verdict(t) FROM phasevec.truth t WHERE key = '3'")
served=$(v -c "SELECT count(*) FROM phasevec.brief('inv') WHERE key = '3' AND verdict = 'verified'")
echo "once that is older than p_every: key 3 reads: $stale; brief() serves it as verified: $served"
[ "$first|$fresh|$stale|$served" = "9 of 9 still verified, not judged|verified true|unproven|0" ] && echo "ok - a claim that cannot be judged keeps its verdict only while it is fresh" \
    || { echo "not ok - a claim that cannot be judged kept serving its verdict"; fallas=1; }
one=$(v -c "SELECT phasevec.verify_one('inv', '4', 5000)" 2>&1)
case "$one" in *"could not judge"*) echo "ok - verify_one() says it could not judge it" ;; *) echo "not ok - verify_one() said: $one"; fallas=1 ;; esac
# ten verify(p_n => 5): pv_u_b's false claims are refuted all the same
for _ in $(seq 1 10); do v -c "SELECT count(*) FROM phasevec.verify('inv', 5, interval '0', interval '30 seconds', 5000)" >/dev/null; done
b=$(q -c "SELECT count(*) FROM phasevec.truth t WHERE key::int BETWEEN 12 AND 21 AND phasevec._verdict(t) = 'refuted'")
a=$(q -c "SELECT count(*) FROM phasevec.truth t WHERE key::int BETWEEN 3 AND 11 AND phasevec._verdict(t) = 'verified'")
echo "after ten verify(p_n => 5): $b of pv_u_b's 10 false claims refuted; $a of pv_u_a's still read verified"
[ "$b|$a" = "10|0" ] && echo "ok - claims that cannot be judged do not hold the head of the queue" \
    || { echo "not ok - claims that cannot be judged held the head of the queue"; fallas=1; }
why=$(q -c "SELECT unjudged_why FROM phasevec.truth WHERE key = '5'")
echo "why: $why"
# its author fixed: judged again, and the mark is gone
q -c "ALTER ROLE pv_u_a RESET ALL" >/dev/null
v -c "SELECT count(*) FROM phasevec.verify('inv', 100, interval '0', interval '30 seconds', 5000)" >/dev/null
after=$(q -c "SELECT count(*) FILTER (WHERE phasevec._verdict(t) = 'refuted') || ' refuted, ' || count(unjudged_at) || ' marked' FROM phasevec.truth t WHERE key::int BETWEEN 3 AND 11")
echo "its author fixed: $after"
[ "$after" = "9 refuted, 0 marked" ] && echo "ok - judged again once its sessions start" || { echo "not ok - not judged again ($after)"; fallas=1; }
left=$(q -c "SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'pg_phasevec proof'")
[ "$left" = "0" ] || { echo "not ok - $left proof workers are left"; fallas=1; }
exit $fallas
