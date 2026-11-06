#!/usr/bin/env bash
# 0.20.0 (thirteenth review): a proof runs in one process. Against the throwaway cluster of installcheck.sh (run that
# first), with the same PV_DATA/PV_PORT/PV_SOCK.
#   PG=~/pg19/bin test/truth_parallel.sh
# A wait for a lock that a PARALLEL WORKER of the proof made was not seen: the proof's session saw only its own waits
# (the time its deadlock timer was armed, the lock it waits for when its clock ends), and the leader waits on the
# Gather's queue. Another session's lock then got a true claim recorded 'refuted' ('took longer than its clock'),
# even with the lock still held when the clock ended. The author needs only settings of its own role:
# debug_parallel_query, or a parallel plan with parallel_leader_participation off. Now the proof's session pins
# max_parallel_workers_per_gather = 0, max_parallel_workers = 0 and debug_parallel_query = off, over every setting of
# the author's: every wait the proof makes is its session's own, and it is not judged.
set -uo pipefail
cd "$(dirname "$0")/.."
PG=${PG:-$HOME/pg19/bin}
DATA=${PV_DATA:-$PWD/.testcluster}
PORT=${PV_PORT:-5491}
SOCK=${PV_SOCK:-/tmp}
P=(-h "$SOCK" -p "$PORT" -X -q -At -d pv_parallel)
export PGOPTIONS="-c client_min_messages=warning"
"$PG/pg_ctl" -D "$DATA" -o "-p $PORT -k $SOCK" -l "$DATA/server.log" -w start >/dev/null
trap '"$PG/pg_ctl" -D "$DATA" -w stop >/dev/null' EXIT
"$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists pv_parallel 2>/dev/null
"$PG/createdb" -h "$SOCK" -p "$PORT" pv_parallel
q() { "$PG/psql" "${P[@]}" "$@"; }
v() { q -c "SET ROLE pv_p_v" "$@"; }
q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
DROP ROLE IF EXISTS pv_p_a; DROP ROLE IF EXISTS pv_p_w; DROP ROLE IF EXISTS pv_p_v;
CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register('r1', repeat('a', 64), 4);
CREATE ROLE pv_p_a LOGIN; CREATE ROLE pv_p_w LOGIN; CREATE ROLE pv_p_v LOGIN;
GRANT pv_p_a TO pv_p_v;
GRANT USAGE ON SCHEMA phasevec TO pv_p_a, pv_p_v;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz) TO pv_p_a;
GRANT EXECUTE ON FUNCTION phasevec.verify(text, int, interval, interval, int, float8),
                          phasevec.verify_one(text, text, int, float8), phasevec.brief(text, int) TO pv_p_v;
-- pv_p_w only writes facts: UPDATE on it is enough to LOCK it
CREATE TABLE facts (id int PRIMARY KEY, ok boolean NOT NULL);
INSERT INTO facts SELECT g, true FROM generate_series(1, 200) g;
GRANT SELECT ON facts TO pv_p_a, pv_p_v; GRANT SELECT, UPDATE ON facts TO pv_p_w;
CREATE FUNCTION public.chk(k int) RETURNS boolean LANGUAGE plpgsql STABLE PARALLEL SAFE
  AS $f$ BEGIN RETURN (SELECT ok FROM public.facts WHERE id = k); END $f$;
-- a: the nested query runs in a parallel worker (debug_parallel_query)
CREATE FUNCTION public.chkq(k int) RETURNS SETOF boolean LANGUAGE plpgsql STABLE PARALLEL SAFE
  AS $f$ BEGIN RETURN QUERY SELECT public.chk(k); END $f$;
-- b: an ordinary Gather over a parallel scan, the leader not taking part
CREATE TABLE big (id int, pad text);
INSERT INTO big SELECT g, 'x' FROM generate_series(1, 20000) g;
ANALYZE big;
CREATE FUNCTION public.chkbig(k int) RETURNS SETOF boolean LANGUAGE plpgsql STABLE PARALLEL SAFE
  AS $f$ BEGIN RETURN QUERY SELECT public.chk(k) FROM public.big WHERE id = k; END $f$;
GRANT SELECT ON big TO pv_p_a, pv_p_v;
CREATE TABLE notes (id int PRIMARY KEY, body text);
INSERT INTO notes SELECT g, 'note ' || g FROM generate_series(1, 20) g;
GRANT SELECT ON notes TO pv_p_a, pv_p_v;
SELECT phasevec.watch('w1', 'notes'::regclass, 'id', 'r.body', 'r1');
-- settings of the author's own role (it may set them itself: all are USERSET)
ALTER ROLE pv_p_a SET debug_parallel_query = on;
ALTER ROLE pv_p_a SET parallel_leader_participation = off;
ALTER ROLE pv_p_a SET parallel_setup_cost = 0;
ALTER ROLE pv_p_a SET parallel_tuple_cost = 0;
ALTER ROLE pv_p_a SET min_parallel_table_scan_size = 0;
SET ROLE pv_p_a;
SELECT phasevec.assert('w1', '1', $p$(SELECT pg_catalog.bool_and(x) FROM public.chkq(1) x)$p$);
SELECT phasevec.assert('w1', '2', $p$(SELECT pg_catalog.bool_and(x) FROM public.chkbig(2) x)$p$);
SELECT phasevec.assert('w1', '3', $p$pg_catalog.current_setting('max_parallel_workers_per_gather') = '0'
  AND pg_catalog.current_setting('max_parallel_workers') = '0'
  AND pg_catalog.current_setting('debug_parallel_query') = 'off'$p$);
RESET ROLE;
SQL
fallas=0
stored() { q -c "SELECT phasevec._verdict(t) FROM phasevec.truth t WHERE key = '$1'"; }
for k in 1 2; do
    base=$(v -c "SELECT phasevec.verify_one('w1', '$k', 1000)" 2>&1)
    # pv_p_w holds facts for 3 s: still held when the proof's clock of 1 s ends
    "$PG/psql" "${P[@]}" -U pv_p_w -c "BEGIN" -c "LOCK TABLE public.facts IN ACCESS EXCLUSIVE MODE" \
        -c "SELECT pg_sleep(3)" -c "COMMIT" >/dev/null &
    h=$!
    for _ in $(seq 1 200); do
        [ "$(q -c "SELECT count(*) FROM pg_locks WHERE relation = 'public.facts'::regclass AND granted AND mode = 'AccessExclusiveLock'")" -gt 0 ] && break
        sleep 0.02
    done
    said=$(v -c "SELECT phasevec.verify_one('w1', '$k', 1000)" 2>&1 | tr '\n' ' ')
    wait $h
    now=$(stored "$k")
    echo "key $k: before the lock: $base; facts held 3 s, clock 1 s: verify_one() said: ${said:0:160}; it reads: $now"
    case "$base|$said|$now" in
        "verified|"*"could not judge"*"not judged: the proof was still waiting for a lock"*"|verified") echo "ok - key $k: a lock held past the clock leaves the claim not judged" ;;
        *) echo "not ok - key $k: another session's lock decided a true claim"; fallas=1 ;;
    esac
done
pinned=$(v -c "SELECT phasevec.verify_one('w1', '3', 1000)" 2>&1)
echo "key 3 (the proof's session has no parallelism, whatever its author's role sets): $pinned"
[ "$pinned" = "verified" ] && echo "ok - a proof runs in one process" || { echo "not ok - a proof may run in parallel workers"; fallas=1; }
left=$(q -c "SELECT count(*) FROM pg_stat_activity WHERE backend_type IN ('pg_phasevec proof', 'parallel worker')")
[ "$left" = "0" ] || { echo "not ok - $left workers are left"; fallas=1; }
exit $fallas
