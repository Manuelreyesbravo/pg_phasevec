#!/usr/bin/env bash
# 0.20.0 (thirteenth review): a claim's turn is spent only once a session of its author can try it. Against the
# throwaway cluster of installcheck.sh (run that first), with the same PV_DATA/PV_PORT/PV_SOCK; this script starts it
# with max_worker_processes = 2 (and no logical replication launcher): room for one verify() at a time.
#   PG=~/pg19/bin test/truth_slots.sh
# verify() needs two background workers at a time: its keeper (a session of the owner, which spends the claims' turns)
# and a session of the claims' author (which tries them). In the twelfth cut the keeper started first, took the last
# free slot and spent the turns of the whole batch; then no session of the author could start, and every claim of the
# batch was 'not judged' with its turn spent. An ordinary author holding one slot with a slow proof of its own (here
# pv_s_h, through verify_one()) on every other call kept the same false claims of another author from ever being
# tried: they went to the back of the queue each time. Now both sessions are started before any turn is spent; when
# one cannot start, the claims are not judged and keep their turn, and the next call that has the slots tries them.
# And with two slots and no one else, one call judges the claims of several authors: when the next author's claims
# come up, its session waits for the one before to leave its slot. In the twelfth cut it did not, the new one often
# found no slot, and 1 to 10 of 50 claims were 'not judged' (with their turns spent).
set -uo pipefail
cd "$(dirname "$0")/.."
PG=${PG:-$HOME/pg19/bin}
DATA=${PV_DATA:-$PWD/.testcluster}
PORT=${PV_PORT:-5491}
SOCK=${PV_SOCK:-/tmp}
P=(-h "$SOCK" -p "$PORT" -X -q -At -d pv_slots)
export PGOPTIONS="-c client_min_messages=warning"
"$PG/pg_ctl" -D "$DATA" -o "-p $PORT -k $SOCK -c max_worker_processes=2 -c max_logical_replication_workers=0" \
    -l "$DATA/server.log" -w start >/dev/null
trap '"$PG/pg_ctl" -D "$DATA" -w stop >/dev/null' EXIT
"$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists pv_slots 2>/dev/null
"$PG/createdb" -h "$SOCK" -p "$PORT" pv_slots
q() { "$PG/psql" "${P[@]}" "$@"; }
v() { q -c "SET ROLE pv_s_v" "$@"; }
q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
DROP ROLE IF EXISTS pv_s_a; DROP ROLE IF EXISTS pv_s_b; DROP ROLE IF EXISTS pv_s_h; DROP ROLE IF EXISTS pv_s_v;
CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register('r1', repeat('a', 64), 4);
CREATE ROLE pv_s_a LOGIN; CREATE ROLE pv_s_b LOGIN; CREATE ROLE pv_s_h LOGIN; CREATE ROLE pv_s_v LOGIN;
GRANT pv_s_a, pv_s_b TO pv_s_v;
GRANT USAGE ON SCHEMA phasevec TO pv_s_a, pv_s_b, pv_s_h, pv_s_v;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz) TO pv_s_a, pv_s_b, pv_s_h;
GRANT EXECUTE ON FUNCTION phasevec.verify(text, int, interval, interval, int, float8),
                          phasevec.verify_one(text, text, int, float8) TO pv_s_v, pv_s_h;
CREATE TABLE facts (id int PRIMARY KEY, ok boolean NOT NULL);
INSERT INTO facts SELECT g, true FROM generate_series(1, 200) g;
CREATE FUNCTION public.ok(k int) RETURNS boolean LANGUAGE sql STABLE AS $$ SELECT ok FROM public.facts WHERE id = k $$;
GRANT SELECT ON facts TO pv_s_a, pv_s_b, pv_s_h, pv_s_v;
CREATE TABLE notes1 (id int PRIMARY KEY, body text); INSERT INTO notes1 SELECT g, 'n' || g FROM generate_series(1, 50) g;
CREATE TABLE notes2 (id int PRIMARY KEY, body text); INSERT INTO notes2 SELECT g, 'n' || g FROM generate_series(1, 50) g;
GRANT SELECT ON notes1, notes2 TO pv_s_a, pv_s_b, pv_s_h, pv_s_v;
SELECT phasevec.watch('w1', 'notes1'::regclass, 'id', 'r.body', 'r1');
SELECT phasevec.watch('w2', 'notes2'::regclass, 'id', 'r.body', 'r1');
SET ROLE pv_s_a;
SELECT count(phasevec.assert('w1', k::text, format('public.ok(%s)', k))) FROM generate_series(1, 20) k;
SET ROLE pv_s_h;
SELECT phasevec.assert('w2', '1', 'pg_catalog.pg_sleep(3) IS NOT NULL');
RESET ROLE;
SQL
fallas=0
first=$(v -c "SELECT verdict || ' ' || count(*) FROM phasevec.verify('w1', 100, interval '0', interval '30 seconds', 5000) GROUP BY verdict")
echo "all 20 judged once: $first"
q -c "UPDATE facts SET ok = false WHERE id <= 20"
snap() { q -c "SELECT string_agg(key || '@' || attempted_at, ',' ORDER BY key) FROM phasevec.attempts a JOIN phasevec.watches w ON w.id = a.watch WHERE w.name = 'w1'"; }
spent() {  # claims whose turn moved between two snapshots
    python3 -I -c 'import sys; a=dict(x.split("@") for x in sys.argv[1].split(",")); b=dict(x.split("@") for x in sys.argv[2].split(",")); print(sum(1 for k in b if a.get(k) != b[k]))' "$1" "$2"
}
for call in 1 2 3 4; do
    h=
    if [ $((call % 2)) = 1 ]; then
        # pv_s_h, an ordinary author, holds one of the two slots with a slow proof of its own
        "$PG/psql" "${P[@]}" -U pv_s_h -c "SELECT phasevec.verify_one('w2', '1', 20000)" >/dev/null 2>&1 &
        h=$!
        for _ in $(seq 1 200); do
            [ "$(q -c "SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'pg_phasevec proof' AND wait_event = 'PgSleep'")" -gt 0 ] && break
            sleep 0.02
        done
    fi
    before=$(snap)
    t0=$(date +%s%N)
    said=$(v -c "SELECT verdict || ' ' || count(*) || coalesce(': ' || left(min(error), 60), '') FROM phasevec.verify('w1', 10, interval '0', interval '30 seconds', 5000) GROUP BY verdict" | tr '\n' ' ')
    ms=$(( ($(date +%s%N) - t0) / 1000000 ))
    moved=$(spent "$before" "$(snap)")
    [ -n "$h" ] && wait $h
    echo "call $call ($([ -n "$h" ] && echo 'one slot held' || echo 'both slots free')): $said; turns spent: $moved; ${ms} ms"
    if [ -n "$h" ]; then
        case "$said|$moved" in
            *"not judged: no background worker is free"*"|0") ;;
            *) echo "not ok - call $call: turns were spent without a session to try them"; fallas=1 ;;
        esac
    fi
done
refuted=$(q -c "SELECT count(*) FROM phasevec.truth t JOIN phasevec.watches w ON w.id = t.watch WHERE w.name = 'w1' AND t.verdict = 'refuted'")
echo "after two calls with both slots free (p_n 10): $refuted of the 20 false claims refuted"
[ "$refuted" = "20" ] && echo "ok - a slot held by another author does not keep chosen claims from being tried" \
    || { echo "not ok - $((20 - refuted)) false claims were never tried"; fallas=1; }
# Two slots and no one else: claims of three authors in one call (a session of each in turn, and the keeper).
# Each author's session leaves its slot as the next one starts: none is said to have found no worker free.
q -c "SET ROLE pv_s_b" -c "SELECT count(phasevec.assert('w1', k::text, format('public.ok(%s)', k))) FROM generate_series(21, 30) k" >/dev/null
q -c "SET ROLE pv_s_a" -c "SELECT count(phasevec.assert('w1', k::text, format('public.ok(%s)', k))) FROM generate_series(31, 40) k" >/dev/null
q -c "SET ROLE pv_s_b" -c "SELECT count(phasevec.assert('w1', k::text, format('public.ok(%s)', k))) FROM generate_series(41, 50) k" >/dev/null
for _ in 1 2 3; do
    turns=$(v -c "SELECT count(*) FILTER (WHERE error LIKE 'not judged%') || ' of ' || count(*) FROM phasevec.verify('w1', 100, interval '0', interval '30 seconds', 5000)")
    echo "claims of two authors, interleaved, with two slots: not judged: $turns"
    case "$turns" in "0 of 50") ;; *) echo "not ok - an author's session found no slot after the one before it"; fallas=1 ;; esac
done
[ $fallas = 0 ] && echo "ok - one call with two slots judges claims of several authors"
left=$(q -c "SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'pg_phasevec proof'")
[ "$left" = "0" ] || { echo "not ok - $left proof workers are left"; fallas=1; }
exit $fallas
