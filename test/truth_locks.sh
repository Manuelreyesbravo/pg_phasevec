#!/usr/bin/env bash
# 0.20.0 (fifth review): who waits on whom, played with several sessions. Against the throwaway cluster of
# installcheck.sh (run that first), with the same PV_DATA/PV_PORT/PV_SOCK.
#   PG=~/pg19/bin test/truth_locks.sh
# 1. A writer does not wait on a verifier. In the fifth cut (ce02558) a write that changed a row's text set that key's
#    verdict to 'unproven' (a trigger on phasevec.sources), so it waited on every open transaction that had judged the
#    key: here it fails on lock_timeout while verify()'s transaction is open. Now staleness is read, not written.
# 2. Two verify() calls of one watch, each holding a claim the other's due list names: in the fifth cut each waited
#    on the other and one was killed as a deadlock, with every verdict it had reached. Now verify() leaves a claim
#    whose row another holds.
# 3. The same under load: writers changing texts, two verifiers judging the whole watch over and over (pgbench).
#    In the fifth cut 36-70% of the verify() calls failed on deadlocks.
set -uo pipefail
cd "$(dirname "$0")/.."
PG=${PG:-$HOME/pg19/bin}
DATA=${PV_DATA:-$PWD/.testcluster}
PORT=${PV_PORT:-5491}
SOCK=${PV_SOCK:-/tmp}
P=(-h "$SOCK" -p "$PORT" -X -q -At -d pv_locks)
export PGOPTIONS="-c client_min_messages=warning"
"$PG/pg_ctl" -D "$DATA" -o "-p $PORT -k $SOCK" -l "$DATA/server.log" -w start >/dev/null
OUT=$(mktemp -d "${TMPDIR:-/tmp}/pv_locks.XXXXXX")
trap '"$PG/pg_ctl" -D "$DATA" -w stop >/dev/null; rm -rf "$OUT"' EXIT
"$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists pv_locks 2>/dev/null
"$PG/createdb" -h "$SOCK" -p "$PORT" pv_locks
"$PG/psql" "${P[@]}" -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register('r1', repeat('a', 64), 4);
CREATE TABLE tasks (id int PRIMARY KEY, done boolean);
INSERT INTO tasks SELECT g, false FROM generate_series(1, 200) g;
CREATE TABLE notes (id int PRIMARY KEY, body text);
INSERT INTO notes SELECT g, 'task ' || g || ' is open' FROM generate_series(1, 200) g;
SELECT phasevec.watch('notes', 'notes'::regclass, 'id', 'r.body', 'r1');
SELECT count(phasevec.assert('notes', g::text, format('NOT (SELECT done FROM public.tasks WHERE id = %s)', g)))
  FROM generate_series(1, 200) g;
CREATE TABLE steps (who text);   -- what a session has done, committed (a session lock goes with its session)
SQL
fallas=0
sleeping() {  # until a session sleeps in pg_sleep (it holds its transaction open there)
    for _ in $(seq 1 200); do
        [ "$("$PG/psql" "${P[@]}" -c "SELECT count(*) FROM pg_stat_activity WHERE wait_event = 'PgSleep' AND datname = 'pv_locks'")" -gt 0 ] && return 0
        sleep 0.05
    done
    return 1
}

# 1. Key 1 is verified; verify() judges it again and keeps its transaction open; a writer edits its text meanwhile.
"$PG/psql" "${P[@]}" -c "SELECT count(*) FROM phasevec.verify('notes', 10, interval '0')" >/dev/null
"$PG/psql" "${P[@]}" >"$OUT/v1" 2>&1 <<'SQL' &
BEGIN;
SELECT count(*) FROM phasevec.verify('notes', 500, interval '0') WHERE key = '1';
SELECT pg_sleep(3);
COMMIT;
SQL
b=$!
sleeping
w=$("$PG/psql" "${P[@]}" 2>&1 <<'SQL'
SET lock_timeout = '1s';
\timing on
UPDATE notes SET body = 'task 1 is open, said again' WHERE id = 1;
SQL
)
wait $b
echo "writer during an open verify(): $(echo "$w" | grep -E '^(ERROR|Time)' | tr '\n' ' ')"
case "$w" in
    *ERROR*) echo "not ok - a write that changes a row's text waits on an open verify() of that key"; fallas=1 ;;
    *) echo "ok - a writer does not wait on a verifier" ;;
esac
now=$("$PG/psql" "${P[@]}" -c "SELECT phasevec._verdict(t) FROM phasevec.truth t WHERE key = '1'")
[ "$now" = "unproven" ] && echo "ok - the verdict judged the old text: it reads unproven" \
    || { echo "not ok - the verdict of a changed text reads $now"; fallas=1; }

# 2. Session A takes claim 2 (verify_one), session B claim 3; then each runs verify() over the whole watch.
"$PG/psql" "${P[@]}" >"$OUT/a" 2>&1 <<'SQL' &
BEGIN;
SELECT phasevec.verify_one('notes', '2');
SELECT pg_advisory_lock(402);
DO $$ BEGIN   -- until B holds claim 3
    WHILE NOT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND objid = 403 AND granted) LOOP
        PERFORM pg_sleep(0.05);
    END LOOP;
END $$;
SELECT 'A judged ' || count(*) FROM phasevec.verify('notes', 500, interval '0');
COMMIT;
INSERT INTO steps VALUES ('A');
SQL
a=$!
"$PG/psql" "${P[@]}" >"$OUT/b" 2>&1 <<'SQL' &
DO $$ BEGIN   -- until A holds claim 2
    WHILE NOT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND objid = 402 AND granted) LOOP
        PERFORM pg_sleep(0.05);
    END LOOP;
END $$;
BEGIN;
SELECT phasevec.verify_one('notes', '3');
SELECT pg_advisory_lock(403);
DO $$ BEGIN   -- until A waits on a row lock, or is done
    WHILE NOT EXISTS (SELECT 1 FROM pg_locks WHERE locktype IN ('transactionid', 'tuple') AND NOT granted)
          AND NOT EXISTS (SELECT 1 FROM steps WHERE who = 'A') LOOP
        PERFORM pg_sleep(0.05);
    END LOOP;
END $$;
SELECT 'B judged ' || count(*) FROM phasevec.verify('notes', 500, interval '0');
COMMIT;
SQL
bb=$!
wait $a $bb
echo "verify A: $(grep -E 'judged|ERROR' "$OUT/a" | tr '\n' ' ')"
echo "verify B: $(grep -E 'judged|ERROR' "$OUT/b" | tr '\n' ' ')"
if grep -q ERROR "$OUT/a" "$OUT/b"; then
    echo "not ok - two verify() calls of one watch deadlock on its verdicts"; fallas=1
else
    echo "ok - two verify() calls of one watch each leave the claim the other holds"
fi
left=$("$PG/psql" "${P[@]}" -c "SELECT count(*) FROM phasevec.truth t WHERE phasevec._verdict(t) <> 'verified' AND key <> '1'")
[ "$left" = "0" ] && echo "ok - between them every claim was judged" \
    || { echo "not ok - $left claims were left unjudged"; fallas=1; }

# 3. Under load: three writers changing texts (and changing them back), two verifiers judging everything, 8 s.
cat >"$OUT/w.sql" <<'SQL'
\set k random(2, 200)
\set v random(0, 1)
UPDATE notes SET body = 'task ' || :k || ' is open' || CASE WHEN :v = 1 THEN ' (seen)' ELSE '' END WHERE id = :k;
SQL
echo "SELECT count(*) FROM phasevec.verify('notes', 500, interval '0', interval '60 seconds');" >"$OUT/v.sql"
"$PG/pgbench" -h "$SOCK" -p "$PORT" -n -T 8 -c 3 -f "$OUT/w.sql" pv_locks >"$OUT/pw" 2>&1 &
pw=$!
"$PG/pgbench" -h "$SOCK" -p "$PORT" -n -T 8 -c 2 -f "$OUT/v.sql" pv_locks >"$OUT/pv" 2>&1
wait $pw
vt=$(grep -E 'number of transactions actually processed' "$OUT/pv" | grep -oE '[0-9]+$')
vf=$(sed -nE 's/^number of failed transactions: ([0-9]+).*/\1/p' "$OUT/pv")
wl=$(grep -E 'latency average' "$OUT/pw" | grep -oE '[0-9.]+ ms')
wf=$(sed -nE 's/^number of failed transactions: ([0-9]+).*/\1/p' "$OUT/pw")
echo "load: verify() calls ${vt:-?} done, ${vf:-?} failed; writers ${wf:-?} failed, latency ${wl:-?}"
grep -E 'ERROR|aborted' "$OUT/pv" | sort | uniq -c | head -3
if [ "${vt:-0}" -gt 0 ] && [ "${vf:-1}" = "0" ] && [ "${wf:-1}" = "0" ]; then
    echo "ok - under writes, concurrent verify() calls of one watch do not fail"
else
    echo "not ok - under writes, concurrent verify() calls of one watch fail"; fallas=1
fi
exit $fallas
