#!/usr/bin/env bash
# 0.20.0 (fourteenth review): a verifier cancelled at any point leaves nothing behind, and the server stays up.
# Against the throwaway cluster of installcheck.sh (run that first), with the same PV_DATA/PV_PORT/PV_SOCK; this
# script starts it with dynamic_shared_memory_type = mmap, so the segments it has are files in pg_dynshmem/.
#   PG=~/pg19/bin test/truth_cancel.sh          (PV_CANCELS=1000: statements cancelled in each of the two rounds)
# verify() stops a proof's session and waits for it to leave (its slot is the one the next author's session takes).
# In the thirteenth cut that wait freed the session's queues first and forgot the session only after it: a cancel
# during the wait (or a statement_timeout) reached verify()'s cleanup, which freed the same queues again. The memory
# was corrupted, the server PANICked ('stuck spinlock detected at shm_mq_detach_internal') and every session of the
# cluster was ended, by any role that may call verify(), cancelling its own call. Now a session is forgotten before
# anything that can be interrupted, each of its parts is freed once (the handle is cleared first), and a session
# still leaving when its verifier is interrupted is ended by the cleanup of the call.
# Each round runs verify() over 60 claims whose authors alternate (a session per claim, each waited for) PV_CANCELS
# times: under a random statement_timeout of 1-80 ms, then cancelled by a session of the same role at random times.
# Then: the postmaster is the same, no PANIC, TRAP or crash in the log, no proof's session is left, the cluster has as
# many dynamic shared memory segments as before, and one verify() judges all 60 claims.
set -uo pipefail
cd "$(dirname "$0")/.."
PG=${PG:-$HOME/pg19/bin}
DATA=${PV_DATA:-$PWD/.testcluster}
PORT=${PV_PORT:-5491}
SOCK=${PV_SOCK:-/tmp}
N=${PV_CANCELS:-1000}
P=(-h "$SOCK" -p "$PORT" -X -q -At -d pv_cancel)
export PGOPTIONS="-c client_min_messages=warning"
logfrom=$(stat -c %s "$DATA/server.log" 2>/dev/null || echo 0)
"$PG/pg_ctl" -D "$DATA" -o "-p $PORT -k $SOCK -c dynamic_shared_memory_type=mmap" -l "$DATA/server.log" -w start >/dev/null
trap '"$PG/pg_ctl" -D "$DATA" -w stop >/dev/null' EXIT
"$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists pv_cancel 2>/dev/null
"$PG/createdb" -h "$SOCK" -p "$PORT" pv_cancel
q() { "$PG/psql" "${P[@]}" "$@"; }
q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
DROP ROLE IF EXISTS pv_c_a; DROP ROLE IF EXISTS pv_c_b; DROP ROLE IF EXISTS pv_c_v;
CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register('r1', repeat('a', 64), 4);
CREATE ROLE pv_c_a LOGIN; CREATE ROLE pv_c_b LOGIN; CREATE ROLE pv_c_v LOGIN;
GRANT pv_c_a, pv_c_b TO pv_c_v;
GRANT USAGE ON SCHEMA phasevec TO pv_c_a, pv_c_b, pv_c_v;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz) TO pv_c_a, pv_c_b;
GRANT EXECUTE ON FUNCTION phasevec.verify(text, int, interval, interval, int, float8) TO pv_c_v;
CREATE TABLE facts (id int PRIMARY KEY, ok boolean NOT NULL);
INSERT INTO facts SELECT g, true FROM generate_series(1, 60) g;
CREATE FUNCTION public.ok(k int) RETURNS boolean LANGUAGE sql STABLE AS $$ SELECT ok FROM public.facts WHERE id = k $$;
CREATE TABLE notes1 (id int PRIMARY KEY, body text);
INSERT INTO notes1 SELECT g, 'n' || g FROM generate_series(1, 60) g;
GRANT SELECT ON facts, notes1 TO pv_c_a, pv_c_b, pv_c_v;
GRANT UPDATE ON facts, notes1 TO pv_c_a, pv_c_b, pv_c_v;
SELECT phasevec.watch('w1', 'notes1'::regclass, 'id', 'r.body', 'r1');
DO $$ BEGIN
  FOR k IN 1..60 LOOP
    EXECUTE format('SET ROLE %I', CASE WHEN k % 2 = 1 THEN 'pv_c_a' ELSE 'pv_c_b' END);
    PERFORM phasevec.assert('w1', k::text, format('public.ok(%s)', k));
    RESET ROLE;
  END LOOP;
END $$;
SQL
since=$(q -c "SELECT pg_postmaster_start_time()")
pm=$(head -1 "$DATA/postmaster.pid")
segs0=$(ls "$DATA/pg_dynshmem" | wc -l)
fallas=0
VERIFY="SELECT count(*) FROM phasevec.verify('w1', 100, interval '0', interval '30 seconds', 5000);"
# Round 1: a statement_timeout of its own, 1 to 80 ms, on every call.
python3 -I -c '
import random, sys
random.seed(14)
for _ in range(int(sys.argv[1])):
    print("SET statement_timeout = %d;" % random.randint(1, 80)); print(sys.argv[2])
' "$N" "$VERIFY" > "$DATA/cancel_r1.sql"
r1=$("$PG/psql" -h "$SOCK" -p "$PORT" -X -q -At -d pv_cancel -U pv_c_v -f "$DATA/cancel_r1.sql" 2>&1 \
     | grep -c "canceling statement due to statement timeout")
echo "round 1: $r1 of $N calls ended by their statement_timeout"
# Round 2: cancelled by another session of the same role (no superuser) at random times, 5 to 125 ms apart.
python3 -I -c '
import sys
for _ in range(int(sys.argv[1])): print(sys.argv[2])
' "$N" "$VERIFY" > "$DATA/cancel_r2.sql"
PGAPPNAME=pv_victim "$PG/psql" -h "$SOCK" -p "$PORT" -X -q -At -d pv_cancel -U pv_c_v -f "$DATA/cancel_r2.sql" \
    > "$DATA/cancel_r2.out" 2>&1 &
victim=$!
"$PG/psql" -h "$SOCK" -p "$PORT" -X -q -At -d pv_cancel -U pv_c_v >/dev/null 2>&1 <<'SQL' &
DO $$ BEGIN
  PERFORM pg_sleep(0.2);
  LOOP
    PERFORM pg_stat_clear_snapshot();
    EXIT WHEN NOT EXISTS (SELECT 1 FROM pg_stat_activity WHERE application_name = 'pv_victim');
    PERFORM pg_cancel_backend(pid) FROM pg_stat_activity
     WHERE application_name = 'pv_victim' AND state = 'active' AND query LIKE '%verify%';
    PERFORM pg_sleep(0.005 + random() * 0.12);
  END LOOP;
END $$;
SQL
canceller=$!
wait $victim
wait $canceller
r2=$(grep -c "canceling statement due to user request" "$DATA/cancel_r2.out")
echo "round 2: $r2 of $N calls cancelled by another session"
[ "$r1" -gt 0 ] && [ "$r2" -gt 0 ] || { echo "not ok - the calls were not cancelled (r1 $r1, r2 $r2)"; fallas=1; }
gone=$(grep -c "server closed the connection\|terminating connection because of crash" "$DATA/cancel_r2.out")
now_since=$(q -c "SELECT pg_postmaster_start_time()" 2>/dev/null)
bad=$(tail -c +"$((logfrom + 1))" "$DATA/server.log" | grep -E "PANIC|TRAP|stuck spinlock|terminated by signal|was terminated|all server processes terminated|leak" | head -5)
if [ "$now_since" = "$since" ] && [ "$(head -1 "$DATA/postmaster.pid")" = "$pm" ] && [ -z "$bad" ] && [ "$gone" = 0 ]; then
    echo "ok - $((r1 + r2)) cancelled calls: the server stayed up, nothing in its log"
else
    echo "not ok - the server did not survive the cancels: ${bad:-sessions ended ($gone)}"; fallas=1
fi
for _ in $(seq 1 100); do
    left=$(q -c "SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'pg_phasevec proof'" 2>/dev/null)
    [ "$left" = "0" ] && break
    python3 -I -c "import time; time.sleep(0.05)"
done
[ "$left" = "0" ] && echo "ok - no proof's session is left" || { echo "not ok - ${left:-?} proof sessions are left"; fallas=1; }
segs1=$(ls "$DATA/pg_dynshmem" 2>/dev/null | wc -l)
[ "$segs1" = "$segs0" ] && echo "ok - as many dynamic shared memory segments as before ($segs0)" \
    || { echo "not ok - dynamic shared memory segments: $segs0 before, $segs1 after"; fallas=1; }
all=$(q -c "SET ROLE pv_c_v" -c "SELECT count(*) FILTER (WHERE verdict = 'verified') FROM phasevec.verify('w1', 100, interval '0', interval '30 seconds', 5000)" 2>&1)
[ "$all" = "60" ] && echo "ok - after them, one verify() judges all 60 claims" || { echo "not ok - after them: $all"; fallas=1; }
rm -f "$DATA/cancel_r1.sql" "$DATA/cancel_r2.sql" "$DATA/cancel_r2.out"
exit $fallas
