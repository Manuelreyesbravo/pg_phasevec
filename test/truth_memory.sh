#!/usr/bin/env bash
# 0.20.0 (fifteenth review): a verifier's session does not grow with its calls. Against the throwaway cluster of
# installcheck.sh (run that first), with the same PV_DATA/PV_PORT/PV_SOCK; the cluster is started twice, once with
# each kind of dynamic shared memory this machine has (mmap and posix).
#   PG=~/pg19/bin test/truth_memory.sh
# In the fourteenth cut every verify_one() started its proof's session in TopMemoryContext: dsm_create() with
# dynamic_shared_memory_type = mmap leaves a zeroed buffer of 8 kB in the current context, and the worker's name
# was looked up into a new string there. 1000 calls left 8.2 MB (mmap) or 24 kB (posix) behind, for as long as the
# session lived. Now only what the session keeps is in TopMemoryContext.
set -uo pipefail
cd "$(dirname "$0")/.."
PG=${PG:-$HOME/pg19/bin}
DATA=${PV_DATA:-$PWD/.testcluster}
PORT=${PV_PORT:-5491}
SOCK=${PV_SOCK:-/tmp}
CALLS=${PV_CALLS:-1000}
P=(-h "$SOCK" -p "$PORT" -X -q -At -d pv_mem)
export PGOPTIONS="-c client_min_messages=warning"
q() { "$PG/psql" "${P[@]}" "$@"; }
fallas=0
for dsm in mmap posix; do
    "$PG/pg_ctl" -D "$DATA" -o "-p $PORT -k $SOCK -c dynamic_shared_memory_type=$dsm" -l "$DATA/server.log" -w start >/dev/null
    "$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists pv_mem 2>/dev/null
    "$PG/createdb" -h "$SOCK" -p "$PORT" pv_mem
    q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
DROP ROLE IF EXISTS pv_mem_a;
CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register('r1', repeat('a', 64), 4);
CREATE ROLE pv_mem_a;
GRANT USAGE ON SCHEMA phasevec TO pv_mem_a;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz) TO pv_mem_a;
CREATE TABLE notes (id int PRIMARY KEY, body text);
INSERT INTO notes SELECT i, 'claim ' || i FROM generate_series(1, 50) i;
GRANT SELECT ON notes TO pv_mem_a;
GRANT UPDATE ON notes TO pv_mem_a;
SELECT phasevec.watch('w', 'notes'::regclass, 'id', 'r.body', 'r1');
SET ROLE pv_mem_a;
SELECT phasevec.assert('w', i::text, 'true') FROM generate_series(1, 50) i;
RESET ROLE;
CREATE FUNCTION tm() RETURNS bigint LANGUAGE sql AS
 $$ SELECT used_bytes FROM pg_backend_memory_contexts WHERE name = 'TopMemoryContext' $$;
SQL
    out=$(q -v calls="$CALLS" <<'SQL'
DO $$ BEGIN FOR i IN 1..20 LOOP PERFORM phasevec.verify_one('w', (1 + i % 50)::text, 5000); END LOOP;
    FOR i IN 1..3 LOOP PERFORM count(*) FROM phasevec.verify('w', 100, '0', p_timeout_ms => 5000); END LOOP; END $$;
SELECT tm() AS before \gset
SELECT set_config('pv.calls', :'calls', false) \g /dev/null
DO $$ BEGIN FOR i IN 1..current_setting('pv.calls')::int LOOP
    PERFORM phasevec.verify_one('w', (1 + i % 50)::text, 5000); END LOOP; END $$;
SELECT tm() - :before;
SELECT tm() AS before \gset
DO $$ BEGIN FOR i IN 1..20 LOOP PERFORM count(*) FROM phasevec.verify('w', 100, '0', p_timeout_ms => 5000); END LOOP; END $$;
SELECT tm() - :before;
SQL
)
    one=$(echo "$out" | sed -n 1p); all=$(echo "$out" | sed -n 2p)
    echo "dynamic_shared_memory_type = $dsm: TopMemoryContext grew $one bytes over $CALLS verify_one() calls, $all over 20 verify() of 50 claims"
    # flat: under 4 bytes a call (the leak was 8 kB a call with mmap, 24 bytes with posix)
    if [ -n "$one" ] && [ "$one" -lt $((CALLS * 4)) ] && [ -n "$all" ] && [ "$all" -lt 4096 ]; then
        echo "ok - $dsm: a verifier's session keeps nothing per call"
    else
        echo "not ok - $dsm: a verifier's session grows with its calls ($out)"; fallas=1
    fi
    left=$(q -c "SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'pg_phasevec proof'")
    [ "$left" = "0" ] || { echo "not ok - $left proof workers are left"; fallas=1; }
    "$PG/pg_ctl" -D "$DATA" -w stop >/dev/null
done
exit $fallas
