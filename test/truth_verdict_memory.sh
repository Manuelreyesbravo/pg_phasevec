#!/usr/bin/env bash
# 0.20.0 (sixteenth review): one query that reads the verdicts of many watches in turn does not grow with its rows.
# Against the throwaway cluster of installcheck.sh (run that first), with the same PV_DATA/PV_PORT/PV_SOCK.
#   PG=~/pg19/bin test/truth_verdict_memory.sh
# In the fifteenth cut _verdict(t) kept, per query, 16 watches; a query whose rows came from 17 or more watches in
# turn (ORDER BY key over phasevec.truth) missed on every row, and each miss left a copy of the watch (its recipe,
# its statement) in the query's memory: ~0.8 kB a row, 1 GB for 40000 rows of 20 watches with an 8 kB recipe.
set -uo pipefail
cd "$(dirname "$0")/.."
PG=${PG:-$HOME/pg19/bin}
DATA=${PV_DATA:-$PWD/.testcluster}
PORT=${PV_PORT:-5491}
SOCK=${PV_SOCK:-/tmp}
WATCHES=${PV_WATCHES:-20}
P=(-h "$SOCK" -p "$PORT" -X -q -At -d pv_vmem)
export PGOPTIONS="-c client_min_messages=warning"
q() { "$PG/psql" "${P[@]}" "$@"; }
fallas=0
"$PG/pg_ctl" -D "$DATA" -o "-p $PORT -k $SOCK" -l "$DATA/server.log" -w start >/dev/null
"$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists pv_vmem 2>/dev/null
"$PG/createdb" -h "$SOCK" -p "$PORT" pv_vmem
q -v ON_ERROR_STOP=1 -v watches="$WATCHES" >/dev/null <<'SQL'
DROP ROLE IF EXISTS pv_vmem_r;
CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register('r1', repeat('a', 64), 4);
CREATE ROLE pv_vmem_r;
GRANT USAGE ON SCHEMA phasevec TO pv_vmem_r;
GRANT SELECT ON phasevec.truth TO pv_vmem_r;
SELECT set_config('pv.watches', :'watches', false);
DO $$
BEGIN
    FOR i IN 1..current_setting('pv.watches')::int LOOP
        EXECUTE format('CREATE TABLE t%s (id int PRIMARY KEY, body text)', i);
        EXECUTE format('INSERT INTO t%s SELECT g, ''row '' || g FROM generate_series(1, 2000) g', i);
        EXECUTE format('GRANT SELECT ON t%s TO pv_vmem_r', i);
        -- a long recipe (a comment of 4 kB): what each miss copied
        PERFORM phasevec.watch('w' || i, format('t%s', i)::regclass, 'id',
                               'r.body /* ' || repeat('x', 4000) || ' */', 'r1');
        PERFORM phasevec.assert('w' || i, g::text, 'true') FROM generate_series(1, 2000) g;
    END LOOP;
END $$;
SQL
# peak memory of a new session after one query over the first n keys of every watch, in turn (key, then watch)
peak() {
    q -v n="$1" <<'SQL'
SET ROLE pv_vmem_r;
SELECT count(phasevec._verdict(t)) FROM (SELECT * FROM phasevec.truth WHERE key::int <= :n ORDER BY key::int, watch) t \g /dev/null
RESET ROLE;
SELECT substring(pg_read_file('/proc/self/status') FROM 'VmHWM:\s*([0-9]+)')::bigint;
SQL
}
small=$(peak 250); large=$(peak 2000)
grew=$(( large - small ))
echo "_verdict over $WATCHES watches in turn: peak $small kB at $((WATCHES * 250)) rows, $large kB at $((WATCHES * 2000)) rows"
if [ -n "$small" ] && [ -n "$large" ] && [ "$grew" -lt 8192 ]; then
    echo "ok - one query's verdicts over many watches do not grow with its rows (+$grew kB)"
else
    echo "not ok - one query's verdicts grow with its rows (+$grew kB)"; fallas=1
fi
"$PG/pg_ctl" -D "$DATA" -w stop >/dev/null
exit $fallas
