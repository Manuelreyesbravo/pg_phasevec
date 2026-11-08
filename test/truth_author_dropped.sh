#!/usr/bin/env bash
# 0.20.0 (sixteenth review): a proof is judged, and its verdict recorded, only while its author is a role. Against the
# throwaway cluster of installcheck.sh (run that first), with the same PV_DATA/PV_PORT/PV_SOCK.
#   PG=~/pg19/bin test/truth_author_dropped.sh
# In the fifteenth cut a verify() call whose author was dropped mid-call went on running that author's proofs in its
# session, and stamped 'verified' in the name of a role that no longer existed (about 20 of 40 claims, 2 s after the
# DROP ROLE committed).
set -uo pipefail
cd "$(dirname "$0")/.."
PG=${PG:-$HOME/pg19/bin}
DATA=${PV_DATA:-$PWD/.testcluster}
PORT=${PV_PORT:-5491}
SOCK=${PV_SOCK:-/tmp}
P=(-h "$SOCK" -p "$PORT" -X -q -At -d pv_drop)
export PGOPTIONS="-c client_min_messages=warning"
q() { "$PG/psql" "${P[@]}" "$@"; }
fallas=0
"$PG/pg_ctl" -D "$DATA" -o "-p $PORT -k $SOCK" -l "$DATA/server.log" -w start >/dev/null
"$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists pv_drop 2>/dev/null
"$PG/createdb" -h "$SOCK" -p "$PORT" pv_drop
q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
DROP ROLE IF EXISTS pv_drop_a;
CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register('r1', repeat('a', 64), 4);
CREATE ROLE pv_drop_a;
GRANT USAGE ON SCHEMA phasevec TO pv_drop_a;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz) TO pv_drop_a;
CREATE TABLE notes (id int PRIMARY KEY, body text);
INSERT INTO notes SELECT g, 'claim ' || g FROM generate_series(1, 40) g;
GRANT SELECT ON notes TO pv_drop_a;
GRANT UPDATE ON notes TO pv_drop_a;
SELECT phasevec.watch('w', 'notes'::regclass, 'id', 'r.body', 'r1');
SET ROLE pv_drop_a;
SELECT phasevec.assert('w', g::text, 'pg_sleep(0.1) IS NOT NULL') FROM generate_series(1, 40) g;
RESET ROLE;
SQL
out=$(mktemp -d)
q -c "SELECT count(*) FROM phasevec.verify('w', 40, '0', p_timeout_ms => 3000)" > "$out/verify" 2>&1 &
vpid=$!
sleep 1
q -c "BEGIN" -c "DROP OWNED BY pv_drop_a" -c "DROP ROLE pv_drop_a" -c "COMMIT" -c "SELECT clock_timestamp()" > "$out/drop" 2>&1
wait $vpid
dropped=$(tail -1 "$out/drop")
res=$(q -c "SELECT count(*) FILTER (WHERE verdict = 'verified' AND verified_at > '$dropped'),
                   count(*) FILTER (WHERE verdict = 'verified'),
                   count(*) FILTER (WHERE verdict = 'unproven' AND last_error LIKE '%dropped during the call%')
              FROM phasevec.truth")
IFS='|' read -r after verified gone <<< "$res"
echo "verify: $(cat "$out/verify"); dropped at $dropped; verified $verified (after the drop: $after), unproven as dropped: $gone"
if [ "$after" = "0" ] && [ "${gone:-0}" -gt 0 ]; then
    echo "ok - nothing is judged in the name of an author dropped during the call"
else
    echo "not ok - verdicts were stamped in the name of a dropped author ($res)"; fallas=1
fi
left=$(q -c "SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'pg_phasevec proof'")
[ "$left" = "0" ] || { echo "not ok - $left proof workers are left"; fallas=1; }
rm -rf "$out"
"$PG/pg_ctl" -D "$DATA" -w stop >/dev/null
exit $fallas
