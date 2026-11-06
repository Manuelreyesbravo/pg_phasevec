#!/usr/bin/env bash
# 0.20.0 (seventeenth review): a verdict is recorded only for the claim it judged, and a claim's identity (phasevec._bind)
# tells every two author environments apart. Against the throwaway cluster of installcheck.sh (run that first), with
# the same PV_DATA/PV_PORT/PV_SOCK.
#   PG=~/pg19/bin test/truth_bind_race.sh
# In the sixteenth cut the settings were joined with a newline: {x.a=1, x.b=2} and {"x.a=1<newline>x.b=2"} bound
# alike. A claim re-asserted under the second while the first was judged was recorded, and served, 'verified', though
# its proof is false under it: through verify_one() (the author held the row) and through verify() (the claim was
# re-asserted while an earlier claim of the call was judged).
set -uo pipefail
cd "$(dirname "$0")/.."
PG=${PG:-$HOME/pg19/bin}
DATA=${PV_DATA:-$PWD/.testcluster}
PORT=${PV_PORT:-5491}
SOCK=${PV_SOCK:-/tmp}
P=(-h "$SOCK" -p "$PORT" -X -q -At -d pv_bind)
export PGOPTIONS="-c client_min_messages=warning"
q() { "$PG/psql" "${P[@]}" "$@"; }
fallas=0
"$PG/pg_ctl" -D "$DATA" -o "-p $PORT -k $SOCK" -l "$DATA/server.log" -w start >/dev/null
"$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists pv_bind 2>/dev/null
"$PG/createdb" -h "$SOCK" -p "$PORT" pv_bind
PROOF="current_setting('x.b', true) IS NOT DISTINCT FROM '2'"
q -v ON_ERROR_STOP=1 >/dev/null <<SQL
DROP ROLE IF EXISTS pv_bind_au;
CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register('r1', repeat('a', 64), 4);
CREATE ROLE pv_bind_au;
GRANT USAGE ON SCHEMA phasevec TO pv_bind_au;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz) TO pv_bind_au;
CREATE TABLE notes (id int PRIMARY KEY, body text);
INSERT INTO notes SELECT g, 'claim ' || g FROM generate_series(1, 4) g;
GRANT SELECT ON notes TO pv_bind_au;
SELECT phasevec.watch('w', 'notes'::regclass, 'id', 'r.body', 'r1');
UPDATE phasevec.watches SET max_age = '1 day' WHERE name = 'w';
SQL
asA() { q -c "SET ROLE pv_bind_au" -c "SET x.a = '1'" -c "SET x.b = '2'" -c "SELECT phasevec.assert('w', '$1', \$p\$$2\$p\$)" >/dev/null; }
out=$(mktemp -d /dev/shm/pv_bind.XXXXXX)

# 1. verify_one(): the author re-asserts key 1 under the colliding settings and holds the row; the worker waits for
#    it, and judges the claim it was sent.
asA 1 "$PROOF"
q -c "SET ROLE pv_bind_au" -c "SET x.a = E'1\\nx.b=2'" -c "BEGIN" -c "SELECT phasevec.assert('w', '1', \$p\$$PROOF\$p\$)" \
  -c "SELECT pg_sleep(2)" -c "COMMIT" > "$out/reassert1" 2>&1 &
apid=$!
sleep 0.7
q -c "SELECT phasevec.verify_one('w', '1', 5000)" > "$out/v1" 2>&1
wait $apid
r1=$(q -c "SELECT t.verdict || '/' || phasevec._verdict(t) FROM phasevec.truth t WHERE t.key = '1'")
echo "verify_one: $(cat "$out/v1"); key 1 now: $r1"
case $r1 in
  *verified*) echo "not ok - verify_one() recorded the verdict of one claim for another"; fallas=1 ;;
  *) echo "ok - verify_one() records nothing for a claim it did not judge" ;;
esac

# 2. verify(): key 2 is judged first and takes 1.5 s; key 3 is re-asserted under the colliding settings meanwhile;
#    key 4 is a control re-asserted under x.b = 3.
asA 2 "pg_sleep(1.5) IS NOT NULL"
asA 3 "$PROOF"
asA 4 "$PROOF"
q -c "SELECT key || '|' || verdict FROM phasevec.verify('w', 10, '0', p_timeout_ms => 5000) ORDER BY 1" > "$out/v2" 2>&1 &
vpid=$!
sleep 0.6
q -c "SET ROLE pv_bind_au" -c "SET x.a = E'1\\nx.b=2'" -c "SELECT phasevec.assert('w', '3', \$p\$$PROOF\$p\$)" >/dev/null
q -c "SET ROLE pv_bind_au" -c "SET x.a = '1'" -c "SET x.b = '3'" -c "SELECT phasevec.assert('w', '4', \$p\$$PROOF\$p\$)" >/dev/null
wait $vpid
r3=$(q -c "SELECT t.verdict || '/' || phasevec._verdict(t) FROM phasevec.truth t WHERE t.key = '3'")
echo "verify: $(tr '\n' ' ' < "$out/v2"); key 3 now: $r3"
case $r3 in
  *verified*) echo "not ok - verify() recorded the verdict of one claim for another"; fallas=1 ;;
  *) echo "ok - verify() records nothing for a claim it did not judge" ;;
esac
# judged now, both claims are what their settings say: false
again=$(q -c "SELECT string_agg(key || '|' || verdict, ' ' ORDER BY key) FROM phasevec.verify('w', 10, '0') WHERE key IN ('1', '3')")
echo "judged again: $again"
[ "$again" = "1|refuted 3|refuted" ] || { echo "not ok - judged again: $again"; fallas=1; }
left=$(q -c "SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'pg_phasevec proof'")
[ "$left" = "0" ] || { echo "not ok - $left proof workers are left"; fallas=1; }
rm -rf "$out"
"$PG/pg_ctl" -D "$DATA" -w stop >/dev/null
exit $fallas
