#!/usr/bin/env bash
# 0.20.0 (seventeenth review): an author dropped after verify() read the claims (DROP OWNED and DROP ROLE in another
# session) makes no call fail; its claims are recorded 'unproven', every other author's are judged. Against the
# throwaway cluster of installcheck.sh (run that first), with the same PV_DATA/PV_PORT/PV_SOCK.
#   PG=~/pg19/bin test/truth_author_gone.sh
# In the sixteenth cut the message that the author may no longer read the table looked the dropped role up by OID and
# the whole verify() ended with "invalid role OID": no claim after it was judged, any author's.
set -uo pipefail
cd "$(dirname "$0")/.."
PG=${PG:-$HOME/pg19/bin}
DATA=${PV_DATA:-$PWD/.testcluster}
PORT=${PV_PORT:-5491}
SOCK=${PV_SOCK:-/tmp}
P=(-h "$SOCK" -p "$PORT" -X -q -At -d pv_gone)
export PGOPTIONS="-c client_min_messages=warning"
q() { "$PG/psql" "${P[@]}" "$@"; }
fallas=0
"$PG/pg_ctl" -D "$DATA" -o "-p $PORT -k $SOCK" -l "$DATA/server.log" -w start >/dev/null
"$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists pv_gone 2>/dev/null
"$PG/createdb" -h "$SOCK" -p "$PORT" pv_gone
q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
DROP ROLE IF EXISTS pv_gone_au;
DROP ROLE IF EXISTS pv_gone_a2;
CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register('r1', repeat('a', 64), 4);
CREATE ROLE pv_gone_au;
CREATE ROLE pv_gone_a2;
GRANT USAGE ON SCHEMA phasevec TO pv_gone_au, pv_gone_a2;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz) TO pv_gone_au, pv_gone_a2;
CREATE TABLE notes (id int PRIMARY KEY, body text);
INSERT INTO notes SELECT g, 'claim ' || g FROM generate_series(1, 50) g;
GRANT SELECT ON notes TO pv_gone_au, pv_gone_a2;
SELECT phasevec.watch('w', 'notes'::regclass, 'id', 'r.body', 'r1');
SET ROLE pv_gone_au;
SELECT count(phasevec.assert('w', g::text, 'true')) FROM generate_series(1, 40) g;
RESET ROLE;
SET ROLE pv_gone_a2;
SELECT count(phasevec.assert('w', g::text, 'true')) FROM generate_series(41, 50) g;
RESET ROLE;
SQL
out=$(mktemp -d /dev/shm/pv_gone.XXXXXX)
# verify() reads the claims, then waits for the watch; the author is dropped meanwhile
q -c "BEGIN" -c "LOCK phasevec.watches IN ACCESS EXCLUSIVE MODE" -c "SELECT pg_sleep(2)" -c "COMMIT" >/dev/null 2>&1 &
lpid=$!
sleep 0.3
q -c "SELECT count(*) FROM phasevec.verify('w', 100, '0')" > "$out/verify" 2>&1 &
vpid=$!
sleep 0.4
q -c "BEGIN" -c "DROP OWNED BY pv_gone_a2" -c "DROP ROLE pv_gone_a2" -c "COMMIT" > "$out/drop" 2>&1
wait $vpid $lpid
res=$(q -c "SELECT count(*) FILTER (WHERE key::int <= 40 AND verdict = 'verified'),
                   count(*) FILTER (WHERE key::int > 40 AND verdict = 'verified'),
                   count(*) FILTER (WHERE key::int > 40 AND verdict = 'unproven' AND last_error IS NOT NULL)
              FROM phasevec.truth")
IFS='|' read -r au a2v a2u <<< "$res"
echo "drop: $(cat "$out/drop"); verify: $(cat "$out/verify"); other author verified $au/40, dropped author verified $a2v, unproven $a2u"
if grep -q ERROR "$out/verify"; then
    echo "not ok - verify() failed: $(cat "$out/verify")"; fallas=1
elif [ "$au" = "40" ] && [ "$a2v" = "0" ]; then
    echo "ok - a dropped author makes no call fail, and nothing is judged in its name"
else
    echo "not ok - $res"; fallas=1
fi
rm -rf "$out"
"$PG/pg_ctl" -D "$DATA" -w stop >/dev/null
exit $fallas
