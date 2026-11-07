#!/usr/bin/env bash
# 0.20.0 (nineteenth review, RT19-CRASH-1): DROP TABLE of watched tables while verify() and verify_one() read them
# ends in the shape refusal ("watch w cannot be read: ...: the table is gone"), never in an internal error. Against
# the throwaway cluster of installcheck.sh (run that first), with the same PV_DATA/PV_PORT/PV_SOCK.
#   PG=~/pg19/bin test/truth_drop_race.sh           (PV_SECONDS=20)
# In the eighteenth cut the lockless shape check opened the table's relcache entry while the DROP committed ("relation
# N deleted while still in use", "pg_attribute catalog is missing 3 attribute(s)": XX000), and the verifier's
# privilege check raised "relation with OID N does not exist".
set -uo pipefail
cd "$(dirname "$0")/.."
PG=${PG:-$HOME/pg19/bin}
DATA=${PV_DATA:-$PWD/.testcluster}
PORT=${PV_PORT:-5491}
SOCK=${PV_SOCK:-/tmp}
SECONDS_RUN=${PV_SECONDS:-20}
P=(-h "$SOCK" -p "$PORT" -X -q -At -d pv_dropr)
export PGOPTIONS="-c client_min_messages=warning"
q() { "$PG/psql" "${P[@]}" "$@"; }
fallas=0
"$PG/pg_ctl" -D "$DATA" -o "-p $PORT -k $SOCK" -l "$DATA/server.log" -w start >/dev/null
"$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists pv_dropr 2>/dev/null
"$PG/createdb" -h "$SOCK" -p "$PORT" pv_dropr
q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register('r1', repeat('a', 64), 4);
SQL
out=$(mktemp -d /dev/shm/pv_dropr.XXXXXX)
end=$(( $(date +%s) + SECONDS_RUN ))
churn() {
    local n=$1
    while [ "$(date +%s)" -lt "$end" ]; do
        q >/dev/null 2>>"$out/churn$n" <<SQL
CREATE TABLE IF NOT EXISTS n$n (id int PRIMARY KEY, body text);
INSERT INTO n$n VALUES (1, 'one') ON CONFLICT DO NOTHING;
SELECT phasevec.watch('w$n', 'n$n'::regclass, 'id', 'r.body', 'r1')
 WHERE NOT EXISTS (SELECT 1 FROM phasevec.watches WHERE name = 'w$n');
SELECT phasevec.assert('w$n', '1', 'true');
SELECT pg_sleep(random() * 0.02);
ALTER TABLE n$n ADD COLUMN z int;
ALTER TABLE n$n DROP COLUMN z;
DROP TABLE n$n;
SQL
    done
}
verifier() {
    local n=$1
    while [ "$(date +%s)" -lt "$end" ]; do
        q -c "SELECT phasevec.verify_one('w$n', '1')" -c "SELECT count(*) FROM phasevec.verify('w$n', 5, '0')" \
          >/dev/null 2>>"$out/verify$n"
    done
}
churn A & churn B & verifier A & verifier A & verifier B & verifier B &
wait
cat "$out"/verify* > "$out/all"
internal=$(grep -c -E "deleted while still in use|catalog is missing|relation with OID" "$out/all")
gone=$(grep -c "the table is gone" "$out/all")
xx=$(grep -c -E "XX000|deleted while still in use|catalog is missing" "$DATA/server.log")
echo "in ${SECONDS_RUN}s: $gone refusals 'the table is gone', $internal internal errors at the verifiers"
if [ "$internal" -eq 0 ]; then
    echo "ok - a concurrent DROP TABLE is the shape refusal, not an internal error"
else
    grep -E "deleted while still in use|catalog is missing|relation with OID" "$out/all" | sort | uniq -c | head -5
    fallas=1
    echo "not ok - $internal internal errors"
fi
rm -rf "$out"
"$PG/dropdb" -h "$SOCK" -p "$PORT" pv_dropr
"$PG/pg_ctl" -D "$DATA" -w stop >/dev/null
exit $fallas
