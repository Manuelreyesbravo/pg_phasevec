#!/usr/bin/env bash
# 0.20.0 lives in a UTF8 database only (eighteenth review): CREATE EXTENSION and the update from 0.19.0 refuse a database
# in any other encoding, and in a UTF8 one a claim's key and identity are the bytes of their text, the same on both
# sides. Against the throwaway cluster of installcheck.sh (run that first), with the same PV_DATA/PV_PORT/PV_SOCK.
#   PG=~/pg19/bin test/truth_halt_encoding.sh
# In the sixteenth cut the proof's session hashed a halted key in the database's encoding and _truth_halted in UTF-8:
# in a LATIN1 database a claim whose key had a character outside ASCII and whose proof ended its own session was never
# recorded halted. In the seventeenth both converted to UTF-8, which raises for a byte with no UTF-8 equivalent: in
# SQL_ASCII (0xe9) and WIN1252 (0x81) one author's assert() stopped verify() for the whole watch, refute() could not
# retire it, and a halt was never recorded.
set -uo pipefail
cd "$(dirname "$0")/.."
PG=${PG:-$HOME/pg19/bin}
DATA=${PV_DATA:-$PWD/.testcluster}
PORT=${PV_PORT:-5491}
SOCK=${PV_SOCK:-/tmp}
export PGOPTIONS="-c client_min_messages=warning" PGCLIENTENCODING=UTF8
q() { local d=$1; shift; "$PG/psql" -h "$SOCK" -p "$PORT" -X -q -At -d "$d" "$@"; }
fallas=0
"$PG/pg_ctl" -D "$DATA" -o "-p $PORT -k $SOCK" -l "$DATA/server.log" -w start >/dev/null
for enc in LATIN1 SQL_ASCII WIN1252; do
    db=pv_enc_$(echo "$enc" | tr 'A-Z' 'a-z')
    "$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists "$db" 2>/dev/null
    "$PG/createdb" -h "$SOCK" -p "$PORT" -E "$enc" -T template0 --locale=C "$db"
    made=$(q "$db" -c "CREATE EXTENSION pg_phasevec" 2>&1)
    up=$(q "$db" -c "CREATE EXTENSION pg_phasevec VERSION '0.19.0'" -c "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" 2>&1)
    v=$(q "$db" -c "SELECT extversion FROM pg_extension WHERE extname = 'pg_phasevec'")
    echo "$enc: create -> $made; update -> $up; version $v"
    if echo "$made" | grep -q "needs a UTF8 database" && echo "$up" | grep -q "needs a UTF8 database" && [ "$v" = "0.19.0" ]; then
        echo "ok - a $enc database: CREATE EXTENSION and the update to 0.20.0 refuse it"
    else
        echo "not ok - a $enc database was given 0.20.0"; fallas=1
    fi
    "$PG/dropdb" -h "$SOCK" -p "$PORT" "$db" 2>/dev/null
done
# In UTF8: a key outside ASCII whose proof ends its session is halted, and a proof and a setting outside ASCII judge.
"$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists pv_enc_utf8 2>/dev/null
"$PG/createdb" -h "$SOCK" -p "$PORT" -E UTF8 -T template0 --locale=C pv_enc_utf8
q pv_enc_utf8 -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register('r1', repeat('a', 64), 4);
CREATE FUNCTION public.end_my_session(pid int, timeout bigint DEFAULT 0) RETURNS boolean
    LANGUAGE internal STRICT VOLATILE AS 'pg_terminate_backend';
CREATE TABLE notes (k text PRIMARY KEY, body text);
INSERT INTO notes VALUES ('año', 'one'), ('plain', 'two'), ('café', 'three'), ('good', 'four');
SELECT phasevec.watch('w', 'notes'::regclass, 'k', 'r.body', 'r1');
SELECT phasevec.assert('w', 'año', 'public.end_my_session(pg_backend_pid())');
SELECT phasevec.assert('w', 'plain', 'public.end_my_session(pg_backend_pid())');
SET app.note = 'café ☕';
SELECT phasevec.assert('w', 'café', $p$'é' <> 'e' AND current_setting('app.note') = 'café ☕' /* ñ */$p$);
RESET app.note;
SELECT phasevec.assert('w', 'good', 'SELECT true');
SQL
said=$(q pv_enc_utf8 -c "SELECT string_agg(key || ' ' || verdict, ', ' ORDER BY key) FROM phasevec.verify('w', 10, '0', p_timeout_ms => 5000)" 2>&1)
now=$(q pv_enc_utf8 -c "SELECT string_agg(key || ' ' || verdict || ' ' || halted, ', ' ORDER BY key) FROM phasevec.truth")
echo "verify said: $said; the claims are: $now"
[ "$now" = "año refuted true, café verified false, good verified false, plain refuted true" ] \
    && echo "ok - in UTF8 a proof that ends its session is halted whatever its key's characters, and one outside ASCII judges" \
    || { echo "not ok - a claim was not halted or judged ($now)"; fallas=1; }
"$PG/dropdb" -h "$SOCK" -p "$PORT" pv_enc_utf8 2>/dev/null
"$PG/pg_ctl" -D "$DATA" -w stop >/dev/null
exit $fallas
