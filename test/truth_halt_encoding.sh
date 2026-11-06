#!/usr/bin/env bash
# 0.20.0 (seventeenth review): a claim's key is named alike on both sides, whatever the database's encoding: the proof's
# session hashes it in UTF-8, as phasevec._truth_halted does. Against the throwaway cluster of installcheck.sh (run
# that first), with the same PV_DATA/PV_PORT/PV_SOCK.
#   PG=~/pg19/bin test/truth_halt_encoding.sh
# In the sixteenth cut the session hashed the bytes of the database's encoding: in a LATIN1 database a claim whose key
# has a character outside ASCII and whose proof ended its own session was never recorded halted (it ran again on
# every verify(), ending its session each time).
set -uo pipefail
cd "$(dirname "$0")/.."
PG=${PG:-$HOME/pg19/bin}
DATA=${PV_DATA:-$PWD/.testcluster}
PORT=${PV_PORT:-5491}
SOCK=${PV_SOCK:-/tmp}
P=(-h "$SOCK" -p "$PORT" -X -q -At -d pv_latin1)
export PGOPTIONS="-c client_min_messages=warning" PGCLIENTENCODING=UTF8
q() { "$PG/psql" "${P[@]}" "$@"; }
fallas=0
"$PG/pg_ctl" -D "$DATA" -o "-p $PORT -k $SOCK" -l "$DATA/server.log" -w start >/dev/null
"$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists pv_latin1 2>/dev/null
"$PG/createdb" -h "$SOCK" -p "$PORT" -E LATIN1 -T template0 --locale=C pv_latin1
q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register('r1', repeat('a', 64), 4);
CREATE FUNCTION public.end_my_session(pid int, timeout bigint DEFAULT 0) RETURNS boolean
    LANGUAGE internal STRICT VOLATILE AS 'pg_terminate_backend';
CREATE TABLE notes (k text PRIMARY KEY, body text);
INSERT INTO notes VALUES ('año', 'one'), ('plain', 'two');
SELECT phasevec.watch('w', 'notes'::regclass, 'k', 'r.body', 'r1');
SELECT phasevec.assert('w', 'año', 'public.end_my_session(pg_backend_pid())');
SELECT phasevec.assert('w', 'plain', 'public.end_my_session(pg_backend_pid())');
SQL
said=$(q -c "SELECT string_agg(key || ' ' || verdict, ', ' ORDER BY key) FROM phasevec.verify('w', 10, '0', p_timeout_ms => 5000)" 2>&1)
now=$(q -c "SELECT string_agg(key || ' ' || verdict || ' ' || halted, ', ' ORDER BY key) FROM phasevec.truth")
echo "verify said: $said; the claims are: $now"
[ "$now" = "año refuted true, plain refuted true" ] && echo "ok - a proof that ends its session is halted, whatever its key's characters" \
    || { echo "not ok - a claim was not halted ($now)"; fallas=1; }
"$PG/dropdb" -h "$SOCK" -p "$PORT" pv_latin1 2>/dev/null
"$PG/pg_ctl" -D "$DATA" -w stop >/dev/null
exit $fallas
