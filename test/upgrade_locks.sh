#!/usr/bin/env bash
# 0.20.0 (fourteenth review): ALTER EXTENSION UPDATE takes the extension's tables in the order its writers do. Against
# the throwaway cluster of installcheck.sh (run that first), with the same PV_DATA/PV_PORT/PV_SOCK. Builds 0.19.0
# (commit 65ae00d) aside, in a temporary directory, like upgrade_reconnect.sh.
#   PG=~/pg19/bin test/upgrade_locks.sh           (PV_ROUNDS=20)
# A writer takes the watched table, then phasevec.watches (the watch trigger reads its watch), then phasevec.truth (a
# trigger of the table that asserts). The update script of the thirteenth cut altered phasevec.truth, then
# phasevec.watches: a writer holding watches and on its way to truth, and the update holding truth and on its way to
# watches, deadlocked, and one of them was aborted. Now the script locks the extension's tables at its top, in the
# writers' order (watches, sources, lexstats, lexdocs, truth): the update waits for the writer, and neither fails.
# Each round: a 0.19.0 cluster with two watched tables, a writer (a session that loaded 0.19.0) that writes the first
# table, sleeps and writes the second (its SECURITY DEFINER trigger asserts), and the update started while it sleeps.
set -uo pipefail
cd "$(dirname "$0")/.."
PG=${PG:-$HOME/pg19/bin}
DATA=${PV_DATA:-$PWD/.testcluster}
PORT=${PV_PORT:-5491}
SOCK=${PV_SOCK:-/tmp}
ROUNDS=${PV_ROUNDS:-20}
V019=65ae00d
W=$(mktemp -d "${TMPDIR:-/tmp}/pv-lk.XXXXXX")
P=(-h "$SOCK" -p "$PORT" -X -q -At -d pv_lk)
export PGOPTIONS="-c client_min_messages=warning"

mkdir -p "$W/v019" "$W/lib"
GIT_INDEX_FILE="$W/index" git read-tree "$V019" && GIT_INDEX_FILE="$W/index" git --work-tree="$W/v019" checkout-index -a
make -s -C "$W/v019" PG_CONFIG="$PG/pg_config" >/dev/null 2>&1 || { echo "not ok - 0.19.0 does not build"; exit 1; }
ln -sfn "$PWD/src/pg_phasevec_observe.so" "$W/lib/pg_phasevec_observe.so"
LIBPATH="$W/lib:\$libdir"
export PGOPTIONS="$PGOPTIONS -c dynamic_library_path=$W/lib:\$libdir"
"$PG/pg_ctl" -D "$DATA" -o "-p $PORT -k $SOCK" -l "$DATA/server.log" -w start >/dev/null
trap '"$PG/pg_ctl" -D "$DATA" -w stop >/dev/null; rm -rf "$W"' EXIT
q() { "$PG/psql" "${P[@]}" "$@"; }
pause() { python3 -I -c "import time, sys; time.sleep(float(sys.argv[1]))" "$1"; }
fallas=0
dead=0
for r in $(seq 1 "$ROUNDS"); do
    ln -sfn "$W/v019/pg_phasevec.so" "$W/lib/pg_phasevec.so"
    "$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists pv_lk 2>/dev/null
    "$PG/createdb" -h "$SOCK" -p "$PORT" pv_lk
    q -v ON_ERROR_STOP=1 >/dev/null <<'SQL' || { echo "not ok - round $r: the 0.19.0 setup failed"; fallas=1; break; }
CREATE EXTENSION pg_phasevec VERSION '0.19.0';
SELECT phasevec.reader_register('r1', repeat('a', 64), 4);
CREATE TABLE notas (id int PRIMARY KEY, body text);
CREATE TABLE hallazgos (id int PRIMARY KEY, body text, prueba text);
INSERT INTO notas SELECT g, 'n' || g FROM generate_series(1, 20) g;
INSERT INTO hallazgos SELECT g, 'h' || g, 'true' FROM generate_series(1, 20) g;
SELECT phasevec.watch('notas', 'notas'::regclass, 'id', 'r.body', 'r1');
SELECT phasevec.watch('hallazgos', 'hallazgos'::regclass, 'id', 'r.body', 'r1');
CREATE FUNCTION public.hallazgo_verdad() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN PERFORM phasevec.assert('hallazgos', NEW.id::text, NEW.prueba); RETURN NEW; END $$;
CREATE TRIGGER hallazgos_verdad AFTER INSERT OR UPDATE ON public.hallazgos
FOR EACH ROW EXECUTE FUNCTION public.hallazgo_verdad();
UPDATE hallazgos SET body = body;
SQL
    # The writer: a session that loaded 0.19.0 (its first write), then the two writes, the update between them.
    PGAPPNAME=pv_lk_writer q -v ON_ERROR_STOP=1 >"$W/writer.out" 2>&1 <<'SQL' &
UPDATE notas SET body = body WHERE id = 1;
SELECT pg_sleep(0.6);
BEGIN;
UPDATE notas SET body = body || '.' WHERE id = 2;
SELECT pg_sleep(1.2);
UPDATE hallazgos SET body = body || '.' WHERE id = 3;
COMMIT;
SQL
    wr=$!
    pause 0.3
    ln -sfn "$PWD/pg_phasevec.so" "$W/lib/pg_phasevec.so"
    # the update starts once the writer holds phasevec.watches (its first write of the transaction)
    for _ in $(seq 1 200); do
        [ "$(q -c "SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a USING (pid) WHERE a.application_name = 'pv_lk_writer' AND a.xact_start IS NOT NULL AND a.wait_event = 'PgSleep' AND l.relation = 'phasevec.watches'::regclass AND l.granted AND a.query LIKE '%1.2%'")" = "1" ] && break
        pause 0.02
    done
    up=$(q -v ON_ERROR_STOP=1 -c "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" 2>&1)
    wait $wr
    wrote=$(grep -v '^$' "$W/writer.out")
    ver=$(q -c "SELECT extversion FROM pg_extension WHERE extname = 'pg_phasevec'")
    if [ -n "$up$wrote" ] || [ "$ver" != "0.20.0" ]; then
        case "$up$wrote" in *"deadlock detected"*) dead=$((dead + 1)) ;; esac
        echo "round $r: the update said '${up:0:120}', the writer said '${wrote:0:160}', version $ver"
        fallas=1
    fi
done
"$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists pv_lk 2>/dev/null
[ $fallas = 0 ] && echo "ok - $ROUNDS updates under a writer that holds watches on its way to truth: no deadlock, no failure" \
    || echo "not ok - $dead of $ROUNDS rounds deadlocked"
exit $fallas
