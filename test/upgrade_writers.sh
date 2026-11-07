#!/usr/bin/env bash
# 0.20.0 (twentieth review, RT20M-3, RT20-CRASH-1/2, R21-MIND-3): ALTER EXTENSION UPDATE under the writers of watched
# tables. Against the throwaway cluster of installcheck.sh (run that first), with the same PV_DATA/PV_PORT/PV_SOCK.
# Builds 0.19.0 (commit 65ae00d) aside, like upgrade_locks.sh.
#   PG=~/pg19/bin test/upgrade_writers.sh
# 1. Steady short writers (pgbench, two clients, a 20 ms transaction each): the update finishes, and no writer fails.
#    In the nineteenth review's cut the update retried LOCK ... NOWAIT on the watched tables until all were free at
#    once, a moment these writers rarely leave: it ran into its statement_timeout (20 s here; how often depends on
#    the timing, once on an assertion-enabled 18 it got through in 3 s). Then the watch's TRUNCATE trigger, if the
#    update found the table busy, is made by phasevec.watch_truncate() while they write.
# 2. A writer idle in its transaction: the update with lock_timeout = 1s stops within it, named, and nothing changed.
#    In the nineteenth review's cut NOWAIT never waited, lock_timeout never applied, and it looped until the writer
#    ended (or, its client gone, committed later with no one watching).
# 3. A transaction that read phasevec, then writes a watched table, while the update waits for phasevec's tables: it
#    commits, and so does the update. In the nineteenth review's cut the update held the watched table and waited for
#    phasevec.watches, and the writer was aborted by the deadlock detector.
# 4. (twentieth review, second pass) A transaction that alters a watched table (ALTER TABLE, TRUNCATE) and then writes
#    it, while the update holds phasevec's tables: the update stops, named, nothing changed, and that transaction
#    commits; the update then goes through. In the first cut of this review the update read the table's shape under a
#    reader's lock it waited for, and the deadlock detector aborted the other transaction.
set -uo pipefail
cd "$(dirname "$0")/.."
PG=${PG:-$HOME/pg19/bin}
DATA=${PV_DATA:-$PWD/.testcluster}
PORT=${PV_PORT:-5491}
SOCK=${PV_SOCK:-/tmp}
V019=65ae00d
W=$(mktemp -d "${TMPDIR:-/tmp}/pv-uw.XXXXXX")
P=(-h "$SOCK" -p "$PORT" -X -q -At -d pv_uw)
export PGOPTIONS="-c client_min_messages=warning"
mkdir -p "$W/v019" "$W/lib"
GIT_INDEX_FILE="$W/index" git read-tree "$V019" && GIT_INDEX_FILE="$W/index" git --work-tree="$W/v019" checkout-index -a
make -s -C "$W/v019" PG_CONFIG="$PG/pg_config" >/dev/null 2>&1 || { echo "not ok - 0.19.0 does not build"; exit 1; }
ln -sfn "$PWD/src/pg_phasevec_observe.so" "$W/lib/pg_phasevec_observe.so"
export PGOPTIONS="$PGOPTIONS -c dynamic_library_path=$W/lib:\$libdir"
"$PG/pg_ctl" -D "$DATA" -o "-p $PORT -k $SOCK" -l "$DATA/server.log" -w start >/dev/null
trap '"$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists pv_uw 2>/dev/null; "$PG/pg_ctl" -D "$DATA" -w stop >/dev/null; rm -rf "$W"' EXIT
q() { "$PG/psql" "${P[@]}" "$@"; }
pause() { python3 -I -c "import time, sys; time.sleep(float(sys.argv[1]))" "$1"; }
fallas=0
ok() { echo "ok - $1"; }
nok() { echo "not ok - $1"; fallas=1; }
fresh() {
    ln -sfn "$W/v019/pg_phasevec.so" "$W/lib/pg_phasevec.so"
    "$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists pv_uw 2>/dev/null
    "$PG/createdb" -h "$SOCK" -p "$PORT" pv_uw
    q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE EXTENSION pg_phasevec VERSION '0.19.0';
SELECT phasevec.reader_register('r1', repeat('a', 64), 4);
CREATE TABLE notas (id int PRIMARY KEY, body text);
CREATE TABLE hallazgos (id int PRIMARY KEY, body text);
INSERT INTO notas SELECT g, 'n' || g FROM generate_series(1, 20) g;
INSERT INTO hallazgos SELECT g, 'h' || g FROM generate_series(1, 20) g;
SELECT phasevec.watch('notas', 'notas'::regclass, 'id', 'r.body', 'r1');
SELECT phasevec.watch('hallazgos', 'hallazgos'::regclass, 'id', 'r.body', 'r1');
SQL
}
version() { q -c "SELECT extversion FROM pg_extension WHERE extname = 'pg_phasevec'"; }
truncate_triggers() { q -c "SELECT count(*) FROM pg_trigger WHERE tgname LIKE 'phasevec\_watch\_%\_truncate'"; }

# 1. steady short writers
fresh
printf '%s\n' '\set id random(1, 20)' 'BEGIN;' 'UPDATE notas SET body = body WHERE id = :id;' 'SELECT pg_sleep(0.02);' \
    'COMMIT;' >"$W/w.sql"
"$PG/pgbench" -h "$SOCK" -p "$PORT" -n -C -c 2 -T 30 -f "$W/w.sql" pv_uw >"$W/pgb.out" 2>&1 &
pb=$!
pause 2
ln -sfn "$PWD/pg_phasevec.so" "$W/lib/pg_phasevec.so"
t0=$(date +%s.%N)
up=$(PGOPTIONS="$PGOPTIONS -c statement_timeout=20s -c client_min_messages=warning" \
     q -c "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" 2>&1)
t1=$(date +%s.%N)
made=$(PGOPTIONS="$PGOPTIONS -c lock_timeout=10s" q -c "SELECT phasevec.watch_truncate(name) FROM phasevec.watches WHERE name = 'notas'" 2>&1)
wait $pb
failed=$(sed -n 's/^number of failed transactions: \([0-9]*\).*/\1/p' "$W/pgb.out")
took=$(python3 -I -c "import sys; print(round(float(sys.argv[2]) - float(sys.argv[1]), 2))" "$t0" "$t1")
if [ "$(version)" = "0.20.0" ] && [ "${failed:-x}" = "0" ] && [ "$(truncate_triggers)" = "2" ] \
   && { [ "$made" = "t" ] || [ "$made" = "f" ]; }; then
    ok "the update under steady short writers took ${took}s, no writer failed, both TRUNCATE triggers made (watch_truncate: $made)"
else
    nok "under writers: version $(version), update '${up:0:200}' in ${took}s, failed writers '${failed:-?}', triggers $(truncate_triggers), watch_truncate '$made'"
fi

# 2. a writer idle in its transaction, and lock_timeout
fresh
q >/dev/null 2>&1 <<'SQL' &
BEGIN;
UPDATE hallazgos SET body = body WHERE id = 1;
SELECT pg_sleep(6);
COMMIT;
SQL
wr=$!
pause 0.5
ln -sfn "$PWD/pg_phasevec.so" "$W/lib/pg_phasevec.so"
t0=$(date +%s.%N)
up=$(PGOPTIONS="$PGOPTIONS -c lock_timeout=1s -c statement_timeout=15s" \
     q -c "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" 2>&1)
t1=$(date +%s.%N)
ver=$(version)
wait $wr
took=$(python3 -I -c "import sys; print(round(float(sys.argv[2]) - float(sys.argv[1]), 2))" "$t0" "$t1")
case "$up" in
    *"could not take phasevec's tables within lock_timeout"*)
        if [ "$ver" = "0.19.0" ] && python3 -I -c "import sys; sys.exit(0 if float(sys.argv[1]) < 4 else 1)" "$took"; then
            ok "the update stops within lock_timeout behind a writer idle in its transaction (${took}s), nothing changed"
        else
            nok "lock_timeout: version $ver after ${took}s"
        fi ;;
    *) nok "lock_timeout: the update said '${up:0:200}' after ${took}s, version $ver" ;;
esac

# 3. a transaction that read phasevec, then writes a watched table
fresh
q >"$W/rw.out" 2>&1 <<'SQL' &
BEGIN;
SELECT count(*) FROM phasevec.watches;
SELECT pg_sleep(1.5);
INSERT INTO notas VALUES (100, 'new');
COMMIT;
SQL
rw=$!
pause 0.5
ln -sfn "$PWD/pg_phasevec.so" "$W/lib/pg_phasevec.so"
up=$(PGOPTIONS="$PGOPTIONS -c statement_timeout=20s -c deadlock_timeout=300ms" \
     q -c "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" 2>&1)
wait $rw
if [ "$(version)" = "0.20.0" ] && ! grep -q -i "error\|deadlock" "$W/rw.out" && [ -z "$(echo "$up" | grep -i 'error')" ] \
   && [ "$(q -c "SELECT count(*) FROM notas WHERE id = 100")" = "1" ]; then
    ok "a transaction that read phasevec and then writes a watched table commits during the update"
else
    nok "read then write: writer '$(tr '\n' ' ' <"$W/rw.out")', update '${up:0:200}', version $(version)"
fi

# 4. a transaction that alters a watched table, then writes it
for ddl in "ALTER TABLE hallazgos ADD COLUMN x int" "TRUNCATE hallazgos"; do
    fresh
    q >"$W/ddl.out" 2>&1 <<SQL &
BEGIN;
$ddl;
SELECT pg_sleep(1.5);
INSERT INTO hallazgos (id, body) VALUES (100, 'new');
COMMIT;
SQL
    dw=$!
    pause 0.5
    ln -sfn "$PWD/pg_phasevec.so" "$W/lib/pg_phasevec.so"
    up=$(PGOPTIONS="$PGOPTIONS -c statement_timeout=20s -c deadlock_timeout=300ms" \
         q -c "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" 2>&1)
    ver=$(version)
    wait $dw
    again=$(PGOPTIONS="$PGOPTIONS -c statement_timeout=20s" q -c "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" 2>&1)
    if [ "$ver" = "0.19.0" ] && echo "$up" | grep -q "being altered by another session" \
       && ! grep -q -i "error\|deadlock" "$W/ddl.out" && [ "$(q -c "SELECT count(*) FROM hallazgos WHERE id = 100")" = "1" ] \
       && [ "$(version)" = "0.20.0" ] && [ -z "$(echo "$again" | grep -i 'error')" ]; then
        ok "${ddl%% *} of a watched table, then a write, during the update: the update stops named, that transaction commits"
    else
        nok "${ddl%% *} then write: writer '$(tr '\n' ' ' <"$W/ddl.out")', update '${up:0:200}' at $ver, again '${again:0:200}'"
    fi
done
exit $fallas
