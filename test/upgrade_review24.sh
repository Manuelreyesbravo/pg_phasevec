#!/usr/bin/env bash
# 0.20.0 (twenty-fourth review): what the update locks, how it waits, and at what isolation it runs. Against the
# throwaway cluster of installcheck.sh (run that first), with the same PV_DATA/PV_PORT/PV_SOCK. Builds 0.19.0
# (commit 65ae00d) aside, like upgrade_writers.sh.
#   PG=~/pg19/bin test/upgrade_review24.sh
# 1. (RT24P-RR) Under REPEATABLE READ or SERIALIZABLE the update refuses to run, nothing changed. Until this review it
#    ran on the snapshot taken when ALTER EXTENSION began, before it waited for phasevec's tables: a refute()
#    committed meanwhile was missed, and the claim came back 'verified' after adopt() and verify().
# 2. (RT24P-DEP) Objects of a role with USAGE on phasevec that depend on functions the update drops (a view, a BEGIN
#    ATOMIC function): the update names every one at once, nothing changed. Until this review DROP FUNCTION named
#    one per run, after every watch was rendered.
# 3. (RT24P-DEP3) A transaction that made a view over phasevec._brief_keys(), then writes a watched table, during the
#    update, every session's deadlock_timeout at 20 ms: the transaction commits, and the update then stops on the
#    view, named, nothing changed. Until this review the update took the lock a COMMENT takes, not a DROP's, waited
#    at its DROP FUNCTION, and either stopped with a bare lock timeout or the writer was aborted as a deadlock (and
#    the update went on to 0.20.0).
# 4. (RT24P-LIVE) Steady writers of a watched table (4 clients) and steady readers of phasevec.truth (6 clients):
#    each of 6 updates, lock_timeout = 0, gets through (rolled back), and no writer or reader fails. Until this
#    review the update stopped after 50 tries in about a second ("never free at once in 50 tries").
# 5. The caller's lock_timeout and deadlock_timeout are its own again after the update.
set -uo pipefail
cd "$(dirname "$0")/.."
PG=${PG:-$HOME/pg19/bin}
DATA=${PV_DATA:-$PWD/.testcluster}
PORT=${PV_PORT:-5491}
SOCK=${PV_SOCK:-/tmp}
V019=65ae00d
W=$(mktemp -d "${TMPDIR:-/tmp}/pv-r24.XXXXXX")
P=(-h "$SOCK" -p "$PORT" -X -q -At -d pv_r24)
export PGOPTIONS="-c client_min_messages=warning"
mkdir -p "$W/v019" "$W/lib"
GIT_INDEX_FILE="$W/index" git read-tree "$V019" \
    && GIT_INDEX_FILE="$W/index" git --work-tree="$W/v019" checkout-index -a
make -s -C "$W/v019" PG_CONFIG="$PG/pg_config" >/dev/null 2>&1 || { echo "not ok - 0.19.0 does not build"; exit 1; }
ln -sfn "$PWD/src/pg_phasevec_observe.so" "$W/lib/pg_phasevec_observe.so"
export PGOPTIONS="$PGOPTIONS -c dynamic_library_path=$W/lib:\$libdir"
"$PG/pg_ctl" -D "$DATA" -o "-p $PORT -k $SOCK" -l "$DATA/server.log" -w start >/dev/null
trap '"$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists pv_r24 2>/dev/null; "$PG/pg_ctl" -D "$DATA" -w stop >/dev/null
      rm -rf "$W"' EXIT
q() { "$PG/psql" "${P[@]}" "$@"; }
qm() {
    PGOPTIONS="-c client_min_messages=warning" \
        "$PG/psql" -h "$SOCK" -p "$PORT" -X -q -At -d pv_r24 -U pv_r24_tenant "$@"
}
pause() { python3 -I -c "import time, sys; time.sleep(float(sys.argv[1]))" "$1"; }
fallas=0
ok() { echo "ok - $1"; }
nok() { echo "not ok - $1"; fallas=1; }
fresh() {
    ln -sfn "$W/v019/pg_phasevec.so" "$W/lib/pg_phasevec.so"
    "$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists pv_r24 2>/dev/null
    "$PG/createdb" -h "$SOCK" -p "$PORT" pv_r24
    q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE EXTENSION pg_phasevec VERSION '0.19.0';
SELECT phasevec.reader_register('r1', repeat('a', 64), 4);
CREATE TABLE notas (id int PRIMARY KEY, body text);
INSERT INTO notas SELECT g, 'n' || g FROM generate_series(1, 20) g;
SELECT phasevec.watch('notas', 'notas'::regclass, 'id', 'r.body', 'r1');
SELECT phasevec.assert('notas', k::text, 'SELECT true') FROM generate_series(1, 3) k;
DO $$BEGIN CREATE ROLE pv_r24_tenant LOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END$$;
DROP SCHEMA IF EXISTS m CASCADE;
CREATE SCHEMA m AUTHORIZATION pv_r24_tenant;
GRANT USAGE ON SCHEMA phasevec TO pv_r24_tenant;
SQL
    ln -sfn "$PWD/pg_phasevec.so" "$W/lib/pg_phasevec.so"
}
version() { q -c "SELECT extversion FROM pg_extension WHERE extname = 'pg_phasevec'"; }

# 1. REPEATABLE READ, SERIALIZABLE
for iso in 'repeatable read' serializable; do
    fresh
    up=$(PGOPTIONS="$PGOPTIONS -c default_transaction_isolation=${iso/ /\\ }" \
         q -c "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" 2>&1)
    if [ "$(version)" = "0.19.0" ] && grep -q "runs only at READ COMMITTED" <<<"$up"; then
        ok "the update refuses $iso, nothing changed"
    else
        nok "the update under $iso: version $(version), '${up:0:300}'"
    fi
done

# 2. committed dependents of functions the update drops
fresh
qm -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE VIEW m.v AS SELECT count(*) AS n FROM phasevec._brief_keys('x') k;
CREATE FUNCTION m.f() RETURNS bigint LANGUAGE sql
    BEGIN ATOMIC SELECT count(*) FROM phasevec._truth_due(1, 1, interval '1s'); END;
SQL
up=$(q -c "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" 2>&1)
if [ "$(version)" = "0.19.0" ] && grep -q "objects outside the extension depend on" <<<"$up" \
   && grep -q "view m.v depends on function phasevec._brief_keys(text)" <<<"$up" \
   && grep -q "function m.f() depends on function phasevec._truth_due(integer,integer,interval)" <<<"$up"; then
    ok "objects that depend on functions the update drops: all named at once, nothing changed"
else
    nok "dependents: version $(version), '${up:0:400}'"
fi
q -c "DROP VIEW m.v" -c "DROP FUNCTION m.f()"
up=$(q -c "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" 2>&1)
[ "$(version)" = "0.20.0" ] && ok "once they are dropped the update goes through" \
    || nok "after the dependents were dropped: version $(version), '${up:0:300}'"

# 3. an open transaction that made a view over a function the update drops, then writes a watched table
for nap in 0.6 1.2; do
    fresh
    q -c "GRANT SELECT, UPDATE ON notas TO pv_r24_tenant" \
      -c "GRANT EXECUTE ON FUNCTION phasevec._note(int, text, bytea, text) TO pv_r24_tenant"
    PGOPTIONS="$PGOPTIONS -c deadlock_timeout=20ms" q >"$W/t3.out" 2>&1 <<SQL &
SET ROLE pv_r24_tenant;
BEGIN;
CREATE VIEW m.v AS SELECT count(*) AS n FROM phasevec._brief_keys('x') k;
SELECT pg_sleep($nap);
UPDATE notas SET body = body || '!' WHERE id = 1;
COMMIT;
SQL
    tw=$!
    pause 0.3
    up=$(PGOPTIONS="$PGOPTIONS -c deadlock_timeout=20ms -c lock_timeout=0 -c statement_timeout=20s" \
         q -c "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" 2>&1)
    wait $tw
    if ! grep -qi "error" "$W/t3.out" && [ "$(q -c "SELECT body FROM notas WHERE id = 1")" = "n1!" ] \
       && [ "$(version)" = "0.19.0" ] \
       && grep -q "view m.v depends on function phasevec._brief_keys(text)" <<<"$up"; then
        ok "a view over a function the update drops, then a write ${nap}s later: the write commits, the view is named"
    else
        nok "view then write ${nap}s later: writer '$(tr '\n' ' ' <"$W/t3.out")', update '${up:0:300}', $(version)"
    fi
done

# 4. steady writers of a watched table and steady readers of phasevec.truth
fresh
printf '%s\n' '\set id random(1, 20)' 'BEGIN;' \
    "UPDATE notas SET body = 'n' || :id || '-' || (random() * 1000)::int WHERE id = :id;" 'SELECT pg_sleep(0.02);' \
    'COMMIT;' >"$W/w.sql"
printf '%s\n' 'BEGIN;' 'SELECT count(*) FROM phasevec.truth;' 'SELECT pg_sleep(0.05);' 'COMMIT;' >"$W/r.sql"
"$PG/pgbench" -h "$SOCK" -p "$PORT" -n -c 4 -T 50 -f "$W/w.sql" pv_r24 >"$W/pw.out" 2>&1 &
pw=$!
"$PG/pgbench" -h "$SOCK" -p "$PORT" -n -c 6 -T 50 -f "$W/r.sql" pv_r24 >"$W/pr.out" 2>&1 &
pr=$!
pause 2
through=0
other=""
for run in 1 2 3 4 5 6; do
    t0=$(date +%s.%N)
    out=$(PGOPTIONS="$PGOPTIONS -c lock_timeout=0 -c statement_timeout=30s" \
          q -c "BEGIN" -c "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" -c "SELECT 'through'" -c "ROLLBACK" 2>&1)
    took=$(python3 -I -c "import sys,time; print(round(time.time()-float(sys.argv[1]),2))" "$t0")
    case $out in *through*) through=$((through + 1)); other="$other ${took}s";; *) other="$other [${out:0:200}]";; esac
done
wait $pw $pr
failed=$(cat "$W/pw.out" "$W/pr.out" | sed -n 's/^number of failed transactions: \([0-9]*\).*/\1/p' | paste -sd+ | bc)
if [ "$through" = 6 ] && [ "${failed:-x}" = 0 ]; then
    ok "under steady writers and readers of phasevec.truth, 6 of 6 updates got through:$other; no client failed"
else
    nok "under writers and readers: $through of 6 through:$other; failed clients '${failed:-?}'"
fi

# 5. the caller's settings after the update
fresh
out=$(q -c "SET lock_timeout = '7s'" -c "SET deadlock_timeout = '777ms'" -c "BEGIN" \
        -c "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" -c "SHOW lock_timeout" -c "SHOW deadlock_timeout" \
        -c "COMMIT" -c "SHOW lock_timeout" -c "SHOW deadlock_timeout" 2>&1 | tr '\n' ' ')
if [ "$out" = "7s 777ms 7s 777ms " ] && [ "$(version)" = "0.20.0" ]; then
    ok "the caller's lock_timeout and deadlock_timeout come back after the update"
else
    nok "settings after the update: '$out', version $(version)"
fi
exit $fallas
