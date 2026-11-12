#!/usr/bin/env bash
# 0.20.0 (package review): what the round-30 red-team pass found that a first evaluator meets
# first. Against the throwaway cluster of installcheck.sh (run that first),
# with the same PV_DATA/PV_PORT/PV_SOCK. Builds 0.19.0 (commit 65ae00d) aside, like review28.sh.
#   PG=~/pg19/bin test/review30.sh
# 1. (RT29PL-2) pg_restore -j N of a database with watches, readings and claims brings back every
#    row of phasevec's tables, the same verdicts and the same coverage, as a plain restore does.
#    Until then the data of phasevec.truth, .sources and .readings was loaded in parallel with
#    phasevec.watches and failed on the extension's own foreign keys. DROP TABLE of a watched table
#    still takes every row of its watch along.
set -uo pipefail
cd "$(dirname "$0")/.."
PG=${PG:-$HOME/pg19/bin}
DATA=${PV_DATA:-$PWD/.testcluster}
PORT=${PV_PORT:-5491}
SOCK=${PV_SOCK:-/tmp}
V019=65ae00d
W=$(mktemp -d "${TMPDIR:-/tmp}/pv-r30.XXXXXX")
DBS="pv_r30 pv_r30_src pv_r30_j1 pv_r30_j2 pv_r30_j4 pv_r30_j8"
ROLES="pv_r30_own pv_r30_ta pv_r30_tb"
export PGOPTIONS="-c client_min_messages=warning"
mkdir -p "$W/v019" "$W/lib"
GIT_INDEX_FILE="$W/index" git read-tree "$V019" \
    && GIT_INDEX_FILE="$W/index" git --work-tree="$W/v019" checkout-index -a
make -s -C "$W/v019" PG_CONFIG="$PG/pg_config" >/dev/null 2>&1 \
    || { echo "not ok - 0.19.0 does not build"; exit 1; }
ln -sfn "$PWD/src/pg_phasevec_observe.so" "$W/lib/pg_phasevec_observe.so"
export PGOPTIONS="$PGOPTIONS -c dynamic_library_path=$W/lib:\$libdir"
"$PG/pg_ctl" -D "$DATA" -o "-p $PORT -k $SOCK" -l "$DATA/server.log" -w start >/dev/null
cleanup() {
    for d in $DBS; do "$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists "$d" 2>/dev/null; done
    for r in $ROLES; do qd postgres -c "DROP ROLE IF EXISTS $r" >/dev/null 2>&1; done
    "$PG/pg_ctl" -D "$DATA" -w stop >/dev/null
    rm -rf "$W"
}
trap cleanup EXIT
qd() { local d=$1; shift; "$PG/psql" -h "$SOCK" -p "$PORT" -X -q -At -d "$d" "$@"; }
q() { qd pv_r30 "$@"; }
qu() {
    local u=$1; shift
    PGOPTIONS="-c client_min_messages=warning" "$PG/psql" -h "$SOCK" -p "$PORT" -X -q -At -d pv_r30 -U "$u" "$@"
}
fallas=0
ok() { echo "ok - $*"; }
nok() { echo "not ok - $*"; fallas=1; }
use019() { ln -sfn "$W/v019/pg_phasevec.so" "$W/lib/pg_phasevec.so"; }
use020() { ln -sfn "$PWD/pg_phasevec.so" "$W/lib/pg_phasevec.so"; }
fresh() {   # fresh DB [VERSION]
    if [ "${2:-0.20.0}" = 0.19.0 ]; then use019; else use020; fi
    "$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists "$1" 2>/dev/null
    "$PG/createdb" -h "$SOCK" -p "$PORT" "$1"
    qd "$1" -v ON_ERROR_STOP=1 -v v="${2:-0.20.0}" >/dev/null <<'SQL'
CREATE EXTENSION pg_phasevec VERSION :'v';
SELECT phasevec.reader_register('r1', repeat('a', 64), 4);
SQL
}
for r in $ROLES; do
    qd postgres -c "DO \$\$BEGIN CREATE ROLE $r LOGIN;
                    EXCEPTION WHEN duplicate_object THEN NULL; END\$\$" >/dev/null
done

# 1. pg_restore -j N
fresh pv_r30_src
qd pv_r30_src -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE TABLE notas (id int PRIMARY KEY, body text);
INSERT INTO notas SELECT g, 'n' || g FROM generate_series(1, 200) g;
SELECT phasevec.watch('notas', 'notas'::regclass, 'id', 'r.body', 'r1');
SELECT count(phasevec.record('notas', n.key, 'r1', n.text_hash, n.key::bigint,
                             ARRAY[n.key::int % 7, n.key::int % 5, 3, 1]::smallint[]))
  FROM phasevec.next('notas') n WHERE n.key::int <= 150;
UPDATE notas SET body = body || ' edited' WHERE id <= 10;
SELECT phasevec.assert('notas', k::text, 'SELECT true', 'topic ' || (k % 3)) FROM generate_series(11, 30) k;
SELECT phasevec.assert('notas', k::text, 'SELECT false') FROM generate_series(31, 35) k;
SELECT phasevec.supersede('notas', '36', '37', 'merged');
SELECT phasevec.refute('notas', '38', 'wrong');
SELECT count(*) FROM phasevec.verify('notas', p_every => '0 s');
SELECT phasevec.lexical('notas', 'pg_catalog.simple');
SQL
SNAP="SELECT string_agg(t || '=' || n, ' ' ORDER BY t) FROM (
  SELECT 'readers' t, count(*) n FROM phasevec.readers UNION ALL
  SELECT 'watches', count(*) FROM phasevec.watches UNION ALL
  SELECT 'readings', count(*) FROM phasevec.readings UNION ALL
  SELECT 'sources', count(*) FROM phasevec.sources UNION ALL
  SELECT 'truth', count(*) FROM phasevec.truth UNION ALL
  SELECT 'lexdocs', count(*) FROM phasevec.lexdocs UNION ALL
  SELECT 'lexstats', count(*) FROM phasevec.lexstats UNION ALL
  SELECT 'counts', count(*) FROM phasevec.counts UNION ALL
  SELECT 'kstate', count(*) FROM phasevec.kstate) x"
VERD="SELECT string_agg(t.key || ':' || phasevec._verdict(t), ' ' ORDER BY t.key) FROM phasevec.truth t"
COV="SELECT string_agg(state || ':' || n, ' ' ORDER BY state) FROM phasevec.coverage('notas')"
CHK="SELECT count(*) FROM phasevec.coverage_check('notas')"
want="$(qd pv_r30_src -c "$SNAP")|$(qd pv_r30_src -c "$VERD")|$(qd pv_r30_src -c "$COV")"
"$PG/pg_dump" -h "$SOCK" -p "$PORT" -Fd -d pv_r30_src -f "$W/dump"
bad=""
for j in 1 2 4 8; do
    db=pv_r30_j$j
    "$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists "$db"; "$PG/createdb" -h "$SOCK" -p "$PORT" "$db"
    err=$("$PG/pg_restore" -h "$SOCK" -p "$PORT" -j $j -d "$db" "$W/dump" 2>&1); rc=$?
    got="$(qd $db -c "$SNAP")|$(qd $db -c "$VERD")|$(qd $db -c "$COV")"
    drift=$(qd $db -c "$CHK" 2>&1)
    if [ $rc -ne 0 ] || [ "$got" != "$want" ] || [ "$drift" != 0 ]; then
        bad="$bad [-j $j rc=$rc drift=$drift got '${got:0:160}' err '$(grep -m1 ERROR <<<"$err" | cut -c1-160)']"
    fi
done
# a watch's table dropped: nothing of the watch is left in any phasevec table
qd pv_r30_j8 -c "DROP TABLE notas" >/dev/null 2>&1
left=$(qd pv_r30_j8 -c "CREATE FUNCTION pg_temp.n(t text) RETURNS bigint LANGUAGE plpgsql AS
            \$f\$DECLARE n bigint; BEGIN EXECUTE format('SELECT count(*) FROM phasevec.%I', t) INTO n;
            RETURN n; END\$f\$" -c "SELECT string_agg(c.relname, ',') FROM pg_class c
         JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'watch' AND NOT a.attisdropped
        WHERE c.relnamespace = 'phasevec'::regnamespace AND c.relkind = 'r' AND pg_temp.n(c.relname) > 0")
if [ -z "$bad" ] && [ -z "$left" ]; then
    ok "pg_restore -j 1/2/4/8 brings back every row, verdict and count; DROP TABLE leaves nothing"
else
    nok "restore:$bad; left after DROP TABLE: '$left' (want '${want:0:160}')"
fi

exit $fallas
