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
# 2. (RT29PA-DEAD-LEAK) recall() shows nothing of a dead claim (one tenant's topic and support,
#    about its deleted row) to the tenant whose new row is under the key.
# 3. (RT29PA-DEAD-VERDICT) A dead claim that read 'replaced' or 'expired' hides the next tenant's
#    rows under its keys from no one: brief(), _verdict(), truth_coverage(), find().
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

# 2 and 3: tenants on one table (ta: rows 1-10, tb: 11-20), owned by pv_r30_own
fresh pv_r30
q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
-- search() needs a reader process. It answers here with what the real one answered: the stub of
-- test/sql/truth_sealed.sql (6), copied verbatim (test/search_capture.sh).
CREATE OR REPLACE FUNCTION phasevec.search(p_watch text, p_question text, p_k int DEFAULT 10, p_partial boolean DEFAULT false,
                                           p_m int DEFAULT 200, p_nprobe int DEFAULT 16)
RETURNS TABLE (key text, score double precision, hamming int, state text, familiarity real, read_at timestamptz,
               truncated boolean)
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $f$
BEGIN
    IF p_watch <> 'hr' OR p_question <> 'salary' OR p_partial OR p_k < 5 THEN
        RAISE EXCEPTION 'phasevec: search(%, %, %, %) was not captured', p_watch, p_question, p_k, p_partial;
    END IF;
    RETURN QUERY SELECT c.* FROM (VALUES
        ('1', 0.7175652430905612::float8, 67, 'fresh', NULL::real, '2026-11-06 03:47:49.020802+00'::timestamptz, false),
        ('2', 0.6675326958141382::float8, 64, 'fresh', NULL::real, '2026-11-06 03:47:49.064404+00'::timestamptz, false),
        ('4', 0.5207186769014545::float8, 76, 'fresh', NULL::real, '2026-11-06 03:47:49.138397+00'::timestamptz, false),
        ('5', 0.4808439675481502::float8, 76, 'fresh', NULL::real, '2026-11-06 03:47:49.178036+00'::timestamptz, false),
        ('3', 0.4492523064285821::float8, 77, 'fresh', NULL::real, '2026-11-06 03:47:49.104384+00'::timestamptz, false))
        c(key, score, hamming, state, familiarity, read_at, truncated);
END $f$;
CREATE TABLE hr (id int PRIMARY KEY, owner_name name NOT NULL, body text);
ALTER TABLE hr OWNER TO pv_r30_own;
INSERT INTO hr VALUES (1, 'pv_r30_ta', 'alice: the salary review is done'),
                      (2, 'pv_r30_ta', 'bob: the salary review is not done'),
                      (3, 'pv_r30_tb', 'alice: plan v1'),
                      (4, 'pv_r30_tb', 'bob: plan v2, layoffs'),
                      (5, 'pv_r30_ta', 'alice: plan v3');
ALTER TABLE hr ENABLE ROW LEVEL SECURITY;
CREATE POLICY own_rows ON hr USING (owner_name = current_user) WITH CHECK (owner_name = current_user);
GRANT USAGE ON SCHEMA phasevec TO pv_r30_own, pv_r30_ta, pv_r30_tb;
GRANT SELECT, INSERT, UPDATE, DELETE ON hr TO pv_r30_ta, pv_r30_tb;
SELECT phasevec.watch('hr', 'hr'::regclass, 'id', 'r.body', 'r1');
SELECT count(phasevec.record('hr', n.key, 'r1', n.text_hash, n.key::bigint,
                             ARRAY[100 - n.key::int, n.key::int, 0, 0]::smallint[]))
  FROM phasevec.next('hr') n;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz),
  phasevec.supersede(text, text, text, text), phasevec.brief(text, int),
  phasevec.truth_coverage(text), phasevec.recall(text, text, int, boolean)
  TO pv_r30_ta, pv_r30_tb;
SQL
# ta: 2 (topic + support), 1 replaced by 5, 5 expired; then deletes 1, 2 and 5
qu pv_r30_ta -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
SELECT phasevec.assert('hr', '2', NULL, 'alice-private-topic', '{"alice_note": "offer 95k, do not tell bob"}');
SELECT phasevec.supersede('hr', '1', '5', 'v3 replaces');
SELECT phasevec.assert('hr', '5', NULL, NULL, NULL, now() - interval '1 day');
DELETE FROM hr WHERE id IN (1, 2, 5);
SQL
# tb writes its own rows under the same keys, with the same words (the reading still holds)
qu pv_r30_tb -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
INSERT INTO hr VALUES (1, 'pv_r30_tb', 'alice: the salary review is done'),
                      (2, 'pv_r30_tb', 'bob: the salary review is not done'),
                      (5, 'pv_r30_tb', 'alice: plan v3');
SQL
dead=$(q -c "SELECT string_agg(key || ':' || phasevec._claim_dead(t), ' ' ORDER BY key) FROM phasevec.truth t")
leak=$(qu pv_r30_tb -c "SELECT key || ':' || coalesce(topic, '-') || ':' || coalesce(support::text, '-')
                          FROM phasevec.recall('hr', 'salary', 10) WHERE key = '2'" 2>&1)
if [ "$dead" = "1:true 2:true 5:true" ] && [ "$leak" = "2:-:-" ]; then
    ok "recall() shows nothing of a dead claim to the tenant whose row is under its key"
else
    nok "dead claim leak: claims '$dead', tb's recall of key 2 '${leak:0:200}'"
fi
br=$(qu pv_r30_tb -c "SELECT string_agg(key, ',' ORDER BY key) FROM phasevec.brief('hr')" 2>&1)
vd=$(q -c "SELECT string_agg(key || ':' || phasevec._verdict(t), ' ' ORDER BY key) FROM phasevec.truth t")
cv=$(qu pv_r30_tb -c "SELECT string_agg(verdict || ':' || n, ' ' ORDER BY verdict)
                        FROM phasevec.truth_coverage('hr')" 2>&1)
fd=$(q -c "SELECT string_agg(key, ',' ORDER BY key)
             FROM phasevec.find('hr', 0, ARRAY[100, 0, 0, 0]::smallint[], 10, true)" 2>&1)
if [ "$br" = "1,2,3,4,5" ] && [ "$vd" = "1:unproven 2:unproven 5:unproven" ] \
   && [ "$cv" = "unproven:5" ] && [ "$fd" = "1,2,3,4,5" ]; then
    ok "a dead claim that read replaced or expired hides no row: brief, _verdict, coverage, find"
else
    nok "dead verdict: tb's brief '$br', verdicts '$vd', tb's coverage '$cv', find '${fd:0:200}'"
fi

exit $fallas
