#!/usr/bin/env bash
# 0.20.0 (twenty-fifth review): a 0.19.0 dump restored where 0.20.0 is installed, a claim as its
# author's, and the update's messages. Against the throwaway cluster of installcheck.sh (run that
# first), with the same PV_DATA/PV_PORT/PV_SOCK. Builds 0.19.0 (commit 65ae00d) aside, like
# upgrade_writers.sh. It starts the cluster with max_prepared_transactions = 4 (case 7).
#   PG=~/pg19/bin test/review25.sh
# 1. (RT25PU-1) A pg_dump of 0.19.0 restored where 0.20.0 is installed: until phasevec.migrate(),
#    what changes or judges a claim of its watch refuses, named, and nothing reads 'verified';
#    migrate() brings it as the update brings the same database (claims, texts, the TRUNCATE
#    trigger), then adopt() and verify() keep the refuted claim refuted. Until this review the
#    restore left 0.19.0's rows as they were, and adopt() + verify() served a refute()d claim
#    'verified'.
# 2. A fresh CREATE EXTENSION and the update from 0.19.0 make the same extension (every function,
#    table, column, default, constraint, index, trigger, comment, grant and dump mark).
# 3. (RT25PC-AUTH-1) Two tenants under row-level security and a role with no SELECT: none changes
#    another's claim, or a claim on a row it does not see, by assert(), refute(), supersede() or
#    unsupersede(); an author changes its own, a member of the author's role and the table's owner
#    change it too, and a claim whose author is gone is changed by a role that sees its row. Until
#    this review every one of them went through.
# 4. (RT25PC-INFO-2) supersede() refuses a cycle (2-3-2, 4-5-6-4), also from two sessions at once,
#    and refuses to run at REPEATABLE READ.
# 5. (RT25PC-INFO-1) verify() and verify_one() refuse a p_max_cost that is NaN, negative or 0
#    (infinity: no cap), and verify() a negative p_n, with phasevec's own message.
# 6. (RT25PU-2) Columns that store the row type of phasevec.truth or phasevec.watches (directly, as
#    an array, through a composite type): the update names every one at once, nothing changed.
# 7. (RT25PU-3, RT26-PREP-1) A prepared transaction holding phasevec.truth, or a function the update
#    drops: the update names it by its gid, and the HINT names pg_prepared_xacts. Until this review:
#    "none any more".
# 8. (RT26-LT-1, RT25PU-4) lock_timeout = 1ms on an idle database: the update goes through (three
#    times). Until this review it stopped before its first try, saying it had waited.
set -uo pipefail
cd "$(dirname "$0")/.."
PG=${PG:-$HOME/pg19/bin}
DATA=${PV_DATA:-$PWD/.testcluster}
PORT=${PV_PORT:-5491}
SOCK=${PV_SOCK:-/tmp}
V019=65ae00d
W=$(mktemp -d "${TMPDIR:-/tmp}/pv-r25.XXXXXX")
DBS="pv_r25 pv_r25u pv_r25r pv_r25f"
ROLES="pv_r25_alice pv_r25_ta pv_r25_tb pv_r25_mallory pv_r25_deputy pv_r25_owner"
export PGOPTIONS="-c client_min_messages=warning"
mkdir -p "$W/v019" "$W/lib"
GIT_INDEX_FILE="$W/index" git read-tree "$V019" \
    && GIT_INDEX_FILE="$W/index" git --work-tree="$W/v019" checkout-index -a
make -s -C "$W/v019" PG_CONFIG="$PG/pg_config" >/dev/null 2>&1 \
    || { echo "not ok - 0.19.0 does not build"; exit 1; }
ln -sfn "$PWD/src/pg_phasevec_observe.so" "$W/lib/pg_phasevec_observe.so"
export PGOPTIONS="$PGOPTIONS -c dynamic_library_path=$W/lib:\$libdir"
"$PG/pg_ctl" -D "$DATA" -o "-p $PORT -k $SOCK -c max_prepared_transactions=4" \
    -l "$DATA/server.log" -w start >/dev/null
cleanup() {
    for d in $DBS; do "$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists "$d" 2>/dev/null; done
    for r in $ROLES; do qd postgres -c "DROP ROLE IF EXISTS $r" >/dev/null 2>&1; done
    "$PG/pg_ctl" -D "$DATA" -w stop >/dev/null
    rm -rf "$W"
}
trap cleanup EXIT
qd() { local d=$1; shift; "$PG/psql" -h "$SOCK" -p "$PORT" -X -q -At -d "$d" "$@"; }
q() { qd pv_r25 "$@"; }
qu() {
    local u=$1; shift
    PGOPTIONS="-c client_min_messages=warning" \
        "$PG/psql" -h "$SOCK" -p "$PORT" -X -q -At -d pv_r25 -U "$u" "$@"
}
fallas=0
ok() { echo "ok - $*"; }
nok() { echo "not ok - $*"; fallas=1; }
use019() { ln -sfn "$W/v019/pg_phasevec.so" "$W/lib/pg_phasevec.so"; }
use020() { ln -sfn "$PWD/pg_phasevec.so" "$W/lib/pg_phasevec.so"; }
version() {
    qd "${1:-pv_r25}" -c "SELECT extversion FROM pg_extension WHERE extname = 'pg_phasevec'"
}
newdb() {
    "$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists "$1" 2>/dev/null
    "$PG/createdb" -h "$SOCK" -p "$PORT" "$1"
}
fresh019() {
    use019
    newdb pv_r25
    q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE EXTENSION pg_phasevec VERSION '0.19.0';
SELECT phasevec.reader_register('r1', repeat('a', 64), 4);
CREATE TABLE notas (id int PRIMARY KEY, body text);
INSERT INTO notas SELECT g, 'n' || g FROM generate_series(1, 20) g;
SELECT phasevec.watch('notas', 'notas'::regclass, 'id', 'r.body', 'r1');
SQL
    for r in $ROLES; do
        q -c "DO \$\$BEGIN CREATE ROLE $r LOGIN;
              EXCEPTION WHEN duplicate_object THEN NULL; END\$\$" >/dev/null
    done
}
# The verdicts of a database, by key.
verdicts() {
    qd "$1" -c "SELECT string_agg(key || '=' || phasevec._verdict(t), ' ' ORDER BY key)
                  FROM phasevec.truth t ${2:-}"
}
# The extension as the catalog has it: every object of phasevec's schema, its definition, comment
# and grants.
SHAPE=$(cat <<'SQL'
WITH n AS (SELECT 'phasevec'::regnamespace AS ns),
x AS (SELECT oid FROM pg_extension WHERE extname = 'pg_phasevec')
SELECT string_agg(l, E'\n' ORDER BY l) FROM (
  SELECT 'f ' || p.oid::regprocedure || ' ' || coalesce(p.proacl::text, '-') || ' ' ||
         coalesce(obj_description(p.oid, 'pg_proc'), '-') || E'\n' ||
         CASE WHEN p.prokind = 'a' THEN '' ELSE pg_get_functiondef(p.oid) END AS l
    FROM pg_proc p, n WHERE p.pronamespace = n.ns
  UNION ALL
  SELECT 'r ' || c.relname || ' ' || c.relkind::text || c.relpersistence::text || ' ' ||
         coalesce(c.relacl::text, '-') || ' ' || coalesce(obj_description(c.oid, 'pg_class'), '-')
    FROM pg_class c, n WHERE c.relnamespace = n.ns
  UNION ALL
  SELECT 'c ' || c.relname || '.' || a.attnum || ' ' || a.attname || ' ' ||
         format_type(a.atttypid, a.atttypmod) || ' ' || a.attnotnull || ' ' ||
         coalesce(pg_get_expr(d.adbin, d.adrelid), '-') || ' ' ||
         coalesce(col_description(c.oid, a.attnum), '-') || ' ' || coalesce(a.attacl::text, '-')
    FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid CROSS JOIN n
    LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
   WHERE c.relnamespace = n.ns AND a.attnum > 0 AND NOT a.attisdropped
  UNION ALL
  SELECT 'k ' || k.conrelid::regclass || ' ' || k.conname || ' ' || pg_get_constraintdef(k.oid)
    FROM pg_constraint k, n WHERE k.connamespace = n.ns
  UNION ALL
  SELECT 'i ' || pg_get_indexdef(i.indexrelid)
    FROM pg_index i JOIN pg_class c ON c.oid = i.indrelid, n
   WHERE c.relnamespace = n.ns
  UNION ALL
  SELECT 't ' || pg_get_triggerdef(t.oid) FROM pg_trigger t JOIN pg_class c ON c.oid = t.tgrelid, n
   WHERE c.relnamespace = n.ns AND NOT t.tgisinternal
  UNION ALL
  SELECT 'y ' || t.typname || ' ' || t.typtype::text FROM pg_type t, n WHERE t.typnamespace = n.ns
  UNION ALL
  SELECT 'e ' || coalesce(array_to_string(ARRAY(SELECT u::regclass::text
                                                  FROM unnest(e.extconfig) u ORDER BY 1), ','),
                          '-') || ' ' || e.extversion || ' ' || e.extrelocatable
    FROM pg_extension e WHERE e.extname = 'pg_phasevec'
  UNION ALL
  SELECT 'm ' || pg_describe_object(d.classid, d.objid, d.objsubid) FROM pg_depend d, x
   WHERE d.refclassid = 'pg_extension'::regclass AND d.refobjid = x.oid AND d.deptype = 'e') s
SQL
)

# 1. a 0.19.0 dump restored where 0.20.0 is installed
fresh019
q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
GRANT USAGE ON SCHEMA phasevec TO pv_r25_alice;
GRANT SELECT ON notas TO pv_r25_alice;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz)
    TO pv_r25_alice;
SELECT phasevec.assert('notas', k::text, 'SELECT true') FROM generate_series(3, 6) k;
SELECT phasevec.assert('notas', '8', 'SELECT false');
SELECT count(*) FROM phasevec.verify('notas', p_every => '0 s');
SELECT phasevec.refute('notas', '3', 'the note is wrong');
SELECT phasevec.refute('notas', '7', 'never asserted');
SELECT phasevec.refute('notas', '5', 'gone');
SELECT phasevec.supersede('notas', '5', '6', 'newer');
SQL
"$PG/pg_dump" -h "$SOCK" -p "$PORT" -Fc -d pv_r25 -f "$W/r019.dump" || nok "pg_dump of 0.19.0"
"$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists pv_r25u 2>/dev/null
"$PG/createdb" -h "$SOCK" -p "$PORT" -T pv_r25 pv_r25u        # the same database, updated in place
use020
qd pv_r25u -c "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" >/dev/null 2>&1
newdb pv_r25r
"$PG/pg_restore" -h "$SOCK" -p "$PORT" -d pv_r25r "$W/r019.dump" 2>"$W/restore.err" \
    || nok "pg_restore of 0.19.0 where 0.20.0 is installed: $(head -c 300 "$W/restore.err")"
[ "$(version pv_r25u)/$(version pv_r25r)" = "0.20.0/0.20.0" ] \
    || nok "versions: $(version pv_r25u)/$(version pv_r25r)"
ser=$(verdicts pv_r25r)
case " $ser " in *=verified*) nok "before migrate(), a restored claim reads verified: $ser" ;;
                 *) ok "before migrate(), no restored claim reads verified ($ser)" ;; esac
refused=0
for s in "SELECT * FROM phasevec.adopt('notas', 'pv_r25_alice')" \
         "SELECT count(*) FROM phasevec.verify('notas', p_every => '0 s')" \
         "SELECT phasevec.verify_one('notas', '4')" \
         "SELECT phasevec.assert('notas', '3', 'SELECT true')" \
         "SELECT phasevec.refute('notas', '4', 'x')" \
         "SELECT phasevec.supersede('notas', '4', '9', 'x')" \
         "SELECT phasevec.unsupersede('notas', '5')"; do
    out=$(qd pv_r25r -c "$s" 2>&1)
    if grep -q "holds what pg_phasevec 0.19.0 wrote" <<<"$out" \
       && grep -q "phasevec.migrate()" <<<"$out"; then
        refused=$((refused + 1))
    else
        nok "before migrate(): '$s' -> '${out:0:200}'"
    fi
done
[ $refused = 7 ] \
    && ok "before migrate(), adopt, verify, verify_one, assert, refute, supersede and" \
          "unsupersede refuse"
mig=$(qd pv_r25r -c "SELECT watch || '|' || claims || '|' || truncate_trigger
                       FROM phasevec.migrate()" 2>&1)
[ "$mig" = "notas|6|made" ] && ok "migrate() brings the watch: $mig" || nok "migrate(): '$mig'"
CMP="SELECT string_agg(concat_ws('|', t.key, t.verdict, t.proof IS NULL, t.retired_at, t.halted,
                                 t.last_error, encode(t.asserted_for, 'hex'), t.asserted_by,
                                 t.data_version, t.replaced_by, phasevec._verdict(t)),
                       E'\n' ORDER BY t.key)
       FROM phasevec.truth t"
SRC="SELECT string_agg(s.key || '=' || encode(s.text_hash, 'hex'), ' ' ORDER BY s.key)
       FROM phasevec.sources s"
WV="SELECT string_agg(name || ':' || data_version, ' ') FROM phasevec.watches"
TG="SELECT string_agg(tgname, ',' ORDER BY tgname) FROM pg_trigger
     WHERE tgrelid = 'notas'::regclass"
for c in CMP SRC WV TG; do
    a=$(qd pv_r25u -c "${!c}"); b=$(qd pv_r25r -c "${!c}")
    [ -n "$a" ] && [ "$a" = "$b" ] && ok "after migrate(), $c reads as on the updated database" \
        || nok "$c differs: updated '$a' / restored '$b'"
done
again=$(qd pv_r25r -c "SELECT count(*) FROM phasevec.migrate()")
[ "$again" = "0" ] && ok "a second migrate() finds nothing" || nok "second migrate(): '$again'"
declare -A ad v br
for d in pv_r25u pv_r25r; do
    ad[$d]=$(qd $d -c "SELECT string_agg(key, ',' ORDER BY key)
                         FROM phasevec.adopt('notas', 'pv_r25_alice')" 2>&1)
    qd $d -c "SELECT count(*) FROM phasevec.verify('notas', p_every => '0 s')" >/dev/null
    v[$d]=$(verdicts $d "WHERE key IN ('3', '4', '7', '8')")
    br[$d]=$(qd $d -c "SELECT string_agg(key || ':' || verdict, ' ' ORDER BY key)
                         FROM phasevec.brief('notas') WHERE verdict = 'verified'")
done
u_="${ad[pv_r25u]}|${v[pv_r25u]}|${br[pv_r25u]}"; r_="${ad[pv_r25r]}|${v[pv_r25r]}|${br[pv_r25r]}"
if [ "$u_" = "$r_" ] \
   && [ "${v[pv_r25r]}" = "3=refuted 4=verified 7=refuted 8=refuted" ] \
   && [ "${br[pv_r25r]}" = "4:verified 6:verified" ]; then
    ok "adopt() + verify() after migrate(): adopted ${ad[pv_r25r]}, ${v[pv_r25r]}," \
       "brief serves ${br[pv_r25r]}"
else
    nok "after adopt + verify: updated '${ad[pv_r25u]}' '${v[pv_r25u]}' '${br[pv_r25u]}'" \
        "/ restored '${ad[pv_r25r]}' '${v[pv_r25r]}' '${br[pv_r25r]}'"
fi
qd pv_r25r -c "TRUNCATE notas" -c "INSERT INTO notas VALUES (4, 'something else')"
t=$(verdicts pv_r25r "WHERE key IN ('3', '4')")
[ "$t" = "3=unproven 4=unproven" ] && ok "after migrate(), a TRUNCATE is seen ($t)" \
    || nok "after TRUNCATE: '$t'"
# a 0.20.0 dump of the migrated database restores as 0.20.0 data: nothing to migrate
"$PG/pg_dump" -h "$SOCK" -p "$PORT" -Fc -d pv_r25r -f "$W/r020.dump"
newdb pv_r25f
"$PG/pg_restore" -h "$SOCK" -p "$PORT" -d pv_r25f "$W/r020.dump" 2>/dev/null
n=$(qd pv_r25f -c "SELECT count(*) FROM phasevec.migrate()")
d=$(qd pv_r25f -c "SELECT count(*) FROM phasevec.truth WHERE data_version <> '0.20.0'")
[ "$n/$d" = "0/0" ] && ok "a dump of 0.20.0 restores as 0.20.0 (nothing to migrate)" \
    || nok "0.20.0 dump: $n/$d"

# 2. a fresh install and the update make the same extension
newdb pv_r25f
qd pv_r25f -c "CREATE EXTENSION pg_phasevec" >/dev/null
fresh019
use020
q -c "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" >/dev/null 2>&1
qd pv_r25f -c "$SHAPE" > "$W/shape.fresh"; q -c "$SHAPE" > "$W/shape.updated"
if [ -s "$W/shape.fresh" ] && cmp -s "$W/shape.fresh" "$W/shape.updated"; then
    ok "CREATE EXTENSION and the update from 0.19.0 make the same extension" \
       "($(grep -c '^[fcrkityem] ' "$W/shape.fresh") objects)"
else
    nok "the fresh and the updated extension differ:" \
        "$(diff "$W/shape.fresh" "$W/shape.updated" | head -c 600)"
fi

# 3. a claim is its author's
q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
ALTER TABLE notas OWNER TO pv_r25_owner;
ALTER TABLE notas ADD COLUMN tenant name DEFAULT 'pv_r25_ta';
UPDATE notas SET tenant = 'pv_r25_tb' WHERE id > 10;
ALTER TABLE notas ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON notas FOR SELECT
    USING (tenant = current_user OR current_user = 'pv_r25_deputy');
GRANT USAGE ON SCHEMA phasevec
    TO pv_r25_ta, pv_r25_tb, pv_r25_mallory, pv_r25_deputy, pv_r25_owner;
GRANT SELECT ON notas TO pv_r25_ta, pv_r25_tb, pv_r25_deputy;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz),
  phasevec.verify(text, int, interval, interval, int, float8), phasevec.refute(text, text, text),
  phasevec.supersede(text, text, text, text), phasevec.unsupersede(text, text),
  phasevec.brief(text, int)
  TO pv_r25_ta, pv_r25_tb, pv_r25_mallory, pv_r25_deputy, pv_r25_owner;
SQL
qu pv_r25_tb -c "SELECT phasevec.assert('notas', k::text, 'SELECT true')
                   FROM generate_series(11, 17) k" \
             -c "SELECT count(*) FROM phasevec.verify('notas', p_every => '0 s')" >/dev/null
q -c "SELECT phasevec.supersede('notas', '17', '16', 'x')" >/dev/null
TRUTH="SELECT string_agg(concat_ws(':', key, asserted_by, verdict, proof IS NOT NULL, replaced_by),
                         ' ' ORDER BY key)
         FROM phasevec.truth"
before=$(q -c "$TRUTH")
denied=0; tries=0
try_denied() {
    local u=$1 s=$2 want=$3 out
    tries=$((tries + 1))
    out=$(qu "$u" -c "$s" 2>&1)
    if grep -q "$want" <<<"$out"; then
        denied=$((denied + 1))
    else
        nok "$u: '$s' -> '${out:0:200}'"
    fi
}
A="SELECT phasevec.assert('notas'"; R="SELECT phasevec.refute('notas'"
S="SELECT phasevec.supersede('notas'"; U="SELECT phasevec.unsupersede('notas'"
for s in "$A, '11', 'SELECT true')" "$A, '12', NULL)" "$R, '13', 'x')" "$S, '14', '1', 'x')" \
         "$U, '17')" "$A, '18', 'SELECT true')" "$R, '19', 'x')" "$R, '99', 'x')"; do
    try_denied pv_r25_ta "$s" 'may not change the claim on key'
done
try_denied pv_r25_ta "$S, '1', '15', 'x')" 'row 15 of watch notas does not exist'
try_denied pv_r25_ta "$S, '1', '99', 'x')" 'row 99 of watch notas does not exist'
for s in "$A, '11', NULL)" "$R, '13', 'x')" "$S, '14', '15', 'x')" "$U, '17')"; do
    try_denied pv_r25_mallory "$s" 'may not read public.notas'
done
# the deputy sees every row, but is not tb: tb's claims are not its to change
for s in "$A, '11', 'SELECT true')" "$R, '13', 'x')" "$S, '14', '15', 'x')" "$U, '17')"; do
    try_denied pv_r25_deputy "$s" 'may not change the claim on key'
done
after=$(q -c "$TRUTH")
if [ $denied = $tries ] && [ "$before" = "$after" ]; then
    ok "another tenant, a role with no SELECT, a role that sees the row: $denied changes" \
       "refused, nothing changed"
else
    nok "refused $denied of $tries; truth before '$before' after '$after'"
fi
# its author, a member of its author's role, the table's owner
q -c "GRANT pv_r25_tb TO pv_r25_deputy"
o1=$(qu pv_r25_tb -c "$R, '13', 'mine')" -c "$U, '17')" 2>&1)
o2=$(qu pv_r25_deputy -c "$S, '14', '15', 'x')" 2>&1)
o3=$(qu pv_r25_owner -c "$R, '11', 'the owner')" -c "$A, '12', NULL)" 2>&1)
o4=$(qu pv_r25_ta -c "$A, '2', 'SELECT true')" -c "$R, '2', 'x')" -c "$S, '1', '2', 'x')" 2>&1)
st=$(q -c "SELECT string_agg(concat_ws(':', key, asserted_by, phasevec._claim_state(t), verdict),
                             ' ' ORDER BY key)
             FROM phasevec.truth t WHERE key IN ('1', '2', '11', '12', '13', '14', '17')")
want="1:pv_r25_ta:bare:replaced 11:pv_r25_owner:retired:refuted 12:pv_r25_owner:bare:unproven"
want="$want 13:pv_r25_tb:retired:refuted 14:pv_r25_tb:judged:replaced"
want="$want 17:pv_r25_tb:judged:unproven 2:pv_r25_ta:retired:refuted"
if [ -z "$o1$o2$o3$o4" ] && [ "$st" = "$want" ]; then
    ok "its author, a member of the author's role and the table's owner change a claim;" \
       "the refuter is its author"
else
    nok "allowed changes: '${o1:0:150}' '${o2:0:150}' '${o3:0:150}' '${o4:0:150}'; '$st'"
fi
# tb can no longer revive what the owner retired; a claim whose author is gone is changed by a
# role that sees its row
o5=$(qu pv_r25_tb -c "$A, '11', 'SELECT true')" 2>&1)
q -c "REVOKE pv_r25_tb FROM pv_r25_deputy" -c "ALTER ROLE pv_r25_tb RENAME TO pv_r25_tb_gone"
o6=$(qu pv_r25_ta -c "$A, '15', NULL)" 2>&1)
o7=$(qu pv_r25_deputy -c "$A, '15', NULL)" 2>&1)
q -c "ALTER ROLE pv_r25_tb_gone RENAME TO pv_r25_tb"
if grep -q 'may not change the claim on key 11' <<<"$o5" \
   && grep -q 'may not change the claim on key 15' <<<"$o6" && [ -z "$o7" ]; then
    ok "the owner's retirement is not tb's to revive; a claim of an author gone is changed by" \
       "a role that sees the row"
else
    nok "after: tb '${o5:0:150}', ta '${o6:0:150}', deputy '${o7:0:150}'"
fi

# 4. supersede() closes no cycle
cyc() { q -c "$S, '$1', '$2', 'x')" 2>&1; }
q -c "DELETE FROM phasevec.truth" >/dev/null
o=$(cyc 2 3; cyc 3 2)
o2=$(cyc 4 5; cyc 5 6; cyc 6 4)
o3=$(q -c "BEGIN ISOLATION LEVEL REPEATABLE READ" -c "$S, '7', '8', 'x')" 2>&1)
q -c "DELETE FROM phasevec.truth" >/dev/null
( q -c "BEGIN" -c "$S, '2', '3', 'x')" -c "SELECT pg_sleep(1)" -c "COMMIT" >"$W/c1.out" 2>&1 & )
sleep 0.3
cyc 3 2 >"$W/c2.out" 2>&1
sleep 1
c=$(q -c "SELECT string_agg(key || '>' || replaced_by, ' ' ORDER BY key)
            FROM phasevec.truth WHERE verdict = 'replaced'")
if grep -q "row 2 of watch notas is replaced, in the end, by row 3" <<<"$o" \
   && grep -q "row 4 of watch notas is replaced, in the end, by row 6" <<<"$o2" \
   && grep -q "runs only at READ COMMITTED" <<<"$o3" \
   && grep -q "replaced, in the end" "$W/c2.out" && [ "$c" = "2>3" ]; then
    ok "supersede() refuses a cycle (2-3-2, 4-5-6-4, and from two sessions at once) and" \
       "REPEATABLE READ"
else
    nok "cycles: '${o:0:200}' '${o2:0:200}' '${o3:0:200}' '$(head -c 200 "$W/c2.out")' '$c'"
fi

# 5. the cost cap and p_n
args=0
for s in "verify('notas', p_max_cost => 'NaN')" "verify('notas', p_max_cost => -1)" \
         "verify('notas', p_max_cost => 0)" "verify_one('notas', '4', p_max_cost => 'NaN')" \
         "verify_one('notas', '4', p_max_cost => -5)"; do
    out=$(q -c "SELECT * FROM phasevec.$s" 2>&1)
    if grep -q "p_max_cost must be above 0" <<<"$out"; then
        args=$((args + 1))
    else
        nok "$s -> '${out:0:200}'"
    fi
done
out=$(q -c "SELECT * FROM phasevec.verify('notas', -1)" 2>&1)
grep -q "p_n is how many claims verify() may judge" <<<"$out" && args=$((args + 1)) \
    || nok "p_n -1 -> '${out:0:200}'"
out=$(q -c "SELECT count(*) FROM phasevec.verify('notas', p_max_cost => 'Infinity')" 2>&1)
[ "$out" = "0" ] && args=$((args + 1)) || nok "p_max_cost infinity -> '${out:0:200}'"
[ $args = 7 ] \
    && ok "NaN, negative and 0 cost caps and a negative p_n refused, named; infinity is no cap"

# 6. columns that store the row type of the tables the update alters
fresh019
use020
q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE TABLE keep_truth (x phasevec.truth);
CREATE TABLE keep_watches (y phasevec.watches[]);
CREATE TYPE wrap AS (w phasevec.watches);
CREATE TABLE keep_wrap (z wrap);
CREATE VIEW only_view AS SELECT t FROM phasevec.truth t;
SQL
up=$(q -c "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" 2>&1)
if [ "$(version)" = "0.19.0" ] \
   && grep -q "column x of public.keep_truth stores type phasevec.truth" <<<"$up" \
   && grep -q "column y of public.keep_watches stores type phasevec.watches\[\]" <<<"$up" \
   && grep -q "column z of public.keep_wrap stores type public.wrap" <<<"$up" \
   && ! grep -q only_view <<<"$up"; then
    ok "columns that store phasevec.truth or phasevec.watches: all named at once, nothing changed"
else
    nok "row-type dependents: version $(version), '${up:0:500}'"
fi
q -c "DROP TABLE keep_truth, keep_watches, keep_wrap" -c "DROP TYPE wrap" >/dev/null
up=$(q -c "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" 2>&1)
[ "$(version)" = "0.20.0" ] && ok "once they are dropped the update goes through (the view kept)" \
    || nok "after the dependents were dropped: version $(version), '${up:0:300}'"

# 7. prepared transactions in the update's way
for case in truth view; do
    fresh019
    use020
    held="Sessions holding it: prepared transaction 'pv_r25_p1'"
    if [ $case = truth ]; then
        q -c "BEGIN" -c "SELECT count(*) FROM phasevec.truth" \
          -c "PREPARE TRANSACTION 'pv_r25_p1'" >/dev/null
        want="It waited last for phasevec.truth. $held"
    else
        q -c "BEGIN" -c "CREATE VIEW kv AS SELECT count(*) AS n FROM phasevec._brief_keys('x') k" \
          -c "PREPARE TRANSACTION 'pv_r25_p1'" >/dev/null
        want="phasevec._brief_keys(p_watch text). $held"
    fi
    up=$(q -c "SET lock_timeout = '700ms'" -c "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" 2>&1)
    q -c "ROLLBACK PREPARED 'pv_r25_p1'" >/dev/null
    if [ "$(version)" = "0.19.0" ] && grep -qF "$want" <<<"$up" \
       && grep -q "pg_prepared_xacts" <<<"$up"; then
        ok "a prepared transaction holding $case is named by its gid"
    else
        nok "prepared holder ($case): version $(version), '${up:0:400}'"
    fi
done

# 8. lock_timeout = 1ms on an idle database
fresh019
use020
through=0
for i in 1 2 3; do
    out=$(q -c "BEGIN" -c "SET LOCAL lock_timeout = '1ms'" \
            -c "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" \
            -c "SELECT extversion FROM pg_extension WHERE extname = 'pg_phasevec'" \
            -c "ROLLBACK" 2>&1)
    [ "$out" = "0.20.0" ] && through=$((through + 1))
done
[ $through = 3 ] && ok "lock_timeout = 1ms on an idle database: 3 of 3 updates through" \
    || nok "lock_timeout = 1ms: $through of 3 through ('${out:0:300}')"
for d in $DBS; do for r in $ROLES; do qd $d -c "DROP OWNED BY $r" >/dev/null 2>&1; done; done
exit $fallas
