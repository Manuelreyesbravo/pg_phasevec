#!/usr/bin/env bash
# 0.20.0 (twenty-seventh review): no claim by coming first, a steward that is the owner's and of
# its rows, authors and stewards bound to their cluster, pg_upgrade, replication between two
# 0.20.0 servers, and the update's first wait. Against the throwaway cluster of installcheck.sh
# (run that first), with the same PV_DATA/PV_PORT/PV_SOCK. Builds 0.19.0 (commit 65ae00d) aside,
# like review26.sh, and starts more clusters under the scratch directory (ports PV_PORT+1 to +6).
#   PG=~/pg19/bin test/review27.sh
#   PG=~/pg19/bin PG_OLD=<bin of an older major, e.g. 18> test/review27.sh   (with case 8)
# 1. (RT28-LT0-1, RT27PU-1) lock_timeout = 0 while readers that each hold phasevec.watches 2 s
#    (more than half the deadlock_timeout) overlap: the update waits in the queue and goes
#    through. In the twenty-sixth review's cut every first wait was bounded (the caller always
#    "had written": ALTER EXTENSION writes pg_extension first), and statement_timeout ended it.
# 2. (RT27PA-1, RT28-DECISION-FIRSTCLAIM) A first claim needs an explicit privilege over the row:
#    a role that only reads it (SELECT, a shared row under row-level security) claims nothing; a
#    tenant that may UPDATE its own row claims it; one whose UPDATE policy does not pass does not.
# 3. (RT28-RESERVE-PRIV) A key with no row is claimed by no one, the owner and a steward included.
# 4. (RT28-STEWARD-ORACLE) A steward does not change a claim on a row it does not see: supersede()
#    of a hidden key is refused alike whether or not the key sits in the chain of the new one.
# 5. (RT28-MIGRATED-ORACLE) A key the caller does not see whose claim 0.19.0 wrote: refused alike,
#    not "holds what pg_phasevec 0.19.0 wrote".
# 6. (RT27PA-4) ALTER TABLE ... OWNER TO ends the stewards the former owner named; the new owner
#    names them again. (RT27PA-2) A revoked steward changes nothing it did not author; what it
#    authored stays in its name, and the owner changes it. (twenty-eighth review, RT28PA-REVOKE-1)
#    A claim it took as a steward alone, it no longer changes either (until then it did).
# 7. (RT27PA-3, RT27PL-1) A pg_dump restored into another cluster whose roles have the same OIDs
#    and names: every claim is an orphan, every steward no one; the owner adopts them. Restored into
#    another database of the same cluster, they are kept.
# 8. (RT27PL-2) pg_upgrade from PG_OLD of a database with a lexical watch: no "reg* data types"
#    refusal; the configuration, authors, stewards and verdicts come through. 0.19.0 is refused too
#    (the column was regconfig since 0.6.0). Skipped without PG_OLD.
# 9. (RT27PL-2) The update turns phasevec.watches.lexical into the configuration's name, and a
#    lexical watch reads its rows as before.
# 10. (RT27PL-3) Logical replication from a 0.20.0 publisher: the rows keep '0.20.0', migrate()
#    finds nothing, no verdict is dropped for "verified before 0.20.0", and a later verify() arrives
#    as 0.20.0. From 0.19.0 (review26.sh, case 6) they still read '0.19.0'.
set -uo pipefail
cd "$(dirname "$0")/.."
PG=${PG:-$HOME/pg19/bin}
PG_OLD=${PG_OLD:-}
DATA=${PV_DATA:-$PWD/.testcluster}
PORT=${PV_PORT:-5491}
SOCK=${PV_SOCK:-/tmp}
V019=65ae00d
W=$(mktemp -d "${TMPDIR:-/tmp}/pv-r27.XXXXXX")
DBS="pv_r27 pv_r27b"
ROLES="pv_r27_own pv_r27_own2 pv_r27_ta pv_r27_tb pv_r27_rd pv_r27_st"
export PGOPTIONS="-c client_min_messages=warning"
mkdir -p "$W/v019" "$W/lib" "$W/lib019" "$W/sock"
GIT_INDEX_FILE="$W/index" git read-tree "$V019" \
    && GIT_INDEX_FILE="$W/index" git --work-tree="$W/v019" checkout-index -a
make -s -C "$W/v019" PG_CONFIG="$PG/pg_config" >/dev/null 2>&1 \
    || { echo "not ok - 0.19.0 does not build"; exit 1; }
ln -sfn "$PWD/src/pg_phasevec_observe.so" "$W/lib/pg_phasevec_observe.so"
ln -sfn "$PWD/src/pg_phasevec_observe.so" "$W/lib019/pg_phasevec_observe.so"
ln -sfn "$W/v019/pg_phasevec.so" "$W/lib019/pg_phasevec.so"
export PGOPTIONS="$PGOPTIONS -c dynamic_library_path=$W/lib:\$libdir"
"$PG/pg_ctl" -D "$DATA" -o "-p $PORT -k $SOCK" -l "$DATA/server.log" -w start >/dev/null
EXTRA=""
cleanup() {
    for c in $EXTRA; do
        [ -f "$W/$c/postmaster.pid" ] && "${PGX[$c]:-$PG}/pg_ctl" -D "$W/$c" -m fast -w stop \
            >/dev/null 2>&1
    done
    for d in $DBS; do "$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists "$d" 2>/dev/null; done
    for r in $ROLES; do qd postgres -c "DROP ROLE IF EXISTS $r" >/dev/null 2>&1; done
    "$PG/pg_ctl" -D "$DATA" -w stop >/dev/null
    rm -rf "$W"
}
declare -A PGX
trap cleanup EXIT
qd() { local d=$1; shift; "$PG/psql" -h "$SOCK" -p "$PORT" -X -q -At -d "$d" "$@"; }
q() { qd pv_r27 "$@"; }
qu() {
    local u=$1; shift
    PGOPTIONS="-c client_min_messages=warning" \
        "$PG/psql" -h "$SOCK" -p "$PORT" -X -q -At -d pv_r27 -U "$u" "$@"
}
pause() { python3 -I -c "import time, sys; time.sleep(float(sys.argv[1]))" "$1"; }
fallas=0
ok() { echo "ok - $*"; }
nok() { echo "not ok - $*"; fallas=1; }
use019() { ln -sfn "$W/v019/pg_phasevec.so" "$W/lib/pg_phasevec.so"; }
use020() { ln -sfn "$PWD/pg_phasevec.so" "$W/lib/pg_phasevec.so"; }
version() {
    qd "${1:-pv_r27}" -c "SELECT extversion FROM pg_extension WHERE extname = 'pg_phasevec'"
}
newdb() {
    "$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists "$1" 2>/dev/null
    "$PG/createdb" -h "$SOCK" -p "$PORT" "$1"
}
roles() {
    for r in $ROLES; do
        q -c "DO \$\$BEGIN CREATE ROLE $r LOGIN;
              EXCEPTION WHEN duplicate_object THEN NULL; END\$\$" >/dev/null
    done
}
fresh() {   # fresh [VERSION]
    if [ "${1:-0.20.0}" = 0.19.0 ]; then use019; else use020; fi
    newdb pv_r27
    q -v ON_ERROR_STOP=1 -v v="${1:-0.20.0}" >/dev/null <<'SQL'
CREATE EXTENSION pg_phasevec VERSION :'v';
SELECT phasevec.reader_register('r1', repeat('a', 64), 4);
CREATE TABLE notas (id int PRIMARY KEY, body text);
INSERT INTO notas SELECT g, 'n' || g FROM generate_series(1, 20) g;
SELECT phasevec.watch('notas', 'notas'::regclass, 'id', 'r.body', 'r1');
SQL
    roles
}
# tenants: ta owns rows 1-10, tb 11-20; every role reads every row (the SELECT policy, given),
# and a tenant updates only its own rows; st is a steward only of what it sees
tenants() {   # tenants SELECT_POLICY
    q -v ON_ERROR_STOP=1 -v sel="$1" >/dev/null <<'SQL'
ALTER TABLE notas ADD COLUMN tenant name DEFAULT 'pv_r27_ta';
UPDATE notas SET tenant = 'pv_r27_tb' WHERE id > 10;
ALTER TABLE notas ENABLE ROW LEVEL SECURITY;
SELECT format('CREATE POLICY rd ON notas FOR SELECT USING (%s)', :'sel') \gexec
CREATE POLICY wr ON notas FOR UPDATE USING (tenant = current_user);
ALTER TABLE notas OWNER TO pv_r27_own;
GRANT USAGE ON SCHEMA phasevec TO pv_r27_own, pv_r27_own2, pv_r27_ta, pv_r27_tb, pv_r27_rd,
    pv_r27_st;
GRANT SELECT ON notas TO pv_r27_ta, pv_r27_tb, pv_r27_rd, pv_r27_st;
GRANT UPDATE ON notas TO pv_r27_ta, pv_r27_tb;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz),
  phasevec.refute(text, text, text), phasevec.supersede(text, text, text, text),
  phasevec.unsupersede(text, text), phasevec.adopt(text, regrole, text[], text[]),
  phasevec.steward(text, regrole, boolean)
  TO pv_r27_own, pv_r27_own2, pv_r27_ta, pv_r27_tb, pv_r27_rd, pv_r27_st;
SQL
}
update() {   # update [LOCK_TIMEOUT [DB]]
    qd "${2:-pv_r27}" -c "SET lock_timeout = '${1:-5s}'" \
        -c "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" 2>&1
}
claims() {   # claims KEYS-IN-LIST
    q -c "SELECT coalesce(string_agg(key || ':' || coalesce(asserted_by, '-'), ' '
                                     ORDER BY key), '')
            FROM phasevec.truth WHERE key IN ($1)"
}
refusal() { grep -o 'may not change the claim on key [0-9]*' <<<"$1" | head -1; }
cluster() {   # cluster NAME BINDIR PORT [LIBDIR]: a new cluster with phasevec's control path
    local c=$1 bin=$2 p=$3 lib=${4:-$DATA/ext/lib}
    "$bin/initdb" -D "$W/$c" -A trust -U postgres -E UTF8 --locale=C >/dev/null \
        || { nok "initdb $c"; return 1; }
    {
        echo "unix_socket_directories = '$W/sock'"; echo "listen_addresses = ''"
        echo "wal_level = logical"; echo "shared_buffers = 16MB"; echo "port = $p"
        echo "extension_control_path = '${5:-$DATA/ext}:\$system'"
        echo "dynamic_library_path = '$lib:\$libdir'"
    } >> "$W/$c/postgresql.conf"
    PGX[$c]=$bin; EXTRA="$EXTRA $c"
}
start() { "${PGX[$1]}/pg_ctl" -D "$W/$1" -l "$W/$1.log" -w start >/dev/null; }
stop() { "${PGX[$1]}/pg_ctl" -D "$W/$1" -m fast -w stop >/dev/null; }
on() {   # on PORT DB [args]: psql as postgres to a cluster of this script
    local p=$1 d=$2; shift 2
    PGOPTIONS="-c client_min_messages=warning" \
        "$PG/psql" -h "$W/sock" -p "$p" -U postgres -X -q -At -d "$d" "$@"
}

# 1. lock_timeout = 0 with overlapping readers that hold longer than half the deadlock_timeout
fresh 0.19.0
use020
for i in 0 1 2; do
    ( q -c "SELECT pg_sleep(0.7 * $i)" \
        -c "DO \$\$BEGIN FOR i IN 1..9 LOOP PERFORM count(*) FROM phasevec.watches;
              PERFORM pg_sleep(2.0); COMMIT; END LOOP; END\$\$" >/dev/null 2>&1 ) &
done
pause 2.5
st=$(date +%s.%N)
up=$(q -c "SET lock_timeout = 0" -c "SET statement_timeout = '15s'" \
       -c "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" 2>&1)
el=$(python3 -I -c "import sys; print(round(float(sys.argv[2]) - float(sys.argv[1]), 2))" \
       "$st" "$(date +%s.%N)")
wait
[ "$(version)" = 0.20.0 ] && [ -z "$up" ] \
    && ok "lock_timeout = 0, readers holding 2 s: the update waits in the queue (${el} s)" \
    || nok "lock_timeout = 0, 2 s readers: version $(version), ${el} s, '${up:0:300}'"

# 2. a first claim needs a privilege over the row; reading it is not one
fresh
tenants "true"
r1=$(qu pv_r27_rd -c "SELECT phasevec.refute('notas', '15', 'mine first')" 2>&1)
r2=$(qu pv_r27_rd -c "SELECT phasevec.assert('notas', '16', NULL)" 2>&1)
r3=$(qu pv_r27_rd -c "SELECT phasevec.supersede('notas', '17', '1', 'mine first')" 2>&1)
r4=$(qu pv_r27_ta -c "SELECT phasevec.refute('notas', '15', 'a shared row, not mine')" 2>&1)
r5=$(qu pv_r27_ta -c "SELECT phasevec.assert('notas', '18', 'SELECT true')" 2>&1)
before=$(claims "'15', '16', '17', '18'")
w1=$(qu pv_r27_tb -c "SELECT phasevec.assert('notas', '15', 'SELECT true')" \
       -c "SELECT phasevec.refute('notas', '16', 'mine')" \
       -c "SELECT phasevec.supersede('notas', '17', '12', 'mine')" 2>&1)
after=$(claims "'15', '16', '17', '18'")
if [ "$(refusal "$r1")" = "may not change the claim on key 15" ] \
   && [ "$(refusal "$r2")" = "may not change the claim on key 16" ] \
   && [ "$(refusal "$r3")" = "may not change the claim on key 17" ] \
   && [ "$(refusal "$r4")" = "may not change the claim on key 15" ] \
   && [ "$(refusal "$r5")" = "may not change the claim on key 18" ] && [ -z "$before" ] \
   && [ -z "$w1" ] && [ "$after" = "15:pv_r27_tb 16:pv_r27_tb 17:pv_r27_tb" ]; then
    ok "a reader, and a tenant on a row it reads but may not UPDATE, claim nothing first; the" \
       "row's writer does"
else
    nok "first claim: rd '${r1:0:120}' '${r2:0:120}' '${r3:0:120}', ta '${r4:0:120}'" \
        "'${r5:0:120}', before '$before', tb '${w1:0:200}', after '$after'"
fi
# a member of the writer's role writes as it; UPDATE on a column only is not UPDATE on the table
q -c "GRANT pv_r27_tb TO pv_r27_rd" >/dev/null
m1=$(qu pv_r27_rd -c "SET ROLE pv_r27_tb" -c "SELECT phasevec.refute('notas', '19', 'as tb')" 2>&1)
q -c "REVOKE pv_r27_tb FROM pv_r27_rd" -c "REVOKE UPDATE ON notas FROM pv_r27_tb" \
  -c "GRANT UPDATE (body) ON notas TO pv_r27_tb" >/dev/null
m2=$(qu pv_r27_tb -c "SELECT phasevec.refute('notas', '20', 'a column only')" 2>&1)
q -c "GRANT UPDATE ON notas TO pv_r27_tb" >/dev/null
if [ -z "$m1" ] && [ "$(refusal "$m2")" = "may not change the claim on key 20" ] \
   && [ "$(claims "'19', '20'")" = "19:pv_r27_tb" ]; then
    ok "SET ROLE to the writer claims as it; UPDATE on one column is no claim first"
else
    nok "writer by role: '${m1:0:150}', column UPDATE '${m2:0:150}', $(claims "'19', '20'")"
fi

# 3. no key with no row is claimed, by the owner or a steward either
q -c "SELECT phasevec.steward('notas', 'pv_r27_st')" >/dev/null
p1=$(qu pv_r27_own -c "SELECT phasevec.refute('notas', '999', 'reserved')" 2>&1)
p2=$(qu pv_r27_st -c "SELECT phasevec.supersede('notas', '998', '2', 'reserved')" 2>&1)
p3=$(qu pv_r27_own -c "SELECT phasevec.assert('notas', '997', 'SELECT true')" 2>&1)
p4=$(qu pv_r27_st -c "SELECT phasevec.refute('notas', '3', 'the steward retires it')" 2>&1)
if [ "$(refusal "$p1")" = "may not change the claim on key 999" ] \
   && [ "$(refusal "$p2")" = "may not change the claim on key 998" ] \
   && [ "$(refusal "$p3")" = "may not change the claim on key 997" ] && [ -z "$p4" ] \
   && [ "$(claims "'997', '998', '999', '3'")" = "3:pv_r27_st" ]; then
    ok "a key with no row: the owner and a steward claim nothing; a steward claims a row first"
else
    nok "no row: owner '${p1:0:150}' '${p3:0:150}', steward '${p2:0:150}', row '${p4:0:150}';" \
        "$(claims "'997', '998', '999', '3'")"
fi

# 4. a steward and a row it does not see; 5. 0.19.0's claim on a row the caller does not see
fresh
tenants "tenant = current_user OR (current_user = 'pv_r27_st' AND tenant = 'pv_r27_ta')"
q -c "SELECT phasevec.steward('notas', 'pv_r27_st')" >/dev/null
qu pv_r27_own -c "SELECT phasevec.supersede('notas', '1', '11', 'chain')" \
  -c "SELECT phasevec.supersede('notas', '11', '12', 'chain')" \
  -c "SELECT phasevec.assert('notas', '13', 'SELECT true')" >/dev/null
o=()
for k in 12 11 13 14; do
    o+=("$(qu pv_r27_st -c "BEGIN" -c "SELECT phasevec.supersede('notas', '$k', '1', 'probe')" \
            -c "ROLLBACK" 2>&1 | grep -o 'ERROR: .*' | sed "s/key $k /key K /")")
done
v=$(qu pv_r27_st -c "SELECT phasevec.refute('notas', '2', 'a row it sees')" 2>&1)
if [ "${o[0]}" = "${o[2]}" ] && [ "${o[1]}" = "${o[2]}" ] && [ "${o[3]}" = "${o[2]}" ] \
   && grep -q 'may not change the claim on key K' <<<"${o[0]}" && [ -z "$v" ]; then
    ok "a steward's supersede() of a hidden key reads alike in the chain or not; a row it sees" \
       "is its to change"
else
    nok "steward oracle: 12 '${o[0]:0:120}', 11 '${o[1]:0:120}', 13 '${o[2]:0:120}'," \
        "14 '${o[3]:0:120}'; seen row '${v:0:120}'"
fi
q -c "UPDATE phasevec.truth SET data_version = '0.19.0' WHERE key = '13'" >/dev/null
m=()
for k in 13 14 15; do
    m+=("$(qu pv_r27_ta -c "SELECT phasevec.refute('notas', '$k', 'probe')" 2>&1 \
            | grep -o 'ERROR: .*' | sed "s/key $k /key K /")")
done
mo=$(qu pv_r27_own -c "SELECT phasevec.refute('notas', '13', 'the owner')" 2>&1)
if [ "${m[0]}" = "${m[1]}" ] && [ "${m[1]}" = "${m[2]}" ] \
   && grep -q 'may not change the claim on key K' <<<"${m[0]}" \
   && grep -q 'holds what pg_phasevec 0.19.0 wrote' <<<"$mo"; then
    ok "0.19.0's claim on a row a tenant does not see reads as any refusal; the owner is told"
else
    nok "0.19.0 oracle: 13 '${m[0]:0:150}', 14 '${m[1]:0:150}', 15 '${m[2]:0:150}'," \
        "owner '${mo:0:150}'"
fi

# 6. a steward is the owner's; a revoked steward
qu pv_r27_ta -c "SELECT phasevec.assert('notas', k::text, 'SELECT true')
                   FROM generate_series(3, 6) k" >/dev/null
s1=$(qu pv_r27_st -c "SELECT phasevec.refute('notas', '3', 'as a steward')" 2>&1)
q -c "ALTER TABLE notas OWNER TO pv_r27_own2" >/dev/null
s2=$(qu pv_r27_st -c "SELECT phasevec.refute('notas', '4', 'named by the former owner')" 2>&1)
s3=$(qu pv_r27_own -c "SELECT phasevec.steward('notas', 'pv_r27_st')" 2>&1)
s4=$(qu pv_r27_own2 -c "SELECT phasevec.steward('notas', 'pv_r27_st')" 2>&1)
s5=$(qu pv_r27_st -c "SELECT phasevec.refute('notas', '4', 'named by the new owner')" 2>&1)
if [ -z "$s1$s5" ] && [ "$(refusal "$s2")" = "may not change the claim on key 4" ] \
   && grep -q 'only the owner of' <<<"$s3" && [ "$s4" = t ]; then
    ok "ALTER TABLE ... OWNER TO ends the former owner's stewards; the new owner names them again"
else
    nok "owner change: '${s1:0:100}' '${s2:0:120}' former '${s3:0:120}' new '$s4' '${s5:0:120}'"
fi
qu pv_r27_own2 -c "SELECT phasevec.steward('notas', 'pv_r27_st', false)" >/dev/null
g1=$(qu pv_r27_st -c "SELECT phasevec.refute('notas', '5', 'no longer a steward')" 2>&1)
g2=$(qu pv_r27_st -c "SELECT phasevec.assert('notas', '3', NULL)" 2>&1)
g3=$(qu pv_r27_ta -c "SELECT phasevec.assert('notas', '3', 'SELECT true')" 2>&1)
g4=$(qu pv_r27_own2 -c "SELECT phasevec.refute('notas', '3', 'the owner')" 2>&1)
if [ "$(refusal "$g1")" = "may not change the claim on key 5" ] && [ -z "$g4" ] \
   && [ "$(refusal "$g2")" = "may not change the claim on key 3" ] \
   && [ "$(refusal "$g3")" = "may not change the claim on key 3" ] \
   && [ "$(claims "'3', '5'")" = "3:pv_r27_own2 5:pv_r27_ta" ]; then
    ok "a revoked steward changes no claim, one it took as a steward included; the owner" \
       "changes it"
else
    nok "revoked steward: '${g1:0:120}' own '${g2:0:120}' ta '${g3:0:120}' owner '${g4:0:120}';" \
        "$(claims "'3', '5'")"
fi

# 7. a restore into another cluster, whose roles have the same OIDs and names
cluster ra "$PG" $((PORT + 3)); cluster rb "$PG" $((PORT + 4))
start ra; start rb
for p in $((PORT + 3)) $((PORT + 4)); do
    on $p postgres -c "CREATE ROLE au LOGIN" -c "CREATE ROLE stw LOGIN" >/dev/null
done
oa=$(on $((PORT + 3)) postgres -c "SELECT string_agg(oid::text, ',' ORDER BY rolname)
                                     FROM pg_roles WHERE rolname IN ('au', 'stw')")
ob=$(on $((PORT + 4)) postgres -c "SELECT string_agg(oid::text, ',' ORDER BY rolname)
                                     FROM pg_roles WHERE rolname IN ('au', 'stw')")
on $((PORT + 3)) postgres -c "CREATE DATABASE src" >/dev/null
on $((PORT + 3)) src -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register('r1', repeat('a', 64), 4);
CREATE TABLE notas (id int PRIMARY KEY, body text);
INSERT INTO notas SELECT g, 'n' || g FROM generate_series(1, 6) g;
SELECT phasevec.watch('notas', 'notas'::regclass, 'id', 'r.body', 'r1');
GRANT USAGE ON SCHEMA phasevec TO au, stw;
GRANT SELECT, UPDATE ON notas TO au;
GRANT SELECT ON notas TO stw;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz),
  phasevec.refute(text, text, text) TO au, stw;
SELECT phasevec.steward('notas', 'stw');
SET ROLE au;
SELECT phasevec.assert('notas', k::text, 'SELECT true') FROM generate_series(1, 4) k;
RESET ROLE;
SELECT count(*) FROM phasevec.verify('notas', p_every => '0 s');
SQL
"$PG/pg_dump" -h "$W/sock" -p $((PORT + 3)) -U postgres -Fc -d src -f "$W/src.dump"
for t in "$((PORT + 4)) dst" "$((PORT + 3)) same"; do
    set -- $t
    on $1 postgres -c "CREATE DATABASE $2" >/dev/null
    "$PG/pg_restore" -h "$W/sock" -p $1 -U postgres -d $2 "$W/src.dump" 2>/dev/null
done
declare -A vv au_r st_r
for t in "$((PORT + 4)) dst" "$((PORT + 3)) same"; do
    set -- $t
    vv[$1]=$(on $1 $2 -c "SELECT string_agg(key || '=' || phasevec._verdict(t), ' ' ORDER BY key)
                            FROM phasevec.truth t")
    au_r[$1]=$(on $1 $2 -c "SET ROLE au" -c "SELECT phasevec.refute('notas', '1', 'mine?')" 2>&1)
    st_r[$1]=$(on $1 $2 -c "SET ROLE stw" -c "SELECT phasevec.refute('notas', '2', 'steward?')" \
                 2>&1)
done
X=$((PORT + 4)); Y=$((PORT + 3))
ad=$(on $X dst -c "SELECT count(*) FILTER (WHERE adopted) FROM phasevec.adopt('notas', 'au')")
on $X dst -c "SELECT count(*) FROM phasevec.verify('notas', p_every => '0 s')" >/dev/null
va=$(on $X dst -c "SELECT string_agg(key || '=' || phasevec._verdict(t), ' ' ORDER BY key)
                     FROM phasevec.truth t")
ra2=$(on $X dst -c "SET ROLE au" -c "SELECT phasevec.refute('notas', '3', 'mine again')" 2>&1)
if [ -n "$oa" ] && [ "$oa" = "$ob" ] \
   && [ "${vv[$X]}" = "1=unproven 2=unproven 3=unproven 4=unproven" ] \
   && [ "$(refusal "${au_r[$X]}")" = "may not change the claim on key 1" ] \
   && [ "$(refusal "${st_r[$X]}")" = "may not change the claim on key 2" ] \
   && [ "$ad" = 4 ] && [ "$va" = "1=verified 2=verified 3=verified 4=verified" ] && [ -z "$ra2" ] \
   && [ "${vv[$Y]}" = "1=verified 2=verified 3=verified 4=verified" ] \
   && [ -z "${au_r[$Y]}${st_r[$Y]}" ]
then
    ok "restored into another cluster whose roles have the same OIDs ($oa): orphans and no" \
       "steward, the owner adopts; into the same cluster: kept"
else
    nok "restore: oids '$oa'/'$ob', verdicts '${vv[$X]}', au '${au_r[$X]:0:120}'," \
        "stw '${st_r[$X]:0:120}', adopted '$ad', '$va', au again '${ra2:0:100}';" \
        "same cluster '${vv[$Y]}' '${au_r[$Y]:0:100}' '${st_r[$Y]:0:100}'"
fi
stop ra; stop rb; rm -rf "$W/ra" "$W/rb"

# 8. pg_upgrade from an older major
if [ -z "$PG_OLD" ]; then
    echo "ok - pg_upgrade # SKIP: no PG_OLD"
else
    mkdir -p "$W/old/src" "$W/oldlib" "$W/oldlib019" "$W/oldext/extension" "$W/o019"
    cp -r Makefile pg_phasevec.control sql src "$W/old/src/"
    find "$W/old/src" -name '*.o' -o -name '*.so' -o -name '*.bc' | xargs rm -f
    make -s -C "$W/old/src" PG_CONFIG="$PG_OLD/pg_config" >/dev/null 2>&1 \
        || nok "the extension does not build for PG_OLD"
    GIT_INDEX_FILE="$W/index2" git read-tree "$V019" \
        && GIT_INDEX_FILE="$W/index2" git --work-tree="$W/o019" checkout-index -a
    make -s -C "$W/o019" PG_CONFIG="$PG_OLD/pg_config" >/dev/null 2>&1 \
        || nok "0.19.0 does not build for PG_OLD"
    for f in pg_phasevec.control sql/*.sql; do
        ln -sfn "$PWD/$f" "$W/oldext/extension/$(basename "$f")"
    done
    ln -sfn "$W/old/src/pg_phasevec.so" "$W/oldlib/pg_phasevec.so"
    ln -sfn "$W/old/src/src/pg_phasevec_observe.so" "$W/oldlib/pg_phasevec_observe.so"
    ln -sfn "$W/o019/pg_phasevec.so" "$W/oldlib019/pg_phasevec.so"
    ln -sfn "$W/old/src/src/pg_phasevec_observe.so" "$W/oldlib019/pg_phasevec_observe.so"
    cluster uo "$PG_OLD" $((PORT + 5)) "$W/oldlib" "$W/oldext"
    cluster un "$PG" $((PORT + 6))
    cluster u9 "$PG_OLD" $((PORT + 5)) "$W/oldlib019" "$W/oldext"
    start uo
    on $((PORT + 5)) postgres -c "CREATE ROLE au LOGIN" -c "CREATE ROLE stw LOGIN" \
       -c "CREATE DATABASE up" >/dev/null
    on $((PORT + 5)) up -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register('r1', repeat('a', 64), 4);
CREATE TABLE notas (id int PRIMARY KEY, body text);
INSERT INTO notas SELECT g, 'the quick brown fox ' || g FROM generate_series(1, 6) g;
SELECT phasevec.watch('notas', 'notas'::regclass, 'id', 'r.body', 'r1');
SELECT phasevec.lexical('notas', 'english');
GRANT USAGE ON SCHEMA phasevec TO au, stw;
GRANT SELECT, UPDATE ON notas TO au;
GRANT SELECT ON notas TO stw;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz),
  phasevec.refute(text, text, text) TO au, stw;
SELECT phasevec.steward('notas', 'stw');
SET ROLE au;
SELECT phasevec.assert('notas', k::text, 'SELECT true') FROM generate_series(1, 4) k;
RESET ROLE;
SELECT count(*) FROM phasevec.verify('notas', p_every => '0 s');
SQL
    before=$(on $((PORT + 5)) up -c "SELECT string_agg(key || '=' || phasevec._verdict(t), ' '
                                                        ORDER BY key) FROM phasevec.truth t")
    stop uo
    start u9
    on $((PORT + 5)) postgres -c "CREATE DATABASE up9" >/dev/null
    on $((PORT + 5)) up9 -c "CREATE EXTENSION pg_phasevec VERSION '0.19.0'" >/dev/null
    stop u9
    ( cd "$W" && "$PG/pg_upgrade" --check -b "$PG_OLD" -B "$PG" -d "$W/u9" -D "$W/un" \
        -U postgres -s "$W/sock" -p $((PORT + 5)) -P $((PORT + 6)) > "$W/up9.out" 2>&1 )
    u9rc=$?
    ( cd "$W" && "$PG/pg_upgrade" -b "$PG_OLD" -B "$PG" -d "$W/uo" -D "$W/un" -U postgres \
        -s "$W/sock" -p $((PORT + 5)) -P $((PORT + 6)) > "$W/up.out" 2>&1 )
    uprc=$?
    if [ $uprc = 0 ]; then
        start un
        U() { on $((PORT + 6)) up "$@"; }
        after=$(U -c "SELECT string_agg(key || '=' || phasevec._verdict(t), ' ' ORDER BY key)
                        FROM phasevec.truth t")
        lx=$(U -c "SELECT lexical FROM phasevec.watches WHERE name = 'notas'")
        U -c "INSERT INTO notas VALUES (7, 'a lazy dog')" >/dev/null
        lw=$(U -c "SELECT lexemes IS NOT NULL FROM phasevec.sources WHERE key = '7'")
        ua=$(U -c "SET ROLE au" -c "SELECT phasevec.refute('notas', '1', 'mine')" 2>&1)
        us=$(U -c "SET ROLE stw" -c "SELECT phasevec.refute('notas', '2', 'steward')" 2>&1)
        stop un
    fi
    if [ $uprc = 0 ] && [ "$after" = "$before" ] \
       && [ "$before" = "1=verified 2=verified 3=verified 4=verified" ] \
       && [ "$lx" = "pg_catalog.english" ] && [ "$lw" = t ] && [ -z "$ua$us" ]; then
        ok "pg_upgrade $("$PG_OLD/pg_config" --version | grep -o '[0-9]*' | head -1) ->" \
           "$("$PG/pg_config" --version | grep -o '[0-9]*' | head -1): lexical, verdicts," \
           "authors and stewards come through"
    else
        nok "pg_upgrade rc $uprc:" \
            "'$(grep -i -A2 'reg\*\|fatal\|failure' "$W/up.out" | head -c 300)'" \
            "before '$before' after '${after:-}' lexical '${lx:-}' '${lw:-}'" \
            "au '${ua:-}' stw '${us:-}'"
    fi
    if [ $u9rc != 0 ] && { grep -rqs 'phasevec.watches.lexical' "$W"/u9/pg_upgrade_output.d \
                               "$W"/un/pg_upgrade_output.d \
                           || grep -q 'reg\* data types' "$W/up9.out"; }; then
        ok "0.19.0 is refused by pg_upgrade too (watches.lexical regconfig, since 0.6.0)"
    else
        nok "0.19.0 pg_upgrade --check: rc $u9rc '$(tail -c 300 "$W/up9.out")'"
    fi
fi

# 9. the update makes lexical a name
fresh 0.19.0
q -c "SELECT phasevec.lexical('notas', 'english')" >/dev/null
use020
up=$(update 5s)
lt=$(q -c "SELECT format_type(atttypid, atttypmod) FROM pg_attribute
            WHERE attrelid = 'phasevec.watches'::regclass AND attname = 'lexical'")
lx=$(q -c "SELECT lexical FROM phasevec.watches WHERE name = 'notas'")
q -c "UPDATE notas SET body = 'running foxes' WHERE id = 1" >/dev/null
lw=$(q -c "SELECT lexemes::text FROM phasevec.sources WHERE key = '1'")
if [ -z "$up" ] && [ "$lt" = text ] && [ "$lx" = pg_catalog.english ] \
   && [ "$lw" = "'fox':2 'run':1" ]; then
    ok "the update keeps a lexical watch's configuration by name ($lx), and reads with it"
else
    nok "lexical: update '${up:0:200}', type '$lt', '$lx', lexemes '$lw'"
fi

# 10. logical replication between two 0.20.0 servers
cluster pub "$PG" $((PORT + 1)); cluster sub "$PG" $((PORT + 2))
start pub; start sub
P() { on $((PORT + 1)) "$@"; }
S() { on $((PORT + 2)) "$@"; }
P postgres -c "CREATE DATABASE src" >/dev/null
P src -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register('r1', repeat('a', 64), 4);
CREATE TABLE notas (id int PRIMARY KEY, body text);
INSERT INTO notas SELECT g, 'n' || g FROM generate_series(1, 6) g;
SELECT phasevec.watch('notas', 'notas'::regclass, 'id', 'r.body', 'r1');
SELECT phasevec.assert('notas', k::text, 'SELECT true') FROM generate_series(1, 3) k;
SELECT count(*) FROM phasevec.verify('notas', p_every => '0 s');
SELECT phasevec.refute('notas', '4', 'wrong');
CREATE PUBLICATION p FOR TABLE phasevec.readers, phasevec.watches, phasevec.sources,
    phasevec.truth, notas;
SQL
S postgres -c "CREATE DATABASE dst" >/dev/null
"$PG/pg_dump" -h "$W/sock" -p $((PORT + 1)) -U postgres --schema-only --no-publications -d src \
    | S dst >/dev/null 2>&1
S dst -c "CREATE SUBSCRIPTION s CONNECTION 'host=$W/sock port=$((PORT + 1)) user=postgres
          dbname=src' PUBLICATION p" >/dev/null 2>&1
synced() {
    local lsn i
    lsn=$(P src -c "SELECT pg_current_wal_lsn()")
    for i in $(seq 1 60); do
        [ "$(S dst -c "SELECT count(*) FROM pg_subscription_rel WHERE srsubstate <> 'r'")" = 0 ] \
          && [ "$(P src -c "SELECT bool_and(confirmed_flush_lsn >= '$lsn')
                              FROM pg_replication_slots")" = t ] && break
        pause 0.5
    done
}
synced
l1=$(S dst -c "SELECT string_agg(DISTINCT data_version, ',') FROM
                 (SELECT data_version FROM phasevec.truth UNION ALL
                  SELECT data_version FROM phasevec.watches) x")
P src -c "SELECT phasevec.assert('notas', '5', 'SELECT true')" \
  -c "SELECT count(*) FROM phasevec.verify('notas', p_every => '0 s')" >/dev/null
synced
l2=$(S dst -c "SELECT string_agg(key || ':' || data_version, ' ' ORDER BY key) FROM phasevec.truth")
mg=$(S dst -c "SELECT count(*) FROM phasevec.migrate()" 2>&1)
le=$(S dst -c "SELECT count(*) FROM phasevec.truth WHERE last_error LIKE '%before 0.20.0%'")
pv=$(P src -c "SELECT string_agg(key || '=' || phasevec._verdict(t), ' ' ORDER BY key)
                 FROM phasevec.truth t")
S dst -c "ALTER SUBSCRIPTION s DISABLE" -c "ALTER SUBSCRIPTION s SET (slot_name = NONE)" \
  -c "DROP SUBSCRIPTION s" >/dev/null 2>&1
P src -c "SELECT pg_drop_replication_slot('s')" >/dev/null 2>&1
if [ "$l1" = 0.20.0 ] && [ "$l2" = "1:0.20.0 2:0.20.0 3:0.20.0 4:0.20.0 5:0.20.0" ] \
   && [ "$mg" = 0 ] && [ "$le" = 0 ] \
   && [ "$pv" = "1=verified 2=verified 3=verified 4=refuted 5=verified" ]; then
    ok "replication from 0.20.0: the rows stay 0.20.0's, migrate() finds nothing, no verdict is" \
       "dropped for 'verified before 0.20.0'"
else
    nok "0.20.0 -> 0.20.0: labels '$l1', after a verify '$l2', migrate '$mg'," \
        "'before 0.20.0' $le," \
        "publisher '$pv'"
fi
stop pub; stop sub

for d in $DBS; do for r in $ROLES; do qd $d -c "DROP OWNED BY $r" >/dev/null 2>&1; done; done
exit $fallas
