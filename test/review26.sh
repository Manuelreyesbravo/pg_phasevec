#!/usr/bin/env bash
# 0.20.0 (twenty-sixth review): who changes a claim (the owner's rule, in place of "first come"),
# replication, migrate(), and the update's waits. Against the throwaway cluster of installcheck.sh
# (run that first), with the same PV_DATA/PV_PORT/PV_SOCK. Builds 0.19.0 (commit 65ae00d) aside,
# like review25.sh, and starts two more clusters for the logical replication case (ports PV_PORT+1
# and +2, under the scratch directory).
#   PG=~/pg19/bin test/review26.sh
# 1. (RT27-LT0-1) lock_timeout = 0 while overlapping readers always hold phasevec.watches: the
#    update waits in the queue and goes through. In the twenty-fifth review's cut it made 1 ms tries
#    for ever, and statement_timeout ended it.
# 2. (RT26PA-1, RT27-ADOPT-1, RT27-DECISION, RT26PA-4) A claim whose author is gone is changed only
#    by the table's owner or a steward of the watch: adopt() by a tenant that is neither is refused,
#    a steward's adopt() leaves (and does not return) the claims on rows it does not see, and a role
#    that sees the row does not take it. Until this review a tenant's adopt() took them all and was
#    handed their proofs, and any role that saw a row took its orphaned claim.
# 3. (RT26PA-2) Without row-level security a reader no longer claims keys no row has yet with
#    refute() or supersede(); the role that then writes the row asserts it.
# 4. (RT26PA-3) supersede() of a key the caller may not change is refused alike whether or not it
#    sits in the chain of the new key: until this review the cycle check came first and told.
# 5. steward(): the table's owner names and unnames one; no one else; a steward dropped and made
#    again (another OID) is no steward.
# 6. (RT26PL-1) Logical replication from a 0.19.0 publisher: a refute() that arrives after
#    migrate() as an UPDATE reads as 0.19.0's, migrate() brings it, and adopt() + verify() keep it
#    refuted (until this review: 'verified'). A session of phasevec's own that set
#    session_replication_role = replica still writes as 0.20.0.
# 7. (RT26PL-INFO-1) DROP EXTENSION ... CASCADE, CREATE EXTENSION and a data-only restore: migrate()
#    makes the watch's row and TRUNCATE triggers again (until this review it found nothing).
# 8. (RT27-CYCLE-019) A supersede() cycle 0.19.0 took: the update and migrate() undo its newest
#    link, with a WARNING, and brief() serves a key of it again.
# 9. (RT26PU-1) A three-party cycle (X reads truth, then waits for Y; the update; Y writes a watched
#    table): no client is aborted, the update goes through. Until this review X was aborted in about
#    half the timings.
# 10. (RT26PU-2) The update after the caller wrote in the same transaction: the update, not the
#    session that then waits for the caller, ends with the deadlock.
# 11. (RT26PU-3) A column that stores a range over phasevec.watches is named before the update locks
#    anything.
# 12. (RT26PU-4) A function's catalog row changed in a savepoint: its holder is named as one of the
#    transactions that may hold the savepoint (until this review "none any more").
# 13. (RT26PU-5) The update's function locks are no DDL: an event trigger sees only the script's own
#    commands (until this review one ALTER FUNCTION ... OWNER TO per function and per try).
set -uo pipefail
cd "$(dirname "$0")/.."
PG=${PG:-$HOME/pg19/bin}
DATA=${PV_DATA:-$PWD/.testcluster}
PORT=${PV_PORT:-5491}
SOCK=${PV_SOCK:-/tmp}
V019=65ae00d
W=$(mktemp -d "${TMPDIR:-/tmp}/pv-r26.XXXXXX")
DBS="pv_r26 pv_r26b"
ROLES="pv_r26_ta pv_r26_tb pv_r26_rd pv_r26_wr pv_r26_owner pv_r26_x"
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
"$PG/pg_ctl" -D "$DATA" -o "-p $PORT -k $SOCK -c max_prepared_transactions=4" \
    -l "$DATA/server.log" -w start >/dev/null
cleanup() {
    for c in pub sub; do
        [ -d "$W/$c" ] && "$PG/pg_ctl" -D "$W/$c" -m fast -w stop >/dev/null 2>&1
    done
    q -c "ROLLBACK PREPARED 'pv_r26_sp'" >/dev/null 2>&1
    for d in $DBS; do "$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists "$d" 2>/dev/null; done
    for r in $ROLES; do qd postgres -c "DROP ROLE IF EXISTS $r" >/dev/null 2>&1; done
    "$PG/pg_ctl" -D "$DATA" -w stop >/dev/null
    rm -rf "$W"
}
trap cleanup EXIT
qd() { local d=$1; shift; "$PG/psql" -h "$SOCK" -p "$PORT" -X -q -At -d "$d" "$@"; }
q() { qd pv_r26 "$@"; }
qu() {
    local u=$1; shift
    PGOPTIONS="-c client_min_messages=warning" \
        "$PG/psql" -h "$SOCK" -p "$PORT" -X -q -At -d pv_r26 -U "$u" "$@"
}
pause() { python3 -I -c "import time, sys; time.sleep(float(sys.argv[1]))" "$1"; }
fallas=0
ok() { echo "ok - $*"; }
nok() { echo "not ok - $*"; fallas=1; }
use019() { ln -sfn "$W/v019/pg_phasevec.so" "$W/lib/pg_phasevec.so"; }
use020() { ln -sfn "$PWD/pg_phasevec.so" "$W/lib/pg_phasevec.so"; }
version() {
    qd "${1:-pv_r26}" -c "SELECT extversion FROM pg_extension WHERE extname = 'pg_phasevec'"
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
    newdb pv_r26
    q -v ON_ERROR_STOP=1 -v v="${1:-0.20.0}" >/dev/null <<'SQL'
CREATE EXTENSION pg_phasevec VERSION :'v';
SELECT phasevec.reader_register('r1', repeat('a', 64), 4);
CREATE TABLE notas (id int PRIMARY KEY, body text);
INSERT INTO notas SELECT g, 'n' || g FROM generate_series(1, 20) g;
SELECT phasevec.watch('notas', 'notas'::regclass, 'id', 'r.body', 'r1');
SQL
    roles
}
update() {   # update [LOCK_TIMEOUT [DB]]
    qd "${2:-pv_r26}" -c "SET lock_timeout = '${1:-5s}'" \
        -c "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" 2>&1
}

# 1. lock_timeout = 0 with overlapping readers of phasevec.watches
fresh 0.19.0
use020
for i in 0 1 2; do
    ( q -c "SELECT pg_sleep(0.13 * $i)" \
        -c "DO \$\$BEGIN FOR i IN 1..30 LOOP PERFORM count(*) FROM phasevec.watches;
              PERFORM pg_sleep(0.4); COMMIT; END LOOP; END\$\$" >/dev/null 2>&1 ) &
done
pause 0.6
st=$(date +%s.%N)
up=$(q -c "SET lock_timeout = 0" -c "SET statement_timeout = '8s'" \
       -c "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" 2>&1)
el=$(python3 -I -c "import sys; print(round(float(sys.argv[2]) - float(sys.argv[1]), 2))" \
       "$st" "$(date +%s.%N)")
wait
[ "$(version)" = 0.20.0 ] && [ -z "$up" ] \
    && ok "lock_timeout = 0, overlapping readers: the update waits in the queue (${el} s)" \
    || nok "lock_timeout = 0, overlapping readers: version $(version), '${up:0:300}'"

# 2. a claim whose author is gone: the owner's or a steward's
fresh
q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
ALTER TABLE notas ADD COLUMN tenant name DEFAULT 'pv_r26_ta';
UPDATE notas SET tenant = 'pv_r26_tb' WHERE id > 10;
ALTER TABLE notas ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON notas FOR SELECT USING (tenant = current_user OR current_user = 'pv_r26_rd');
ALTER TABLE notas OWNER TO pv_r26_owner;
GRANT USAGE ON SCHEMA phasevec
  TO pv_r26_ta, pv_r26_tb, pv_r26_rd, pv_r26_wr, pv_r26_owner, pv_r26_x;
GRANT SELECT ON notas TO pv_r26_ta, pv_r26_tb, pv_r26_rd, pv_r26_x;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz),
  phasevec.refute(text, text, text), phasevec.supersede(text, text, text, text),
  phasevec.unsupersede(text, text), phasevec.adopt(text, regrole, text[], text[])
  TO pv_r26_ta, pv_r26_tb, pv_r26_rd, pv_r26_wr, pv_r26_owner, pv_r26_x;
SQL
q -c "GRANT EXECUTE ON FUNCTION phasevec.steward(text, regrole, boolean)
        TO pv_r26_ta, pv_r26_tb, pv_r26_rd, pv_r26_wr, pv_r26_owner, pv_r26_x" >/dev/null 2>&1
qu pv_r26_tb -c "SELECT phasevec.assert('notas', k::text, \$p\$SELECT 'tb secret' IS NOT NULL\$p\$)
                   FROM generate_series(11, 13) k" >/dev/null
# orphans, as after the update from 0.19.0 or a restore into another cluster
q -c "UPDATE phasevec.truth SET asserted_by_oid = NULL WHERE key IN ('11', '12', '13')"
a1=$(qu pv_r26_ta -c "SELECT key, proof FROM phasevec.adopt('notas', 'pv_r26_ta')" 2>&1)
s1=$(qu pv_r26_ta -c "SELECT phasevec.steward('notas', 'pv_r26_ta')" 2>&1)
s2=$(qu pv_r26_owner -c "SELECT phasevec.steward('notas', 'pv_r26_ta')" 2>&1)
a2=$(qu pv_r26_ta -c "SELECT key, proof FROM phasevec.adopt('notas', 'pv_r26_ta')" 2>&1)
o=$(q -c "SELECT string_agg(key || ':' || coalesce(asserted_by_oid::regrole::text, '-'), ' '
                            ORDER BY key) FROM phasevec.truth WHERE key IN ('11', '12', '13')")
if grep -q 'may not adopt the claims of watch notas' <<<"$a1" && ! grep -q secret <<<"$a1$a2" \
   && grep -q 'only the owner of' <<<"$s1" && [ "$s2" = t ] && [ -z "$a2" ] \
   && [ "$o" = "11:- 12:- 13:-" ]; then
    ok "adopt(): refused to a tenant that is no steward; a steward's leaves, unseen, the claims" \
       "on rows it does not see"
else
    nok "adopt(): tenant '${a1:0:200}', steward() by ta '${s1:0:120}', by owner '$s2'," \
        "steward's adopt '${a2:0:200}', claims '$o'"
fi
qu pv_r26_owner -c "SELECT phasevec.steward('notas', 'pv_r26_ta', false)" >/dev/null
# a role that sees the row (rd sees every row), and the author's name on another role: refused
r1=$(qu pv_r26_rd -c "SELECT phasevec.refute('notas', '11', 'mine now')" 2>&1)
r2=$(qu pv_r26_rd -c "SELECT phasevec.assert('notas', '12', 'SELECT true')" 2>&1)
r3=$(qu pv_r26_tb -c "SELECT phasevec.assert('notas', '13', 'SELECT true')" 2>&1)
qu pv_r26_owner -c "SELECT phasevec.steward('notas', 'pv_r26_rd')" >/dev/null
r4=$(qu pv_r26_rd -c "SELECT phasevec.refute('notas', '11', 'the steward retires it')" 2>&1)
qu pv_r26_owner -c "SELECT phasevec.steward('notas', 'pv_r26_rd', false)" >/dev/null
r5=$(q -c "SELECT key || ':' || adopted FROM phasevec.adopt('notas', 'pv_r26_tb', ARRAY['12', '13'])
           ORDER BY key" 2>&1 | tr '\n' ' ')
r6=$(qu pv_r26_tb -c "SELECT phasevec.assert('notas', '13', 'SELECT 1 = 1')" 2>&1)
o=$(q -c "SELECT string_agg(key || ':' || coalesce(asserted_by, '-') || ':'
                            || phasevec._claim_state(t), ' ' ORDER BY key)
            FROM phasevec.truth t WHERE key IN ('11', '12', '13')")
if grep -q 'may not change the claim on key 11' <<<"$r1" \
   && grep -q 'may not change the claim on key 12' <<<"$r2" \
   && grep -q 'may not change the claim on key 13' <<<"$r3" && [ -z "$r4$r6" ] \
   && [ "$r5" = "12:true 13:true " ] \
   && [ "$o" = "11:pv_r26_rd:retired 12:pv_r26_tb:judged 13:pv_r26_tb:judged" ]; then
    ok "an orphaned claim is no longer taken by a role that sees its row; a steward retires it," \
       "the owner adopts it for its author"
else
    nok "orphans: rd '${r1:0:150}' '${r2:0:150}', tb '${r3:0:150}', steward '${r4:0:150}'," \
        "owner's adopt '$r5', tb '${r6:0:150}'; '$o'"
fi

# 3. without row-level security, no key with no row is claimed
q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE TABLE plain (id int PRIMARY KEY, body text);
INSERT INTO plain SELECT g, 'p' || g FROM generate_series(1, 5) g;
SELECT phasevec.watch('plain', 'plain'::regclass, 'id', 'r.body', 'r1');
GRANT SELECT ON plain TO pv_r26_rd, pv_r26_wr;
GRANT INSERT ON plain TO pv_r26_wr;
SQL
p1=$(qu pv_r26_rd -c "SELECT phasevec.refute('plain', '500', 'reserved')" 2>&1)
p2=$(qu pv_r26_rd -c "SELECT phasevec.supersede('plain', '501', '1', 'reserved')" 2>&1)
p3=$(qu pv_r26_wr -c "INSERT INTO plain VALUES (500, 'x'), (501, 'y')" \
       -c "SELECT phasevec.assert('plain', '500', 'SELECT true')" \
       -c "SELECT phasevec.assert('plain', '501', 'SELECT true')" 2>&1)
o=$(q -c "SELECT string_agg(t.key || ':' || t.asserted_by || ':' || t.verdict, ' ' ORDER BY t.key)
            FROM phasevec.truth t JOIN phasevec.watches w ON w.id = t.watch WHERE w.name = 'plain'")
if grep -q 'may not change the claim on key 500' <<<"$p1" \
   && grep -q 'may not change the claim on key 501' <<<"$p2" && [ -z "$p3" ] \
   && [ "$o" = "500:pv_r26_wr:unproven 501:pv_r26_wr:unproven" ]; then
    ok "no RLS: a reader claims no key that has no row; the row's writer asserts it"
else
    nok "no RLS: refute '${p1:0:150}', supersede '${p2:0:150}', writer '${p3:0:200}'; '$o'"
fi

# 4. supersede(): the claim check before the cycle check
q -c "SELECT phasevec.supersede('notas', '2', '12', 'twelve')" >/dev/null
c1=$(qu pv_r26_ta -c "SELECT phasevec.supersede('notas', '12', '2', 'x')" 2>&1)
c2=$(qu pv_r26_ta -c "SELECT phasevec.supersede('notas', '19', '2', 'x')" 2>&1)
if grep -q 'may not change the claim on key 12' <<<"$c1" \
   && grep -q 'may not change the claim on key 19' <<<"$c2" && ! grep -q 'in the end' <<<"$c1"; then
    ok "supersede() of a hidden key reads alike, in a chain or not"
else
    nok "supersede() as an oracle: '${c1:0:200}' / '${c2:0:200}'"
fi

# 5. steward(): the table's owner's; a steward made again is none
x1=$(qu pv_r26_x -c "SELECT phasevec.steward('notas', 'pv_r26_x')" 2>&1)
x2=$(qu pv_r26_owner -c "SELECT phasevec.steward('notas', 'pv_r26_x')" \
       -c "SELECT phasevec.steward('notas', 'pv_r26_x')" 2>&1 | tr '\n' ' ')
x3=$(qu pv_r26_x -c "SELECT phasevec.refute('notas', '12', 'the steward')" 2>&1)
q -c "DROP OWNED BY pv_r26_x" -c "DROP ROLE pv_r26_x" -c "CREATE ROLE pv_r26_x LOGIN" \
  -c "GRANT USAGE ON SCHEMA phasevec TO pv_r26_x" -c "GRANT SELECT ON notas TO pv_r26_x" \
  -c "GRANT EXECUTE ON FUNCTION phasevec.refute(text, text, text) TO pv_r26_x" >/dev/null
x4=$(qu pv_r26_x -c "SELECT phasevec.refute('notas', '13', 'the steward again')" 2>&1)
if grep -q 'only the owner of' <<<"$x1" && [ "$x2" = "t f " ] && [ -z "$x3" ] \
   && grep -q 'may not change the claim on key 13' <<<"$x4"; then
    ok "steward(): the owner's only; a steward changes a claim; one dropped and made again is none"
else
    nok "steward(): x '${x1:0:150}', owner '$x2', steward '${x3:0:150}', made again '${x4:0:150}'"
fi

# 6. logical replication from 0.19.0
o=$(q -c "SET session_replication_role = replica" \
      -c "SELECT phasevec.assert('notas', '3', 'SELECT true')" -c "RESET session_replication_role" \
      -c "SELECT data_version FROM phasevec.truth WHERE key = '3'" 2>&1 | grep -v '^$')
[ "$o" = 0.20.0 ] && ok "a session that set session_replication_role = replica writes as 0.20.0" \
    || nok "assert() under replica: '$o'"
for c in pub sub; do
    "$PG/initdb" -D "$W/$c" -A trust -U postgres -E UTF8 --locale=C >/dev/null || nok "initdb $c"
    {
        echo "unix_socket_directories = '$W/sock'"; echo "listen_addresses = ''"
        echo "wal_level = logical"; echo "shared_buffers = 16MB"
        echo "extension_control_path = '$DATA/ext:\$system'"
    } >> "$W/$c/postgresql.conf"
done
echo "dynamic_library_path = '$W/lib019:\$libdir'" >> "$W/pub/postgresql.conf"
echo "dynamic_library_path = '$DATA/ext/lib:\$libdir'" >> "$W/sub/postgresql.conf"
"$PG/pg_ctl" -D "$W/pub" -o "-p $((PORT + 1))" -l "$W/pub.log" -w start >/dev/null
"$PG/pg_ctl" -D "$W/sub" -o "-p $((PORT + 2))" -l "$W/sub.log" -w start >/dev/null
P() { PGOPTIONS= "$PG/psql" -h "$W/sock" -p $((PORT + 1)) -U postgres -X -q -At "$@"; }
S() { PGOPTIONS="-c client_min_messages=warning" \
        "$PG/psql" -h "$W/sock" -p $((PORT + 2)) -U postgres -X -q -At "$@"; }
P -d postgres -c "CREATE DATABASE src" >/dev/null
P -d src -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE EXTENSION pg_phasevec VERSION '0.19.0';
SELECT phasevec.reader_register('r1', repeat('a', 64), 4);
CREATE TABLE notas (id int PRIMARY KEY, body text);
INSERT INTO notas SELECT g, 'n' || g FROM generate_series(1, 6) g;
SELECT phasevec.watch('notas', 'notas'::regclass, 'id', 'r.body', 'r1');
SELECT phasevec.assert('notas', k::text, 'SELECT true') FROM generate_series(1, 2) k;
SELECT count(*) FROM phasevec.verify('notas', p_every => '0 s');
CREATE PUBLICATION p FOR TABLE phasevec.readers, phasevec.watches, phasevec.sources,
    phasevec.truth, notas;
SQL
S -d postgres -c "CREATE DATABASE dst" >/dev/null
"$PG/pg_dump" -h "$W/sock" -p $((PORT + 1)) -U postgres --schema-only --no-publications -d src \
    | S -d dst >/dev/null 2>&1
S -d dst -c "CREATE SUBSCRIPTION s CONNECTION 'host=$W/sock port=$((PORT + 1)) user=postgres
             dbname=src' PUBLICATION p" >/dev/null 2>&1
for i in $(seq 1 60); do
    [ "$(S -d dst -c "SELECT count(*) FROM pg_subscription_rel WHERE srsubstate <> 'r'")" = 0 ] \
        && break
    pause 0.5
done
m1=$(S -d dst -c "SELECT watch || '|' || claims FROM phasevec.migrate()" 2>&1)
P -d src -c "SELECT phasevec.refute('notas', '1', 'n1 is wrong')" >/dev/null
lsn=$(P -d src -c "SELECT pg_current_wal_lsn()")
for i in $(seq 1 60); do
    [ "$(P -d src -c "SELECT bool_and(confirmed_flush_lsn >= '$lsn') FROM pg_replication_slots")" \
      = t ] && break
    pause 0.5
done
dv=$(S -d dst -c "SELECT data_version FROM phasevec.truth WHERE key = '1'")
S -d dst -c "ALTER SUBSCRIPTION s DISABLE" -c "ALTER SUBSCRIPTION s SET (slot_name = NONE)" \
  -c "DROP SUBSCRIPTION s" >/dev/null 2>&1
P -d src -c "SELECT pg_drop_replication_slot('s')" >/dev/null 2>&1
m2=$(S -d dst -c "SELECT watch || '|' || claims FROM phasevec.migrate()" 2>&1)
S -d dst -c "CREATE ROLE alice" -c "GRANT USAGE ON SCHEMA phasevec TO alice" \
  -c "GRANT SELECT ON notas TO alice" \
  -c "SELECT count(*) FROM phasevec.adopt('notas', 'alice')" \
  -c "SELECT count(*) FROM phasevec.verify('notas', p_every => '0 s')" >/dev/null 2>&1
v=$(S -d dst -c "SELECT string_agg(key || '=' || phasevec._verdict(t), ' ' ORDER BY key)
                   FROM phasevec.truth t WHERE key IN ('1', '2')")
if [ "$m1" = "notas|2" ] && [ "$dv" = 0.19.0 ] && [ "$m2" = "notas|1" ] \
   && [ "$v" = "1=refuted 2=verified" ]; then
    ok "a 0.19.0 refute() replicated after migrate() reads as 0.19.0's; migrate() brings it," \
       "and adopt() + verify() keep it refuted"
else
    nok "replication: migrate '$m1', label after the refute '$dv', migrate again '$m2', '$v'"
fi
for c in pub sub; do "$PG/pg_ctl" -D "$W/$c" -m fast -w stop >/dev/null; done
rm -rf "$W/pub" "$W/sub"

# 7. the triggers after DROP EXTENSION ... CASCADE and a data-only restore
fresh
q -c "SELECT phasevec.assert('notas', '1', 'SELECT true')" \
  -c "SELECT count(*) FROM phasevec.verify('notas', p_every => '0 s')" >/dev/null
q -c "SELECT phasevec.steward('notas', 'pv_r26_ta')" >/dev/null 2>&1
"$PG/pg_dump" -h "$SOCK" -p "$PORT" -Fc --data-only -n phasevec -d pv_r26 -f "$W/d020.dump"
q -c "DROP EXTENSION pg_phasevec CASCADE" -c "CREATE EXTENSION pg_phasevec" >/dev/null
r=$("$PG/pg_restore" -h "$SOCK" -p "$PORT" --data-only -d pv_r26 "$W/d020.dump" 2>&1)
m=$(q -c "SELECT watch || '|' || claims || '|' || truncate_trigger || '|' || row_trigger
            FROM phasevec.migrate()" 2>&1)
q -c "UPDATE notas SET body = 'changed' WHERE id = 1" >/dev/null
v=$(q -c "SELECT phasevec._verdict(t) FROM phasevec.truth t WHERE key = '1'")
st=$(q -c "SELECT count(*) FROM phasevec.stewards")
if [ "$m" = "notas|0|made|made" ] && [ "$v" = unproven ] && [ "$st" = 1 ] && [ -z "$r" ]; then
    ok "migrate() makes the triggers a CASCADE dropped; a change after it is seen"
else
    nok "after CASCADE + restore: restore '${r:0:200}', migrate '$m', verdict '$v', stewards $st"
fi

# 8. a supersede() cycle written by 0.19.0
fresh 0.19.0
q -c "SELECT phasevec.assert('notas', k::text, 'SELECT true') FROM generate_series(9, 16) k" \
  -c "SELECT phasevec.supersede('notas', '9', '10', 'a')" \
  -c "SELECT phasevec.supersede('notas', '10', '9', 'b')" \
  -c "SELECT phasevec.supersede('notas', '14', '15', 'c')" \
  -c "SELECT phasevec.supersede('notas', '15', '16', 'd')" \
  -c "SELECT phasevec.supersede('notas', '16', '14', 'e')" >/dev/null
"$PG/pg_dump" -h "$SOCK" -p "$PORT" -Fc -d pv_r26 -f "$W/c019.dump"
use020
up=$(PGOPTIONS="-c client_min_messages=warning -c dynamic_library_path=$W/lib:\$libdir" \
     q -c "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" 2>&1)
c1=$(q -c "SELECT string_agg(key || ':' || verdict || ':' || coalesce(replaced_by, '-'), ' '
                             ORDER BY key)
             FROM phasevec.truth WHERE key IN ('9', '10', '14', '15', '16')")
newdb pv_r26b
"$PG/pg_restore" -h "$SOCK" -p "$PORT" -d pv_r26b "$W/c019.dump" >/dev/null 2>&1
mg=$(qd pv_r26b -c "SELECT watch || '|' || claims FROM phasevec.migrate()" 2>&1)
c2=$(qd pv_r26b -c "SELECT string_agg(key || ':' || verdict || ':' || coalesce(replaced_by, '-'),
                                      ' ' ORDER BY key)
                      FROM phasevec.truth WHERE key IN ('9', '10', '14', '15', '16')")
want="10:unproven:- 14:replaced:15 15:replaced:16 16:unproven:- 9:replaced:10"
if [ "$c1" = "$want" ] && [ "$c2" = "$c1" ] \
   && grep -q 'row 10 replaced by row 9 closed a cycle' <<<"$up" \
   && grep -q 'row 16 replaced by row 14 closed a cycle' <<<"$mg"; then
    ok "0.19.0 supersede() cycles: the newest link of each undone, named, by the update and by" \
       "migrate()"
else
    nok "0.19.0 cycle: update '${up:0:200}' -> '$c1'; migrate '${mg:0:200}' -> '$c2'"
fi

# 9. a three-party cycle: X reads truth and waits for Y; Y writes notas while the update holds
#    watches
hits=0; n=0; through=0
for tu in 0.96 1.00 1.04 1.08; do
    for dy in 0.02 0.06; do
        fresh 0.19.0
        use020
        q -c "CREATE TABLE app (id int PRIMARY KEY, v int); INSERT INTO app VALUES (1, 0)"
        ty=$(python3 -I -c "import sys; print(float(sys.argv[1]) + float(sys.argv[2]))" $tu $dy)
        ( q -c "BEGIN" -c "UPDATE app SET v = v + 1 WHERE id = 1" -c "SELECT pg_sleep($ty)" \
            -c "INSERT INTO notas VALUES (500, 'y')" -c "COMMIT" > "$W/y.out" 2>&1 ) &
        ( q -c "SELECT pg_sleep(0.1)" -c "BEGIN" -c "SELECT count(*) FROM phasevec.truth" \
            -c "UPDATE app SET v = v + 1 WHERE id = 1" -c "COMMIT" > "$W/x.out" 2>&1 ) &
        ( q -c "SELECT pg_sleep($tu)" -c "SET lock_timeout = '5s'" \
            -c "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" > "$W/u.out" 2>&1 ) &
        wait
        n=$((n + 1))
        grep -q ERROR "$W/x.out" "$W/y.out" && hits=$((hits + 1))
        [ "$(version)" = 0.20.0 ] && through=$((through + 1))
    done
done
[ $hits = 0 ] && [ $through = $n ] \
    && ok "three-party cycle: no client aborted in $n timings, the update through each time" \
    || nok "three-party cycle: clients aborted in $hits of $n timings, update through $through"

# 10. the update after the caller wrote in the same transaction
fresh 0.19.0
use020
q -c "CREATE TABLE app (id int PRIMARY KEY, v int); INSERT INTO app VALUES (1, 0)"
( q -c "BEGIN" -c "INSERT INTO notas VALUES (500, 'x')" -c "SELECT pg_sleep(0.5)" \
    -c "UPDATE app SET v = v + 1 WHERE id = 1" -c "COMMIT" > "$W/x.out" 2>&1 ) &
( q -c "SELECT pg_sleep(0.2)" -c "SET lock_timeout = '5s'" -c "BEGIN" \
    -c "UPDATE app SET v = v + 1 WHERE id = 1" \
    -c "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" -c "COMMIT" > "$W/u.out" 2>&1 ) &
wait
if ! grep -q ERROR "$W/x.out" && grep -q 'deadlock detected' "$W/u.out" \
   && [ "$(version)" = 0.19.0 ]; then
    ok "the update after the caller wrote: the update ends with the deadlock, the other goes on"
else
    nok "caller wrote first: X '$(grep -h ERROR "$W/x.out")', update" \
        "'$(grep -h ERROR "$W/u.out")', version $(version)"
fi

# 11. a range over phasevec.watches
fresh 0.19.0
use020
q -c "CREATE TYPE public.wr AS RANGE (subtype = phasevec.watches)" \
  -c "CREATE TABLE public.m1 (c public.wr)" >/dev/null
up=$(update 5s)
if grep -q 'column c of public.m1 stores type public.wr' <<<"$up" && grep -q 'nothing was changed' <<<"$up" \
   && [ "$(version)" = 0.19.0 ]; then
    ok "a column of a range over phasevec.watches is named before the update locks anything"
else
    nok "range dependent: '${up:0:300}', version $(version)"
fi

# 12. a catalog row changed in a savepoint
fresh 0.19.0
use020
( q -c "BEGIN" -c "SAVEPOINT s" -c "GRANT EXECUTE ON FUNCTION phasevec.coverage(text) TO pv_r26_x" \
    -c "RELEASE s" -c "SELECT pg_backend_pid()" -c "SELECT pg_sleep(3)" -c "COMMIT" \
    > "$W/sp.out" 2>&1 ) &
pause 0.8
up=$(update 700ms)
wait
pid=$(grep -E '^[0-9]+$' "$W/sp.out" | head -1)
q -c "BEGIN" -c "SAVEPOINT s" -c "GRANT EXECUTE ON FUNCTION phasevec.coverage(text) TO pv_r26_x" \
  -c "RELEASE s" -c "PREPARE TRANSACTION 'pv_r26_sp'" >/dev/null
up2=$(update 700ms)
q -c "ROLLBACK PREPARED 'pv_r26_sp'" >/dev/null
if [ -n "$pid" ] && grep -q "a subtransaction of one of: .*$pid" <<<"$up" \
   && grep -q "a subtransaction of one of: .*prepared transaction 'pv_r26_sp'" <<<"$up2"; then
    ok "a catalog row changed in a savepoint: its holder named among the candidates"
else
    nok "savepoint holder (pid $pid): '${up:0:400}' / '${up2:0:400}'"
fi

# 13. event triggers see no ALTER FUNCTION ... OWNER TO
fresh 0.19.0
use020
q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE TABLE ddl_log (tag text, obj text);
CREATE FUNCTION log_ddl() RETURNS event_trigger LANGUAGE plpgsql AS $$
DECLARE r record;
BEGIN
  FOR r IN SELECT * FROM pg_event_trigger_ddl_commands() LOOP
    INSERT INTO public.ddl_log (tag, obj) VALUES (r.command_tag, r.object_identity);
  END LOOP;
END $$;
CREATE EVENT TRIGGER pv_r26_log_ddl ON ddl_command_end EXECUTE FUNCTION log_ddl();
SQL
up=$(update 5s)
na=$(q -c "SELECT count(*) FROM ddl_log WHERE tag = 'ALTER FUNCTION'")
q -c "DROP EVENT TRIGGER pv_r26_log_ddl" >/dev/null
if [ "$(version)" = 0.20.0 ] && [ "$na" -lt 20 ]; then
    ok "the update's function locks are no DDL: $na ALTER FUNCTION seen by an event trigger"
else
    nok "event trigger: version $(version), $na ALTER FUNCTION, '${up:0:200}'"
fi

for d in $DBS; do for r in $ROLES; do qd $d -c "DROP OWNED BY $r" >/dev/null 2>&1; done; done
exit $fallas
