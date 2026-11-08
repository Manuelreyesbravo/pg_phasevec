#!/usr/bin/env bash
# 0.20.0 (twenty-eighth review): a claim is about its row, a steward's right ends with it, a probe
# waits for no one, phasevec.rebind() after a copy of the cluster, a lexical configuration by its
# owner, and the update's first wait under an event trigger. Against the throwaway cluster of
# installcheck.sh (run that first), with the same PV_DATA/PV_PORT/PV_SOCK. Builds 0.19.0 (commit
# 65ae00d) aside, like review27.sh, and starts two more clusters under the scratch directory (ports
# PV_PORT+1 and +2).
#   PG=~/pg19/bin test/review28.sh
# 1. (RT28PA-REUSE-1) A tenant claims its own row, deletes it, and another tenant writes a row
#    under that key: the first one changes nothing of it (refute(), assert() refused), the claim
#    reads 'unproven', a refutation of the same text included, and the new row's writer claims it.
# 2. (RT28PA-REVOKE-1) A steward that took a claim as a steward alone changes it no more once the
#    owner revokes it; the owner changes it, and the steward again once named again. One it took
#    with a right of its own (the row's writer) stays its own to change.
# 3. (RT28PA-LOCK-ORACLE) A probe of a key the caller does not see, whose claim another session is
#    changing, is refused at once, as a key with no claim is: no lock timeout.
# 4. (RV29-1, RT28PA-CLONE-1, the direction) A pg_basebackup copy of a cluster: a role made there
#    by a CREATEROLE role under an author's OID and name takes the author's claims (the documented
#    limit); after phasevec.rebind() it does not, the owner's own claim stays, the stewards are
#    gone, and the owner adopts what it keeps. The original is untouched. A role that is not the
#    table's owner may not rebind it.
# 5. (RV29-4) A lexical watch whose configuration is renamed: one made under the old name by
#    another role is not read with; phasevec.lexical() names one again.
# 6. (RT28PU-1) An event trigger that writes on the update's own DDL: a session in the update's
#    queue that then waits for what the trigger wrote is not the one aborted.
# 7. (RT28PU-2) The update gives way, with lock_timeout, while it holds a session-level advisory
#    lock: its HINT says why.
set -uo pipefail
cd "$(dirname "$0")/.."
PG=${PG:-$HOME/pg19/bin}
DATA=${PV_DATA:-$PWD/.testcluster}
PORT=${PV_PORT:-5491}
SOCK=${PV_SOCK:-/tmp}
V019=65ae00d
W=$(mktemp -d "${TMPDIR:-/tmp}/pv-r28.XXXXXX")
DBS="pv_r28"
ROLES="pv_r28_own pv_r28_ta pv_r28_tb pv_r28_st pv_r28_mal"
export PGOPTIONS="-c client_min_messages=warning"
mkdir -p "$W/v019" "$W/lib" "$W/sock"
GIT_INDEX_FILE="$W/index" git read-tree "$V019" \
    && GIT_INDEX_FILE="$W/index" git --work-tree="$W/v019" checkout-index -a
make -s -C "$W/v019" PG_CONFIG="$PG/pg_config" >/dev/null 2>&1 \
    || { echo "not ok - 0.19.0 does not build"; exit 1; }
ln -sfn "$PWD/src/pg_phasevec_observe.so" "$W/lib/pg_phasevec_observe.so"
export PGOPTIONS="$PGOPTIONS -c dynamic_library_path=$W/lib:\$libdir"
"$PG/pg_ctl" -D "$DATA" -o "-p $PORT -k $SOCK" -l "$DATA/server.log" -w start >/dev/null
EXTRA=""
declare -A PGX
cleanup() {
    for c in $EXTRA; do
        [ -f "$W/$c/postmaster.pid" ] && "$PG/pg_ctl" -D "$W/$c" -m immediate -w stop \
            >/dev/null 2>&1
    done
    for d in $DBS; do "$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists "$d" 2>/dev/null; done
    for r in $ROLES; do qd postgres -c "DROP ROLE IF EXISTS $r" >/dev/null 2>&1; done
    "$PG/pg_ctl" -D "$DATA" -w stop >/dev/null
    rm -rf "$W"
}
trap cleanup EXIT
qd() { local d=$1; shift; "$PG/psql" -h "$SOCK" -p "$PORT" -X -q -At -d "$d" "$@"; }
q() { qd pv_r28 "$@"; }
qu() {
    local u=$1; shift
    PGOPTIONS="-c client_min_messages=warning" \
        "$PG/psql" -h "$SOCK" -p "$PORT" -X -q -At -d pv_r28 -U "$u" "$@"
}
pause() { python3 -I -c "import time, sys; time.sleep(float(sys.argv[1]))" "$1"; }
fallas=0
ok() { echo "ok - $*"; }
nok() { echo "not ok - $*"; fallas=1; }
use019() { ln -sfn "$W/v019/pg_phasevec.so" "$W/lib/pg_phasevec.so"; }
use020() { ln -sfn "$PWD/pg_phasevec.so" "$W/lib/pg_phasevec.so"; }
version() { q -c "SELECT extversion FROM pg_extension WHERE extname = 'pg_phasevec'"; }
refusal() { grep -o 'may not change the claim on key [0-9]*' <<<"$1" | head -1; }
fresh() {   # fresh [VERSION]
    if [ "${1:-0.20.0}" = 0.19.0 ]; then use019; else use020; fi
    "$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists pv_r28 2>/dev/null
    "$PG/createdb" -h "$SOCK" -p "$PORT" pv_r28
    q -v ON_ERROR_STOP=1 -v v="${1:-0.20.0}" >/dev/null <<'SQL'
CREATE EXTENSION pg_phasevec VERSION :'v';
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
# tenants: ta owns rows 1-10, tb 11-20; each sees, writes, inserts and deletes only its own rows;
# st reads every row (SELECT only) and is a steward of the watch
tenants() {
    q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
ALTER TABLE notas ADD COLUMN tenant name DEFAULT current_user;
UPDATE notas SET tenant = CASE WHEN id > 10 THEN 'pv_r28_tb' ELSE 'pv_r28_ta' END;
ALTER TABLE notas ENABLE ROW LEVEL SECURITY;
CREATE POLICY own ON notas USING (tenant = current_user OR current_user = 'pv_r28_st')
    WITH CHECK (tenant = current_user);
ALTER TABLE notas OWNER TO pv_r28_own;
GRANT USAGE ON SCHEMA phasevec TO pv_r28_own, pv_r28_ta, pv_r28_tb, pv_r28_st;
GRANT SELECT, INSERT, UPDATE, DELETE ON notas TO pv_r28_ta, pv_r28_tb;
GRANT SELECT ON notas TO pv_r28_st;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz),
  phasevec.refute(text, text, text), phasevec.supersede(text, text, text, text),
  phasevec.unsupersede(text, text), phasevec.adopt(text, regrole, text[], text[]),
  phasevec.steward(text, regrole, boolean), phasevec.brief(text, int)
  TO pv_r28_own, pv_r28_ta, pv_r28_tb, pv_r28_st;
SQL
}
verdict() { q -c "SELECT phasevec._verdict(t) FROM phasevec.truth t WHERE key = '$1'"; }
author() { q -c "SELECT coalesce(asserted_by, '-') FROM phasevec.truth WHERE key = '$1'"; }

# 1. a claim outlives its row no more
fresh
tenants
a0=$(qu pv_r28_ta -c "INSERT INTO notas (id, body) VALUES (100, 'ta writes 100')" \
       -c "SELECT phasevec.refute('notas', '100', 'mine')" \
       -c "INSERT INTO notas (id, body) VALUES (101, 'the same words')" \
       -c "SELECT phasevec.refute('notas', '101', 'false')" \
       -c "DELETE FROM notas WHERE id IN (100, 101)" 2>&1)
qu pv_r28_tb -c "INSERT INTO notas (id, body) VALUES (100, 'tb writes 100')" \
   -c "INSERT INTO notas (id, body) VALUES (101, 'the same words')" >/dev/null
v100=$(verdict 100); v101=$(verdict 101)
a1=$(qu pv_r28_ta -c "SELECT phasevec.refute('notas', '100', 'still mine?')" 2>&1)
a2=$(qu pv_r28_ta -c "SELECT phasevec.assert('notas', '100', 'SELECT false')" 2>&1)
b1=$(qu pv_r28_tb -c "SELECT count(*) FROM phasevec.brief('notas', 1000)
                      WHERE key IN ('100', '101')" 2>&1)
b2=$(qu pv_r28_tb -c "SELECT phasevec.assert('notas', '100', 'SELECT true')" 2>&1)
if [ -z "$a0" ] && [ "$v100" = unproven ] && [ "$v101" = unproven ] \
   && [ "$(refusal "$a1")" = "may not change the claim on key 100" ] \
   && [ "$(refusal "$a2")" = "may not change the claim on key 100" ] && [ "$b1" = 2 ] \
   && [ -z "$b2" ] && [ "$(author 100)" = pv_r28_tb ]; then
    ok "a claim dies with its row: its author changes nothing of the next row under the key," \
       "which reads 'unproven' (the same words too), and the new row's writer claims it"
else
    nok "key reuse: '${a0:0:100}' verdicts '$v100' '$v101', ta '${a1:0:120}' '${a2:0:120}'," \
        "tb brief '$b1' assert '${b2:0:120}', author '$(author 100)'"
fi

# 2. a revoked steward and the claims it took as a steward only
q -c "SELECT phasevec.steward('notas', 'pv_r28_st')" \
  -c "SELECT phasevec.steward('notas', 'pv_r28_ta')" >/dev/null
qu pv_r28_ta -c "SELECT phasevec.refute('notas', '6', 'its own row, as its writer')" >/dev/null
q -c "SELECT phasevec.steward('notas', 'pv_r28_ta', false)" >/dev/null
s6=$(qu pv_r28_ta -c "SELECT phasevec.assert('notas', '6', 'SELECT true')" 2>&1)
s1=$(qu pv_r28_st -c "SELECT phasevec.refute('notas', '12', 'as a steward')" \
       -c "SELECT phasevec.assert('notas', '13', 'SELECT true')" 2>&1)
q -c "SELECT phasevec.steward('notas', 'pv_r28_st', false)" >/dev/null
s2=$(qu pv_r28_st -c "SELECT phasevec.refute('notas', '13', 'no longer a steward')" 2>&1)
s3=$(qu pv_r28_st -c "SELECT phasevec.assert('notas', '12', 'SELECT false')" 2>&1)
s4=$(qu pv_r28_own -c "SELECT phasevec.refute('notas', '13', 'the owner')" 2>&1)
q -c "SELECT phasevec.steward('notas', 'pv_r28_st')" >/dev/null
s5=$(qu pv_r28_st -c "SELECT phasevec.assert('notas', '12', 'SELECT true')" 2>&1)
if [ -z "$s1$s4$s5$s6" ] && [ "$(refusal "$s2")" = "may not change the claim on key 13" ] \
   && [ "$(refusal "$s3")" = "may not change the claim on key 12" ] \
   && [ "$(author 12)" = pv_r28_st ] && [ "$(author 13)" = pv_r28_own ]; then
    ok "a steward revoked changes no claim it took as a steward (one it took as the row's" \
       "writer it does); the owner does, and the steward named again"
else
    nok "revoked steward: writer's '${s6:0:100}' '${s1:0:100}' after '${s2:0:120}' '${s3:0:120}' owner '${s4:0:100}'" \
        "again '${s5:0:100}'; authors $(author 12) $(author 13)"
fi

# 3. a probe of a hidden key waits for no one
qu pv_r28_ta -c "SELECT phasevec.assert('notas', '3', 'SELECT true')" >/dev/null
( qu pv_r28_ta -c "BEGIN" -c "SELECT phasevec.refute('notas', '3', 'held')" \
     -c "SELECT pg_sleep(3)" -c "COMMIT" >/dev/null 2>&1 ) &
pause 1
st=$(date +%s.%N)
p1=$(qu pv_r28_tb -c "SET lock_timeout = '1s'" \
       -c "SELECT phasevec.refute('notas', '3', 'probe')" 2>&1)
p2=$(qu pv_r28_tb -c "SET lock_timeout = '1s'" \
       -c "SELECT phasevec.refute('notas', '4', 'probe')" 2>&1)
el=$(python3 -I -c "import sys; print(round(float(sys.argv[2]) - float(sys.argv[1]), 2))" \
       "$st" "$(date +%s.%N)")
wait
if [ "$(refusal "$p1")" = "may not change the claim on key 3" ] \
   && [ "$(refusal "$p2")" = "may not change the claim on key 4" ] \
   && python3 -I -c "import sys; sys.exit(0 if float(sys.argv[1]) < 1.0 else 1)" "$el"; then
    ok "a probe of a hidden key whose claim is being changed is refused at once (${el} s)"
else
    nok "lock oracle: '${p1:0:150}' / '${p2:0:150}' (${el} s)"
fi

# 4. phasevec.rebind() on a pg_basebackup copy
"$PG/initdb" -D "$W/a" -A trust -U postgres -E UTF8 --locale=C >/dev/null
{
    echo "unix_socket_directories = '$W/sock'"; echo "listen_addresses = ''"
    echo "wal_level = replica"; echo "shared_buffers = 16MB"; echo "port = $((PORT + 1))"
    echo "extension_control_path = '$DATA/ext:\$system'"
    echo "dynamic_library_path = '$DATA/ext/lib:\$libdir'"
} >> "$W/a/postgresql.conf"
EXTRA="a b"
on() { local p=$1 d=$2; shift 2; "$PG/psql" -h "$W/sock" -p "$p" -U postgres -X -q -At -d "$d" "$@"; }
A=$((PORT + 1)); B=$((PORT + 2))
"$PG/pg_ctl" -D "$W/a" -l "$W/a.log" -w start >/dev/null
on $A postgres -c "CREATE ROLE own LOGIN" -c "CREATE ROLE stw LOGIN" \
   -c "CREATE ROLE mal LOGIN CREATEROLE" -c "CREATE DATABASE src OWNER own" >/dev/null
"$PG/pg_basebackup" -h "$W/sock" -p $A -U postgres -D "$W/b" -X stream -c fast >/dev/null 2>&1
sed -i "s/^port = $A/port = $B/" "$W/b/postgresql.conf"
# in A, after the copy: an author made under an OID B's counter has not reached yet
aoid=$(on $A postgres -c "SELECT max(o) FROM (SELECT lo_create(0) AS o
                                                FROM generate_series(1, 20000)) x" \
         -c "SELECT lo_unlink(oid) FROM pg_largeobject_metadata" >/dev/null 2>&1
       on $A postgres -c "CREATE ROLE au LOGIN" -c "SELECT oid FROM pg_roles WHERE rolname = 'au'")
on $A src -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register('r1', repeat('a', 64), 4);
CREATE TABLE notas (id int PRIMARY KEY, body text);
INSERT INTO notas SELECT g, 'n' || g FROM generate_series(1, 6) g;
SELECT phasevec.watch('notas', 'notas'::regclass, 'id', 'r.body', 'r1');
ALTER TABLE notas OWNER TO own;
GRANT USAGE ON SCHEMA phasevec TO own, au, stw;
GRANT SELECT, UPDATE ON notas TO au;
GRANT SELECT ON notas TO stw;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz),
  phasevec.refute(text, text, text), phasevec.adopt(text, regrole, text[], text[]),
  phasevec.steward(text, regrole, boolean), phasevec.rebind(text) TO own, au, stw;
SET ROLE own;
SELECT phasevec.steward('notas', 'stw');
SELECT phasevec.assert('notas', '4', 'SELECT true');
SET ROLE au;
SELECT phasevec.assert('notas', k::text, 'SELECT true') FROM generate_series(1, 3) k;
RESET ROLE;
SELECT count(*) FROM phasevec.verify('notas', p_every => '0 s');
SQL
"$PG/pg_dump" -h "$W/sock" -p $A -U postgres -Fc -d src -f "$W/src.dump"
"$PG/pg_ctl" -D "$W/b" -l "$W/b.log" -w start >/dev/null
# in B, the copy: a CREATEROLE role moves the counter to the author's OID and makes "au"
boid=$(on $B postgres -c "SET ROLE mal" \
         -c "DO \$\$DECLARE o oid; BEGIN LOOP o := lo_create(0); PERFORM lo_unlink(o);
               EXIT WHEN o >= $aoid - 1; END LOOP; END\$\$" \
         -c "CREATE ROLE au LOGIN" -c "SELECT oid FROM pg_roles WHERE rolname = 'au'" 2>&1)
on $B postgres -c "CREATE DATABASE dst OWNER own" >/dev/null
"$PG/pg_restore" -h "$W/sock" -p $B -U postgres -d dst "$W/src.dump" 2>/dev/null
c0=$(on $B dst -c "SET ROLE au" -c "SELECT phasevec.refute('notas', '1', 'the impostor')" 2>&1)
rr=$(on $B dst -c "SET ROLE stw" -c "SELECT * FROM phasevec.rebind('notas')" 2>&1)
rb=$(on $B dst -c "SET ROLE own" -c "SELECT watch || ':' || claims || ':' || stewards
                                       FROM phasevec.rebind()" 2>&1)
vb=$(on $B dst -c "SELECT string_agg(key || '=' || phasevec._verdict(t), ' ' ORDER BY key)
                     FROM phasevec.truth t")
c1=$(on $B dst -c "SET ROLE au" -c "SELECT phasevec.assert('notas', '2', 'SELECT false')" 2>&1)
c2=$(on $B dst -c "SET ROLE stw" -c "SELECT phasevec.refute('notas', '3', 'a steward?')" 2>&1)
c3=$(on $B dst -c "SET ROLE own" -c "SELECT phasevec.refute('notas', '4', 'the owner''s own')" \
       -c "SELECT phasevec.assert('notas', '4', 'SELECT true')" 2>&1)
ad=$(on $B dst -c "SET ROLE own" \
       -c "SELECT count(*) FILTER (WHERE adopted) FROM phasevec.adopt('notas', 'own')")
va=$(on $A src -c "SET ROLE au" -c "SELECT phasevec.refute('notas', '3', 'in the original')" 2>&1)
if [ "$boid" = "$aoid" ] && [ -z "$c0" ] && grep -q 'only the owner of' <<<"$rr" \
   && [ "$rb" = "notas:3:1" ] && [ "$vb" = "1=refuted 2=unproven 3=unproven 4=verified" ] \
   && [ "$(refusal "$c1")" = "may not change the claim on key 2" ] \
   && [ "$(refusal "$c2")" = "may not change the claim on key 3" ] && [ -z "$c3" ] \
   && [ "$ad" = 2 ] && [ -z "$va" ]; then
    ok "a pg_basebackup copy: a role made under the author's OID ($aoid) takes its claims;" \
       "after rebind() it does not, the stewards are gone, the owner keeps its own and adopts"
else
    nok "rebind: oids '$aoid'/'${boid:0:100}', impostor '${c0:0:100}', steward rebinds" \
        "'${rr:0:100}', '$rb', verdicts '$vb', after '${c1:0:100}' '${c2:0:100}' owner" \
        "'${c3:0:100}', adopted '$ad', original '${va:0:100}'"
fi
"$PG/pg_ctl" -D "$W/b" -m fast -w stop >/dev/null; "$PG/pg_ctl" -D "$W/a" -m fast -w stop >/dev/null

# 5. a lexical configuration renamed, and one made under its old name by another role
fresh
q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
GRANT CREATE ON SCHEMA public TO pv_r28_mal;
ALTER TABLE notas OWNER TO pv_r28_own;
GRANT CREATE ON SCHEMA public TO pv_r28_own;
SET ROLE pv_r28_own;
CREATE TEXT SEARCH CONFIGURATION public.c28 (COPY = pg_catalog.english);
RESET ROLE;
SELECT phasevec.lexical('notas', 'public.c28');
ALTER TEXT SEARCH CONFIGURATION public.c28 RENAME TO c28_old;
SET ROLE pv_r28_mal;
CREATE TEXT SEARCH CONFIGURATION public.c28 (COPY = pg_catalog.simple);
RESET ROLE;
INSERT INTO notas VALUES (50, 'running foxes');
SQL
l1=$(q -c "SELECT coalesce(lexemes::text, '-') FROM phasevec.sources WHERE key = '50'")
q -c "SELECT phasevec.lexical('notas', 'public.c28_old')" \
  -c "INSERT INTO notas VALUES (51, 'running foxes')" >/dev/null
l2=$(q -c "SELECT coalesce(lexemes::text, '-') FROM phasevec.sources WHERE key = '51'")
if [ "$l1" = "-" ] && [ "$l2" = "'fox':2 'run':1" ]; then
    ok "a configuration made under the old name by another role is not read with; lexical()" \
       "names one again"
else
    nok "lexical by name: with the impostor '$l1', named again '$l2'"
fi

# 6. an event trigger that writes on the update's own DDL
fresh 0.19.0
use020
q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE TABLE public.ddl_marker (id int PRIMARY KEY, n bigint);
INSERT INTO public.ddl_marker VALUES (1, 0);
CREATE FUNCTION public.mark_ddl() RETURNS event_trigger LANGUAGE plpgsql AS $$
BEGIN UPDATE public.ddl_marker SET n = n + 1 WHERE id = 1; END $$;
CREATE EVENT TRIGGER mark_ddl ON ddl_command_end EXECUTE FUNCTION public.mark_ddl();
SQL
( q -c "BEGIN" -c "INSERT INTO notas VALUES (100, 'x')" -c "SELECT pg_sleep(1.5)" \
    -c "CREATE TABLE app_scratch (i int)" -c "COMMIT" > "$W/x.out" 2>&1 ) &
pause 0.4
up=$(q -c "SET lock_timeout = 0" -c "SET statement_timeout = '20s'" \
       -c "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" 2>&1)
wait
xo=$(cat "$W/x.out")
xt=$(q -c "SELECT count(*) FROM pg_tables WHERE tablename = 'app_scratch'")
q -c "DROP EVENT TRIGGER mark_ddl" >/dev/null
if [ -z "$xo" ] && [ "$xt" = 1 ]; then
    ok "an event trigger that writes on the update's DDL: the session in its queue goes on" \
       "(update: $(version)${up:+, '$(grep -o 'ERROR: .*' <<<"$up" | head -1 | cut -c1-80)'})"
else
    nok "event trigger: the session '${xo:0:200}', its table '$xt', update '${up:0:200}'"
fi

# 7. a session-level advisory lock: the update gives way, and says why
fresh 0.19.0
use020
( q -c "BEGIN" -c "SELECT count(*) FROM phasevec.watches" -c "SELECT pg_sleep(3)" \
    -c "COMMIT" >/dev/null 2>&1 ) &
pause 0.4
ul=$(q -c "SELECT pg_advisory_lock(28)" -c "SET lock_timeout = '1500ms'" \
       -c "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" 2>&1)
wait
if [ "$(version)" = 0.19.0 ] && grep -q 'session-level advisory lock' <<<"$ul"; then
    ok "holding a session-level advisory lock, the update gives way and its HINT says why"
else
    nok "advisory: version $(version), '${ul:0:300}'"
fi

exit $fallas
