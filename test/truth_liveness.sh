#!/usr/bin/env bash
# 0.20.0 (eleventh review): safety does not depend on liveness. Each attack below stopped judgment from moving while
# the old verdict was still served; the rules that answer them are in sql/pg_phasevec--0.19.0--0.20.0.sql (37-39).
# Against the throwaway cluster of installcheck.sh (run that first), with the same PV_DATA/PV_PORT/PV_SOCK.
#   PG=~/pg19/bin test/truth_liveness.sh
# M1. (last: it restarts the cluster with a small lock table) A role with no grants fills the shared lock table with session advisory locks: the proof fails 'out of shared
#     memory' (53200). It was recorded refuted, for a true claim. Now: not the proof's answer, nothing judged.
# M2. An uncommitted assert() of a key, by a role that may assert (not the author), holds its truth row for as long as
#     it stays open: the claim cannot be judged, and brief() kept serving the old 'verified' after the committed state
#     refuted it. Now the verdict serves only until its horizon (watches.max_age), then reads 'unproven'.
# H1. Once p_n claims are stale (their rows edited, not asserted again) they sorted first in every verify(p_n), and no
#     other claim was judged again. Now every attempt spends the claim's turn: each claim is tried within
#     ceil(N / p_n) calls.
# M3. An author holds its own claims' rows in an open transaction: verify(p_n) skipped them, recorded nothing, and
#     they kept the head of the queue. Same rule as H1.
# L.  The property: N claims of three authors, hostile actors at once (a row holder, an assert holder, a stale editor,
#     a worker-slot hog); every claim is tried within ceil(N / p_n) calls, and brief() never serves a verdict older
#     than its horizon, even while the hog leaves no worker free and nothing can be judged.
set -uo pipefail
cd "$(dirname "$0")/.."
PG=${PG:-$HOME/pg19/bin}
DATA=${PV_DATA:-$PWD/.testcluster}
PORT=${PV_PORT:-5491}
SOCK=${PV_SOCK:-/tmp}
DB=pv_live
P=(-h "$SOCK" -p "$PORT" -X -q -At -d $DB)
export PGOPTIONS="-c client_min_messages=warning"
"$PG/pg_ctl" -D "$DATA" -o "-p $PORT -k $SOCK" -l "$DATA/server.log" -w start >/dev/null
bg=()
cleanup() {
    for p in "${bg[@]}"; do kill "$p" 2>/dev/null; done
    "$PG/psql" "${P[@]}" -c "SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE datname = '$DB' AND pid <> pg_backend_pid()" >/dev/null 2>&1
    wait 2>/dev/null
    "$PG/pg_ctl" -D "$DATA" -w stop >/dev/null
}
trap cleanup EXIT
"$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists $DB 2>/dev/null
"$PG/createdb" -h "$SOCK" -p "$PORT" $DB
q() { "$PG/psql" "${P[@]}" "$@"; }
as() { local r=$1; shift; "$PG/psql" -h "$SOCK" -p "$PORT" -X -q -At -d $DB -U "$r" "$@"; }
v() { q -c "SET ROLE pv_l_v" "$@"; }
q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
DO $$ DECLARE r text; BEGIN
  FOREACH r IN ARRAY ARRAY['pv_l_a','pv_l_b','pv_l_c','pv_l_s','pv_l_w','pv_l_x','pv_l_h','pv_l_v'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('DROP OWNED BY %I CASCADE', r); EXECUTE format('DROP ROLE %I', r);
    END IF;
  END LOOP; END $$;
CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register('r1', repeat('a', 64), 4);
CREATE ROLE pv_l_a LOGIN; CREATE ROLE pv_l_b LOGIN; CREATE ROLE pv_l_c LOGIN;  -- authors
CREATE ROLE pv_l_s LOGIN;   -- may assert (not an author of these claims)
CREATE ROLE pv_l_w LOGIN;   -- writes the watched tables
CREATE ROLE pv_l_x LOGIN;   -- no grants at all
CREATE ROLE pv_l_h LOGIN;   -- the worker-slot hog: an author with slow proofs, its own verifier
CREATE ROLE pv_l_v LOGIN;   -- the verifier
GRANT pv_l_a, pv_l_b, pv_l_c TO pv_l_v;
GRANT USAGE ON SCHEMA phasevec TO pv_l_a, pv_l_b, pv_l_c, pv_l_s, pv_l_h, pv_l_v;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz) TO pv_l_a, pv_l_b, pv_l_c, pv_l_s, pv_l_h;
GRANT EXECUTE ON FUNCTION phasevec.verify(text, int, interval, interval, int, float8),
                          phasevec.verify_one(text, text, int, float8), phasevec.brief(text, int) TO pv_l_v, pv_l_h;
CREATE TABLE facts (id int PRIMARY KEY, ok boolean NOT NULL);
INSERT INTO facts SELECT g, true FROM generate_series(1, 200) g;
CREATE FUNCTION public.ok(k int) RETURNS boolean LANGUAGE sql STABLE AS $$ SELECT ok FROM public.facts WHERE id = k $$;
CREATE TABLE parted (id int, v int) PARTITION BY RANGE (id);
DO $$ BEGIN FOR i IN 0..59 LOOP
  EXECUTE format('CREATE TABLE parted_%s PARTITION OF parted FOR VALUES FROM (%s) TO (%s)', i, i * 10, i * 10 + 10);
END LOOP; END $$;
DO $$ BEGIN FOR i IN 1..6 LOOP
  EXECUTE format('CREATE TABLE notes%s (id int PRIMARY KEY, body text)', i);
  EXECUTE format('INSERT INTO notes%s SELECT g, %L || g FROM generate_series(1, 200) g', i, 'note ');
  EXECUTE format('GRANT SELECT ON notes%s TO pv_l_a, pv_l_b, pv_l_c, pv_l_s, pv_l_h, pv_l_v', i);
  EXECUTE format('GRANT SELECT, UPDATE ON notes%s TO pv_l_w', i);
  PERFORM phasevec.watch('w' || i, ('notes' || i)::regclass, 'id', 'r.body', 'r1');
END LOOP; END $$;
GRANT SELECT ON facts, parted TO pv_l_a, pv_l_b, pv_l_c, pv_l_s, pv_l_h, pv_l_v;
GRANT EXECUTE ON FUNCTION public.ok(int) TO PUBLIC;
SQL
fallas=0
pass() { echo "ok - $1"; }
fail() { echo "not ok - $1"; fallas=1; }
# The horizon: watches.max_age (0.20.0, eleventh review). The SQL of 07b019f has no such column: this says so.
horizon() { q -c "UPDATE phasevec.watches SET max_age = interval '$2' WHERE name = '$1'" >/dev/null 2>&1 || echo "(no max_age: 07b019f)"; }
stored() { q -c "SELECT verdict || '|' || coalesce(last_error, '') FROM phasevec.truth t JOIN phasevec.watches w ON w.id = t.watch WHERE w.name = '$1' AND key = '$2'"; }
reads() { q -c "SELECT phasevec._verdict(t) FROM phasevec.truth t JOIN phasevec.watches w ON w.id = t.watch WHERE w.name = '$1' AND key = '$2'"; }
assert_as() { as "$1" -c "SELECT phasevec.assert('$2', '$3', \$p\$$4\$p\$)" >/dev/null; }
wait_for() {  # wait_for <sql that returns t> [tries]
    for _ in $(seq 1 "${2:-200}"); do [ "$(q -c "$1")" = "t" ] && return 0; sleep 0.05; done; return 1
}

# ------------------------------------------------------------------------------------------------------------- M2 --
horizon w2 '3 seconds'
assert_as pv_l_a w2 1 'public.ok(1)'
v -c "SELECT count(*) FROM phasevec.verify('w2', 10, interval '0', interval '30 seconds', 5000)" >/dev/null
q -c "UPDATE facts SET ok = false WHERE id = 1"
as pv_l_s -c "BEGIN" -c "SELECT phasevec.assert('w2', '1', 'true')" -c "SELECT pg_sleep(12)" -c "ROLLBACK" >/dev/null 2>&1 &
holder=$!; bg+=("$holder")
wait_for "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE usename = 'pv_l_s' AND wait_event = 'PgSleep')" || echo "M2: no holder"
said=$(v -c "SELECT count(*) FROM phasevec.verify('w2', 10, interval '0', interval '30 seconds', 5000)" 2>&1)
early=$(v -c "SELECT coalesce(string_agg(verdict, ','), 'none') FROM phasevec.brief('w2') WHERE key = '1'")
sleep 3.5
v -c "SELECT count(*) FROM phasevec.verify('w2', 10, interval '0', interval '30 seconds', 5000)" >/dev/null
late=$(v -c "SELECT coalesce(string_agg(verdict, ','), 'none') FROM phasevec.brief('w2') WHERE key = '1'")
one=$(v -c "SELECT phasevec.verify_one('w2', '1', 1000)" 2>&1 | tr '\n' ' ' | cut -c1-120)
echo "M2 while the assert is open: verify() rows: $said; brief() at once: $early; past the horizon: $late (reads $(reads w2 1)); verify_one(): $one"
[ "$late" = "unproven" ] && pass "M2: a claim kept from its verifiers by an open assert() is not served past its horizon" \
    || fail "M2: an open assert() kept a refuted claim served as '$late' past its horizon"
wait "$holder" 2>/dev/null
after=$(v -c "SELECT key || ' ' || verdict FROM phasevec.verify('w2', 10, interval '0', interval '30 seconds', 5000)")
echo "M2 after the ROLLBACK: $after"
[ "$after" = "1 refuted" ] && pass "M2: judged as soon as the row is free" || fail "M2: after the ROLLBACK: $after"

# ------------------------------------------------------------------------------------------------------------- H1 --
# 20 claims of pv_l_a; p_n = 5; before each call pv_l_w edits the rows of keys 1-5 (stale, not asserted again).
q -c "SET ROLE pv_l_a" -c "SELECT count(phasevec.assert('w3', k::text, format('public.ok(%s)', 100 + k))) FROM generate_series(1, 20) k" >/dev/null
v -c "SELECT count(*) FROM phasevec.verify('w3', 100, interval '0', interval '30 seconds', 5000)" >/dev/null
q -c "UPDATE facts SET ok = false WHERE id = 120"
calls=0; got=no
for c in $(seq 1 8); do
    as pv_l_w -c "UPDATE notes3 SET body = body || '.' WHERE id <= 5" >/dev/null
    v -c "SELECT count(*) FROM phasevec.verify('w3', 5, interval '0', interval '30 seconds', 5000)" >/dev/null
    calls=$c
    [ "$(reads w3 20)" = "refuted" ] && { got=yes; break; }
done
echo "H1: key 20 (false) after $calls calls of verify(p_n => 5) with keys 1-5 edited before each: $(reads w3 20)"
[ "$got" = yes ] && [ "$calls" -le 4 ] && pass "H1: stale claims do not hold the head of the queue (judged within ceil(20/5) = 4 calls)" \
    || fail "H1: stale claims held the head of the queue ($calls calls, key 20 reads $(reads w3 20))"

# ------------------------------------------------------------------------------------------------------------- M3 --
# pv_l_b's 5 claims (keys 1-5) and pv_l_a's 10 (keys 6-15); pv_l_b holds its own rows in an open assert().
q -c "SET ROLE pv_l_b" -c "SELECT count(phasevec.assert('w4', k::text, 'true')) FROM generate_series(1, 5) k" >/dev/null
q -c "SET ROLE pv_l_a" -c "SELECT count(phasevec.assert('w4', k::text, format('public.ok(%s)', 100 + k))) FROM generate_series(6, 15) k" >/dev/null
v -c "SELECT count(*) FROM phasevec.verify('w4', 100, interval '0', interval '30 seconds', 5000)" >/dev/null
q -c "UPDATE facts SET ok = false WHERE id BETWEEN 106 AND 115"
as pv_l_b -c "BEGIN" -c "SELECT count(phasevec.assert('w4', k::text, 'true')) FROM generate_series(1, 5) k" -c "SELECT pg_sleep(15)" -c "ROLLBACK" >/dev/null 2>&1 &
holder=$!; bg+=("$holder")
wait_for "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE usename = 'pv_l_b' AND wait_event = 'PgSleep')" || echo "M3: no holder"
for c in 1 2 3; do v -c "SELECT count(*) FROM phasevec.verify('w4', 5, interval '0', interval '30 seconds', 5000)" >/dev/null; done
n=$(q -c "SELECT count(*) FROM phasevec.truth t JOIN phasevec.watches w ON w.id = t.watch WHERE w.name = 'w4' AND key::int BETWEEN 6 AND 15 AND phasevec._verdict(t) = 'refuted'")
echo "M3: after 3 calls of verify(p_n => 5), pv_l_b holding its 5 rows: $n of pv_l_a's 10 false claims refuted"
[ "$n" = "10" ] && pass "M3: an author holding its own claims does not hold the head of the queue (ceil(15/5) = 3 calls)" \
    || fail "M3: an author holding its own claims held the head of the queue ($n of 10 refuted)"
q -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = 'pv_l_b'" >/dev/null
wait "$holder" 2>/dev/null

# -------------------------------------------------------------------------------------------------------------- L --
# N = 60 claims in w5: pv_l_a 1-30, pv_l_b 31-45, pv_l_c 46-60; p_n = 6, so every claim within ceil(60/6) = 10 calls.
# Hostile at once: pv_l_b holds keys 31-35 (open assert), pv_l_s holds keys 1-3 (open assert), pv_l_w edits the rows of
# keys 40-49 before each call, pv_l_h keeps four workers busy with slow proofs of its own.
N=60; PN=6; BOUND=$(( (N + PN - 1) / PN ))
q -c "SET ROLE pv_l_a" -c "SELECT count(phasevec.assert('w5', k::text, format('public.ok(%s)', k))) FROM generate_series(1, 30) k" >/dev/null
q -c "SET ROLE pv_l_b" -c "SELECT count(phasevec.assert('w5', k::text, format('public.ok(%s)', k))) FROM generate_series(31, 45) k" >/dev/null
q -c "SET ROLE pv_l_c" -c "SELECT count(phasevec.assert('w5', k::text, format('public.ok(%s)', k))) FROM generate_series(46, 60) k" >/dev/null
q -c "SET ROLE pv_l_h" -c "SELECT count(phasevec.assert('w6', k::text, 'pg_sleep(1.5) IS NOT NULL')) FROM generate_series(1, 12) k" >/dev/null
horizon w5 '8 seconds'
v -c "SELECT count(*) FROM phasevec.verify('w5', 100, interval '0', interval '60 seconds', 5000)" >/dev/null
# every claim false from now on: each one tried must read 'refuted', unless something keeps it from being judged
q -c "UPDATE facts SET ok = false WHERE id <= 60"
as pv_l_b -c "BEGIN" -c "SELECT count(phasevec.assert('w5', k::text, format('public.ok(%s)', k))) FROM generate_series(31, 35) k" -c "SELECT pg_sleep(60)" >/dev/null 2>&1 &
bg+=("$!")
as pv_l_s -c "BEGIN" -c "SELECT count(phasevec.assert('w5', k::text, 'true')) FROM generate_series(1, 3) k" -c "SELECT pg_sleep(60)" >/dev/null 2>&1 &
bg+=("$!")
hog() { for _ in $(seq 1 40); do as pv_l_h -c "SELECT phasevec.verify_one('w6', '$1', 3000)" >/dev/null 2>&1; done; }
for k in 1 2 3 4; do hog $k & bg+=("$!"); done
wait_for "SELECT count(*) = 2 FROM pg_stat_activity WHERE usename IN ('pv_l_b', 'pv_l_s') AND wait_event = 'PgSleep'" || echo "L: holders not ready"
start=$(q -c "SELECT clock_timestamp()")
brief_bad=0; brief_seen=0
check_brief() {
    # a key brief() serves as verified (or refuted, in _verdict) must have been judged within its horizon
    local r
    r=$(q -c "SELECT count(*) FROM phasevec.brief('w5', 1000000) b JOIN phasevec.truth t ON t.key = b.key
              JOIN phasevec.watches w ON w.id = t.watch AND w.name = 'w5'
             WHERE b.verdict = 'verified' AND t.verified_at + coalesce((SELECT max_age FROM phasevec.watches WHERE name = 'w5'), interval '8 seconds') <= now()" 2>/dev/null || echo 999)
    brief_seen=$((brief_seen + 1)); [ "$r" = "0" ] || brief_bad=$((brief_bad + 1))
}
for c in $(seq 1 "$BOUND"); do
    as pv_l_w -c "UPDATE notes5 SET body = body || '.' WHERE id BETWEEN 40 AND 49" >/dev/null
    v -c "SELECT count(*) FROM phasevec.verify('w5', $PN, interval '0', interval '60 seconds', 5000)" >/dev/null
    check_brief
done
untried=$(q -c "SELECT count(*) FROM phasevec.truth t JOIN phasevec.watches w ON w.id = t.watch AND w.name = 'w5'
                 LEFT JOIN phasevec.attempts a ON a.watch = t.watch AND a.key = t.key
                WHERE a.attempted_at IS NULL OR a.attempted_at < '$start'" 2>&1)
free=$(q -c "SELECT string_agg(phasevec._verdict(t), ',' ORDER BY key::int) FROM phasevec.truth t JOIN phasevec.watches w ON w.id = t.watch AND w.name = 'w5'
              WHERE key::int BETWEEN 4 AND 30 OR key::int BETWEEN 36 AND 39 OR key::int BETWEEN 50 AND 60")
nfree=$(echo "$free" | tr ',' '\n' | grep -c '^refuted$')
echo "L: after $BOUND calls of verify(p_n => $PN) under attack: $untried of $N claims not tried since the attack began; $nfree of 42 claims no one holds read refuted"
[ "$untried" = "0" ] && [ "$nfree" = "42" ] && pass "L: every claim is tried within ceil(N/p_n) = $BOUND calls" \
    || fail "L: claims were not tried within ceil(N/p_n) calls ($untried untried, $nfree of 42 refuted)"
# the hog takes every worker: nothing can be judged; past the horizon nothing is served as verified
for k in 5 6 7 8 9 10 11 12; do hog $k & bg+=("$!"); done
sleep 1
for _ in 1 2 3 4 5 6 7 8 9 10; do
    v -c "SELECT count(*) FROM phasevec.verify('w5', $PN, interval '0', interval '60 seconds', 5000)" >/dev/null 2>&1
    check_brief; sleep 1
done
held=$(v -c "SELECT count(*) FROM phasevec.brief('w5', 1000000) WHERE verdict = 'verified' AND key::int IN (1, 2, 3, 31, 32, 33, 34, 35)")
echo "L: brief() checked $brief_seen times, $brief_bad of them served a verdict past its horizon; held keys served verified now: $held"
[ "$brief_bad|$held" = "0|0" ] && pass "L: brief() never serves a verdict older than its horizon, even with no worker free" \
    || fail "L: brief() served verdicts past their horizon ($brief_bad times; $held held keys verified)"
for p in "${bg[@]}"; do kill "$p" 2>/dev/null; done
q -c "SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE datname = '$DB' AND pid <> pg_backend_pid()" >/dev/null
wait 2>/dev/null; bg=()
sleep 1
left=$(q -c "SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'pg_phasevec proof'")
[ "$left" = "0" ] || fail "$left proof workers are left"
# ------------------------------------------------------------------------------------------------------------- M1 --
# The cluster again, with a small lock table (max_locks_per_transaction = 10, as the review ran it), so a proof that
# reads 60 partitions needs entries of the shared table. A full lock table refuses new connections too: the
# verifier's and a superuser's sessions are open (and warm) before the fill, psql reading a FIFO.
"$PG/pg_ctl" -D "$DATA" -w stop >/dev/null
"$PG/pg_ctl" -D "$DATA" -o "-p $PORT -k $SOCK -c max_locks_per_transaction=10 -c autovacuum=off" -l "$DATA/server.log" -w start >/dev/null
assert_as pv_l_a w1 1 '(SELECT count(*) FROM public.parted) = 0'
one=$(v -c "SELECT phasevec.verify_one('w1', '1', 10000)" 2>&1)
echo "M1 before the fill: $one"
W=$(mktemp -d "$DATA/../pvlive.XXXXXX")
mkfifo "$W/v" "$W/s"
"$PG/psql" "${P[@]}" < "$W/v" > "$W/v.out" 2>&1 &
vp=$!; bg+=("$vp")
"$PG/psql" "${P[@]}" < "$W/s" > "$W/s.out" 2>&1 &
sp=$!; bg+=("$sp")
exec 7> "$W/v" 8> "$W/s"
echo "SET ROLE pv_l_v; SELECT 'warm ' || phasevec.verify_one('w1', '1', 10000);" >&7
echo "SELECT 1;" >&8
said_at() { local f=$1 want=$2; for _ in $(seq 1 600); do [ "$(grep -c "$3" "$f")" -ge "$want" ] && return 0; sleep 0.05; done; return 1; }
said_at "$W/v.out" 1 "warm" || echo "M1: the verifier is not warm"
said_n=0
refuted=0; filled=0
for k in 12 20 32; do
    as pv_l_x -c "DO \$\$ DECLARE i int := 0; BEGIN LOOP i := i + 1;
                    BEGIN PERFORM pg_advisory_lock(i); EXCEPTION WHEN out_of_memory THEN EXIT; END; END LOOP;
                    PERFORM pg_advisory_unlock(g) FROM generate_series(1, $k) g; END \$\$" \
              -c "SELECT 'filled'" -c "SELECT pg_sleep(60)" > "$W/x.out" 2>&1 &
    filler=$!; bg+=("$filler")
    said_at "$W/x.out" 1 filled && filled=$((filled + 1))
    grep -v "^filled" "$W/x.out" | head -3
    said_n=$((said_n + 1))
    echo "SELECT 'M1 said: ' || coalesce(phasevec.verify_one('w1', '1', 10000), 'NULL');" >&7
    echo "\\echo M1 done" >&7
    said_at "$W/v.out" $said_n "M1 done" || echo "M1: the verifier did not answer (k=$k)"
    echo "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = 'pv_l_x';" >&8
    wait $filler 2>/dev/null
    now=$(stored w1 1)
    echo "M1 k=$k: recorded: $now"
    case "$now" in refuted*) refuted=$((refuted + 1)) ;; esac
done
exec 7>&- 8>&-
wait $vp $sp 2>/dev/null
grep -E "M1 said|ERROR|DETAIL" "$W/v.out" | cut -c1-200
rm -rf "$W"
after=$(v -c "SELECT phasevec.verify_one('w1', '1', 10000)" 2>&1)
echo "M1 after the fill: $after (the lock table was filled $filled of 3 times)"
[ "$filled|$refuted|$after" = "3|0|verified" ] && pass "M1: a lock table filled by a role with no grants decides no verdict" \
    || fail "M1: a lock table filled by a role with no grants refuted a true claim ($refuted of $filled times)"

exit $fallas
