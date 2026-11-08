#!/usr/bin/env bash
# 0.20.0 (twelfth review): what is the proof's own, and when. Against the throwaway cluster of installcheck.sh (run
# that first), with the same PV_DATA/PV_PORT/PV_SOCK.
#   PG=~/pg19/bin test/truth_own_time.sh
# M1. Only the proof's own work can refute it by time. A session held a lock the proof needs (a table, by a writer;
#     an advisory key, by a role with no grants) and let go just before the proof's clock of 1 s ended: the proof then
#     ran past its clock and a true claim was recorded refuted ("the proof took longer than 1000 ms"). Here the hold
#     sweeps 0.80-1.10 s, so some runs let go before the clock ends and some after. Now nothing is judged in either.
#     A proof slow by itself is still refuted for its time.
# M2. A turn is spent by a session its author cannot end. An author that terminated its own proof sessions before
#     they spent its claims' turns kept them at the head of the queue, and no other author's claim was tried again.
#     Now the turns are spent by the call's keeper (a session of the owner): of N claims, each is tried within
#     ceil(N / p_n) calls, with the attacker terminating its sessions the whole time.
# M3. Freshness is judged at the moment of reading. Inside one READ COMMITTED transaction begun before the horizon,
#     brief(), truth_coverage() and _verdict() served 'verified' past max_age (and past expires_at), after that
#     transaction could see the claim was false. Now they read 'unproven' ('expired') once the horizon has passed.
# L1. A clock near the int limit overflowed the verifier's deadline (p_timeout_ms + 5 s): every claim was "not taken
#     within -2147478649 ms". Now it is judged.
set -uo pipefail
cd "$(dirname "$0")/.."
PG=${PG:-$HOME/pg19/bin}
DATA=${PV_DATA:-$PWD/.testcluster}
PORT=${PV_PORT:-5491}
SOCK=${PV_SOCK:-/tmp}
DB=pv_own
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
v() { as pv_k_v "$@"; }
q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
DO $$ DECLARE r text; BEGIN
  FOREACH r IN ARRAY ARRAY['pv_k_a','pv_k_p','pv_k_w','pv_k_x','pv_k_v'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('DROP OWNED BY %I CASCADE', r); EXECUTE format('DROP ROLE %I', r);
    END IF;
  END LOOP; END $$;
CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register('r1', repeat('a', 64), 4);
CREATE ROLE pv_k_a LOGIN;   -- an author
CREATE ROLE pv_k_p LOGIN;   -- an author that terminates its own sessions
CREATE ROLE pv_k_w LOGIN;   -- writes the facts table (and may lock it)
CREATE ROLE pv_k_x LOGIN;   -- no grants at all
CREATE ROLE pv_k_v LOGIN;   -- the verifier and reader
GRANT pv_k_a, pv_k_p TO pv_k_v;
GRANT USAGE ON SCHEMA phasevec TO pv_k_a, pv_k_p, pv_k_v;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz) TO pv_k_a, pv_k_p;
GRANT EXECUTE ON FUNCTION phasevec.verify(text, int, interval, interval, int, float8),
                          phasevec.verify_one(text, text, int, float8), phasevec.brief(text, int),
                          phasevec.truth_coverage(text) TO pv_k_v;
CREATE TABLE facts (id int PRIMARY KEY, ok boolean NOT NULL);
INSERT INTO facts SELECT g, true FROM generate_series(1, 200) g;
CREATE FUNCTION public.ok(k int) RETURNS boolean LANGUAGE sql STABLE AS $$ SELECT ok FROM public.facts WHERE id = k $$;
GRANT SELECT ON facts TO pv_k_a, pv_k_p, pv_k_v; GRANT SELECT, UPDATE ON facts TO pv_k_w;
GRANT UPDATE ON facts TO pv_k_a, pv_k_p, pv_k_v;
GRANT EXECUTE ON FUNCTION public.ok(int) TO PUBLIC;
DO $$ BEGIN FOR i IN 1..4 LOOP
  EXECUTE format('CREATE TABLE notes%s (id int PRIMARY KEY, body text)', i);
  EXECUTE format('INSERT INTO notes%s SELECT g, %L || g FROM generate_series(1, 200) g', i, 'note ');
  EXECUTE format('GRANT SELECT, UPDATE ON notes%s TO pv_k_a, pv_k_p, pv_k_v', i);
  PERFORM phasevec.watch('w' || i, ('notes' || i)::regclass, 'id', 'r.body', 'r1');
END LOOP; END $$;
SQL
fallas=0
pass() { echo "ok - $1"; }
fail() { echo "not ok - $1"; fallas=1; }
stored() { q -c "SELECT verdict || '|' || coalesce(last_error, '') FROM phasevec.truth t JOIN phasevec.watches w ON w.id = t.watch WHERE w.name = '$1' AND key = '$2'"; }
reads() { q -c "SELECT phasevec._verdict(t) FROM phasevec.truth t JOIN phasevec.watches w ON w.id = t.watch WHERE w.name = '$1' AND key = '$2'"; }
assert_as() { as "$1" -c "SELECT phasevec.assert('$2', '$3', \$p\$$4\$p\$)" >/dev/null; }
wait_for() {  # wait_for <sql that returns t> [tries]
    for _ in $(seq 1 "${2:-400}"); do [ "$(q -c "$1")" = "t" ] && return 0; sleep 0.01; done; return 1
}

# ------------------------------------------------------------------------------------------------------------- M1 --
# 0.3 s of the proof's own (pg_sleep) after the lock; a clock of 1000 ms.
OWN='(SELECT count(*) FROM (SELECT pg_catalog.pg_sleep(0.3)) s) = 1'
assert_as pv_k_a w1 2 "(SELECT f.ok FROM public.facts f WHERE f.id = 2) AND $OWN"
assert_as pv_k_a w4 6 "(SELECT pg_catalog.pg_advisory_xact_lock_shared(42)::text = '') AND (SELECT f.ok FROM public.facts f WHERE f.id = 6) AND $OWN"
assert_as pv_k_a w4 9 "(SELECT f.ok FROM public.facts f WHERE f.id = 9) AND (SELECT count(*) FROM (SELECT pg_catalog.pg_sleep(1.5)) s) = 1"
base=$(v -c "SELECT phasevec.verify_one('w1', '2', 1000)" -c "SELECT phasevec.verify_one('w4', '6', 1000)" | tr '\n' ' ')
echo "M1 baseline (no lock held): $base"
for variant in table advisory; do
    refuted=0; waited=0; still=0; runs=""
    for hold in 0.80 0.85 0.90 0.95 1.00 1.02 1.05 1.10; do
        if [ $variant = table ]; then
            key=2
            as pv_k_w -c "BEGIN" -c "LOCK TABLE public.facts IN ACCESS EXCLUSIVE MODE" -c "SELECT pg_sleep($hold)" -c "COMMIT" >/dev/null 2>&1 &
            bg+=($!)
            wait_for "SELECT EXISTS (SELECT 1 FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid WHERE a.usename = 'pv_k_w' AND l.mode = 'AccessExclusiveLock' AND l.granted)" \
                || echo "M1: no lock holder"
            out=$(v -c "SELECT key || ' ' || verdict || ' ' || coalesce(error, '') FROM phasevec.verify('w1', 10, interval '0', interval '30 seconds', 1000) WHERE key = '2'" 2>&1)
        else
            key=6
            as pv_k_x -c "SELECT pg_advisory_lock(42)" -c "SELECT pg_sleep($hold)" -c "SELECT pg_advisory_unlock(42)" >/dev/null 2>&1 &
            bg+=($!)
            wait_for "SELECT EXISTS (SELECT 1 FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid WHERE a.usename = 'pv_k_x' AND l.locktype = 'advisory' AND l.granted)" \
                || echo "M1: no advisory holder"
            out=$(v -c "SELECT phasevec.verify_one('w4', '6', 1000)" 2>&1 | tr '\n' ' ')
        fi
        wait
        wn=w1; [ $key = 6 ] && wn=w4
        s=$(stored $wn $key)
        [ -n "${PV_DEBUG:-}" ] && echo "  hold $hold: $out | $s | clock began $(q -c "SELECT round(extract(epoch FROM t.verified_at - (SELECT max(attempted_at) FROM phasevec.attempts)) * 1000) FROM phasevec.truth t JOIN phasevec.watches w ON w.id = t.watch WHERE w.name = '$wn' AND key = '$key'") ms after the attempt"
        case "$s" in
            refuted*) refuted=$((refuted + 1)); runs="$runs $hold:REFUTED" ;;
            *"not all of its time"*) waited=$((waited + 1)); runs="$runs $hold:waited" ;;
            *) case "$out" in
                   *"not all of its time"*) waited=$((waited + 1)); runs="$runs $hold:waited" ;;
                   *"still waiting"*) still=$((still + 1)); runs="$runs $hold:still-waiting" ;;
                   *) runs="$runs $hold:$(echo "$s" | cut -c1-40)" ;;
               esac ;;
        esac
        # put a refuted true claim back, for the next hold
        [ "${s%%|*}" = refuted ] && v -c "SELECT phasevec.verify_one('$wn', '$key', 5000)" >/dev/null 2>&1
    done
    echo "M1 $variant lock held for 0.80-1.10 s, clock 1000 ms:$runs"
    [ $refuted -eq 0 ] && pass "M1 ($variant): a lock another session let go before the clock ended refuted no true claim" \
        || fail "M1 ($variant): $refuted of 8 holds recorded a true claim refuted for its time"
    [ $waited -ge 1 ] && pass "M1 ($variant): the window was hit ($waited runs waited, then ran past the clock; $still still waiting at it)" \
        || fail "M1 ($variant): no run waited and then ran past its clock (the test missed its window: $runs)"
done
slow=$(v -c "SELECT phasevec.verify_one('w4', '9', 1000)" 2>&1 | tr '\n' ' ')
echo "M1 a proof slow by itself (1.5 s, no lock): $slow | stored: $(stored w4 9)"
case "$(stored w4 9)" in
    "refuted|the proof took longer than 1000 ms"*) pass "M1: a proof slow by itself is still refuted for its time" ;;
    *) fail "M1: a proof slow by itself: $(stored w4 9)" ;;
esac

# ------------------------------------------------------------------------------------------------------------- M2 --
# pv_k_p's 5 claims first (the oldest), then pv_k_a's 20; pv_k_p terminates its own sessions all along.
q -c "SET ROLE pv_k_p" -c "SELECT count(phasevec.assert('w2', k::text, 'true')) FROM generate_series(1, 5) k" >/dev/null
q -c "SET ROLE pv_k_a" -c "SELECT count(phasevec.assert('w2', k::text, format('public.ok(%s)', k))) FROM generate_series(101, 120) k" >/dev/null
as pv_k_p >"$DATA/attacker.out" 2>&1 <<'SQL' &
DO $$ DECLARE t0 timestamptz := clock_timestamp(); n int := 0; m int; BEGIN
  WHILE clock_timestamp() < t0 + interval '90 s' LOOP
    PERFORM pg_stat_clear_snapshot();
    SELECT count(pg_terminate_backend(pid)) INTO m FROM pg_stat_activity WHERE usename = 'pv_k_p' AND pid <> pg_backend_pid();
    n := n + m;
  END LOOP; RAISE WARNING 'terminated % of its own sessions', n; END $$;
SQL
attacker=$!; bg+=("$attacker")
wait_for "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE usename = 'pv_k_p' AND state = 'active')" || echo "M2: no attacker"
first=$(v -c "SELECT verdict || ' ' || count(*) FROM phasevec.verify('w2', 100, interval '0', interval '60 seconds', 3000) GROUP BY verdict ORDER BY 1" | tr '\n' ',')
q -c "UPDATE facts SET ok = false WHERE id BETWEEN 101 AND 120"
calls=0; got=no
for c in $(seq 1 8); do
    v -c "SELECT count(*) FROM phasevec.verify('w2', 5, interval '0', interval '60 seconds', 3000)" >/dev/null
    calls=$c
    n=$(q -c "SELECT count(*) FROM phasevec.truth t JOIN phasevec.watches w ON w.id = t.watch WHERE w.name = 'w2' AND key::int > 100 AND phasevec._verdict(t) = 'refuted'")
    [ "$n" = 20 ] && { got=yes; break; }
done
spent=$(q -c "SELECT count(*) FROM phasevec.attempts a JOIN phasevec.watches w ON w.id = a.watch WHERE w.name = 'w2' AND a.key::int <= 5")
served=$(v -c "SELECT count(*) FROM phasevec.brief('w2', 100000) WHERE key::int > 100 AND verdict = 'verified'")
q -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = 'pv_k_p'" >/dev/null
wait "$attacker" 2>/dev/null
echo "M2 first call: $first; after $calls calls of verify(p_n => 5): $n of pv_k_a's 20 false claims refuted, $served served verified; the attacker's claims with a spent turn: $spent"
[ "$got" = yes ] && [ "$calls" -le 5 ] && pass "M2: an author ending its own sessions does not hold the head of the queue (all tried within ceil(25/5) = 5 calls)" \
    || fail "M2: an author ending its own sessions held the head of the queue ($calls calls, $n of 20 refuted)"
[ "$spent" = 5 ] && pass "M2: the turns of the claims whose sessions were ended are spent" || fail "M2: $spent of the attacker's 5 turns spent"

# ------------------------------------------------------------------------------------------------------------- M3 --
q -c "UPDATE phasevec.watches SET max_age = interval '3 seconds' WHERE name = 'w3'" >/dev/null
assert_as pv_k_a w3 1 'public.ok(1)'
as pv_k_a -c "SELECT phasevec.assert('w3', '2', 'public.ok(2)', NULL, NULL, clock_timestamp() + interval '3 seconds')" >/dev/null
v -c "SELECT count(*) FROM phasevec.verify('w3', 10, interval '0', interval '30 seconds', 5000)" >/dev/null
v >"$DATA/m3.reader" 2>&1 <<'SQL' &
BEGIN;
SELECT 'start ' || string_agg(key || '=' || verdict, ',' ORDER BY key) FROM phasevec.brief('w3') WHERE key IN ('1', '2');
SELECT pg_sleep(4);
SELECT 'own-view ' || (SELECT ok FROM public.facts WHERE id = 1);
SELECT 'brief ' || coalesce(string_agg(key || '=' || verdict, ',' ORDER BY key), 'none') FROM phasevec.brief('w3') WHERE key IN ('1', '2');
SELECT 'coverage ' || string_agg(verdict || '=' || n, ',' ORDER BY verdict) FROM phasevec.truth_coverage('w3');
COMMIT;
SQL
reader=$!
q >"$DATA/m3.owner" 2>&1 <<'SQL' &
BEGIN;
SELECT 'begun ' || (SELECT string_agg(key || '=' || phasevec._verdict(t), ',' ORDER BY key) FROM phasevec.truth t JOIN phasevec.watches w ON w.id = t.watch WHERE w.name = 'w3');
SELECT pg_sleep(4);
SELECT 'verdict ' || string_agg(key || '=' || phasevec._verdict(t), ',' ORDER BY key) FROM phasevec.truth t JOIN phasevec.watches w ON w.id = t.watch WHERE w.name = 'w3';
COMMIT;
SQL
owner=$!
sleep 0.5
q -c "UPDATE facts SET ok = false WHERE id = 1"   # key 1's claim turns false, committed, while both read
wait $reader $owner
r=$(tr '\n' ' ' <"$DATA/m3.reader"); r2=$(tr '\n' ' ' <"$DATA/m3.owner")
echo "M3 a reader in one transaction, 4 s past a 3 s horizon (key 2 expires at 3 s): $r| $r2"
case "$r" in
    *"start 1=verified,2=verified"*"own-view false"*) ;;
    *) fail "M3: the reader did not start from two verified claims, or did not see key 1 turn false: $r" ;;
esac
case "$(grep '^brief' "$DATA/m3.reader")" in
    *=verified*) fail "M3: brief() served 'verified' past the horizon, in a transaction begun before it" ;;
    brief*) pass "M3: brief() reads the horizon at the moment of reading" ;;
    *) fail "M3: brief() said nothing: $r" ;;
esac
case "$(grep '^coverage' "$DATA/m3.reader")" in
    *verified=*) fail "M3: truth_coverage() counted 'verified' past the horizon" ;;
    coverage*) pass "M3: truth_coverage() reads the horizon at the moment of reading" ;;
    *) fail "M3: truth_coverage() said nothing: $r" ;;
esac
case "$r2" in
    *"begun 1=verified,2=verified"*"verdict 1=unproven,2=expired"*) pass "M3: _verdict() reads max_age and expires_at at the moment of reading" ;;
    *) fail "M3: _verdict() in a transaction begun before the horizon: $r2" ;;
esac

old=$(q -c "SELECT coalesce(string_agg(proname, ', ' ORDER BY proname), 'none') FROM pg_proc WHERE pronamespace = 'phasevec'::regnamespace AND prosrc ~ 'expires_at <= now\(\)'")
[ "$old" = none ] && pass "M3: no read path compares expires_at with the transaction's start" \
    || fail "M3: read paths that compare expires_at with now(): $old"

# ------------------------------------------------------------------------------------------------------------- L1 --
big=$(v -c "SELECT key || ' ' || verdict || ' ' || coalesce(error, '') FROM phasevec.verify('w3', 10, interval '0', interval '30 seconds', 2147483647) WHERE key = '1'" 2>&1)
echo "L1 verify() with p_timeout_ms 2147483647: $big"
case "$big" in
    "1 verified"*|"1 refuted"*) pass "L1: a clock near the int limit is a clock" ;;
    *) fail "L1: a clock near the int limit: $big" ;;
esac

exit $fallas
