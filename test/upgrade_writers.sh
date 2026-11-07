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
# 5. (twenty-first review, RT21P-UPD-1, RT21P-UPD-2) The same with a lock the table's own lock does not show: a REINDEX
#    of the key's index, an ALTER TABLE of a table the recipe reads in a subquery, a LOCK TABLE of a table the recipe
#    reads through a function of its own. Once it holds phasevec's tables the update waits for no lock: it stops,
#    named, nothing changed, and that transaction commits. In the twentieth review's second cut only the watched
#    table was taken with NOWAIT; the update then waited for the index or the recipe's table, and the deadlock
#    detector aborted the other transaction (the update went on to 0.20.0).
# 6. (twenty-second review, RT22P-UPD-1) A recipe that reads a table through a function that catches every error and
#    returns a fallback text, while another session holds that table: the update stops, named, nothing changed, and
#    the message names the table the step waited for and not a table locked apart. Once the lock is gone the update
#    goes through, every row is noted as _render() renders it, and a refuted claim stays refuted after a write that
#    changes nothing. In the twenty-first review's cut the 1 ms lock_timeout of the update's step raised inside the
#    function, which caught it: the update noted the fallback text for every row, bound the refuted claims to it, and
#    the first write of such a row brought it back to brief() as 'unproven'.
# 7. The same recipe after the update, for a writer with a lock_timeout of its own: the write fails with
#    lock_not_available and notes nothing; before, it noted the fallback text as the row's.
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
# $1: the recipe of hallazgos (r.body if not given); side and side_label() are what a recipe may read beyond its row
fresh() {
    ln -sfn "$W/v019/pg_phasevec.so" "$W/lib/pg_phasevec.so"
    "$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists pv_uw 2>/dev/null
    "$PG/createdb" -h "$SOCK" -p "$PORT" pv_uw
    q -v ON_ERROR_STOP=1 -v recipe="${1:-r.body}" >/dev/null <<'SQL'
CREATE EXTENSION pg_phasevec VERSION '0.19.0';
SELECT phasevec.reader_register('r1', repeat('a', 64), 4);
CREATE TABLE notas (id int PRIMARY KEY, body text);
CREATE TABLE hallazgos (id int PRIMARY KEY, body text);
CREATE TABLE side (id int PRIMARY KEY, label text);
INSERT INTO notas SELECT g, 'n' || g FROM generate_series(1, 20) g;
INSERT INTO hallazgos SELECT g, 'h' || g FROM generate_series(1, 20) g;
INSERT INTO side SELECT g, 's' || g FROM generate_series(1, 20) g;
CREATE FUNCTION side_label(int) RETURNS text LANGUAGE sql STABLE AS 'SELECT s.label FROM public.side s WHERE s.id = $1';
CREATE FUNCTION side_label_or(int) RETURNS text LANGUAGE plpgsql STABLE AS $f$
DECLARE l text;
BEGIN
    SELECT s.label INTO l FROM public.side s WHERE s.id = $1;
    RETURN l;
EXCEPTION WHEN OTHERS THEN
    RETURN '(label unavailable)';
END
$f$;
CREATE TABLE apart (id int);
SELECT phasevec.watch('notas', 'notas'::regclass, 'id', 'r.body', 'r1');
SELECT phasevec.watch('hallazgos', 'hallazgos'::regclass, 'id', :'recipe', 'r1');
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

# 4. a transaction that alters a watched table, then writes it; 5. one that locks what the update reads beyond the
#    table's own lock (its key's index, a table its recipe reads directly or through a function), then writes it
recipes=("r.body" "r.body" "r.body" "r.body || coalesce((SELECT s.label FROM public.side s WHERE s.id = r.id), '')"
         "r.body || coalesce(public.side_label(r.id), '')")
ddls=("ALTER TABLE hallazgos ADD COLUMN x int" "TRUNCATE hallazgos" "REINDEX INDEX hallazgos_pkey"
      "ALTER TABLE side ADD COLUMN extra int" "LOCK TABLE side IN ACCESS EXCLUSIVE MODE")
for i in "${!ddls[@]}"; do
    ddl=${ddls[$i]}
    fresh "${recipes[$i]}"
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
    if [ "$ver" = "0.19.0" ] && echo "$up" | grep -q "locked by another session: nothing was changed" \
       && ! grep -q -i "error\|deadlock" "$W/ddl.out" && [ "$(q -c "SELECT count(*) FROM hallazgos WHERE id = 100")" = "1" ] \
       && [ "$(version)" = "0.20.0" ] && [ -z "$(echo "$again" | grep -i 'error')" ]; then
        ok "$ddl (recipe ${recipes[$i]}), then a write, during the update: the update stops named, that transaction commits"
    else
        nok "$ddl (recipe ${recipes[$i]}) then write: writer '$(tr '\n' ' ' <"$W/ddl.out")', update '${up:0:200}' at $ver, again '${again:0:200}'"
    fi
done
# 6. a recipe that catches the update's lock failure (RT22P-UPD-1)
fresh "r.body || ' / ' || public.side_label_or(r.id)"
q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
SELECT phasevec.assert('hallazgos', '1', 'SELECT true');
SELECT phasevec.assert('hallazgos', '2', 'SELECT true');
SELECT phasevec.refute('hallazgos', '1', 'deleted');
SELECT phasevec.refute('hallazgos', '3', 'deleted');
SQL
q >"$W/lk.out" 2>&1 <<'SQL' &
BEGIN;
LOCK TABLE side IN ACCESS EXCLUSIVE MODE;
SELECT pg_sleep(2);
COMMIT;
SQL
lk=$!
q >/dev/null 2>&1 <<'SQL' &
BEGIN;
LOCK TABLE apart IN ACCESS EXCLUSIVE MODE;
SELECT pg_sleep(3);
COMMIT;
SQL
ap=$!
pause 0.5
ln -sfn "$PWD/pg_phasevec.so" "$W/lib/pg_phasevec.so"
up=$(PGOPTIONS="$PGOPTIONS -c statement_timeout=20s" q -c "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" 2>&1)
ver=$(version)
wait $lk $ap
again=$(PGOPTIONS="$PGOPTIONS -c statement_timeout=20s" q -c "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" 2>&1)
# PostgreSQL 18 gives no context for a lock wait: the guard cannot name the table, and the message lists the
# relations a recipe could read (the one apart too)
apart_named=no
[ "$(q -c "SELECT current_setting('server_version_num')::int >= 190000")" = "t" ] || apart_named=n/a
[ "$apart_named" = "no" ] && echo "$up" | grep "^DETAIL" | grep -q "apart" && apart_named=yes
off=$(q -c "SELECT count(*) FROM phasevec.sources s JOIN phasevec.watches w ON w.id = s.watch AND w.name = 'hallazgos'
             LEFT JOIN phasevec._render('hallazgos', NULL) r ON r.key = s.key
            WHERE s.text_hash IS DISTINCT FROM r.text_hash" 2>&1)
q -c "UPDATE hallazgos SET body = body WHERE id IN (1, 3)" >/dev/null 2>&1
verdicts=$(q -c "SELECT string_agg(t.key || ':' || phasevec._verdict(t), ',' ORDER BY t.key) FROM phasevec.truth t
                  WHERE t.key IN ('1', '3')" 2>&1)
briefed=$(q -c "SELECT count(*) FROM phasevec.brief('hallazgos', 100000) WHERE key IN ('1', '3')" 2>&1)
if [ "$ver" = "0.19.0" ] && echo "$up" | grep -q "locked by another session: nothing was changed" \
   && echo "$up" | grep "^DETAIL" | grep -q "side" && [ "$apart_named" != "yes" ] \
   && [ "$(version)" = "0.20.0" ] && [ -z "$(echo "$again" | grep -i 'error')" ] && [ "$off" = "0" ] \
   && [ "$verdicts" = "1:refuted,3:refuted" ] && [ "$briefed" = "0" ]; then
    ok "a recipe that catches the update's lock failure: the update stops named (the table it waited for; one locked apart: $apart_named), then notes the rows as rendered; refuted claims stay retired"
else
    nok "recipe catching the lock failure: update at $ver '${up:0:300}', again '${again:0:200}', apart named $apart_named, rows off $off, verdicts '$verdicts', in brief $briefed"
fi

# 7. the same recipe, a writer with a lock_timeout of its own, after the update
q >/dev/null 2>&1 <<'SQL' &
BEGIN;
LOCK TABLE side IN ACCESS EXCLUSIVE MODE;
SELECT pg_sleep(2);
COMMIT;
SQL
lk=$!
pause 0.5
before=$(q -c "SELECT encode(s.text_hash, 'hex') FROM phasevec.sources s JOIN phasevec.watches w ON w.id = s.watch
                WHERE w.name = 'hallazgos' AND s.key = '2'")
wr=$(PGOPTIONS="$PGOPTIONS -c lock_timeout=100ms" q -c "UPDATE hallazgos SET body = 'h2 again' WHERE id = 2" 2>&1)
wait $lk
after=$(q -c "SELECT encode(s.text_hash, 'hex') FROM phasevec.sources s JOIN phasevec.watches w ON w.id = s.watch
               WHERE w.name = 'hallazgos' AND s.key = '2'")
body=$(q -c "SELECT body FROM hallazgos WHERE id = 2")
if echo "$wr" | grep -q "ERROR" && echo "$wr" | grep -q "not its own" && [ "$before" = "$after" ] && [ "$body" = "h2" ]; then
    ok "a write whose recipe caught a lock failure fails and notes nothing"
else
    nok "write with a recipe that caught a lock failure: '${wr:0:300}', noted $before -> $after, body '$body'"
fi
# 8. (twenty-third review, RT23P-UPD-1, RT23P-UPD-2) A transaction that read phasevec.truth or phasevec.sources, or
#    changed what the update changes (a GRANT on phasevec.truth; a GRANT, COMMENT or ALTER of one of phasevec's
#    functions), then writes a watched table, during the update: it commits, and so does the update, whichever of the
#    two the deadlock check would have looked at first (the write 0.6 s or 1.5 s after the transaction began; the
#    update's deadlock_timeout is 300 ms, the writer's 1 s). In the twenty-second review's cut one queued LOCK took
#    phasevec's tables one by one and held watches while it waited for truth, and the update waited, with no bound,
#    for a catalog row the transaction had changed: one of the two was aborted by the deadlock detector (the writer,
#    and the update went on, or the update, with a bare "deadlock detected").
firsts=("SELECT count(*) FROM phasevec.truth" "SELECT count(*) FROM phasevec.sources"
        "GRANT SELECT ON phasevec.truth TO PUBLIC" "GRANT EXECUTE ON FUNCTION phasevec.brief(text, int) TO PUBLIC"
        "COMMENT ON FUNCTION phasevec._verdict(phasevec.truth) IS 'mine'" "ALTER FUNCTION phasevec.brief(text, int) COST 7")
for first in "${firsts[@]}"; do
    for nap in 0.6 1.5; do
        fresh
        q >"$W/fw.out" 2>&1 <<SQL &
BEGIN;
$first;
SELECT pg_sleep($nap);
INSERT INTO notas VALUES (100, 'new');
COMMIT;
SQL
        fw=$!
        pause 0.3
        ln -sfn "$PWD/pg_phasevec.so" "$W/lib/pg_phasevec.so"
        up=$(PGOPTIONS="$PGOPTIONS -c statement_timeout=20s -c deadlock_timeout=300ms" \
             q -c "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" 2>&1)
        wait $fw
        if [ "$(version)" = "0.20.0" ] && ! grep -q -i "error\|deadlock" "$W/fw.out" && [ -z "$(echo "$up" | grep -i 'error')" ] \
           && [ "$(q -c "SELECT count(*) FROM notas WHERE id = 100")" = "1" ]; then
            ok "$first, then a write ${nap}s later, during the update: both commit"
        else
            nok "$first, then a write ${nap}s later: writer '$(tr '\n' ' ' <"$W/fw.out")', update '${up:0:300}', version $(version)"
        fi
    done
done

# 9. What the update waits for, it waits for holding nothing of phasevec's, within lock_timeout: a transaction that
#    granted on one of phasevec's functions and stays open stops the update within it, named, nothing changed, and
#    the writers of watched tables go on meanwhile.
fresh
q >/dev/null 2>&1 <<'SQL' &
BEGIN;
GRANT EXECUTE ON FUNCTION phasevec.brief(text, int) TO PUBLIC;
SELECT pg_sleep(4);
COMMIT;
SQL
gw=$!
pause 0.5
ln -sfn "$PWD/pg_phasevec.so" "$W/lib/pg_phasevec.so"
PGOPTIONS="$PGOPTIONS -c lock_timeout=2s -c statement_timeout=15s" \
    q -c "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" >"$W/up9.out" 2>&1 &
u9=$!
pause 0.5
wr=$(PGOPTIONS="$PGOPTIONS -c lock_timeout=1s" q -c "UPDATE notas SET body = 'n1 again' WHERE id = 1" 2>&1)
wait $u9
up=$(cat "$W/up9.out")
ver=$(version)
wait $gw
if [ "$ver" = "0.19.0" ] && grep -q "could not take phasevec's function phasevec.brief(p_watch text, p_budget integer) within lock_timeout (2s): nothing was changed" <<<"$up" \
   && [ -z "$wr" ] && [ "$(q -c "SELECT body FROM notas WHERE id = 1")" = "n1 again" ]; then
    ok "an open transaction that granted on a function: the update stops within lock_timeout, named; writers go on"
else
    nok "open grant: update at $ver '${up:0:300}', writer '${wr:0:200}'"
fi

# 10. (RT23P-UPD-3) Watches whose recipes fail on their rows: a RAISE of the recipe's own, of 55P03 or of P0001. The
#     update names every such watch, with its error, at once, nothing changed, and blames no other session; once
#     the recipes render it goes through. A recipe that caught the update's lock failure and raised an error of its
#     own is a lock failure: the update stops named as one, and goes through when the lock is gone. In the
#     twenty-second review's cut a RAISE of 55P03 was retried as a lock and blamed on "another session", any other
#     stopped the update with only the recipe's message, and the first such watch hid the rest.
fresh
q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE TABLE flag (on_ boolean);
CREATE FUNCTION tricky(t text, code text) RETURNS text LANGUAGE plpgsql STABLE AS $f$
BEGIN
    IF EXISTS (SELECT 1 FROM public.flag) THEN
        RAISE EXCEPTION 'not a lock, says the recipe' USING ERRCODE = code;
    END IF;
    RETURN t;
END
$f$;
CREATE TABLE otra1 (id int PRIMARY KEY, body text);
CREATE TABLE otra2 (id int PRIMARY KEY, body text);
INSERT INTO otra1 VALUES (1, 'a');
INSERT INTO otra2 VALUES (1, 'b');
SELECT phasevec.watch('otra1', 'otra1'::regclass, 'id', 'public.tricky(r.body, ''55P03'')', 'r1');
SELECT phasevec.watch('otra2', 'otra2'::regclass, 'id', 'public.tricky(r.body, ''P0001'')', 'r1');
INSERT INTO flag VALUES (true);
SQL
ln -sfn "$PWD/pg_phasevec.so" "$W/lib/pg_phasevec.so"
t0=$(date +%s.%N)
up=$(PGOPTIONS="$PGOPTIONS -c statement_timeout=20s" q -c "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" 2>&1)
t1=$(date +%s.%N)
ver=$(version)
took=$(python3 -I -c "import sys; print(round(float(sys.argv[2]) - float(sys.argv[1]), 2))" "$t0" "$t1")
q -c "DELETE FROM flag" >/dev/null
again=$(PGOPTIONS="$PGOPTIONS -c statement_timeout=20s" q -c "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" 2>&1)
if [ "$ver" = "0.19.0" ] && grep -q "could not render the rows of these watches: nothing was changed" <<<"$up" \
   && grep -q "watch otra1 (table public.otra1): not a lock, says the recipe (SQLSTATE P0001)" <<<"$up" \
   && grep -q "watch otra2 (table public.otra2): not a lock, says the recipe (SQLSTATE P0001)" <<<"$up" \
   && ! grep -q "^ERROR: .*another session" <<<"$up" && [ "$(version)" = "0.20.0" ] && [ -z "$(echo "$again" | grep -i 'error')" ]; then
    ok "recipes that fail on their rows (55P03, P0001): the update names both at once (${took}s), nothing changed; then goes through"
else
    nok "recipes failing: update at $ver in ${took}s '${up:0:400}', again '${again:0:200}' at $(version)"
fi
fresh
q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
CREATE FUNCTION side_label_raise(int) RETURNS text LANGUAGE plpgsql STABLE AS $f$
DECLARE l text;
BEGIN
    SELECT s.label INTO l FROM public.side s WHERE s.id = $1;
    RETURN l;
EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'no label for %, says the recipe', $1;
END
$f$;
CREATE TABLE otra3 (id int PRIMARY KEY, body text);
INSERT INTO otra3 SELECT g, 'o' || g FROM generate_series(1, 5) g;
SELECT phasevec.watch('raiser', 'otra3'::regclass, 'id', 'r.body || public.side_label_raise(r.id)', 'r1');
SQL
q >/dev/null 2>&1 <<'SQL' &
BEGIN;
LOCK TABLE public.side IN ACCESS EXCLUSIVE MODE;
SELECT pg_sleep(2);
COMMIT;
SQL
lk=$!
pause 0.5
ln -sfn "$PWD/pg_phasevec.so" "$W/lib/pg_phasevec.so"
up=$(PGOPTIONS="$PGOPTIONS -c statement_timeout=20s" q -c "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" 2>&1)
ver=$(version)
wait $lk
again=$(PGOPTIONS="$PGOPTIONS -c statement_timeout=20s" q -c "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" 2>&1)
if [ "$ver" = "0.19.0" ] && grep -q "locked by another session: nothing was changed" <<<"$up" \
   && ! grep -q "^ERROR: .*could not render" <<<"$up" && [ "$(version)" = "0.20.0" ] && [ -z "$(echo "$again" | grep -i 'error')" ]; then
    ok "a recipe that caught the update's lock failure and raised its own error: a lock failure, named; then goes through"
else
    nok "recipe raising after a lock failure: update at $ver '${up:0:300}', again '${again:0:200}' at $(version)"
fi
exit $fallas
