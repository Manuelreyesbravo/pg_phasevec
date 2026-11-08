#!/usr/bin/env bash
# 0.20.0 (nineteenth review, second pass): every read-then-write of a claim is read again under the claim's row lock.
# Against the throwaway cluster of installcheck.sh (run that first), with the same PV_DATA/PV_PORT/PV_SOCK.
#   PG=~/pg19/bin test/truth_adopt_race.sh
# 1. (R19-F7) refute() of an orphaned claim commits while adopt() waits for its row: the claim stays retired. In the
#    eighteenth cut adopt() read the orphans with no lock and asserted the stale proof again: the retired claim got
#    its proof back, and the next verify() served it 'verified'.
# 2. (R19-F7) another author's assert() of an orphaned claim commits while adopt() waits: that assert stands. In the
#    eighteenth cut the stale orphan proof replaced it, in the adopter's name.
# 3. (R19-F10) verify_one() waits for a transaction that refutes the claim and asserts it again with a new proof: it
#    says it could not judge it. In the eighteenth cut it took the new claim, judged the old proof, recorded nothing,
#    and answered 'unproven'.
set -uo pipefail
cd "$(dirname "$0")/.."
PG=${PG:-$HOME/pg19/bin}
DATA=${PV_DATA:-$PWD/.testcluster}
PORT=${PV_PORT:-5491}
SOCK=${PV_SOCK:-/tmp}
P=(-h "$SOCK" -p "$PORT" -X -q -At -d pv_adoptr)
export PGOPTIONS="-c client_min_messages=warning"
q() { "$PG/psql" "${P[@]}" "$@"; }
fallas=0
"$PG/pg_ctl" -D "$DATA" -o "-p $PORT -k $SOCK" -l "$DATA/server.log" -w start >/dev/null
"$PG/dropdb" -h "$SOCK" -p "$PORT" --if-exists pv_adoptr 2>/dev/null
"$PG/createdb" -h "$SOCK" -p "$PORT" pv_adoptr
q -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
DROP ROLE IF EXISTS pv_ar_au;
DROP ROLE IF EXISTS pv_ar_b;
DROP ROLE IF EXISTS pv_ar_gone;
CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register('r1', repeat('a', 64), 4);
CREATE ROLE pv_ar_au;
CREATE ROLE pv_ar_b;
CREATE ROLE pv_ar_gone;
CREATE TABLE notes (id int PRIMARY KEY, body text);
INSERT INTO notes SELECT g, 'ok ' || g FROM generate_series(1, 4) g;
SELECT phasevec.watch('w', 'notes'::regclass, 'id', 'r.body', 'r1');
GRANT USAGE ON SCHEMA phasevec TO pv_ar_au, pv_ar_b, pv_ar_gone;
GRANT SELECT ON notes TO pv_ar_au, pv_ar_b, pv_ar_gone;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz) TO pv_ar_au, pv_ar_b, pv_ar_gone;
GRANT EXECUTE ON FUNCTION phasevec.refute(text, text, text) TO pv_ar_au;
GRANT EXECUTE ON FUNCTION phasevec.adopt(text, regrole, text[], text[]) TO pv_ar_au;
GRANT EXECUTE ON FUNCTION phasevec.verify_one(text, text, int, float8) TO pv_ar_au;
-- (twenty-sixth review) a claim whose author is gone is changed by the table's owner or a steward
-- of the watch only: the two that race adopt() are stewards
SELECT phasevec.steward('w', 'pv_ar_au'), phasevec.steward('w', 'pv_ar_b');
SET ROLE pv_ar_gone;
SELECT phasevec.assert('w', '1',
       $p$SELECT coalesce((SELECT n.body LIKE 'ok%' FROM public.notes n WHERE n.id = 1), false)$p$);
SELECT phasevec.assert('w', '2', 'SELECT true');
RESET ROLE;
DROP OWNED BY pv_ar_gone;
DROP ROLE pv_ar_gone;
SET ROLE pv_ar_au;
SELECT phasevec.assert('w', '3', 'SELECT true');
RESET ROLE;
SQL
out=$(mktemp -d /dev/shm/pv_adoptr.XXXXXX)

# 1 and 2: the orphans of keys 1 and 2, adopted while refute() (key 1) and another author's assert() (key 2) hold them
q -c "SET ROLE pv_ar_au" -c "BEGIN" -c "SELECT phasevec.refute('w', '1', 'memory deleted')" -c "SELECT pg_sleep(2)" \
  -c "COMMIT" > "$out/refute" 2>&1 &
p1=$!
q -c "SET ROLE pv_ar_b" -c "BEGIN" -c "SELECT phasevec.assert('w', '2', 'SELECT false')" -c "SELECT pg_sleep(2)" \
  -c "COMMIT" > "$out/assert" 2>&1 &
p2=$!
sleep 0.7
q -c "SET ROLE pv_ar_au" -c "SELECT key || ':' || adopted FROM phasevec.adopt('w', 'pv_ar_au') ORDER BY key" \
  > "$out/adopt" 2>&1
wait $p1 $p2
q -c "SELECT count(*) FROM phasevec.verify('w', 10, '0')" >/dev/null 2>&1
res=$(q -c "SELECT string_agg(key || '|' || coalesce(asserted_by::text, '-') || '|' || (proof IS NULL) || '|'
                              || phasevec._verdict(t) || '|' || phasevec._claim_state(t), ' ' ORDER BY key)
              FROM phasevec.truth t WHERE key IN ('1', '2')")
echo "adopt: $(tr '\n' ' ' < "$out/adopt"); claims: $res"
k1=$(echo "$res" | tr ' ' '\n' | grep '^1|'); k2=$(echo "$res" | tr ' ' '\n' | grep '^2|')
# (twenty-fifth review) the role that retired a claim is its author
if [ "$k1" = "1|pv_ar_au|true|refuted|retired" ]; then
    echo "ok - a claim refute() retired while adopt() waited for it stays retired"
else
    echo "not ok - key 1 (refuted while adopt() ran): $k1"; fallas=1
fi
if [[ "$k2" == "2|pv_ar_b|false|refuted|judged" ]]; then
    echo "ok - an assert() that committed while adopt() waited for the claim stands"
else
    echo "not ok - key 2 (asserted by pv_ar_b while adopt() ran): $k2"; fallas=1
fi
if grep -q ERROR "$out/refute" "$out/assert" "$out/adopt"; then
    echo "not ok - a session failed: $(cat "$out/refute" "$out/assert" "$out/adopt" | tr '\n' ' ')"; fallas=1
fi

# 3: verify_one() waits for a transaction that refutes key 3 and asserts it again with a new proof
q -c "SELECT key || ':' || verdict FROM phasevec.verify('w', 10, '0') WHERE key = '3'" > "$out/v0" 2>&1
q -c "SET ROLE pv_ar_au" -c "BEGIN" -c "SELECT phasevec.refute('w', '3', 'gone')" \
  -c "SELECT phasevec.assert('w', '3', 'SELECT false')" -c "SELECT pg_sleep(1.5)" -c "COMMIT" > "$out/reassert" 2>&1 &
p3=$!
sleep 0.5
q -c "SET ROLE pv_ar_au" -c "SELECT phasevec.verify_one('w', '3')" > "$out/v1" 2>&1
wait $p3
q -c "SET ROLE pv_ar_au" -c "SELECT phasevec.verify_one('w', '3')" > "$out/v2" 2>&1
echo "before: $(cat "$out/v0"); verify_one while it was asserted again: $(tr '\n' ' ' < "$out/v1");" \
     "after: $(cat "$out/v2")"
if grep -q "could not judge key 3" "$out/v1" && [ "$(cat "$out/v2")" = "refuted" ]; then
    echo "ok - verify_one() does not answer for a claim asserted again while it waited, and judges it when called again"
else
    echo "not ok - verify_one() answered '$(tr '\n' ' ' < "$out/v1")' for a claim it did not run"; fallas=1
fi
rm -rf "$out"
"$PG/dropdb" -h "$SOCK" -p "$PORT" pv_adoptr
q() { "$PG/psql" -h "$SOCK" -p "$PORT" -X -q -At -d postgres "$@"; }
q -c "DROP ROLE pv_ar_au" -c "DROP ROLE pv_ar_b" >/dev/null 2>&1
"$PG/pg_ctl" -D "$DATA" -w stop >/dev/null
exit $fallas
