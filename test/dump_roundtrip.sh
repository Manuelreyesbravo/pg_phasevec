#!/usr/bin/env bash
# 0.19.0: pg_dump + pg_restore bring the extension's data back (rows, sequences, verdicts), and
# the restored database keeps working. Against the throwaway cluster of installcheck.sh (:5491).
#   PG=~/pg19/bin test/dump_roundtrip.sh
set -euo pipefail
cd "$(dirname "$0")/.."
PG=${PG:-$HOME/pg19/bin}
P=(-h /tmp -p 5491 -X -q -v ON_ERROR_STOP=1)
D=$(mktemp -d)
"$PG/pg_ctl" -D .testcluster -o "-p 5491 -k /tmp" -l .testcluster/server.log -w start >/dev/null
trap '"$PG/pg_ctl" -D .testcluster -w stop >/dev/null; rm -rf "$D"' EXIT
for db in rt_src rt_dst; do "$PG/dropdb" -h /tmp -p 5491 --if-exists "$db"; "$PG/createdb" -h /tmp -p 5491 "$db"; done

"$PG/psql" "${P[@]}" -d rt_src <<'SQL' >/dev/null
CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register('r1', repeat('a', 64), 4);
CREATE TABLE work (id int PRIMARY KEY, body text);
INSERT INTO work SELECT g, 'note ' || g FROM generate_series(1, 50) g;
SELECT phasevec.watch('work', 'work'::regclass, 'id', 'r.body', 'r1');
SELECT phasevec.supersede('work', '1', '2', 'closed');
SELECT phasevec.assert('work', '3', 'SELECT true');
SELECT phasevec.assert('work', '4', 'SELECT false');
SELECT phasevec.assert('work', '5', p_expires_at => now() - interval '1 day');
SELECT * FROM phasevec.verify('work');
SELECT phasevec.note_use('work', '2', 1::smallint);
-- readings and the coarse index (the biggest tables in real use), with deterministic codes as in ivf.sql
SELECT phasevec.reader_register('r256', repeat('b', 64), 256);
CREATE TABLE docs (id int PRIMARY KEY, body text);
INSERT INTO docs SELECT g, 'doc ' || g FROM generate_series(1, 300) g;
SELECT phasevec.watch('docs', 'docs'::regclass, 'id', 'r.body', 'r256');
CREATE FUNCTION code_of(g int) RETURNS smallint[] LANGUAGE sql IMMUTABLE AS $$
    SELECT array(SELECT (((g * 31 + j * 17 * (g % 7 + 1) + (g / 13) * j) % 255) - 127)::smallint
                   FROM generate_series(1, 256) j) $$;
CREATE FUNCTION signs_of(c smallint[]) RETURNS bit(256) LANGUAGE sql IMMUTABLE AS $$
    SELECT string_agg(CASE WHEN x > 0 THEN '1' ELSE '0' END, '' ORDER BY o)::bit(256)
      FROM unnest(c) WITH ORDINALITY u(x, o) $$;
SELECT count(phasevec.record('docs', s.key, 'r256', s.text_hash, 0::bigint, code_of(s.key::int), NULL,
                             signs_of(code_of(s.key::int))))
  FROM phasevec.sources s JOIN phasevec.watches w ON w.id = s.watch AND w.name = 'docs';
SELECT phasevec.ivf_build('docs');
SQL

FOTO="select string_agg(t || '=' || n, ' ' order by t) from (
  select 'readers' t, count(*) n from phasevec.readers union all select 'watches', count(*) from phasevec.watches
  union all select 'readings', count(*) from phasevec.readings union all select 'sources', count(*) from phasevec.sources
  union all select 'truth', count(*) from phasevec.truth union all select 'usefulness', count(*) from phasevec.usefulness
  union all select 'kstate', count(*) from phasevec.kstate union all select 'counts', count(*) from phasevec.counts
  union all select 'ivf_cents', count(*) from phasevec.ivf_cents union all select 'ivf_lists', count(*) from phasevec.ivf_lists) x"
VERD="select string_agg(key || ':' || verdict, ' ' order by key) from phasevec.truth"
FIND="select array_agg(key order by score desc, key)::text from phasevec.find('docs', 0, code_of(100), 10, false, 300, signs_of(code_of(100)))"
SEQ="select string_agg(last_value::text, ',') from (select last_value from phasevec.readers_id_seq union all select last_value from phasevec.watches_id_seq) s"

a=$("$PG/psql" "${P[@]}" -At -d rt_src -c "$FOTO"); av=$("$PG/psql" "${P[@]}" -At -d rt_src -c "$VERD"); as=$("$PG/psql" "${P[@]}" -At -d rt_src -c "$SEQ"); af=$("$PG/psql" "${P[@]}" -At -d rt_src -c "$FIND")
"$PG/pg_dump" -h /tmp -p 5491 -Fc -d rt_src -f "$D/rt.dump"
"$PG/pg_restore" -h /tmp -p 5491 -d rt_dst --exit-on-error "$D/rt.dump"
b=$("$PG/psql" "${P[@]}" -At -d rt_dst -c "$FOTO"); bv=$("$PG/psql" "${P[@]}" -At -d rt_dst -c "$VERD"); bs=$("$PG/psql" "${P[@]}" -At -d rt_dst -c "$SEQ"); bf=$("$PG/psql" "${P[@]}" -At -d rt_dst -c "$FIND")

echo "src: $a | $av | seq $as"
echo "dst: $b | $bv | seq $bs"
fallas=0
[ "$a" = "$b" ] || { echo "not ok - rows differ"; fallas=1; }
[ "$av" = "$bv" ] || { echo "not ok - verdicts differ"; fallas=1; }
[ "$as" = "$bs" ] || { echo "not ok - sequences differ"; fallas=1; }
echo "find src: $af"; echo "find dst: $bf"
[ -n "$af" ] && [ "$af" = "$bf" ] || { echo "not ok - find answers differently after restore"; fallas=1; }
[ -n "$(echo "$a" | grep -o 'readings=[1-9]')" ] || { echo "not ok - nothing to compare (readings empty)"; fallas=1; }
[ -n "$(echo "$a" | grep -o 'truth=[1-9]')" ] || { echo "not ok - nothing to compare (truth empty)"; fallas=1; }

# the restored database keeps working: the watch still sees new rows, a new watch does not collide
c=$("$PG/psql" "${P[@]}" -At -d rt_dst <<'SQL'
INSERT INTO work VALUES (51, 'note 51');
SELECT (SELECT count(*) FROM phasevec.sources s JOIN phasevec.watches w ON w.id = s.watch
         WHERE w.name = 'work' AND s.key = '51') || ' ' ||
       phasevec.watch('work2', 'work'::regclass, 'id', 'r.body', 'r1');
SQL
)
echo "dst after restore: sources for the new row + id of a new watch = $c"
[ "${c%% *}" = "1" ] || { echo "not ok - the watch does not see new rows after restore"; fallas=1; }
[ "${c##* }" -gt 1 ] || { echo "not ok - the new watch reused id 1"; fallas=1; }
[ $fallas = 0 ] && echo "ok - dump/restore keeps the extension's data and the restored database works"
exit $fallas
