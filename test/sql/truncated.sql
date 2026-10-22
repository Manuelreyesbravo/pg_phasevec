-- 0.5.0: a reading says whether the reader saw the whole text.
\set VERBOSITY terse

CREATE EXTENSION pg_phasevec VERSION '0.4.0';
SELECT phasevec.reader_register('t1', repeat('a', 64), 4) > 0 AS t1;
CREATE TABLE docs (id int PRIMARY KEY, body text);
INSERT INTO docs SELECT g, 'doc ' || g FROM generate_series(1, 4) g;
SELECT phasevec.watch('docs', 'docs'::regclass, 'id', 'r.body', 't1') > 0 AS watch;
-- read under 0.4.0: no counts
SELECT count(phasevec.record('docs', n.key, 't1', n.text_hash, n.key::bigint, ARRAY[1,2,3,4]::smallint[]))
  FROM phasevec.next('docs', 1) n;

ALTER EXTENSION pg_phasevec UPDATE TO '0.5.0';
SELECT extversion FROM pg_extension WHERE extname = 'pg_phasevec';
-- a reading from before 0.5.0 is unknown, not complete
SELECT key, tokens_read, tokens_total, truncated FROM phasevec.readings ORDER BY key;

-- counts must come together and make sense
SELECT phasevec.record('docs', '2', 't1', (SELECT text_hash FROM phasevec.sources WHERE key = '2'), 2, ARRAY[1,2,3,4]::smallint[], NULL, NULL, 10, NULL);
SELECT phasevec.record('docs', '2', 't1', (SELECT text_hash FROM phasevec.sources WHERE key = '2'), 2, ARRAY[1,2,3,4]::smallint[], NULL, NULL, 11, 10);
SELECT phasevec.record('docs', '2', 't1', (SELECT text_hash FROM phasevec.sources WHERE key = '2'), 2, ARRAY[1,2,3,4]::smallint[], NULL, NULL, 0, 10);
-- a reading that saw everything, one that saw a prefix
SELECT phasevec.record('docs', '2', 't1', (SELECT text_hash FROM phasevec.sources WHERE key = '2'), 2, ARRAY[1,2,3,4]::smallint[], NULL, NULL, 10, 10);
SELECT phasevec.record('docs', '3', 't1', (SELECT text_hash FROM phasevec.sources WHERE key = '3'), 3, ARRAY[1,2,3,4]::smallint[], NULL, NULL, 1021, 2380);
SELECT key, tokens_read, tokens_total, truncated FROM phasevec.readings ORDER BY key;

-- find and alike say it; truncations() lists only the current truncated readings
SELECT key, truncated FROM phasevec.find('docs', 3, ARRAY[1,2,3,4]::smallint[], 10, true) ORDER BY key;
SELECT key, truncated FROM phasevec.alike('docs', '2', 10, true) ORDER BY key;
SELECT * FROM phasevec.truncations('docs');
-- a failed reading carries no counts
SELECT phasevec.record_failure('docs', '3', 't1', (SELECT text_hash FROM phasevec.sources WHERE key = '3'), 'no tokens');
SELECT key, tokens_read, tokens_total, truncated FROM phasevec.readings WHERE key = '3';
SELECT * FROM phasevec.truncations('docs');
-- once the row changes, the old truncated reading is not listed: it is no longer of this text
SELECT phasevec.record('docs', '4', 't1', (SELECT text_hash FROM phasevec.sources WHERE key = '4'), 4, ARRAY[1,2,3,4]::smallint[], NULL, NULL, 5, 9);
UPDATE docs SET body = 'changed' WHERE id = 4;
SELECT * FROM phasevec.truncations('docs');
SELECT count(*) AS mismatches FROM phasevec.coverage_check('docs');

DROP TABLE docs;
DROP EXTENSION pg_phasevec;
