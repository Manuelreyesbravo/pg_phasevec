-- 0.1.0 -> 0.2.0 with live data: the counts 0.2.0 keeps must start equal to a full recount of what
-- 0.1.0 left, in every state.
\set VERBOSITY terse

CREATE EXTENSION pg_muninn VERSION '0.1.0';
SELECT muninn.reader_register('u1', repeat('1', 64), 4) > 0 AS u1;
SELECT muninn.reader_register('u2', repeat('2', 64), 4) > 0 AS u2;
CREATE TABLE up (id int PRIMARY KEY, body text);
INSERT INTO up SELECT g, 'row ' || g FROM generate_series(1, 10) g;
SELECT muninn.watch('up', 'up'::regclass, 'id', 'r.body', 'u1') > 0 AS watch;
-- rows 1-6 read; 7-10 pending
SELECT count(muninn.record('up', n.key, 'u1', n.text_hash, n.key::bigint, ARRAY[1,2,3,4]::smallint[]))
  FROM muninn.next('up', 6) n;
-- 1 stale, 2 failed, 3 orphan (row deleted after reading)
UPDATE up SET body = 'changed' WHERE id = 1;
SELECT muninn.record_failure('up', '2', 'u1', (SELECT text_hash FROM muninn.sources WHERE key = '2'), 'no tokens');
DELETE FROM up WHERE id = 3;
SELECT state, n FROM muninn.coverage('up') WHERE n > 0;

ALTER EXTENSION pg_muninn UPDATE TO '0.2.0';
SELECT extversion FROM pg_extension WHERE extname = 'pg_muninn';
-- the counts kept by 0.2.0 equal the recount of the tables
SELECT state, n FROM muninn.coverage('up') WHERE n > 0;
SELECT count(*) AS mismatches FROM muninn.coverage_check('up');
-- and they keep agreeing after changes made under 0.2.0, a reader switch included
UPDATE up SET body = 'changed again' WHERE id = 4;
SELECT muninn.reader_switch('up', 'u2');
SELECT count(*) AS mismatches FROM muninn.coverage_check('up');
SELECT state, n FROM muninn.coverage('up') WHERE n > 0;

-- 0.2.0 -> 0.3.0: the queue now comes from kstate; it hands out the same rows the 0.2.0 one did
SELECT count(*) AS to_read_020 FROM muninn.next('up', 100);
ALTER EXTENSION pg_muninn UPDATE TO '0.3.0';
SELECT extversion FROM pg_extension WHERE extname = 'pg_muninn';
SELECT count(*) AS to_read_030 FROM muninn.next('up', 100);
SELECT count(*) AS mismatches FROM muninn.coverage_check('up');

DROP TABLE up;
DROP EXTENSION pg_muninn;
