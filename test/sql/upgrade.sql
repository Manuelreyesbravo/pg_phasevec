-- 0.1.0 -> 0.2.0 with live data: the counts 0.2.0 keeps must start equal to a full recount of what
-- 0.1.0 left, in every state.
\set VERBOSITY terse

CREATE EXTENSION pg_phasevec VERSION '0.1.0';
SELECT phasevec.reader_register('u1', repeat('1', 64), 4) > 0 AS u1;
SELECT phasevec.reader_register('u2', repeat('2', 64), 4) > 0 AS u2;
CREATE TABLE up (id int PRIMARY KEY, body text);
INSERT INTO up SELECT g, 'row ' || g FROM generate_series(1, 10) g;
SELECT phasevec.watch('up', 'up'::regclass, 'id', 'r.body', 'u1') > 0 AS watch;
-- rows 1-6 read; 7-10 pending
SELECT count(phasevec.record('up', n.key, 'u1', n.text_hash, n.key::bigint, ARRAY[1,2,3,4]::smallint[]))
  FROM phasevec.next('up', 6) n;
-- 1 stale, 2 failed, 3 orphan (row deleted after reading)
UPDATE up SET body = 'changed' WHERE id = 1;
SELECT phasevec.record_failure('up', '2', 'u1', (SELECT text_hash FROM phasevec.sources WHERE key = '2'), 'no tokens');
DELETE FROM up WHERE id = 3;
SELECT state, n FROM phasevec.coverage('up') WHERE n > 0;

ALTER EXTENSION pg_phasevec UPDATE TO '0.2.0';
SELECT extversion FROM pg_extension WHERE extname = 'pg_phasevec';
-- the counts kept by 0.2.0 equal the recount of the tables
SELECT state, n FROM phasevec.coverage('up') WHERE n > 0;
SELECT count(*) AS mismatches FROM phasevec.coverage_check('up');
-- and they keep agreeing after changes made under 0.2.0, a reader switch included
UPDATE up SET body = 'changed again' WHERE id = 4;
SELECT phasevec.reader_switch('up', 'u2');
SELECT count(*) AS mismatches FROM phasevec.coverage_check('up');
SELECT state, n FROM phasevec.coverage('up') WHERE n > 0;

-- 0.2.0 -> 0.3.0: the queue now comes from kstate; it hands out the same rows the 0.2.0 one did
SELECT count(*) AS to_read_020 FROM phasevec.next('up', 100);
ALTER EXTENSION pg_phasevec UPDATE TO '0.3.0';
SELECT extversion FROM pg_extension WHERE extname = 'pg_phasevec';
SELECT count(*) AS to_read_030 FROM phasevec.next('up', 100);
SELECT count(*) AS mismatches FROM phasevec.coverage_check('up');

DROP TABLE up;
DROP EXTENSION pg_phasevec;

-- 0.16.0 -> 0.17.0: the recall guard arrives empty, owner-only, every function with its search_path pinned
CREATE EXTENSION pg_phasevec VERSION '0.16.0';
ALTER EXTENSION pg_phasevec UPDATE TO '0.17.0';
SELECT extversion FROM pg_extension WHERE extname = 'pg_phasevec';
SELECT count(*) AS baselines FROM phasevec.recall_baseline;
SELECT count(*) AS checked FROM phasevec.recall_check();
SELECT p.proname, p.prosecdef, p.proconfig, has_function_privilege('public', p.oid, 'EXECUTE') AS public_exec
  FROM pg_proc p
 WHERE p.pronamespace = 'phasevec'::regnamespace AND p.proname IN ('recall_approve', 'recall_check', '_recall_measure')
 ORDER BY p.proname;
SELECT has_table_privilege('public', 'phasevec.recall_baseline', 'SELECT') AS public_reads_baselines;
DROP EXTENSION pg_phasevec;
