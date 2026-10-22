-- 0.7.0: the counts are kept as deltas. A bulk load in ONE transaction is linear, and the counts
-- still never lie: coverage() equals a full recount before and after folding the deltas in.
\set VERBOSITY terse

CREATE EXTENSION pg_phasevec VERSION '0.6.0';
SELECT phasevec.reader_register('t1', repeat('a', 64), 4) > 0 AS t1;
CREATE TABLE docs (id int PRIMARY KEY, body text);
INSERT INTO docs SELECT g, 'row ' || g FROM generate_series(1, 10) g;
SELECT phasevec.watch('docs', 'docs'::regclass, 'id', 'r.body', 't1') > 0 AS watch;

-- from 0.6.0 with live counts: nothing to fold yet, and the counts agree with a recount
ALTER EXTENSION pg_phasevec UPDATE TO '0.7.0';
SELECT extversion FROM pg_extension WHERE extname = 'pg_phasevec';
SELECT count(*) AS deltas FROM phasevec.count_deltas;
SELECT count(*) AS mismatches FROM phasevec.coverage_check('docs');

-- a bulk load in one transaction: 20,000 rows noted, then 10,000 of them read
BEGIN;
INSERT INTO docs SELECT g, 'row ' || g FROM generate_series(11, 20010) g;
SELECT count(phasevec.record('docs', n.key, 't1', n.text_hash, 1::bigint,
                             ARRAY[1, 1, 0, 0]::smallint[], NULL, NULL, 5, 5))
  FROM phasevec.next('docs', 10000) n;
COMMIT;
SELECT state, n FROM phasevec.coverage('docs') WHERE n > 0;
SELECT count(*) AS mismatches FROM phasevec.coverage_check('docs');
SELECT count(*) > 1000 AS deltas_pending FROM phasevec.count_deltas;

-- folded in: no delta left, the same coverage, still equal to a recount
SELECT phasevec.counts_compact('docs') > 1000 AS folded;
SELECT count(*) AS deltas FROM phasevec.count_deltas;
SELECT state, n FROM phasevec.coverage('docs') WHERE n > 0;
SELECT count(*) AS mismatches FROM phasevec.coverage_check('docs');

-- after folding, a change is still stale in its own transaction (through a new delta)
UPDATE docs SET body = 'changed' WHERE id = (SELECT key::int FROM phasevec.readings ORDER BY key LIMIT 1);
SELECT state, n FROM phasevec.coverage('docs') WHERE state IN ('fresh', 'stale');
SELECT count(*) AS mismatches FROM phasevec.coverage_check('docs');

-- a delta that would drive a count below zero is caught when it is folded, not silently kept
INSERT INTO phasevec.count_deltas SELECT id, 'orphan', -5 FROM phasevec.watches WHERE name = 'docs';
SELECT phasevec.counts_compact('docs');
DELETE FROM phasevec.count_deltas WHERE d = -5;
SELECT count(*) AS mismatches FROM phasevec.coverage_check('docs');

DROP TABLE docs;
DROP EXTENSION pg_phasevec;
