-- 0.17.0: the recall guard. It measures the path a watch is SERVED by -- find_ivf with its m and nprobe, or
-- find with its m -- against find over every live row. A baseline approved on a healthy index reads ok, and reads the same twice;
-- the index degraded for real (new rows absorbed into lists trained without them, or far too many lists)
-- reads degraded or critical; rebuilt, ok again. A watch it cannot measure is a row, never an exception.
-- And the negative control: the truth is find over EVERY live row; with the production m on both sides a
-- small m would look perfect.
--
-- Only verdicts and inequalities are printed: the coarse index is k-means in float, and the exact recall
-- can move from one CPU to another. Each assertion keeps a margin (measured on 31-10, this sample, nprobe 2:
-- approved 0.9975, absorbed 0.865, rebuilt 1.0, 500 lists 0.58). The degraded band is shown on the find
-- path, which has no k-means: m 80 reads 1.0 at 500 rows and 0.945 at 1000.
\set VERBOSITY terse

CREATE EXTENSION pg_phasevec;
SELECT extversion FROM pg_extension WHERE extname = 'pg_phasevec';
SELECT phasevec.reader_register('r256', repeat('a', 64), 256) > 0 AS r256;
CREATE TABLE docs (id int PRIMARY KEY, body text);
SELECT phasevec.watch('docs', 'docs'::regclass, 'id', 'r.body', 'r256') > 0 AS watch;

-- a row's code: the centre c plus noise of its own, both from hashes, so deterministic
CREATE FUNCTION code_of(g int, c int) RETURNS smallint[] LANGUAGE sql IMMUTABLE AS $$
    SELECT array(SELECT greatest(-127, least(127, (hashint8(c * 1000 + j) % 100)
                                                + (hashint8(1000000 + g::int8 * 1000 + j) % 60)))::smallint
                   FROM generate_series(1, 256) j) $$;
CREATE FUNCTION signs_of(c smallint[]) RETURNS bit(256) LANGUAGE sql IMMUTABLE AS $$
    SELECT string_agg(CASE WHEN x > 0 THEN '1' ELSE '0' END, '' ORDER BY o)::bit(256)
      FROM unnest(c) WITH ORDINALITY u(x, o) $$;

-- rows 1..500 around centres 0..9, and the index trained on them
INSERT INTO docs SELECT g, 'old ' || g FROM generate_series(1, 500) g;
SELECT count(phasevec.record('docs', s.key, 'r256', s.text_hash, 0::bigint, code_of(s.key::int, s.key::int % 10),
                             NULL, signs_of(code_of(s.key::int, s.key::int % 10)))) AS recorded
  FROM phasevec.sources s;
SELECT phasevec.ivf_build('docs') AS lists;
-- rows 501..1000 around NEW centres 100..109, read after the build: they wait in the delta, which every
-- question sweeps row by row
INSERT INTO docs SELECT g, 'new ' || g FROM generate_series(501, 1000) g;
SELECT count(phasevec.record('docs', s.key, 'r256', s.text_hash, 0::bigint, code_of(s.key::int, 100 + s.key::int % 10),
                             NULL, signs_of(code_of(s.key::int, 100 + s.key::int % 10)))) AS recorded
  FROM phasevec.sources s WHERE s.key::int > 500;
SELECT count(*) AS delta FROM phasevec.ivf_dirty;
-- the truth is find over every row: without statistics its plan is ~20x slower
ANALYZE;

-- (1) approve on the healthy index, with a production nprobe of 2 (a watch this small has 22 lists)
SELECT setseed(0.17);
SELECT phasevec.recall_approve('docs', 10, 40, 2) >= 0.98 AS approved_high;
SELECT k, via, nprobe, m, cardinality(sample_keys) AS sample, measured, approved_by = session_user AS by_me
  FROM phasevec.recall_baseline;
SELECT watch, verdict, k, sample, via, nprobe, m, drift >= -0.02 AS within_ok FROM phasevec.recall_check('docs');
-- (2) twice in a row, nothing changed: the same row
CREATE TEMP TABLE first AS SELECT watch, verdict, baseline, current, drift, k, sample, nprobe, m FROM phasevec.recall_check('docs');
SELECT (SELECT row(f.*)::text FROM first f)
     = (SELECT row(c.watch, c.verdict, c.baseline, c.current, c.drift, c.k, c.sample, c.nprobe, c.m)::text
          FROM phasevec.recall_check('docs') c) AS same_twice;
-- a session that lowers nothing changes nothing either: nprobe and m are the stored ones
SELECT nprobe, m FROM phasevec.recall_check('docs');

-- (3) degrade the DATA: the new rows absorbed into lists trained without them
SELECT phasevec.ivf_absorb('docs') AS absorbed;
SELECT watch, verdict <> 'ok' AS not_ok, current < baseline - 0.05 AS fell_clearly
  FROM phasevec.recall_check('docs');
-- (4) fix it: retrain the lists
SELECT phasevec.ivf_build('docs') AS lists;
SELECT watch, verdict FROM phasevec.recall_check('docs');
-- (5) degrade the INDEX: rebuilt with far too many lists for the nprobe it is searched with
SELECT phasevec.ivf_build('docs', 500) AS lists;
SELECT watch, verdict, current < baseline - 0.20 AS fell_far, drift < 0 AS drift_negative
  FROM phasevec.recall_check('docs');
SELECT phasevec.ivf_build('docs') AS lists;
SELECT watch, verdict FROM phasevec.recall_check('docs');

-- (6) coverage below the declared minimum: find and find_ivf would refuse; the guard measures what is read
INSERT INTO docs SELECT g, 'unread ' || g FROM generate_series(2001, 2200) g;
SELECT count(*) FROM phasevec.find_ivf('docs', 0, code_of(1, 1), 10, false, 200, signs_of(code_of(1, 1)), 4);
SELECT watch, verdict FROM phasevec.recall_check('docs');
DELETE FROM docs WHERE id > 2000;

-- (6b) a watch with no coarse index is served by find, with its m: approving picks that path by itself. find
-- prefilters by Hamming distance and keeps m candidates, so with m fixed it loses neighbours as the watch grows
-- (measured on 31-10, m 80: 500 rows 1.0, 1000 rows 0.945). Fixed by serving with a larger m.
CREATE TABLE notes (id int PRIMARY KEY, body text);
SELECT phasevec.watch('notes', 'notes'::regclass, 'id', 'r.body', 'r256') > 0 AS watch;
INSERT INTO notes SELECT g, 'note ' || g FROM generate_series(1, 500) g;
SELECT count(phasevec.record('notes', s.key, 'r256', s.text_hash, 0::bigint, code_of(s.key::int, s.key::int % 10),
                             NULL, signs_of(code_of(s.key::int, s.key::int % 10)))) AS recorded
  FROM phasevec.sources s JOIN phasevec.watches w ON w.id = s.watch WHERE w.name = 'notes';
ANALYZE;
SELECT setseed(0.17);
SELECT phasevec.recall_approve('notes', 10, 40, NULL, 80) >= 0.98 AS approved_high;
SELECT watch, verdict, via, nprobe, m FROM phasevec.recall_check('notes');
-- the data doubles, the m it is served with does not
INSERT INTO notes SELECT g, 'note ' || g FROM generate_series(501, 1000) g;
SELECT count(phasevec.record('notes', s.key, 'r256', s.text_hash, 0::bigint, code_of(s.key::int, s.key::int % 10),
                             NULL, signs_of(code_of(s.key::int, s.key::int % 10)))) AS recorded
  FROM phasevec.sources s JOIN phasevec.watches w ON w.id = s.watch WHERE w.name = 'notes' AND s.key::int > 500;
ANALYZE;
SELECT watch, verdict, current < baseline - 0.03 AND current > baseline - 0.09 AS inside_degraded
  FROM phasevec.recall_check('notes');
-- served with a larger m now: approve that path
SELECT phasevec.recall_approve('notes', 10, 40, NULL, 200) >= 0.98 AS approved_high;
SELECT watch, verdict, via, m FROM phasevec.recall_check('notes');
-- find_ivf cannot be approved where there is no coarse index, and nprobe means nothing to find
SELECT phasevec.recall_approve('notes', 10, 40, NULL, 200, 'find_ivf');
SELECT phasevec.recall_approve('notes', 10, 40, 4, 200, 'find');
SELECT phasevec.recall_approve('notes', 10, 40, NULL, 200, 'hnsw');
-- an indexed watch can still be approved on find, if that is what serves it
SELECT setseed(0.17);
SELECT phasevec.recall_approve('docs', 10, 40, NULL, 1000, 'find') >= 0.98 AS approved_high;
SELECT watch, verdict, via, nprobe, m FROM phasevec.recall_check('docs');
SELECT watch, via FROM phasevec.recall_check() ORDER BY watch;
DELETE FROM phasevec.recall_baseline b USING phasevec.watches w WHERE w.id = b.watch AND w.name = 'notes';

-- (7) the negative control. A production m of 11 (the Hamming prefilter keeps only 11 candidates) with
-- every list probed (nprobe 1000), so the number does not depend on the k-means. The guard compares it
-- against find over every row and reads low; with the same m = 11 on the truth side it would read ~1.
SET client_min_messages = error;   -- approving a baseline under 0.5 warns, with the number
SELECT phasevec.recall_approve('docs', 10, 40, 1000, 11) < 0.7 AS low_baseline;
RESET client_min_messages;
CREATE TEMP TABLE neg AS
SELECT (SELECT current FROM phasevec.recall_check('docs')) AS guard,
       (SELECT round(recall::numeric, 4)::float8 FROM phasevec._recall_measure('docs', b.sample_keys, 10, 'find_ivf', 11, 1000)) AS every_row,
       (SELECT round(recall::numeric, 4)::float8 FROM phasevec._recall_measure('docs', b.sample_keys, 10, 'find_ivf', 11, 1000, 11)) AS same_m,
       (SELECT m_ref FROM phasevec._recall_measure('docs', b.sample_keys, 10, 'find_ivf', 11, 1000)) AS m_ref
  FROM phasevec.recall_baseline b;
SELECT guard = every_row AS guard_uses_every_row, guard < 0.7 AS guard_low, same_m > 0.9 AS same_m_looks_fine,
       same_m - guard > 0.3 AS gap, m_ref FROM neg;

-- (8) most of the sample gone: a row, asking for a new approval
SELECT setseed(0.17);
SELECT phasevec.recall_approve('docs', 10, 40, 2) >= 0.98 AS approved_high;
-- a sampled row replaced since the approval is not asked any more: its replacement would come back first on
-- both sides, outside the index, and count as a hit the index never made
SELECT count(*) AS superseded FROM (SELECT phasevec.supersede('docs', b.sample_keys[1], b.sample_keys[2], 'a correction')
                                      FROM phasevec.recall_baseline b) t;
SELECT watch, verdict, sample FROM phasevec.recall_check('docs');
DELETE FROM docs d USING phasevec.recall_baseline b WHERE d.id::text = ANY (b.sample_keys[1:25]);
SELECT watch, verdict, sample, current FROM phasevec.recall_check('docs');

-- (9) what cannot be measured is a row: no baseline, no such watch, a reader switched under the baseline
CREATE TABLE other (id int PRIMARY KEY, body text);
SELECT phasevec.watch('other', 'other'::regclass, 'id', 'r.body', 'r256') > 0 AS watch;
SELECT watch, verdict, baseline, current FROM phasevec.recall_check('other');
SELECT watch, verdict, baseline, current FROM phasevec.recall_check('nope');
SELECT watch FROM phasevec.recall_check();
SELECT phasevec.reader_register('r256b', repeat('b', 64), 256) > 0 AS r256b;
SELECT phasevec.reader_switch('docs', 'r256b');
SELECT watch, verdict, baseline, current FROM phasevec.recall_check('docs');
-- approving refuses a watch without a coarse index, and k, sample, nprobe or m out of range
SELECT phasevec.recall_approve('other', p_via => 'find_ivf');
SELECT phasevec.recall_approve('other');
SELECT phasevec.recall_approve('docs', 0);
SELECT phasevec.recall_approve('docs', 10, 20000);
SELECT phasevec.recall_approve('docs', 10, 40, NULL, 10);

-- (10) owner work: nothing is executable by PUBLIC, every new function pins its search_path
SELECT p.proname, p.prosecdef, p.proconfig, has_function_privilege('public', p.oid, 'EXECUTE') AS public_exec
  FROM pg_proc p
 WHERE p.pronamespace = 'phasevec'::regnamespace AND p.proname IN ('recall_approve', 'recall_check', '_recall_measure')
 ORDER BY p.proname;
SELECT has_table_privilege('public', 'phasevec.recall_baseline', 'SELECT') AS public_reads_baselines;
CREATE ROLE regress_pv_recall;
SET ROLE regress_pv_recall;
SELECT phasevec.recall_approve('docs');
SELECT * FROM phasevec.recall_check();
SELECT count(*) FROM phasevec.recall_baseline;
RESET ROLE;
-- a monitoring role is given the check, and only the check
GRANT USAGE ON SCHEMA phasevec TO regress_pv_recall;
GRANT EXECUTE ON FUNCTION phasevec.recall_check(text) TO regress_pv_recall;
SET ROLE regress_pv_recall;
SELECT watch, verdict FROM phasevec.recall_check();
SELECT phasevec.recall_approve('docs');
SELECT count(*) FROM phasevec.recall_baseline;
RESET ROLE;
REVOKE ALL ON FUNCTION phasevec.recall_check(text) FROM regress_pv_recall;
REVOKE ALL ON SCHEMA phasevec FROM regress_pv_recall;
DROP ROLE regress_pv_recall;

DROP TABLE docs;
DROP TABLE other;
DROP TABLE notes;
DROP FUNCTION code_of(int, int);
DROP FUNCTION signs_of(smallint[]);
DROP EXTENSION pg_phasevec;
