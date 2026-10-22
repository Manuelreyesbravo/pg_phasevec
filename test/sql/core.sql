-- The core of pg_phasevec: readings with provenance, the seven states, loud coverage, and a search
-- that never mixes readers nor answers from stale text. Every tooth has its control.
\set VERBOSITY terse

CREATE EXTENSION pg_phasevec;

-- A sealed reader of 4 dimensions (tests hand-craft the codes the reader would produce).
SELECT phasevec.reader_register('r1', repeat('a', 64), 4) AS r1;
SELECT phasevec.reader_register('r2', repeat('b', 64), 4) AS r2;

CREATE TABLE docs (id int PRIMARY KEY, body text);
INSERT INTO docs VALUES (1, 'apple'), (2, 'banana');

SELECT phasevec.watch('docs', 'docs'::regclass, 'id', 'r.body', 'r1') AS watch;
-- A row written after the watch exists is noted by the trigger.
INSERT INTO docs VALUES (3, 'cherry');

-- ------------------------------------------------ nothing read yet: pending, and find refuses
SELECT state, n, share FROM phasevec.coverage('docs') WHERE n > 0;
SELECT * FROM phasevec.find('docs', 1, ARRAY[90,10,0,0]::smallint[]);

-- ------------------------------------------------ the reader reads what next() hands out
CREATE FUNCTION pg_temp.codes(body text) RETURNS TABLE (c64 bigint, c smallint[]) LANGUAGE sql AS $$
    SELECT CASE body WHEN 'apple' THEN 1 WHEN 'banana' THEN 2 WHEN 'cherry' THEN 4 ELSE 8 END,
           CASE body WHEN 'apple'  THEN ARRAY[100,0,0,0]
                     WHEN 'banana' THEN ARRAY[0,100,0,0]
                     WHEN 'cherry' THEN ARRAY[0,0,100,0]
                     ELSE ARRAY[0,0,0,100] END::smallint[]
$$;
SELECT count(*) AS handed_out FROM phasevec.next('docs');
SELECT count(phasevec.record('docs', n.key, 'r1', n.text_hash, c.c64, c.c)) AS recorded
  FROM phasevec.next('docs') n, pg_temp.codes(n.body) c;
SELECT count(*) AS left_to_read FROM phasevec.next('docs');

SELECT state, n, share FROM phasevec.coverage('docs') WHERE n > 0;
SELECT key, round(score::numeric, 4) AS score, hamming, state
  FROM phasevec.find('docs', 1, ARRAY[90,10,0,0]::smallint[]);
SELECT key FROM phasevec.alike('docs', '2', 1);

-- ------------------------------------------------ a changed row is stale IN THE SAME TRANSACTION
CREATE TEMP TABLE handed AS SELECT text_hash FROM phasevec.sources WHERE key = '1';
BEGIN;
UPDATE docs SET body = 'apricot' WHERE id = 1;
SELECT key, state FROM phasevec.reading_states WHERE key = '1';
COMMIT;
-- control: the untouched rows are still fresh
SELECT key, state FROM phasevec.reading_states WHERE key IN ('2', '3') ORDER BY key;

-- stale text is never searched, and coverage now refuses...
SELECT state, n, share FROM phasevec.coverage('docs') WHERE n > 0;
SELECT * FROM phasevec.find('docs', 1, ARRAY[90,10,0,0]::smallint[]);
-- ...unless the caller accepts a partial answer knowingly, and then the stale row is not in it
SELECT key, state FROM phasevec.find('docs', 1, ARRAY[90,10,0,0]::smallint[], p_partial => true) ORDER BY key;

-- a reading of the text that was there before is refused
SELECT phasevec.record('docs', '1', 'r1', (SELECT text_hash FROM handed), 1, ARRAY[100,0,0,0]::smallint[]);
-- control: a reading of the current text is accepted, and the row is fresh again
SELECT count(phasevec.record('docs', n.key, 'r1', n.text_hash, c.c64, c.c)) AS recorded
  FROM phasevec.next('docs') n, pg_temp.codes(n.body) c;
SELECT key, state FROM phasevec.reading_states WHERE key = '1';

-- ------------------------------------------------ readers are never mixed
SELECT phasevec.record('docs', '2', 'r2', (SELECT text_hash FROM phasevec.sources WHERE key = '2'), 2, ARRAY[0,100,0,0]::smallint[]);
-- a question of the wrong size is refused
SELECT * FROM phasevec.find('docs', 1, ARRAY[1,2,3]::smallint[]);

-- ------------------------------------------------ a deleted row leaves an orphan, not a silent ghost
DELETE FROM docs WHERE id = 3;
SELECT key, state FROM phasevec.reading_states WHERE key = '3';
SELECT key FROM phasevec.find('docs', 4, ARRAY[0,0,100,0]::smallint[]) ORDER BY key;

-- ------------------------------------------------ a failed reading says why, and counts
SELECT phasevec.record_failure('docs', '2', 'r1', (SELECT text_hash FROM phasevec.sources WHERE key = '2'), '');
SELECT phasevec.record_failure('docs', '2', 'r1', (SELECT text_hash FROM phasevec.sources WHERE key = '2'), 'empty after cleaning');
SELECT key, state, failed FROM phasevec.reading_states WHERE key = '2';

-- ------------------------------------------------ the trigger's writers cannot be called directly
SELECT phasevec._note((SELECT id FROM phasevec.watches WHERE name = 'docs'), '1', '\x00', 'forged');
SELECT phasevec._forget((SELECT id FROM phasevec.watches WHERE name = 'docs'), '1');

-- ------------------------------------------------ a new reader makes every old reading foreign
SELECT phasevec.reader_switch('docs', 'r2');
SELECT state, n, share FROM phasevec.coverage('docs') WHERE n > 0;
SELECT * FROM phasevec.find('docs', 1, ARRAY[90,10,0,0]::smallint[]);

-- ------------------------------------------------ the manifest contract (a trained reader)
\set m '{"reader":"vec","version":"0.1.0","base_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","adapter_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","heads_sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","marker":"<v>","pooling":"none","read_at":"last_marker_token","mrl_dims":[4096,1024,256,64],"query_instruction":"Query: "}'
-- the base must be sealed by whoever serves it
SELECT phasevec.reader_register(jsonb_set(:'m'::jsonb, '{base_sha256}', 'null'));
-- not the marker contract
SELECT phasevec.reader_register(jsonb_set(:'m'::jsonb, '{pooling}', '"last"'));
-- no 64-dim prefix: there would be no binary code
SELECT phasevec.reader_register(jsonb_set(:'m'::jsonb, '{mrl_dims}', '[4096,1024]'));
-- a heads sha that is not a sha
SELECT phasevec.reader_register(jsonb_set(:'m'::jsonb, '{heads_sha256}', '"x"'));
-- control: the same manifest, sealed, registers; it keeps the 1024 prefix and its heads
SELECT phasevec.reader_register(:'m'::jsonb) > 0 AS registered;
SELECT name, dims, left(heads_sha, 4) AS heads, manifest->>'marker' AS marker FROM phasevec.readers WHERE name = 'vec-0.1.0';
SELECT left(model_sha, 4) AS model, left(adapter_sha, 4) AS adapter, dims, left(heads_sha, 4) AS heads,
       manifest->>'query_instruction' AS instruction
  FROM phasevec.reader_seal('vec-0.1.0');
-- the same weights cannot be registered twice under another version
SELECT phasevec.reader_register(jsonb_set(:'m'::jsonb, '{version}', '"0.1.1"'));
-- different heads are a different reader
SELECT phasevec.reader_register(jsonb_set(jsonb_set(:'m'::jsonb, '{version}', '"0.1.1"'), '{heads_sha256}', to_jsonb(repeat('f', 64)))) > 0 AS other_heads;

-- ------------------------------------------------ only the table's owner may watch it
CREATE ROLE regress_phasevec_stranger;
GRANT USAGE ON SCHEMA phasevec TO regress_phasevec_stranger;
GRANT EXECUTE ON FUNCTION phasevec.watch(text, regclass, name, text, text, numeric, real) TO regress_phasevec_stranger;
SET ROLE regress_phasevec_stranger;
SELECT phasevec.watch('stolen', 'docs'::regclass, 'id', 'r.body', 'r1');
-- and a stranger reads nothing
SELECT count(*) FROM phasevec.readings;
RESET ROLE;

-- an unknown reader, a missing column, a recipe that is not an expression over the row
SELECT phasevec.watch('w2', 'docs'::regclass, 'id', 'r.body', 'nobody');
SELECT phasevec.watch('w2', 'docs'::regclass, 'nope', 'r.body', 'r1');
SELECT phasevec.watch('w2', 'docs'::regclass, 'id', 'r.missing_column', 'r1');

DROP OWNED BY regress_phasevec_stranger;
DROP ROLE regress_phasevec_stranger;

-- ------------------------------------------------ a reading the reader did not recognize is doubtful
-- The seventh state: the text is current and the reading is the reader's, but its familiarity is
-- under the watch's doubt_below. It still counts as covered and is still found, marked as such.
CREATE TABLE notes (id int PRIMARY KEY, body text);
INSERT INTO notes VALUES (1, 'known'), (2, 'invented');
SELECT phasevec.watch('notes', 'notes'::regclass, 'id', 'r.body', 'r1', 0.95, 0.5) > 0 AS watch;
SELECT count(phasevec.record('notes', n.key, 'r1', n.text_hash,
                           CASE n.key WHEN '1' THEN 1 ELSE 2 END,
                           CASE n.key WHEN '1' THEN ARRAY[100,0,0,0] ELSE ARRAY[90,10,0,0] END::smallint[],
                           CASE n.key WHEN '1' THEN 0.9 ELSE 0.2 END::real)) AS recorded
  FROM phasevec.next('notes') n;
-- control: the familiar reading is fresh; the other one, under 0.5, is doubtful
SELECT key, state FROM phasevec.reading_states WHERE watch = 'notes' ORDER BY key;
SELECT state, n, share FROM phasevec.coverage('notes') WHERE n > 0;
SELECT key, state FROM phasevec.find('notes', 2, ARRAY[90,10,0,0]::smallint[]) ORDER BY key;
DROP TABLE notes;

-- ------------------------------------------------ the counts never lie (0.2.0)
-- coverage() reads counts the triggers keep; coverage_check() recounts the tables from scratch.
-- After every kind of change above -- readings, stale text, an orphan, a failure, a new reader --
-- they agree.
SELECT count(*) AS mismatches FROM phasevec.coverage_check('docs');
-- control: a count corrupted by hand is reported...
UPDATE phasevec.counts SET n = n + 1 WHERE watch = (SELECT id FROM phasevec.watches WHERE name = 'docs') AND state = 'foreign';
SELECT state, counted, recounted FROM phasevec.coverage_check('docs');
-- ...a recount repairs it...
SELECT phasevec._recount((SELECT id FROM phasevec.watches WHERE name = 'docs'));
SELECT count(*) AS mismatches FROM phasevec.coverage_check('docs');
-- ...and a count can never go below zero
UPDATE phasevec.counts SET n = -1 WHERE watch = (SELECT id FROM phasevec.watches WHERE name = 'docs') AND state = 'orphan';

-- ------------------------------------------------ the 256-bit sweep (0.2.0)
-- Three rows of a 256-dimension reader. Row 'a' is the nearest by its 256-bit code but the farthest
-- by its 64-bit code; with m = 1 only the candidate the sweep picks is reranked, so the answer says
-- which code was swept.
SELECT phasevec.reader_register('r256', repeat('9', 64), 256) > 0 AS r256;
CREATE TABLE wide (id text PRIMARY KEY, body text);
INSERT INTO wide VALUES ('a', 'alpha'), ('b', 'beta'), ('c', 'gamma');
SELECT phasevec.watch('wide', 'wide'::regclass, 'id', 'r.body', 'r256') > 0 AS watch;
SELECT count(phasevec.record('wide', n.key, 'r256', n.text_hash,
                           CASE n.key WHEN 'a' THEN -1 ELSE 0 END,          -- 64 bits: 'a' is far
                           array_fill(CASE n.key WHEN 'a' THEN 100 WHEN 'b' THEN 50 ELSE -100 END::smallint, ARRAY[256]),
                           NULL,
                           CASE n.key WHEN 'a' THEN repeat('1', 256) WHEN 'b' THEN repeat('1', 128) || repeat('0', 128)
                                      ELSE repeat('0', 256) END::bit(256)))  -- 256 bits: 'a' is near
                           AS recorded
  FROM phasevec.next('wide') n;
-- the question: all ones in 256 bits, all zeros in 64
SELECT key, hamming FROM phasevec.find('wide', 0, array_fill(100::smallint, ARRAY[256]), 1, false, 1,
                                     repeat('1', 256)::bit(256));
-- control: the same question without its 256-bit code sweeps the 64-bit one and gets another row
SELECT key, hamming FROM phasevec.find('wide', 0, array_fill(100::smallint, ARRAY[256]), 1, false, 1);
-- a 256-bit code from a reader of fewer dimensions is refused
SELECT phasevec.record('docs', '2', 'r2', (SELECT text_hash FROM phasevec.sources WHERE key = '2' AND watch = (SELECT id FROM phasevec.watches WHERE name = 'docs')),
                     2, ARRAY[0,100,0,0]::smallint[], NULL, repeat('1', 256)::bit(256));
SELECT count(*) AS mismatches FROM phasevec.coverage_check('wide');
DROP TABLE wide;

-- ------------------------------------------------ the reader on its own: queue, audits, dupes (0.3.0)
CREATE TABLE q3 (id int PRIMARY KEY, body text);
INSERT INTO q3 VALUES (1, 'one'), (2, 'two'), (3, 'three'), (4, 'four');
SELECT phasevec.watch('q3', 'q3'::regclass, 'id', 'r.body', 'r1') > 0 AS watch;
SELECT count(phasevec.record('q3', n.key, 'r1', n.text_hash, n.key::bigint,
                           CASE WHEN n.key IN ('1', '2') THEN ARRAY[100,0,0,0] ELSE ARRAY[0,0,n.key::int * 10,100] END::smallint[]))
  FROM phasevec.next('q3') n WHERE n.key <> '4';
SELECT phasevec.record_failure('q3', '4', 'r1', (SELECT text_hash FROM phasevec.sources WHERE key = '4' AND watch = (SELECT id FROM phasevec.watches WHERE name = 'q3')), 'no tokens');
-- a failed reading of the current text is not handed out again...
SELECT count(*) AS to_read FROM phasevec.next('q3');
-- ...but once its text changes it is, exactly as in 0.1.0
UPDATE q3 SET body = 'four, now readable' WHERE id = 4;
SELECT key FROM phasevec.next('q3');
-- a re-reading that reproduces the reading holds
SELECT phasevec.record_audit('q3', '1', 'r1', (SELECT text_hash FROM phasevec.readings WHERE key = '1' AND watch = (SELECT id FROM phasevec.watches WHERE name = 'q3')),
                           ARRAY[100,0,0,0]::smallint[], NULL) AS holds;
-- control: a re-reading that does not is recorded as a broken assertion
SELECT phasevec.record_audit('q3', '2', 'r1', (SELECT text_hash FROM phasevec.readings WHERE key = '2' AND watch = (SELECT id FROM phasevec.watches WHERE name = 'q3')),
                           ARRAY[0,100,0,0]::smallint[], NULL) AS holds;
SELECT key, same_code256, round(cosine::numeric, 3) AS cosine, holds FROM phasevec.audits ORDER BY id;
-- a row that changed is not audited: there is no reading of its current text
UPDATE q3 SET body = 'one, edited' WHERE id = 1;
SELECT phasevec.record_audit('q3', '1', 'r1', (SELECT text_hash FROM phasevec.sources WHERE key = '1' AND watch = (SELECT id FROM phasevec.watches WHERE name = 'q3')),
                           ARRAY[100,0,0,0]::smallint[], NULL) AS holds;
SELECT key FROM phasevec.audit_sample('q3', 10) ORDER BY key;
-- dupes counts only fresh readings: 1 back to the text it was read from is fresh again; 1 and 2
-- share a code, 3 is not alike
UPDATE q3 SET body = 'one' WHERE id = 1;
SELECT key_a, key_b, round(cosine::numeric, 3) AS cosine FROM phasevec.dupes('q3', 0.98);
-- control: with a lower threshold the dissimilar pair appears too
SELECT count(*) AS pairs FROM phasevec.dupes('q3', -1);
SELECT count(*) AS mismatches FROM phasevec.coverage_check('q3');
DROP TABLE q3;
-- ------------------------------------------------ dropping the table drops its watch
SELECT count(*) AS watches_before FROM phasevec.watches;
DROP TABLE docs;
SELECT count(*) AS watches_after FROM phasevec.watches;
DROP EXTENSION pg_phasevec;
