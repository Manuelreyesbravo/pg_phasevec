-- The core of pg_muninn: readings with provenance, the seven states, loud coverage, and a search
-- that never mixes readers nor answers from stale text. Every tooth has its control.
\set VERBOSITY terse

CREATE EXTENSION pg_muninn;

-- A sealed reader of 4 dimensions (tests hand-craft the codes the reader would produce).
SELECT muninn.reader_register('r1', repeat('a', 64), 4) AS r1;
SELECT muninn.reader_register('r2', repeat('b', 64), 4) AS r2;

CREATE TABLE docs (id int PRIMARY KEY, body text);
INSERT INTO docs VALUES (1, 'apple'), (2, 'banana');

SELECT muninn.watch('docs', 'docs'::regclass, 'id', 'r.body', 'r1') AS watch;
-- A row written after the watch exists is noted by the trigger.
INSERT INTO docs VALUES (3, 'cherry');

-- ------------------------------------------------ nothing read yet: pending, and find refuses
SELECT state, n, share FROM muninn.coverage('docs') WHERE n > 0;
SELECT * FROM muninn.find('docs', 1, ARRAY[90,10,0,0]::smallint[]);

-- ------------------------------------------------ the reader reads what next() hands out
CREATE FUNCTION pg_temp.codes(body text) RETURNS TABLE (c64 bigint, c smallint[]) LANGUAGE sql AS $$
    SELECT CASE body WHEN 'apple' THEN 1 WHEN 'banana' THEN 2 WHEN 'cherry' THEN 4 ELSE 8 END,
           CASE body WHEN 'apple'  THEN ARRAY[100,0,0,0]
                     WHEN 'banana' THEN ARRAY[0,100,0,0]
                     WHEN 'cherry' THEN ARRAY[0,0,100,0]
                     ELSE ARRAY[0,0,0,100] END::smallint[]
$$;
SELECT count(*) AS handed_out FROM muninn.next('docs');
SELECT count(muninn.record('docs', n.key, 'r1', n.text_hash, c.c64, c.c)) AS recorded
  FROM muninn.next('docs') n, pg_temp.codes(n.body) c;
SELECT count(*) AS left_to_read FROM muninn.next('docs');

SELECT state, n, share FROM muninn.coverage('docs') WHERE n > 0;
SELECT key, round(score::numeric, 4) AS score, hamming, state
  FROM muninn.find('docs', 1, ARRAY[90,10,0,0]::smallint[]);
SELECT key FROM muninn.alike('docs', '2', 1);

-- ------------------------------------------------ a changed row is stale IN THE SAME TRANSACTION
CREATE TEMP TABLE handed AS SELECT text_hash FROM muninn.sources WHERE key = '1';
BEGIN;
UPDATE docs SET body = 'apricot' WHERE id = 1;
SELECT key, state FROM muninn.reading_states WHERE key = '1';
COMMIT;
-- control: the untouched rows are still fresh
SELECT key, state FROM muninn.reading_states WHERE key IN ('2', '3') ORDER BY key;

-- stale text is never searched, and coverage now refuses...
SELECT state, n, share FROM muninn.coverage('docs') WHERE n > 0;
SELECT * FROM muninn.find('docs', 1, ARRAY[90,10,0,0]::smallint[]);
-- ...unless the caller accepts a partial answer knowingly, and then the stale row is not in it
SELECT key, state FROM muninn.find('docs', 1, ARRAY[90,10,0,0]::smallint[], p_partial => true) ORDER BY key;

-- a reading of the text that was there before is refused
SELECT muninn.record('docs', '1', 'r1', (SELECT text_hash FROM handed), 1, ARRAY[100,0,0,0]::smallint[]);
-- control: a reading of the current text is accepted, and the row is fresh again
SELECT count(muninn.record('docs', n.key, 'r1', n.text_hash, c.c64, c.c)) AS recorded
  FROM muninn.next('docs') n, pg_temp.codes(n.body) c;
SELECT key, state FROM muninn.reading_states WHERE key = '1';

-- ------------------------------------------------ readers are never mixed
SELECT muninn.record('docs', '2', 'r2', (SELECT text_hash FROM muninn.sources WHERE key = '2'), 2, ARRAY[0,100,0,0]::smallint[]);
-- a question of the wrong size is refused
SELECT * FROM muninn.find('docs', 1, ARRAY[1,2,3]::smallint[]);

-- ------------------------------------------------ a deleted row leaves an orphan, not a silent ghost
DELETE FROM docs WHERE id = 3;
SELECT key, state FROM muninn.reading_states WHERE key = '3';
SELECT key FROM muninn.find('docs', 4, ARRAY[0,0,100,0]::smallint[]) ORDER BY key;

-- ------------------------------------------------ a failed reading says why, and counts
SELECT muninn.record_failure('docs', '2', 'r1', (SELECT text_hash FROM muninn.sources WHERE key = '2'), '');
SELECT muninn.record_failure('docs', '2', 'r1', (SELECT text_hash FROM muninn.sources WHERE key = '2'), 'empty after cleaning');
SELECT key, state, failed FROM muninn.reading_states WHERE key = '2';

-- ------------------------------------------------ the trigger's writers cannot be called directly
SELECT muninn._note((SELECT id FROM muninn.watches WHERE name = 'docs'), '1', '\x00');
SELECT muninn._forget((SELECT id FROM muninn.watches WHERE name = 'docs'), '1');

-- ------------------------------------------------ a new reader makes every old reading foreign
SELECT muninn.reader_switch('docs', 'r2');
SELECT state, n, share FROM muninn.coverage('docs') WHERE n > 0;
SELECT * FROM muninn.find('docs', 1, ARRAY[90,10,0,0]::smallint[]);

-- ------------------------------------------------ the manifest contract (a trained reader)
\set m '{"reader":"vec","version":"0.1.0","base_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","adapter_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","heads_sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","marker":"<v>","pooling":"none","read_at":"last_marker_token","mrl_dims":[4096,1024,256,64],"query_instruction":"Query: "}'
-- the base must be sealed by whoever serves it
SELECT muninn.reader_register(jsonb_set(:'m'::jsonb, '{base_sha256}', 'null'));
-- not the marker contract
SELECT muninn.reader_register(jsonb_set(:'m'::jsonb, '{pooling}', '"last"'));
-- no 64-dim prefix: there would be no binary code
SELECT muninn.reader_register(jsonb_set(:'m'::jsonb, '{mrl_dims}', '[4096,1024]'));
-- a heads sha that is not a sha
SELECT muninn.reader_register(jsonb_set(:'m'::jsonb, '{heads_sha256}', '"x"'));
-- control: the same manifest, sealed, registers; it keeps the 1024 prefix and its heads
SELECT muninn.reader_register(:'m'::jsonb) > 0 AS registered;
SELECT name, dims, left(heads_sha, 4) AS heads, manifest->>'marker' AS marker FROM muninn.readers WHERE name = 'vec-0.1.0';
SELECT left(model_sha, 4) AS model, left(adapter_sha, 4) AS adapter, dims, left(heads_sha, 4) AS heads,
       manifest->>'query_instruction' AS instruction
  FROM muninn.reader_seal('vec-0.1.0');
-- the same weights cannot be registered twice under another version
SELECT muninn.reader_register(jsonb_set(:'m'::jsonb, '{version}', '"0.1.1"'));
-- different heads are a different reader
SELECT muninn.reader_register(jsonb_set(jsonb_set(:'m'::jsonb, '{version}', '"0.1.1"'), '{heads_sha256}', to_jsonb(repeat('f', 64)))) > 0 AS other_heads;

-- ------------------------------------------------ only the table's owner may watch it
CREATE ROLE regress_muninn_stranger;
GRANT USAGE ON SCHEMA muninn TO regress_muninn_stranger;
GRANT EXECUTE ON FUNCTION muninn.watch(text, regclass, name, text, text, numeric, real) TO regress_muninn_stranger;
SET ROLE regress_muninn_stranger;
SELECT muninn.watch('stolen', 'docs'::regclass, 'id', 'r.body', 'r1');
-- and a stranger reads nothing
SELECT count(*) FROM muninn.readings;
RESET ROLE;

-- an unknown reader, a missing column, a recipe that is not an expression over the row
SELECT muninn.watch('w2', 'docs'::regclass, 'id', 'r.body', 'nobody');
SELECT muninn.watch('w2', 'docs'::regclass, 'nope', 'r.body', 'r1');
SELECT muninn.watch('w2', 'docs'::regclass, 'id', 'r.missing_column', 'r1');

DROP OWNED BY regress_muninn_stranger;
DROP ROLE regress_muninn_stranger;

-- ------------------------------------------------ a reading the reader did not recognize is doubtful
-- The seventh state: the text is current and the reading is the reader's, but its familiarity is
-- under the watch's doubt_below. It still counts as covered and is still found, marked as such.
CREATE TABLE notes (id int PRIMARY KEY, body text);
INSERT INTO notes VALUES (1, 'known'), (2, 'invented');
SELECT muninn.watch('notes', 'notes'::regclass, 'id', 'r.body', 'r1', 0.95, 0.5) > 0 AS watch;
SELECT count(muninn.record('notes', n.key, 'r1', n.text_hash,
                           CASE n.key WHEN '1' THEN 1 ELSE 2 END,
                           CASE n.key WHEN '1' THEN ARRAY[100,0,0,0] ELSE ARRAY[90,10,0,0] END::smallint[],
                           CASE n.key WHEN '1' THEN 0.9 ELSE 0.2 END::real)) AS recorded
  FROM muninn.next('notes') n;
-- control: the familiar reading is fresh; the other one, under 0.5, is doubtful
SELECT key, state FROM muninn.reading_states WHERE watch = 'notes' ORDER BY key;
SELECT state, n, share FROM muninn.coverage('notes') WHERE n > 0;
SELECT key, state FROM muninn.find('notes', 2, ARRAY[90,10,0,0]::smallint[]) ORDER BY key;
DROP TABLE notes;
-- ------------------------------------------------ dropping the table drops its watch
SELECT count(*) AS watches_before FROM muninn.watches;
DROP TABLE docs;
SELECT count(*) AS watches_after FROM muninn.watches;
DROP EXTENSION pg_muninn;
