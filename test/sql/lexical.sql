-- 0.6.0: a watch read by its words too, in the same transaction as its text; find_hybrid() asks both.
\set VERBOSITY terse

CREATE EXTENSION pg_phasevec VERSION '0.5.0';
SELECT phasevec.reader_register('t1', repeat('a', 64), 4) > 0 AS t1;
CREATE TABLE docs (id int PRIMARY KEY, body text);
INSERT INTO docs VALUES
    (1, 'nbtree treats heap TID as a tiebreaker column'),
    (2, 'fix memory alignment in pg_mcv_list serialization'),
    (3, 'the planner chooses a merge append plan'),
    (4, 'vacuum cost delay is fractional since twelve'),
    (5, 'nbtree deduplication of posting lists');
-- forty rows of common words, so that the rare ones are rare
INSERT INTO docs SELECT g, 'common filler words in row ' || g FROM generate_series(10, 49) g;
SELECT phasevec.watch('docs', 'docs'::regclass, 'id', 'r.body', 't1') > 0 AS watch;
ALTER EXTENSION pg_phasevec UPDATE TO '0.6.0';
SELECT extversion FROM pg_extension WHERE extname = 'pg_phasevec';

-- every row read; the vector of row k points at k, so the vector arm alone prefers 49, 48, ...
SELECT count(phasevec.record('docs', n.key, 't1', n.text_hash, n.key::bigint,
                           ARRAY[n.key::int, 1, 0, 0]::smallint[], NULL, NULL, 5, 5))
  FROM phasevec.next('docs', 100) n;

-- not read lexically: find_hybrid refuses, it does not answer with the vector alone
SELECT * FROM phasevec.find_hybrid('docs', 'heap tiebreaker', 1, ARRAY[100, 1, 0, 0]::smallint[]);
SELECT phasevec.lexical_maintain('docs') AS maintained;

SELECT phasevec.lexical('docs', 'english') AS read_lexically;
SELECT n, round(avg_n::numeric, 2) AS avg_n FROM phasevec.lexdocs;
SELECT lexeme, ndoc FROM phasevec.lexstats WHERE lexeme IN ('nbtree', 'mcv', 'tiebreak', 'common') ORDER BY 1;
SELECT count(*) AS without_lexemes FROM phasevec.sources WHERE lexemes IS NULL;

-- the question's vector points at row 49 (m covers every row, so the vector arm is exact): the vector
-- arm alone ranks 49, 48, 47; the rare words bring row 1 into the top, and each hit says which arm
-- brought it, and where
SELECT key, round(score::numeric, 5) AS score, vector_rank, lexical_rank, state
  FROM phasevec.find_hybrid('docs', 'what made heap TID a tiebreaker in nbtree?', 49, ARRAY[100, 1, 0, 0]::smallint[], 4, false, 100, NULL, 4);
-- k = m + lm: every candidate of both arms, each with its ranks (vector top 3 and lexical top 2 here)
SELECT key, vector_rank, lexical_rank
  FROM phasevec.find_hybrid('docs', 'what made heap TID a tiebreaker in nbtree?', 49, ARRAY[100, 1, 0, 0]::smallint[], 5, false, 3, NULL, 2)
 ORDER BY vector_rank NULLS LAST, lexical_rank;
-- a question made only of common words has no lexical arm: the vector ranking alone
SELECT key, vector_rank, lexical_rank
  FROM phasevec.find_hybrid('docs', 'common filler words', 49, ARRAY[100, 1, 0, 0]::smallint[], 3, false, 100, NULL, 3);

-- the text changes: in the same transaction its lexical reading is the new one, and its vector
-- reading is stale, so neither arm serves the row
BEGIN;
UPDATE docs SET body = 'nbtree heap tiebreaker rewritten' WHERE id = 5;
SELECT lexemes @@ phasevec._term('rewritten') AS new_words_now FROM phasevec.sources WHERE key = '5';
SELECT key, lexical_rank FROM phasevec.find_hybrid('docs', 'heap tiebreaker nbtree rewritten', 49, ARRAY[100, 1, 0, 0]::smallint[], 5, true, 100, NULL, 5)
 WHERE key IN ('1', '5') ORDER BY key;
COMMIT;
-- the weights follow when the reader's queue empties
SELECT phasevec.lexical_maintain('docs') AS maintained;
SELECT phasevec.lexical_maintain('docs') AS maintained_again;
SELECT ndoc FROM phasevec.lexstats WHERE lexeme = 'rewritten';

-- a row without its lexical reading: refused unless partial
UPDATE phasevec.sources SET lexemes = NULL, lexeme_n = NULL WHERE key = '3';
SELECT count(*) FROM phasevec.find_hybrid('docs', 'merge append', 1, ARRAY[1, 1, 0, 0]::smallint[]);
SELECT count(*) > 0 AS partial_answers FROM phasevec.find_hybrid('docs', 'merge append', 1, ARRAY[1, 1, 0, 0]::smallint[], 10, true);
SELECT phasevec.lexical('docs', 'english') AS read_again;
SELECT key, lexical_rank FROM phasevec.find_hybrid('docs', 'merge append planner', 49, ARRAY[100, 1, 0, 0]::smallint[], 3, false, 100, NULL, 3)
 WHERE lexical_rank IS NOT NULL;

-- a text far longer than a tsvector holds is still written; its lexical reading is of its head
INSERT INTO docs VALUES (60, 'needle ' || repeat('hay ', 200000) || 'tailword');
SELECT lexemes @@ phasevec._term('needl') AS head_read, lexemes @@ phasevec._term('tailword') AS tail_read
  FROM phasevec.sources WHERE key = '60';

-- lexemes with quotes and backslashes are terms, not syntax
SELECT phasevec._term($$o'k\x$$) AS term;
SELECT to_tsvector('simple', $$o'k\x$$) @@ phasevec._term('o') AS quoted;

-- only a trigger notes a row
SELECT phasevec._note(1, '1', '\x00'::bytea, 'forged');

-- the counts still agree with a recount
SELECT count(*) AS mismatches FROM phasevec.coverage_check('docs');

-- reading lexically can stop
SELECT phasevec.lexical('docs', NULL) AS stopped;
SELECT count(*) AS with_lexemes FROM phasevec.sources WHERE lexemes IS NOT NULL;
SELECT * FROM phasevec.find_hybrid('docs', 'nbtree', 1, ARRAY[1, 1, 0, 0]::smallint[]);

DROP TABLE docs;
DROP EXTENSION pg_phasevec;
