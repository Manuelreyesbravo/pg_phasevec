-- pg_phasevec 0.4.0 -> 0.5.0: a reading says when the reader saw only part of the text.
--
-- A reader has a context of so many tokens. A row longer than that was read from its beginning only,
-- and until 0.5.0 that reading was recorded fresh like any other: what the reader understood of the
-- row was a prefix, and nothing said so. That is a provenance gap, not a detail. A reading now
-- carries how many tokens of its text the reader read and how many the text has; when the first is
-- smaller, the reading is truncated, and find, alike and truncations() say it.
--
-- Readings recorded before 0.5.0 have neither count (NULL): unknown, not "complete".

\echo Use "ALTER EXTENSION pg_phasevec UPDATE TO '0.5.0'" to load this file. \quit

ALTER TABLE phasevec.readings
    ADD COLUMN tokens_read  int,
    ADD COLUMN tokens_total int,
    ADD CONSTRAINT readings_token_counts CHECK (
        (tokens_read IS NULL) = (tokens_total IS NULL)
        AND (tokens_read IS NULL OR (tokens_read >= 1 AND tokens_read <= tokens_total))),
    ADD COLUMN truncated boolean GENERATED ALWAYS AS (tokens_read < tokens_total) STORED;
COMMENT ON COLUMN phasevec.readings.truncated IS
    'The reader read only the first tokens_read of tokens_total tokens of the text: it understood a prefix. NULL when the counts are unknown (recorded before 0.5.0).';

-- ----------------------------------------------------------------- recording --

DROP FUNCTION phasevec.record(text, text, text, bytea, bigint, smallint[], real, bit);
CREATE FUNCTION phasevec.record(p_watch text, p_key text, p_reader text, p_text_hash bytea,
                              p_code64 bigint, p_code smallint[], p_familiarity real DEFAULT NULL,
                              p_code256 bit(256) DEFAULT NULL,
                              p_tokens_read int DEFAULT NULL, p_tokens_total int DEFAULT NULL)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    w   phasevec.watches := phasevec._watch(p_watch);
    rd  phasevec.readers;
    cur bytea;
BEGIN
    SELECT * INTO rd FROM phasevec.readers WHERE name = p_reader;
    IF NOT FOUND OR rd.id <> w.reader THEN
        RAISE EXCEPTION 'phasevec: watch % is read by reader #%, not by %', p_watch, w.reader, p_reader
            USING HINT = 'Readings by different readers are never mixed.';
    END IF;
    SELECT s.text_hash INTO cur FROM phasevec.sources s WHERE s.watch = w.id AND s.key = p_key;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'phasevec: watch % has no row %', p_watch, p_key;
    END IF;
    IF cur IS DISTINCT FROM p_text_hash THEN
        RAISE EXCEPTION 'phasevec: row % of watch % changed since it was handed out; this reading would be stale', p_key, p_watch;
    END IF;
    IF p_code64 IS NULL OR p_code IS NULL OR cardinality(p_code) <> rd.dims THEN
        RAISE EXCEPTION 'phasevec: reader % produces % dimensions, got %', p_reader, rd.dims, cardinality(p_code);
    END IF;
    IF EXISTS (SELECT 1 FROM unnest(p_code) x WHERE x NOT BETWEEN -128 AND 127) THEN
        RAISE EXCEPTION 'phasevec: codes are int8, every value in -128..127';
    END IF;
    IF p_code256 IS NOT NULL AND rd.dims < 256 THEN
        RAISE EXCEPTION 'phasevec: reader % has % dimensions; a 256-bit code needs at least 256', p_reader, rd.dims;
    END IF;
    IF (p_tokens_read IS NULL) <> (p_tokens_total IS NULL)
       OR p_tokens_read < 1 OR p_tokens_read > p_tokens_total THEN
        RAISE EXCEPTION 'phasevec: a reading counts the tokens it read and the tokens its text has, both or neither (read %, total %)',
            p_tokens_read, p_tokens_total;
    END IF;
    INSERT INTO phasevec.readings AS r (watch, key, reader, text_hash, code64, code, code256, familiarity, failed,
                                      tokens_read, tokens_total, read_at)
    VALUES (w.id, p_key, rd.id, p_text_hash, p_code64, p_code, p_code256, p_familiarity, NULL,
            p_tokens_read, p_tokens_total, clock_timestamp())
    ON CONFLICT (watch, key, reader) DO UPDATE
       SET text_hash = EXCLUDED.text_hash, code64 = EXCLUDED.code64, code = EXCLUDED.code,
           code256 = EXCLUDED.code256, familiarity = EXCLUDED.familiarity, failed = NULL,
           tokens_read = EXCLUDED.tokens_read, tokens_total = EXCLUDED.tokens_total,
           read_at = EXCLUDED.read_at;
END;
$$;

-- A failed reading read nothing: its counts go with its code.
CREATE OR REPLACE FUNCTION phasevec.record_failure(p_watch text, p_key text, p_reader text, p_text_hash bytea, p_reason text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    w  phasevec.watches := phasevec._watch(p_watch);
    rd phasevec.readers;
BEGIN
    SELECT * INTO rd FROM phasevec.readers WHERE name = p_reader;
    IF NOT FOUND OR rd.id <> w.reader THEN
        RAISE EXCEPTION 'phasevec: watch % is read by reader #%, not by %', p_watch, w.reader, p_reader;
    END IF;
    IF coalesce(p_reason, '') = '' THEN
        RAISE EXCEPTION 'phasevec: a failed reading says why';
    END IF;
    INSERT INTO phasevec.readings AS r (watch, key, reader, text_hash, failed, read_at)
    VALUES (w.id, p_key, rd.id, p_text_hash, p_reason, clock_timestamp())
    ON CONFLICT (watch, key, reader) DO UPDATE
       SET text_hash = EXCLUDED.text_hash, code64 = NULL, code = NULL, code256 = NULL, familiarity = NULL,
           tokens_read = NULL, tokens_total = NULL, failed = EXCLUDED.failed, read_at = EXCLUDED.read_at;
END;
$$;

-- -------------------------------------------------------------------- asking --

DROP FUNCTION phasevec.alike(text, text, int, boolean);
DROP FUNCTION phasevec.find(text, bigint, smallint[], int, boolean, int, bit);

-- As in 0.2.0, plus whether each answer was read whole: a truncated reading is still served (it is
-- of the current text), but it says that the reader saw only the beginning.
CREATE FUNCTION phasevec.find(p_watch text, p_q64 bigint, p_q smallint[], p_k int DEFAULT 10,
                            p_partial boolean DEFAULT false, p_m int DEFAULT 200,
                            p_q256 bit(256) DEFAULT NULL)
RETURNS TABLE (key text, score double precision, hamming int, state text, familiarity real, read_at timestamptz,
               truncated boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    w      phasevec.watches := phasevec._watch(p_watch);
    dims   int;
    fresh  numeric;
    missing text;
    qnorm  double precision;
BEGIN
    SELECT rd.dims INTO dims FROM phasevec.readers rd WHERE rd.id = w.reader;
    IF p_q IS NULL OR cardinality(p_q) <> dims THEN
        RAISE EXCEPTION 'phasevec: the question must be read by the watch''s reader (% dimensions)', dims;
    END IF;
    IF p_k NOT BETWEEN 1 AND 1000 OR p_m NOT BETWEEN p_k AND 100000 THEN
        RAISE EXCEPTION 'phasevec: k must be in 1..1000 and m in k..100000';
    END IF;

    SELECT coalesce(sum(c.share) FILTER (WHERE c.state IN ('fresh', 'doubtful')), 0),
           string_agg(format('%s %s%%', c.state, round(c.share * 100, 1)), ', ')
               FILTER (WHERE c.state IN ('stale', 'pending', 'failed') AND c.n > 0)
      INTO fresh, missing
      FROM phasevec.coverage(p_watch) c;
    IF fresh < w.min_coverage AND NOT p_partial THEN
        RAISE EXCEPTION '%', format('phasevec: watch %s covers %s%% of its rows and declared %s%%: %s',
            p_watch, round(fresh * 100, 1), round(w.min_coverage * 100, 1), coalesce(missing, 'nothing read yet'))
            USING HINT = 'Answering from what happens to be read would look like a full answer. Pass p_partial => true to accept it knowingly.';
    END IF;

    SELECT sqrt(sum(x::float8 * x)) INTO qnorm FROM unnest(p_q) x;

    RETURN QUERY
    WITH sweep AS (
        SELECT r.key, r.text_hash, r.code, r.familiarity, r.read_at, r.truncated,
               CASE WHEN p_q256 IS NOT NULL THEN bit_count(r.code256 # p_q256)
                    ELSE bit_count((r.code64 # p_q64)::bit(64)) END::int AS ham
          FROM phasevec.readings r
         WHERE r.watch = w.id AND r.reader = w.reader AND r.failed IS NULL
           AND (p_q256 IS NULL OR r.code256 IS NOT NULL)
         ORDER BY ham, r.key
         LIMIT p_m
    ), cand AS (
        SELECT sw.* FROM sweep sw
          JOIN phasevec.sources s ON s.watch = w.id AND s.key = sw.key AND s.text_hash = sw.text_hash
    )
    SELECT c.key,
           (SELECT sum(a::float8 * b) FROM unnest(c.code, p_q) t(a, b))
             / nullif((SELECT sqrt(sum(a::float8 * a)) FROM unnest(c.code) a) * qnorm, 0),
           c.ham,
           CASE WHEN w.doubt_below IS NOT NULL AND c.familiarity < w.doubt_below THEN 'doubtful' ELSE 'fresh' END,
           c.familiarity, c.read_at, c.truncated
      FROM cand c
     ORDER BY 2 DESC NULLS LAST, c.key
     LIMIT p_k;
END;
$$;

CREATE FUNCTION phasevec.alike(p_watch text, p_key text, p_k int DEFAULT 10, p_partial boolean DEFAULT false)
RETURNS TABLE (key text, score double precision, hamming int, state text, familiarity real, read_at timestamptz,
               truncated boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    w    phasevec.watches := phasevec._watch(p_watch);
    q64  bigint;
    q    smallint[];
    q256 bit(256);
BEGIN
    SELECT r.code64, r.code, r.code256 INTO q64, q, q256
      FROM phasevec.readings r JOIN phasevec.sources s ON s.watch = r.watch AND s.key = r.key
     WHERE r.watch = w.id AND r.key = p_key AND r.reader = w.reader
       AND r.failed IS NULL AND r.text_hash = s.text_hash;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'phasevec: row % of watch % has no fresh reading to ask with', p_key, p_watch;
    END IF;
    RETURN QUERY SELECT f.* FROM phasevec.find(p_watch, q64, q, p_k + 1, p_partial, 200, q256) f
                  WHERE f.key <> p_key LIMIT p_k;
END;
$$;

-- The rows of a watch its reader understood only in part, by the current reader and of the current
-- text: how much of each it read.
CREATE FUNCTION phasevec.truncations(p_watch text)
RETURNS TABLE (key text, tokens_read int, tokens_total int)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT r.key, r.tokens_read, r.tokens_total
      FROM phasevec._watch(p_watch) w
      JOIN phasevec.readings r ON r.watch = w.id AND r.reader = w.reader
      JOIN phasevec.sources s ON s.watch = r.watch AND s.key = r.key AND s.text_hash = r.text_hash
     WHERE r.truncated
     ORDER BY r.key;
$$;

-- ---------------------------------------------------------------- privileges --
-- record, find and alike were recreated: grants made on the 0.4.0 functions are gone and must be
-- made again by the DBA.
REVOKE ALL ON FUNCTION phasevec.record(text, text, text, bytea, bigint, smallint[], real, bit, int, int),
    phasevec.find(text, bigint, smallint[], int, boolean, int, bit), phasevec.alike(text, text, int, boolean),
    phasevec.truncations(text)
  FROM PUBLIC;
