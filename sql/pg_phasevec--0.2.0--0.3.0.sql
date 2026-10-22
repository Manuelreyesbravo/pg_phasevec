-- Copyright 2026 Manuel Reyes Bravo
-- SPDX-License-Identifier: Apache-2.0

-- pg_phasevec 0.2.0 -> 0.3.0: the reader runs on its own, supervised, and audits itself
--
--   * the queue a reader drains is computed from the tables, never from NOTIFY: _todo() now reads
--     what each key is (phasevec.kstate, kept by the 0.2.0 triggers) through an index, so a reader
--     polling every 30 s does not join every source to every reading;
--   * a reader re-reads a sample of its own fresh readings and records what it found; a reading
--     that does not reproduce is a broken assertion, kept, not discovered months later;
--   * dupes(): pairs of fresh readings of one watch whose codes are this close.

\echo Use "ALTER EXTENSION pg_phasevec UPDATE TO '0.3.0'" to load this file. \quit

-- ------------------------------------------------------------------ the queue --

CREATE INDEX kstate_to_read ON phasevec.kstate (watch) WHERE main IN ('pending', 'stale', 'failed');

-- What the watch's reader still has to read: never read, or read from older text -- a failed
-- reading of older text included, exactly as 0.1.0 handed it out (kstate keeps such a row as
-- 'failed', because failed outranks stale). Readings by another reader leave the row pending for
-- the current one, so they are in here too.
CREATE OR REPLACE FUNCTION phasevec._todo(p_watch text, p_limit int)
RETURNS TABLE (key text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT k.key
      FROM phasevec._watch(p_watch) w
      JOIN phasevec.kstate k ON k.watch = w.id AND k.main IN ('pending', 'stale', 'failed')
      JOIN phasevec.sources s ON s.watch = k.watch AND s.key = k.key
      LEFT JOIN phasevec.readings r ON r.watch = k.watch AND r.key = k.key AND r.reader = w.reader
     WHERE k.main IN ('pending', 'stale') OR r.text_hash IS DISTINCT FROM s.text_hash
     ORDER BY s.changed_at
     LIMIT p_limit;
$$;

-- ----------------------------------------------------------------- the audits --

CREATE TABLE phasevec.audits (
    id          bigserial PRIMARY KEY,
    watch       int  NOT NULL REFERENCES phasevec.watches(id) ON DELETE CASCADE,
    key         text NOT NULL,
    reader      int  NOT NULL REFERENCES phasevec.readers(id),
    text_hash   bytea NOT NULL,
    same_code256 boolean,
    cosine      double precision,
    holds       boolean NOT NULL,
    audited_at  timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp()
);
COMMENT ON TABLE phasevec.audits IS
    'A reader re-reading its own fresh readings. holds = false is a broken assertion: the same sealed reader, the same text, another answer.';
REVOKE ALL ON phasevec.audits FROM PUBLIC;

-- A sample of fresh readings to re-read: the text as it is NOW, so a row that changed since is not
-- in the sample (it is stale, not a reading to audit).
CREATE FUNCTION phasevec.audit_sample(p_watch text, p_n int)
RETURNS TABLE (key text, body text, text_hash bytea, code smallint[], code256 bit(256))
LANGUAGE plpgsql STABLE
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    w phasevec.watches := phasevec._watch(p_watch);
BEGIN
    RETURN QUERY EXECUTE format(
        -- the recipe is an expression over the source row aliased r, as everywhere else
        'SELECT rd.key, (%2$s)::text, rd.text_hash, rd.code, rd.code256
           FROM phasevec.readings rd
           JOIN phasevec.kstate k ON k.watch = rd.watch AND k.key = rd.key AND k.main IN (''fresh'', ''doubtful'')
           JOIN %3$s r ON r.%1$I::text = rd.key
          WHERE rd.watch = $1 AND rd.reader = $2 AND rd.failed IS NULL
          ORDER BY md5(rd.key || $3) LIMIT $4', w.key_col, w.recipe, w.source)
    USING w.id, w.reader, clock_timestamp()::text, p_n;
END;
$$;

CREATE FUNCTION phasevec.record_audit(p_watch text, p_key text, p_reader text, p_text_hash bytea,
                                    p_code smallint[], p_code256 bit(256))
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    w   phasevec.watches := phasevec._watch(p_watch);
    rd  phasevec.readers;
    r   phasevec.readings;
    cos double precision;
    same boolean;
    ok  boolean;
BEGIN
    SELECT * INTO rd FROM phasevec.readers WHERE name = p_reader;
    IF NOT FOUND OR rd.id <> w.reader THEN
        RAISE EXCEPTION 'phasevec: watch % is read by reader #%, not by %', p_watch, w.reader, p_reader;
    END IF;
    SELECT * INTO r FROM phasevec.readings x WHERE x.watch = w.id AND x.key = p_key AND x.reader = rd.id;
    IF NOT FOUND OR r.failed IS NOT NULL OR r.text_hash IS DISTINCT FROM p_text_hash THEN
        RETURN NULL;  -- nothing to audit: the row changed or has no reading of this text
    END IF;
    SELECT sum(a::float8 * b) / nullif(sqrt(sum(a::float8 * a)) * sqrt(sum(b::float8 * b)), 0)
      INTO cos FROM unnest(r.code, p_code) t(a, b);
    same := r.code256 IS NOT DISTINCT FROM p_code256;
    ok := same AND cos >= 0.999;
    INSERT INTO phasevec.audits (watch, key, reader, text_hash, same_code256, cosine, holds)
    VALUES (w.id, p_key, rd.id, p_text_hash, same, cos, ok);
    RETURN ok;
END;
$$;

-- --------------------------------------------------------------------- dupes --

-- Pairs of fresh readings of one watch whose full codes are at least this similar. Exact: every
-- pair is compared, so it is for curating a watch, not for every question.
CREATE FUNCTION phasevec.dupes(p_watch text, p_threshold double precision DEFAULT 0.98)
RETURNS TABLE (key_a text, key_b text, cosine double precision)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    WITH w AS (SELECT * FROM phasevec._watch(p_watch)),
    f AS (SELECT r.key, r.code, sqrt((SELECT sum(x::float8 * x) FROM unnest(r.code) x)) AS norm
            FROM w JOIN phasevec.readings r ON r.watch = w.id AND r.reader = w.reader AND r.failed IS NULL
            JOIN phasevec.kstate k ON k.watch = r.watch AND k.key = r.key AND k.main IN ('fresh', 'doubtful'))
    SELECT a.key, b.key, c.cos
      FROM f a JOIN f b ON a.key < b.key
     CROSS JOIN LATERAL (SELECT sum(x::float8 * y) / nullif(a.norm * b.norm, 0) AS cos
                           FROM unnest(a.code, b.code) t(x, y)) c
     WHERE c.cos >= p_threshold
     ORDER BY c.cos DESC, a.key, b.key;
$$;

REVOKE ALL ON FUNCTION phasevec.audit_sample(text, int), phasevec.record_audit(text, text, text, bytea, smallint[], bit),
    phasevec.dupes(text, double precision)
  FROM PUBLIC;
