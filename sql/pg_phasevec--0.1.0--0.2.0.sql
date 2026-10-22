-- Copyright 2026 Manuel Reyes Bravo
-- SPDX-License-Identifier: Apache-2.0

-- pg_phasevec 0.1.0 -> 0.2.0
--
-- Two things measured in F1 (yggdrasil sql/155-156), and fixed where the measurement pointed:
--
--   * find() over 1,000,000 readings took 1157 ms, and ~980 ms of it was coverage(): every
--     question recounted the seven states of every row. Coverage is now kept by triggers, so
--     asking for it costs a lookup of seven rows. Freshness is checked only for the m candidates
--     of the binary sweep, by primary key, instead of joining every reading to its source.
--   * the 64-bit sweep with m = 200 recovered 0.765 of the exact top 10 with the vec reader;
--     a 256-bit code (the signs of the first 256 dimensions, computed by the reader from its float
--     vector) recovered 0.967 in an exploratory measurement. Readings and questions may now carry
--     it, and find() sweeps it when the question does.
--
-- A cache of a count can lie cheaply, which is worse than counting slowly. So the counts are kept
-- the idempotent way -- each change recomputes what ITS key contributes, from the tables, and
-- applies the difference -- n can never go below zero, and coverage_check() compares the counts
-- with an independent recount of the tables.

\echo Use "ALTER EXTENSION pg_phasevec UPDATE TO '0.2.0'" to load this file. \quit

-- ------------------------------------------------------------- 256-bit codes --

ALTER TABLE phasevec.readings ADD COLUMN code256 bit(256);
ALTER TABLE phasevec.readings ADD CONSTRAINT a_failed_reading_has_no_code256
    CHECK (failed IS NULL OR code256 IS NULL);

-- ------------------------------------------------------------------ counting --

-- What one key contributes to its watch's coverage: at most one of the five states of a watched
-- row (none when the row is gone), its readings by other readers, and whether it is an orphan.
CREATE TABLE phasevec.kstate (
    watch     int  NOT NULL REFERENCES phasevec.watches(id) ON DELETE CASCADE,
    key       text NOT NULL,
    main      text CHECK (main IN ('fresh', 'doubtful', 'stale', 'pending', 'failed')),
    foreign_n int  NOT NULL DEFAULT 0 CHECK (foreign_n >= 0),
    orphan    boolean NOT NULL DEFAULT false,
    PRIMARY KEY (watch, key)
);

-- The seven counts of each watch. Seven rows per watch, from the moment the watch exists.
CREATE TABLE phasevec.counts (
    watch int  NOT NULL REFERENCES phasevec.watches(id) ON DELETE CASCADE,
    state text NOT NULL CHECK (state IN ('fresh', 'doubtful', 'stale', 'pending', 'failed', 'foreign', 'orphan')),
    n     bigint NOT NULL DEFAULT 0 CONSTRAINT a_count_is_never_negative CHECK (n >= 0),
    PRIMARY KEY (watch, state)
);
COMMENT ON TABLE phasevec.counts IS
    'Coverage kept by triggers. phasevec.coverage_check() compares it with a full recount of the tables.';
REVOKE ALL ON phasevec.kstate, phasevec.counts FROM PUBLIC;

-- The 0.1.0 coverage(), kept as the independent recount: it reads sources and readings directly
-- and never the counts.
CREATE FUNCTION phasevec._coverage_full(p_watch text)
RETURNS TABLE (state text, n bigint, share numeric)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    WITH w AS (SELECT * FROM phasevec._watch(p_watch)),
    per_row AS (
        SELECT CASE
                   WHEN r.key IS NULL                 THEN 'pending'
                   WHEN r.failed IS NOT NULL          THEN 'failed'
                   WHEN r.text_hash <> s.text_hash    THEN 'stale'
                   WHEN w.doubt_below IS NOT NULL AND r.familiarity < w.doubt_below THEN 'doubtful'
                   ELSE 'fresh'
               END AS state
          FROM w JOIN phasevec.sources s ON s.watch = w.id
          LEFT JOIN phasevec.readings r ON r.watch = s.watch AND r.key = s.key AND r.reader = w.reader
        UNION ALL
        SELECT 'foreign' FROM w JOIN phasevec.readings r ON r.watch = w.id AND r.reader <> w.reader
        UNION ALL
        SELECT 'orphan' FROM w JOIN phasevec.readings r ON r.watch = w.id AND r.reader = w.reader
         WHERE NOT EXISTS (SELECT 1 FROM phasevec.sources s WHERE s.watch = r.watch AND s.key = r.key)
    ),
    total AS (SELECT count(*) AS t FROM w JOIN phasevec.sources s ON s.watch = w.id)
    SELECT st.state, count(p.state),
           CASE WHEN (SELECT t FROM total) = 0 OR st.state IN ('foreign', 'orphan') THEN NULL
                ELSE round(count(p.state)::numeric / (SELECT t FROM total), 4) END
      FROM unnest(ARRAY['fresh','doubtful','stale','pending','failed','foreign','orphan']) WITH ORDINALITY st(state, o)
      LEFT JOIN per_row p ON p.state = st.state
     GROUP BY st.state, st.o
     ORDER BY st.o;
$$;

-- Recompute what (watch, key) contributes, from the tables, and apply the difference to the counts.
-- Idempotent: calling it twice changes nothing, and a later change of the same key repairs any
-- earlier miss.
CREATE FUNCTION phasevec._refresh(p_watch int, p_key text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    new_main text; new_foreign int; new_orphan boolean;
    old_main text; old_foreign int := 0; old_orphan boolean := false;
BEGIN
    SELECT CASE WHEN s.key IS NULL                 THEN NULL
                WHEN r.key IS NULL                 THEN 'pending'
                WHEN r.failed IS NOT NULL          THEN 'failed'
                WHEN r.text_hash <> s.text_hash    THEN 'stale'
                WHEN w.doubt_below IS NOT NULL AND r.familiarity < w.doubt_below THEN 'doubtful'
                ELSE 'fresh' END,
           (SELECT count(*) FROM phasevec.readings o
             WHERE o.watch = w.id AND o.key = p_key AND o.reader <> w.reader)::int,
           s.key IS NULL AND r.key IS NOT NULL
      INTO new_main, new_foreign, new_orphan
      FROM phasevec.watches w
      LEFT JOIN phasevec.sources s ON s.watch = w.id AND s.key = p_key
      LEFT JOIN phasevec.readings r ON r.watch = w.id AND r.key = p_key AND r.reader = w.reader
     WHERE w.id = p_watch;
    IF NOT FOUND THEN
        RETURN;  -- the watch is being dropped; its counts go with it
    END IF;

    SELECT k.main, k.foreign_n, k.orphan INTO old_main, old_foreign, old_orphan
      FROM phasevec.kstate k WHERE k.watch = p_watch AND k.key = p_key
       FOR UPDATE;
    IF NOT FOUND THEN
        old_main := NULL; old_foreign := 0; old_orphan := false;
    END IF;
    IF old_main IS NOT DISTINCT FROM new_main AND old_foreign = new_foreign AND old_orphan = new_orphan THEN
        RETURN;
    END IF;

    UPDATE phasevec.counts c
       SET n = c.n + d.delta
      FROM (SELECT x.state, sum(x.delta)::bigint AS delta
              FROM (VALUES (old_main, -1), (new_main, 1),
                           ('foreign', new_foreign - old_foreign),
                           ('orphan', new_orphan::int - old_orphan::int)) x(state, delta)
             WHERE x.state IS NOT NULL
             GROUP BY x.state) d
     WHERE c.watch = p_watch AND c.state = d.state AND d.delta <> 0;

    IF new_main IS NULL AND new_foreign = 0 AND NOT new_orphan THEN
        DELETE FROM phasevec.kstate WHERE watch = p_watch AND key = p_key;
    ELSE
        INSERT INTO phasevec.kstate AS k (watch, key, main, foreign_n, orphan)
        VALUES (p_watch, p_key, new_main, new_foreign, new_orphan)
        ON CONFLICT (watch, key) DO UPDATE
           SET main = EXCLUDED.main, foreign_n = EXCLUDED.foreign_n, orphan = EXCLUDED.orphan;
    END IF;
END;
$$;

-- One AFTER trigger per table, for every way a row of sources or readings changes: inserts, upserts
-- (which fire BEFORE INSERT and then BEFORE/AFTER UPDATE, so a before/after pair would subtract
-- twice), updates, deletes and the cascades of a dropped watch.
CREATE FUNCTION phasevec._counted()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF TG_OP IN ('UPDATE', 'DELETE') THEN
        PERFORM phasevec._refresh(OLD.watch, OLD.key);
    END IF;
    IF TG_OP = 'INSERT' OR (TG_OP = 'UPDATE' AND (NEW.watch, NEW.key) IS DISTINCT FROM (OLD.watch, OLD.key)) THEN
        PERFORM phasevec._refresh(NEW.watch, NEW.key);
    END IF;
    RETURN NULL;
END;
$$;
CREATE TRIGGER phasevec_counted AFTER INSERT OR UPDATE OR DELETE ON phasevec.sources
    FOR EACH ROW EXECUTE FUNCTION phasevec._counted();
CREATE TRIGGER phasevec_counted AFTER INSERT OR UPDATE OR DELETE ON phasevec.readings
    FOR EACH ROW EXECUTE FUNCTION phasevec._counted();

-- Everything of one watch, recounted at once: when the watch is created, and when its reader or its
-- doubt_below change (every key's state can change then).
CREATE FUNCTION phasevec._recount(p_watch int)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    DELETE FROM phasevec.kstate WHERE watch = p_watch;
    INSERT INTO phasevec.kstate (watch, key, main, foreign_n, orphan)
    SELECT w.id, k.key,
           CASE WHEN s.key IS NULL                 THEN NULL
                WHEN r.key IS NULL                 THEN 'pending'
                WHEN r.failed IS NOT NULL          THEN 'failed'
                WHEN r.text_hash <> s.text_hash    THEN 'stale'
                WHEN w.doubt_below IS NOT NULL AND r.familiarity < w.doubt_below THEN 'doubtful'
                ELSE 'fresh' END,
           coalesce(f.n, 0),
           s.key IS NULL AND r.key IS NOT NULL
      FROM phasevec.watches w
      JOIN (SELECT key FROM phasevec.sources WHERE watch = p_watch
            UNION SELECT key FROM phasevec.readings WHERE watch = p_watch) k ON true
      LEFT JOIN phasevec.sources s ON s.watch = w.id AND s.key = k.key
      LEFT JOIN phasevec.readings r ON r.watch = w.id AND r.key = k.key AND r.reader = w.reader
      LEFT JOIN (SELECT o.key, count(*)::int AS n FROM phasevec.readings o JOIN phasevec.watches ww ON ww.id = o.watch
                  WHERE o.watch = p_watch AND o.reader <> ww.reader GROUP BY o.key) f ON f.key = k.key
     WHERE w.id = p_watch;

    INSERT INTO phasevec.counts (watch, state, n)
    SELECT p_watch, st.state,
           CASE st.state WHEN 'foreign' THEN (SELECT coalesce(sum(foreign_n), 0) FROM phasevec.kstate WHERE watch = p_watch)
                         WHEN 'orphan'  THEN (SELECT count(*) FROM phasevec.kstate WHERE watch = p_watch AND orphan)
                         ELSE (SELECT count(*) FROM phasevec.kstate WHERE watch = p_watch AND main = st.state) END
      FROM unnest(ARRAY['fresh','doubtful','stale','pending','failed','foreign','orphan']) st(state)
    ON CONFLICT (watch, state) DO UPDATE SET n = EXCLUDED.n;
END;
$$;

CREATE FUNCTION phasevec._watch_changed()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    PERFORM phasevec._recount(NEW.id);
    RETURN NULL;
END;
$$;
-- A new watch gets its seven counts before its first source is noted.
CREATE TRIGGER phasevec_watch_counted AFTER INSERT ON phasevec.watches
    FOR EACH ROW EXECUTE FUNCTION phasevec._watch_changed();
CREATE TRIGGER phasevec_watch_recounted AFTER UPDATE OF reader, doubt_below ON phasevec.watches
    FOR EACH ROW EXECUTE FUNCTION phasevec._watch_changed();

-- Same answer as 0.1.0, from the counts.
CREATE OR REPLACE FUNCTION phasevec.coverage(p_watch text)
RETURNS TABLE (state text, n bigint, share numeric)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    WITH w AS (SELECT * FROM phasevec._watch(p_watch)),
    c AS (SELECT c.state, c.n FROM phasevec.counts c, w WHERE c.watch = w.id),
    total AS (SELECT coalesce(sum(n), 0) AS t FROM c WHERE state NOT IN ('foreign', 'orphan'))
    SELECT st.state, coalesce(c.n, 0),
           CASE WHEN (SELECT t FROM total) = 0 OR st.state IN ('foreign', 'orphan') THEN NULL
                ELSE round(coalesce(c.n, 0)::numeric / (SELECT t FROM total), 4) END
      FROM unnest(ARRAY['fresh','doubtful','stale','pending','failed','foreign','orphan']) WITH ORDINALITY st(state, o)
      LEFT JOIN c ON c.state = st.state
     ORDER BY st.o;
$$;

-- The invariant: the counts the triggers keep against a full recount of the tables. Returns the
-- states where they differ; no row means they agree.
CREATE FUNCTION phasevec.coverage_check(p_watch text)
RETURNS TABLE (state text, counted bigint, recounted bigint)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT f.state, c.n, f.n
      FROM phasevec._coverage_full(p_watch) f
      JOIN phasevec.coverage(p_watch) c USING (state)
     WHERE c.n IS DISTINCT FROM f.n;
$$;

-- Every watch that existed before 0.2.0 gets its counts now.
DO $$
DECLARE
    wid int;
BEGIN
    FOR wid IN SELECT id FROM phasevec.watches LOOP
        PERFORM phasevec._recount(wid);
    END LOOP;
END $$;

-- ----------------------------------------------------------------- recording --

DROP FUNCTION phasevec.record(text, text, text, bytea, bigint, smallint[], real);
CREATE FUNCTION phasevec.record(p_watch text, p_key text, p_reader text, p_text_hash bytea,
                              p_code64 bigint, p_code smallint[], p_familiarity real DEFAULT NULL,
                              p_code256 bit(256) DEFAULT NULL)
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
    INSERT INTO phasevec.readings AS r (watch, key, reader, text_hash, code64, code, code256, familiarity, failed, read_at)
    VALUES (w.id, p_key, rd.id, p_text_hash, p_code64, p_code, p_code256, p_familiarity, NULL, clock_timestamp())
    ON CONFLICT (watch, key, reader) DO UPDATE
       SET text_hash = EXCLUDED.text_hash, code64 = EXCLUDED.code64, code = EXCLUDED.code,
           code256 = EXCLUDED.code256, familiarity = EXCLUDED.familiarity, failed = NULL,
           read_at = EXCLUDED.read_at;
END;
$$;

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
           failed = EXCLUDED.failed, read_at = EXCLUDED.read_at;
END;
$$;

-- -------------------------------------------------------------------- asking --

DROP FUNCTION phasevec.alike(text, text, int, boolean);
DROP FUNCTION phasevec.find(text, bigint, smallint[], int, boolean, int);

-- The binary sweep reads only readings (the 256-bit code when the question carries one, the 64-bit
-- one otherwise), keeps the m nearest by Hamming distance, and only THEN checks those m against
-- their sources: a candidate whose text changed is dropped, never reranked, never served.
CREATE FUNCTION phasevec.find(p_watch text, p_q64 bigint, p_q smallint[], p_k int DEFAULT 10,
                            p_partial boolean DEFAULT false, p_m int DEFAULT 200,
                            p_q256 bit(256) DEFAULT NULL)
RETURNS TABLE (key text, score double precision, hamming int, state text, familiarity real, read_at timestamptz)
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
        SELECT r.key, r.text_hash, r.code, r.familiarity, r.read_at,
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
           c.familiarity, c.read_at
      FROM cand c
     ORDER BY 2 DESC NULLS LAST, c.key
     LIMIT p_k;
END;
$$;

-- Rows like a given row: its own fresh reading is the question, 256-bit code included when it has one.
CREATE FUNCTION phasevec.alike(p_watch text, p_key text, p_k int DEFAULT 10, p_partial boolean DEFAULT false)
RETURNS TABLE (key text, score double precision, hamming int, state text, familiarity real, read_at timestamptz)
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

-- ---------------------------------------------------------------- privileges --
REVOKE ALL ON FUNCTION phasevec._coverage_full(text), phasevec._refresh(int, text), phasevec._counted(),
    phasevec._recount(int), phasevec._watch_changed(), phasevec.coverage_check(text),
    phasevec.record(text, text, text, bytea, bigint, smallint[], real, bit),
    phasevec.record_failure(text, text, text, bytea, text),
    phasevec.find(text, bigint, smallint[], int, boolean, int, bit), phasevec.alike(text, text, int, boolean)
  FROM PUBLIC;
