-- pg_phasevec 0.17.0: a recall guard of its own. Is a watch still served the neighbours it was served
-- when its owner approved it? And the coarse index kept in memory no longer outlives its installation.
--
-- A search does not fail when it degrades: find_ivf and find keep returning k plausible rows. Until now
-- the only guard for that was pg_recall_guard, which needs pgvector's vector type; phasevec has its own
-- codes and its own searches, so nothing watched them. Now:
--
--   phasevec.recall_approve(watch, k, sample, nprobe, m,  measures recall@k now, on a fresh random
--                           via)                          sample of the watch's rows, and stores it as
--                                                         the baseline, with the sample and the path the
--                                                         watch is SERVED by: find_ivf with its m and
--                                                         nprobe, or find with its m (via NULL: find_ivf
--                                                         when the watch has a coarse index, else find)
--   phasevec.recall_check(watch)                          measures again, same sample, same path, m and
--                                                         nprobe, and says ok, degraded or critical; one row
--                                                         per watch with a baseline (all of them when
--                                                         watch is NULL)
--
-- What is measured: for each sampled row, its own codes are the question (the row itself left out of
-- both answers). What is SERVED is the stored path: find_ivf with its nprobe and m, or find with its m (ygg's
-- own mind has no coarse index and is served by find with m 1000; a corpus by find with m 200). The TRUTH is find with m = every
-- live reading of the watch: find prefilters by Hamming distance (ORDER BY ham LIMIT m) and rescores only
-- those m by cosine, so with a small m it is not exact. Measured on 31-10 (2000 rows, 256 dimensions,
-- k = 10, 200 questions): served with m = 11 against the truth with every row, 0.33; against find with the
-- same m = 11, 0.97. With the same small m on both sides the guard would only see what nprobe loses.
-- recall@k = the mean over the questions of the share of the true top-k the served top-k holds, counted by
-- score: a served row no worse than the k-th true one is a hit, so two equal codes are not a miss.
--
-- Verdicts are pg_recall_guard's own bands, so a console reads both the same: ok if current >= baseline
-- - 0.02, degraded if >= baseline - 0.10, critical below. A watch that cannot be measured (no baseline,
-- no coarse index, its reader switched, most of the sample gone) is a row with verdict
-- 'COULD NOT MEASURE: <why>', never an exception. Both searches run with p_partial = true: a watch below
-- its declared coverage is measured on what is read, not refused.
--
-- What degrades find, measured on 31-10 (rows in 10 clusters, k = 10): the watch growing under a fixed m. The
-- Hamming prefilter keeps m candidates of ever more rows: m 50 reads 1.0 at 500 rows, 0.76 at 1000, 0.61 at
-- 2000; m 200 stays 1.0. Fixed by serving with a larger m (and approving that).
-- What degrades find_ivf, measured on 31-10 (2000 rows in 20 clusters, nprobe 16, m 200):
--   * the index rebuilt with far too many lists for the nprobe it is searched with: 45 lists 1.0, 400
--     lists 0.996, 1000 lists 0.89 (critical). Rebuilding with the default number of lists gives 1.0.
--   * rows absorbed into lists trained on less data (ivf_absorb): three times the rows, 0.96 (degraded).
-- What does NOT: rows read after the build and still in the delta (it is swept row by row: 1.0 with the
-- data doubled), fewer lists (each list holds more), and lowering nprobe or m in the session (the guard
-- searches with the stored ones).
--
-- Limits, said here and not discovered later:
--   * the truth is find over every live reading: its cost grows with the rows, ~30 microseconds per row
--     per question here (2000 rows: ~60 ms a question, 12 s for the default 200). Size the sample to it.
--   * find's m is at most 100000: above 100000 live readings the truth is a Hamming-prefiltered find and
--     the guard can read better than what is served.
--   * the sample is keys: a sampled row deleted, changed without a fresh reading, or replaced, refuted or
--     expired since the approval is skipped;
--     with less than half of it left the check says COULD NOT MEASURE and asks for a new approval.
--
-- The library: a kept copy of a coarse index (per backend, and the copy shared by the cluster since 0.10.0)
-- and the kept delta were found by (database, watch, generation). DROP EXTENSION and CREATE EXTENSION start
-- the watch ids and phasevec.ivf_gen over, so on a server that had not restarted the new installation's
-- watch matched the OLD copy: find_ivf swept the old lists, every candidate failed validation, and the
-- answer came back short without a word (test/sql/ivf_reinstall.sql: 0 of 10 rows with the 0.16.0 library).
-- Found by this release's own recall test, which read 0.525 against 1.0 when it ran after the ivf test.
-- Every copy now also carries the installation it belongs to, the OID of phasevec.ivf_cents.
-- The shared copy changed format, so it lives under a new name (phasevec_ivf_cache_v2): a server that loaded
-- 0.16.0 keeps the old segment, unused, until it restarts. Restart after installing this library.
\echo Use "ALTER EXTENSION pg_phasevec UPDATE TO '0.17.0'" to load this file. \quit

CREATE TABLE phasevec.recall_baseline (
    watch       int PRIMARY KEY REFERENCES phasevec.watches(id) ON DELETE CASCADE,
    reader      int NOT NULL,
    k           int NOT NULL CHECK (k BETWEEN 1 AND 999),
    via         text NOT NULL CHECK (via IN ('find', 'find_ivf')),
    nprobe      int CHECK (nprobe BETWEEN 1 AND 100000),
    m           int NOT NULL CHECK (m BETWEEN 2 AND 100000),
    sample_keys text[] NOT NULL CHECK (cardinality(sample_keys) BETWEEN 1 AND 10000),
    recall      double precision NOT NULL CHECK (recall BETWEEN 0 AND 1),
    measured    int NOT NULL,
    approved_at timestamptz NOT NULL DEFAULT now(),
    approved_by name NOT NULL,
    CHECK (m > k),
    CHECK ((via = 'find_ivf') = (nprobe IS NOT NULL))
);
COMMENT ON TABLE phasevec.recall_baseline IS
    'The recall@k the owner approved for a watch, with the sample and the path it is served by: find with its m, or find_ivf with its m and nprobe.';
REVOKE ALL ON phasevec.recall_baseline FROM PUBLIC;

-- recall@k of what the watch serves (find with p_m, or find_ivf with p_m and p_nprobe) against find over every
-- live reading (or p_m_ref, which only the regression suite passes: it is how the suite shows that a small m on
-- the truth side lies).
CREATE FUNCTION phasevec._recall_measure(p_watch text, p_keys text[], p_k int, p_via text, p_m int, p_nprobe int,
                                         p_m_ref int DEFAULT NULL,
                                         OUT recall double precision, OUT measured int, OUT m_ref int)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    w     phasevec.watches := phasevec._watch(p_watch);
    q     record;
    kth   double precision;
    nt    int;
    hits  int;
    total numeric := 0;
BEGIN
    IF p_m_ref IS NULL THEN
        SELECT least(100000, greatest(p_k + 1, count(*)))::int INTO m_ref
          FROM phasevec.readings r WHERE r.watch = w.id AND r.reader = w.reader AND r.failed IS NULL;
    ELSE
        m_ref := p_m_ref;
    END IF;
    measured := 0;
    -- each sampled row asks with its own fresh reading, as alike does. A row replaced, refuted or expired since
    -- the approval is not asked: its replacement would come back first on BOTH sides (find and find_ivf add it
    -- outside the index, scored with the replaced row's own codes) and count as a hit the index never made.
    FOR q IN SELECT r.key, r.code64, r.code, r.code256
               FROM unnest(p_keys) WITH ORDINALITY u(key, o)
               JOIN phasevec.readings r ON r.watch = w.id AND r.key = u.key AND r.reader = w.reader
               JOIN phasevec.sources s ON s.watch = r.watch AND s.key = r.key AND s.text_hash = r.text_hash
              WHERE r.failed IS NULL AND r.code256 IS NOT NULL
                AND NOT EXISTS (SELECT 1 FROM phasevec.truth tr WHERE tr.watch = r.watch AND tr.key = r.key
                                  AND (tr.verdict IN ('replaced', 'refuted') OR tr.expires_at <= now()))
              ORDER BY u.o
    LOOP
        SELECT min(t.score), count(*) INTO kth, nt FROM (
            SELECT f.score FROM phasevec.find(p_watch, q.code64, q.code, p_k + 1, true, m_ref, q.code256) f
             WHERE f.key <> q.key AND f.score IS NOT NULL
             ORDER BY f.score DESC, f.key LIMIT p_k) t;
        CONTINUE WHEN nt = 0;
        IF p_via = 'find' THEN
            SELECT count(*) INTO hits FROM (
                SELECT f.score FROM phasevec.find(p_watch, q.code64, q.code, p_k + 1, true, p_m, q.code256) f
                 WHERE f.key <> q.key AND f.score IS NOT NULL
                 ORDER BY f.score DESC, f.key LIMIT p_k) s
             WHERE s.score >= kth - 1e-9;
        ELSE
            SELECT count(*) INTO hits FROM (
                SELECT f.score FROM phasevec.find_ivf(p_watch, q.code64, q.code, p_k + 1, true, p_m, q.code256, p_nprobe) f
                 WHERE f.key <> q.key AND f.score IS NOT NULL
                 ORDER BY f.score DESC, f.key LIMIT p_k) s
             WHERE s.score >= kth - 1e-9;
        END IF;
        total := total + least(hits, nt)::numeric / nt;
        measured := measured + 1;
    END LOOP;
    -- four decimals, as pg_recall_guard: the verdict follows from the numbers shown, not from the order a
    -- float sum happened to take
    recall := CASE WHEN measured > 0 THEN round(total / measured, 4) END;
END;
$$;
COMMENT ON FUNCTION phasevec._recall_measure(text, text[], int, text, int, int, int) IS
    'recall@k of the served path (find with m, or find_ivf with m and nprobe) against find over every live reading, asked with each sampled row''s own codes.';

CREATE FUNCTION phasevec.recall_approve(p_watch text, p_k int DEFAULT 10, p_sample int DEFAULT 200,
                                        p_nprobe int DEFAULT NULL, p_m int DEFAULT NULL, p_via text DEFAULT NULL)
RETURNS double precision
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    w      phasevec.watches := phasevec._watch(p_watch);
    has_ix boolean := EXISTS (SELECT 1 FROM phasevec.ivf_cents c WHERE c.watch = w.id AND c.reader = w.reader);
    -- the path the watch is served by: NULL means find_ivf when it has a coarse index, find when not
    via    text := coalesce(p_via, CASE WHEN has_ix THEN 'find_ivf' ELSE 'find' END);
    -- a watch keeps no nprobe or m of its own: NULL means the searches' defaults (m 200, nprobe 16)
    nprobe int := CASE WHEN via = 'find_ivf' THEN coalesce(p_nprobe, 16) END;
    m      int := coalesce(p_m, 200);
    keys   text[];
    r      record;
BEGIN
    IF p_k IS NULL OR p_k NOT BETWEEN 1 AND 999 THEN
        RAISE EXCEPTION 'phasevec: k must be in 1..999 (the question''s own row is asked for too, and left out)';
    END IF;
    IF p_sample IS NULL OR p_sample NOT BETWEEN 1 AND 10000 THEN
        RAISE EXCEPTION 'phasevec: sample must be in 1..10000';
    END IF;
    IF via NOT IN ('find', 'find_ivf') THEN
        RAISE EXCEPTION 'phasevec: a watch is served by find or find_ivf, not %', via;
    END IF;
    IF via = 'find' AND p_nprobe IS NOT NULL THEN
        RAISE EXCEPTION 'phasevec: nprobe is find_ivf''s; find is served with m alone';
    END IF;
    IF nprobe NOT BETWEEN 1 AND 100000 OR m NOT BETWEEN p_k + 1 AND 100000 THEN
        RAISE EXCEPTION 'phasevec: nprobe must be in 1..100000 and m in k+1..100000';
    END IF;
    IF via = 'find_ivf' AND NOT has_ix THEN
        RAISE EXCEPTION 'phasevec: watch % has no coarse index for its reader: find_ivf serves nothing here', p_watch
            USING HINT = 'Build it with phasevec.ivf_build(watch), or approve the path that serves it: p_via => ''find''.';
    END IF;

    -- rows drawn at random from the ones a question can come from: a fresh reading with a 256-bit code,
    -- and not hidden by the truth. Drawn in key order, so that setseed() gives the same sample whatever
    -- plan the join takes.
    SELECT array_agg(t.key) INTO keys FROM (
        SELECT c.key FROM (
            SELECT r2.key FROM phasevec.readings r2
              JOIN phasevec.sources s ON s.watch = r2.watch AND s.key = r2.key AND s.text_hash = r2.text_hash
             WHERE r2.watch = w.id AND r2.reader = w.reader AND r2.failed IS NULL AND r2.code256 IS NOT NULL
               AND NOT EXISTS (SELECT 1 FROM phasevec.truth tr WHERE tr.watch = r2.watch AND tr.key = r2.key
                                 AND (tr.verdict IN ('replaced', 'refuted') OR tr.expires_at <= now()))
             ORDER BY r2.key) c
         ORDER BY random()
         LIMIT p_sample) t;
    IF keys IS NULL THEN
        RAISE EXCEPTION 'phasevec: watch % has no fresh reading with a 256-bit code to ask with', p_watch;
    END IF;

    r := phasevec._recall_measure(p_watch, keys, p_k, via, m, nprobe);
    IF r.measured = 0 THEN
        RAISE EXCEPTION 'phasevec: no sampled row of watch % had a neighbour to measure', p_watch;
    END IF;
    IF r.recall < 0.5 THEN
        RAISE WARNING 'phasevec: approving a recall@% of % for watch %: a baseline this low can hardly degrade',
            p_k, round(r.recall::numeric, 4), p_watch;
    END IF;

    INSERT INTO phasevec.recall_baseline AS b (watch, reader, k, via, nprobe, m, sample_keys, recall, measured, approved_by)
    VALUES (w.id, w.reader, p_k, via, nprobe, m, keys, r.recall, r.measured, session_user)
    ON CONFLICT (watch) DO UPDATE SET reader = EXCLUDED.reader, k = EXCLUDED.k, via = EXCLUDED.via, nprobe = EXCLUDED.nprobe,
        m = EXCLUDED.m, sample_keys = EXCLUDED.sample_keys, recall = EXCLUDED.recall,
        measured = EXCLUDED.measured, approved_at = now(), approved_by = EXCLUDED.approved_by;
    RETURN r.recall;
END;
$$;
COMMENT ON FUNCTION phasevec.recall_approve(text, int, int, int, int, text) IS
    'Measure a watch''s recall@k now, on a fresh sample and the path it is served by, and store it as the baseline recall_check compares against.';

CREATE FUNCTION phasevec.recall_check(p_watch text DEFAULT NULL)
RETURNS TABLE (watch text, verdict text, baseline double precision, current double precision,
               drift double precision, k int, sample int, nprobe int, m int, checked_at timestamptz, via text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
#variable_conflict use_column
DECLARE
    b record;
    r record;
BEGIN
    IF p_watch IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM phasevec.recall_baseline rb JOIN phasevec.watches w ON w.id = rb.watch
             WHERE w.name = p_watch) THEN
        watch := p_watch;
        verdict := CASE WHEN EXISTS (SELECT 1 FROM phasevec.watches w WHERE w.name = p_watch)
                        THEN 'COULD NOT MEASURE: no approved baseline (phasevec.recall_approve)'
                        ELSE 'COULD NOT MEASURE: no watch named ' || p_watch END;
        checked_at := clock_timestamp();
        RETURN NEXT;
        RETURN;
    END IF;

    FOR b IN SELECT w.name, w.reader AS watch_reader, rb.*
               FROM phasevec.recall_baseline rb JOIN phasevec.watches w ON w.id = rb.watch
              WHERE p_watch IS NULL OR w.name = p_watch
              ORDER BY w.name
    LOOP
        watch := b.name; baseline := b.recall; k := b.k; via := b.via; nprobe := b.nprobe; m := b.m;
        current := NULL; drift := NULL; sample := NULL;
        IF b.watch_reader <> b.reader THEN
            verdict := 'COULD NOT MEASURE: the watch switched readers after the baseline; approve it again';
            checked_at := clock_timestamp();
            RETURN NEXT;
            CONTINUE;
        END IF;
        BEGIN
            r := phasevec._recall_measure(b.name, b.sample_keys, b.k, b.via, b.m, b.nprobe);
        EXCEPTION WHEN OTHERS THEN
            verdict := 'COULD NOT MEASURE: ' || SQLERRM;
            checked_at := clock_timestamp();
            RETURN NEXT;
            CONTINUE;
        END;
        sample := r.measured;
        checked_at := clock_timestamp();
        IF r.measured * 2 < cardinality(b.sample_keys) THEN
            verdict := format('COULD NOT MEASURE: only %s of the %s sampled rows still have a fresh reading; approve it again',
                              r.measured, cardinality(b.sample_keys));
            RETURN NEXT;
            CONTINUE;
        END IF;
        current := r.recall;
        drift   := round(r.recall::numeric - b.recall::numeric, 4);
        -- in numeric: both are four-decimal values, and 1.0 - 0.02 must be 0.98, not the float below it
        verdict := CASE WHEN r.recall::numeric >= b.recall::numeric - 0.02 THEN 'ok'
                        WHEN r.recall::numeric >= b.recall::numeric - 0.10 THEN 'degraded'
                        ELSE 'critical' END;
        RETURN NEXT;
    END LOOP;
END;
$$;
COMMENT ON FUNCTION phasevec.recall_check(text) IS
    'Measure each approved watch again (same sample, same served path, m and nprobe) against its baseline: ok, degraded, critical or COULD NOT MEASURE, as a row.';

-- Owner work: nothing here is executable by PUBLIC. A monitoring role is granted recall_check explicitly.
REVOKE ALL ON FUNCTION phasevec._recall_measure(text, text[], int, text, int, int, int) FROM PUBLIC;
REVOKE ALL ON FUNCTION phasevec.recall_approve(text, int, int, int, int, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION phasevec.recall_check(text) FROM PUBLIC;
