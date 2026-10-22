-- pg_phasevec 0.8.0: the coarse index that beat pgvector HNSW in Track B (sql/165: 100k and 1M, clean
-- lanes, 2026-10-21) moves INTO pg_phasevec. Until now it was a separate extension (phasevec_b 0.2).
--
--   phasevec.ivf_build(watch)       builds (or rebuilds) a watch's index: spherical k-means centroids in
--                                   float, a second (SOAR) list per reading
--   phasevec.find_ivf(watch, ...)   phasevec.find's contract (same checks, same coverage refusal, same
--                                   columns, same int8 score), sweeping the nprobe nearest lists plus the
--                                   readings recorded after the build, each candidate validated against
--                                   phasevec.sources in the caller's snapshot: never a stale answer
--
-- phasevec.find stays as it is: find_ivf is the fast path once a watch has an index.
\echo Use "ALTER EXTENSION pg_phasevec UPDATE TO '0.8.0'" to load this file. \quit

CREATE TABLE phasevec.ivf_cents (
    watch    int PRIMARY KEY REFERENCES phasevec.watches(id) ON DELETE CASCADE,
    reader   int NOT NULL,
    k        int NOT NULL,
    dims     int NOT NULL,
    n        int NOT NULL,                -- readings indexed (SOAR copies not counted)
    soar     boolean NOT NULL,
    c        bytea NOT NULL,              -- k x dims float4: the centroids, unit length
    built_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE phasevec.ivf_cents ALTER COLUMN c SET STORAGE EXTERNAL;

-- One row per list. A copy of what the readings said WHEN THE INDEX WAS BUILT, with the text hash
-- each code was read from: find_v2 never trusts it, it validates against phasevec.sources.
CREATE TABLE phasevec.ivf_lists (
    watch  int NOT NULL REFERENCES phasevec.watches(id) ON DELETE CASCADE,
    list   int NOT NULL,
    n      int NOT NULL,
    docs   bytea NOT NULL,                -- n x int4: the reading's ordinal (drops SOAR's second copy)
    keys   bytea NOT NULL,                -- the keys, concatenated
    koff   bytea NOT NULL,                -- (n + 1) x int4: where each key starts in keys
    hashes bytea NOT NULL,                -- n x 32
    c256   bytea NOT NULL,                -- n x 32
    c8     bytea NOT NULL,                -- n x dims (int8)
    sn     int NOT NULL,                  -- SOAR copies in this list: only what the sweep reads
    sdocs  bytea NOT NULL,                -- sn x int4: their ordinals (the full row is in their first list)
    sc256  bytea NOT NULL,                -- sn x 32
    PRIMARY KEY (watch, list)
);
ALTER TABLE phasevec.ivf_lists ALTER COLUMN keys SET STORAGE EXTERNAL, ALTER COLUMN koff SET STORAGE EXTERNAL,
                    ALTER COLUMN docs SET STORAGE EXTERNAL, ALTER COLUMN sdocs SET STORAGE EXTERNAL,
                    ALTER COLUMN sc256 SET STORAGE EXTERNAL, ALTER COLUMN hashes SET STORAGE EXTERNAL,
                    ALTER COLUMN c256 SET STORAGE EXTERNAL, ALTER COLUMN c8 SET STORAGE EXTERNAL;

-- The delta: rows read (or read again) after the index was built. find_v2 sweeps them linearly, so a
-- reading recorded a second after the build is found, not lost until the next build.
CREATE TABLE phasevec.ivf_dirty (
    watch int NOT NULL,
    key   text NOT NULL,
    PRIMARY KEY (watch, key)
);

CREATE FUNCTION phasevec._ivf_dirty() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM phasevec.ivf_cents c WHERE c.watch = NEW.watch AND c.reader = NEW.reader) THEN
        INSERT INTO phasevec.ivf_dirty VALUES (NEW.watch, NEW.key) ON CONFLICT DO NOTHING;
    END IF;
    RETURN NULL;
END $$;
CREATE TRIGGER phasevec_ivf_dirty AFTER INSERT OR UPDATE ON phasevec.readings
    FOR EACH ROW EXECUTE FUNCTION phasevec._ivf_dirty();

CREATE FUNCTION phasevec._ivf_build(int, int, int, int, int, int, boolean) RETURNS int
    AS 'MODULE_PATHNAME', 'phasevec_ivf_build' LANGUAGE C STRICT VOLATILE;
CREATE FUNCTION phasevec.ivf_sweep(p_watch int, p_q256 bit(256), p_q smallint[], p_nprobe int, p_m int, p_kk int)
RETURNS TABLE (key text, text_hash bytea, score double precision, hamming int)
    AS 'MODULE_PATHNAME', 'phasevec_ivf_sweep' LANGUAGE C STRICT STABLE ROWS 50;
-- ROWS 50: it returns kk (40 by default) rows. With the default estimate of 1000 the planner hashes
-- all of phasevec.readings and phasevec.sources to validate 40 candidates (measured: ~13 ms at 100k).

-- Build (or rebuild) the coarse index of a watch. Recording waits while it builds (SHARE lock), so
-- the delta starts exactly where the lists end.
CREATE FUNCTION phasevec.ivf_build(p_watch text, p_k int DEFAULT NULL, p_iters int DEFAULT 8, p_sample int DEFAULT 200000,
                        p_soar boolean DEFAULT true)
RETURNS int LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    w phasevec.watches := phasevec._watch(p_watch);
    dims int;
    n bigint;
BEGIN
    -- a build is maintenance: the count deltas of a bulk load are folded first (0.7.0), or every
    -- find_ivf after it would sum them in coverage() (measured: ~25 ms per question at 100k)
    PERFORM phasevec.counts_compact(p_watch);
    LOCK TABLE phasevec.readings IN SHARE MODE;
    SELECT rd.dims INTO dims FROM phasevec.readers rd WHERE rd.id = w.reader;
    SELECT count(*) INTO n FROM phasevec.readings r WHERE r.watch = w.id AND r.reader = w.reader;
    RETURN phasevec._ivf_build(w.id, w.reader, dims, coalesce(p_k, greatest(1, round(sqrt(n))::int)), p_iters, p_sample, p_soar);
END $$;

CREATE TYPE phasevec.ivf_hit AS (key text, score double precision, hamming int, state text, familiarity real,
                      read_at timestamptz, truncated boolean);

-- The candidates of the coarse index and of the delta, each served only if its code was read from
-- the CURRENT text of its row (text hash = phasevec.sources) by the watch's reader.
CREATE FUNCTION phasevec._ivf_valid(w phasevec.watches, p_q256 bit(256), p_q smallint[], qnorm float8,
                         p_nprobe int, p_m int, kk int, p_k int)
RETURNS SETOF phasevec.ivf_hit LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    WITH c AS (
        SELECT s.key, s.text_hash, s.score, s.hamming FROM phasevec.ivf_sweep(w.id, p_q256, p_q, p_nprobe, p_m, kk) s
        UNION ALL
        SELECT r.key, r.text_hash,
               (SELECT sum(a::float8 * b) FROM unnest(r.code, p_q) t(a, b))
                 / nullif((SELECT sqrt(sum(a::float8 * a)) FROM unnest(r.code) a) * qnorm, 0),
               bit_count(r.code256 # p_q256)::int
          FROM phasevec.ivf_dirty d
          JOIN phasevec.readings r ON r.watch = d.watch AND r.key = d.key AND r.reader = w.reader
                                AND r.failed IS NULL AND r.code256 IS NOT NULL
         WHERE d.watch = w.id
    ), valid AS (
        SELECT DISTINCT ON (c.key) c.key, c.score, c.hamming, r.familiarity, r.read_at, r.truncated
          FROM c
          JOIN phasevec.readings r ON r.watch = w.id AND r.key = c.key AND r.reader = w.reader
                                AND r.failed IS NULL AND r.text_hash = c.text_hash
          JOIN phasevec.sources s ON s.watch = w.id AND s.key = c.key AND s.text_hash = c.text_hash
         ORDER BY c.key, c.score DESC
    )
    SELECT v.key, v.score, v.hamming,
           CASE WHEN w.doubt_below IS NOT NULL AND v.familiarity < w.doubt_below THEN 'doubtful' ELSE 'fresh' END,
           v.familiarity, v.read_at, v.truncated
      FROM valid v
     ORDER BY v.score DESC NULLS LAST, v.key
     LIMIT p_k
$$;

-- find_v2: phasevec.find's contract (same checks, same coverage refusal, same columns, same score),
-- with the sweep restricted to the nprobe nearest lists plus the delta.
CREATE FUNCTION phasevec.find_ivf(p_watch text, p_q64 bigint, p_q smallint[], p_k int DEFAULT 10,
                          p_partial boolean DEFAULT false, p_m int DEFAULT 200,
                          p_q256 bit(256) DEFAULT NULL, p_nprobe int DEFAULT 16)
RETURNS TABLE (key text, score double precision, hamming int, state text, familiarity real, read_at timestamptz,
               truncated boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    w       phasevec.watches := phasevec._watch(p_watch);
    dims    int;
    fresh   numeric;
    missing text;
    qnorm   double precision;
    kk      int;
    res     phasevec.ivf_hit[];
BEGIN
    SELECT rd.dims INTO dims FROM phasevec.readers rd WHERE rd.id = w.reader;
    IF p_q IS NULL OR cardinality(p_q) <> dims THEN
        RAISE EXCEPTION 'phasevec: the question must be read by the watch''s reader (% dimensions)', dims;
    END IF;
    IF p_k NOT BETWEEN 1 AND 1000 OR p_m NOT BETWEEN p_k AND 100000 THEN
        RAISE EXCEPTION 'phasevec: k must be in 1..1000 and m in k..100000';
    END IF;
    IF p_q256 IS NULL THEN
        RAISE EXCEPTION 'phasevec: find_v2 sweeps the 256-bit codes: pass the question''s code256';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM phasevec.ivf_cents c WHERE c.watch = w.id AND c.reader = w.reader) THEN
        RAISE EXCEPTION 'phasevec: watch % has no coarse index for its reader', p_watch
            USING HINT = 'Build it with phasevec.ivf_build(watch).';
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
    -- validate k + 2 first: if at least k of them are valid they are exactly the k best valid ones
    -- (candidates come in score order); if not, the loop asks again for all m. 0.1 validated 40 for
    -- k = 10: ~0.3 ms of every question went to checking readings nobody returned.
    kk := least(p_m, p_k + 2);
    LOOP
        SELECT array_agg(h ORDER BY h.score DESC NULLS LAST, h.key) INTO res
          FROM phasevec._ivf_valid(w, p_q256, p_q, qnorm, p_nprobe, p_m, kk, p_k) h;
        -- fewer than k survived validation (stale rows near the question) while the sweep held
        -- candidates back: ask again for all m. Never pad with anything unvalidated.
        EXIT WHEN coalesce(cardinality(res), 0) >= p_k OR kk >= p_m;
        kk := p_m;
    END LOOP;
    RETURN QUERY SELECT (x).* FROM unnest(res) x;
END;
$$;

REVOKE ALL ON FUNCTION phasevec._ivf_build(int, int, int, int, int, int, boolean) FROM PUBLIC;
