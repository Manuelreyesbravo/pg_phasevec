-- pg_phasevec 0.15.0: a replaced note hands its place to its replacement.
--
-- Measured on 25-10 (yggdrasil, vara 623): hiding what is false works (0 of 21 old notes served), but in 5 of 21
-- the correction was worded so differently that the question never reached it: not in the top-10 before nor
-- after. The old note was the top-1 and already knew who replaced it (truth.replaced_by); the search only hid it.
--
-- Now find and find_ivf are the 0.14 searches (renamed _find_hide and _find_ivf_hide, unchanged: they still hide
-- replaced, refuted and expired rows) plus one step: every replaced note of the watch is scored against the
-- question with its own codes, and if it would have made the top-k, its replacement takes that place with state
-- 'replacement' (the familiarity, read_at and truncated shown are the replacement's own). A key present twice
-- keeps its best score. search() and recall() call find / find_ivf, so they get it without changes.
--
-- Limits, said here and not discovered later:
--   * one hop: a replacement that is itself replaced, refuted or expired is not served in anyone's place;
--   * the cost grows with the number of replaced notes of the watch (each one is scored on every question);
--   * find_hybrid and find_npu still only hide (v1): their scores are not on the same scale.
--
-- The library is the same as 0.14.2.
\echo Use "ALTER EXTENSION pg_phasevec UPDATE TO '0.15.0'" to load this file. \quit

ALTER FUNCTION phasevec.find(text, bigint, smallint[], int, boolean, int, bit) RENAME TO _find_hide;
ALTER FUNCTION phasevec.find_ivf(text, bigint, smallint[], int, boolean, int, bit, int) RENAME TO _find_ivf_hide;

-- The replacements a question would reach through the notes they replaced: one row per replacement, with the
-- best score among the notes it replaced. Only current, read, valid replacements.
CREATE FUNCTION phasevec._replacements(p_watch text, p_q64 bigint, p_q smallint[], p_q256 bit(256))
RETURNS TABLE (key text, score double precision, hamming int, familiarity real, read_at timestamptz,
               truncated boolean)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $f$
    SELECT DISTINCT ON (tr.replaced_by)
           tr.replaced_by,
           (SELECT sum(a::float8 * b) FROM unnest(o.code, p_q) t(a, b))
             / nullif((SELECT sqrt(sum(a::float8 * a)) FROM unnest(o.code) a)
                      * (SELECT sqrt(sum(x::float8 * x)) FROM unnest(p_q) x), 0) AS score,
           CASE WHEN p_q256 IS NOT NULL THEN bit_count(o.code256 # p_q256)
                ELSE bit_count((o.code64 # p_q64)::bit(64)) END::int,
           n.familiarity, n.read_at, n.truncated
      FROM phasevec.watches w
      JOIN phasevec.truth tr ON tr.watch = w.id AND tr.verdict = 'replaced' AND tr.replaced_by IS NOT NULL
      JOIN phasevec.readings o ON o.watch = w.id AND o.key = tr.key AND o.reader = w.reader AND o.failed IS NULL
      JOIN phasevec.sources os ON os.watch = w.id AND os.key = o.key AND os.text_hash = o.text_hash
      JOIN phasevec.readings n ON n.watch = w.id AND n.key = tr.replaced_by AND n.reader = w.reader
                              AND n.failed IS NULL
      JOIN phasevec.sources ns ON ns.watch = w.id AND ns.key = n.key AND ns.text_hash = n.text_hash
     WHERE w.name = p_watch
       AND (p_q256 IS NULL OR o.code256 IS NOT NULL)
       AND NOT EXISTS (SELECT 1 FROM phasevec.truth t2
                        WHERE t2.watch = w.id AND t2.key = n.key
                          AND (t2.verdict IN ('replaced', 'refuted') OR t2.expires_at <= now()))
     ORDER BY tr.replaced_by, 2 DESC NULLS LAST
$f$;
COMMENT ON FUNCTION phasevec._replacements(text, bigint, smallint[], bit) IS
    'The replacements a question reaches through the notes they replaced (one hop), scored with the replaced note''s codes.';

CREATE FUNCTION phasevec.find(p_watch text, p_q64 bigint, p_q smallint[], p_k int DEFAULT 10,
                              p_partial boolean DEFAULT false, p_m int DEFAULT 200,
                              p_q256 bit(256) DEFAULT NULL)
RETURNS TABLE (key text, score double precision, hamming int, state text, familiarity real, read_at timestamptz,
               truncated boolean)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $f$
    WITH base AS MATERIALIZED (
        SELECT * FROM phasevec._find_hide(p_watch, p_q64, p_q, p_k, p_partial, p_m, p_q256)
    ), allr AS (
        SELECT b.key, b.score, b.hamming, b.state, b.familiarity, b.read_at, b.truncated, 0 AS via FROM base b
        UNION ALL
        SELECT r.key, r.score, r.hamming, 'replacement', r.familiarity, r.read_at, r.truncated, 1
          FROM phasevec._replacements(p_watch, p_q64, p_q, p_q256) r
    ), best AS (
        SELECT DISTINCT ON (a.key) a.* FROM allr a ORDER BY a.key, a.score DESC NULLS LAST, a.via
    )
    SELECT b.key, b.score, b.hamming, b.state, b.familiarity, b.read_at, b.truncated
      FROM best b
     ORDER BY b.score DESC NULLS LAST, b.key
     LIMIT p_k
$f$;
COMMENT ON FUNCTION phasevec.find(text, bigint, smallint[], int, boolean, int, bit) IS
    'Exact search (0.15.0): hides replaced, refuted and expired rows, and a replaced row that would have been served hands its place to its replacement (state replacement).';

CREATE FUNCTION phasevec.find_ivf(p_watch text, p_q64 bigint, p_q smallint[], p_k int DEFAULT 10,
                                  p_partial boolean DEFAULT false, p_m int DEFAULT 200,
                                  p_q256 bit(256) DEFAULT NULL, p_nprobe int DEFAULT 16)
RETURNS TABLE (key text, score double precision, hamming int, state text, familiarity real, read_at timestamptz,
               truncated boolean)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $f$
    WITH base AS MATERIALIZED (
        SELECT * FROM phasevec._find_ivf_hide(p_watch, p_q64, p_q, p_k, p_partial, p_m, p_q256, p_nprobe)
    ), allr AS (
        SELECT b.key, b.score, b.hamming, b.state, b.familiarity, b.read_at, b.truncated, 0 AS via FROM base b
        UNION ALL
        SELECT r.key, r.score, r.hamming, 'replacement', r.familiarity, r.read_at, r.truncated, 1
          FROM phasevec._replacements(p_watch, p_q64, p_q, p_q256) r
    ), best AS (
        SELECT DISTINCT ON (a.key) a.* FROM allr a ORDER BY a.key, a.score DESC NULLS LAST, a.via
    )
    SELECT b.key, b.score, b.hamming, b.state, b.familiarity, b.read_at, b.truncated
      FROM best b
     ORDER BY b.score DESC NULLS LAST, b.key
     LIMIT p_k
$f$;
COMMENT ON FUNCTION phasevec.find_ivf(text, bigint, smallint[], int, boolean, int, bit, int) IS
    'Coarse-index search (0.15.0): as find, through the coarse index; a replaced row hands its place to its replacement.';

REVOKE ALL ON FUNCTION phasevec._replacements(text, bigint, smallint[], bit) FROM PUBLIC;
