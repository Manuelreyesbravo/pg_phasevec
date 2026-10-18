-- pg_muninn 0.5.0 -> 0.6.0: a watch can be read by its words too, and find_hybrid() asks both.
--
-- F5 (yggdrasil sql/161, measured 2026-10-18) put find() against the RAG MIMIR serves over 39,420
-- PostgreSQL commits and lost: recall@10 0.153 against 0.403. The reader (vec-0.1.0) searched worse
-- than an off-the-shelf embedder outside the data it was trained on, which is the reader's to fix.
-- But the questions also name what they look for by its words -- nbtree, pg_mcv_list,
-- InstrStartNode, vacuum_cost_delay -- and a vector alone blurs a rare word into its neighbours.
--
-- So a watch can now be read lexically as well. The lexical reading needs no reader: it is the row's
-- own text, parsed by a text search configuration, and it is written by the watch trigger in the
-- same transaction that writes the text's hash. It can never be stale. What is NOT transactional,
-- and is said so: the weights of the words (how many rows carry each one), which
-- lexical_refresh() recomputes; the reader process calls lexical_maintain() whenever its queue
-- empties, so they follow the rows within one idle turn of the reader.
--
-- find_hybrid() fuses the vector ranking of find() with a lexical ranking by reciprocal ranks
-- (k = 60, equal weights). The lexical ranking is BM25 with every term frequency taken as 1 (k1 = 1.2,
-- b = 0.75), over the question's ten rarest words among those carried by at most 5 % of the rows:
-- common words cost the most to look up and say the least. These constants were fixed before
-- measuring (yggdrasil sql/163) and are not tuned on any evaluation.
--
-- Both arms answer only with rows whose vector reading is fresh, so coverage keeps its meaning; and a
-- watch read lexically with rows that have no lexical reading refuses to answer, as it refuses below
-- its declared coverage, unless partial is asked for.

\echo Use "ALTER EXTENSION pg_muninn UPDATE TO '0.6.0'" to load this file. \quit

-- ------------------------------------------------------------------ tables --

-- What a reader is. Until 0.6.0 its weights and its compute: the same model could not be registered
-- twice. But how it reads is part of what it understands -- a pooled reader's pooling, its context
-- (where a long text is cut), its query instruction and how it tokenizes; a contract reader's marker
-- and instruction -- and two readers that read questions differently are two readers, whose answers
-- are never mixed. A label (reader, version) is still not a new reader.
-- Immutable: it only picks values out of a jsonb (jsonb_build_object is marked stable for the sake of
-- arguments of other types, whose output may depend on settings; these are all jsonb).
CREATE FUNCTION muninn._reads(p_manifest jsonb)
RETURNS jsonb
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
    SELECT pg_catalog.jsonb_strip_nulls(pg_catalog.jsonb_build_object(
        'pooling', p_manifest->'pooling', 'ctx', p_manifest->'ctx', 'query_prefix', p_manifest->'query_prefix',
        'tokens', p_manifest->'tokens', 'marker', p_manifest->'marker',
        'query_instruction', p_manifest->'query_instruction'));
$$;
ALTER TABLE muninn.readers ADD COLUMN reads jsonb GENERATED ALWAYS AS (muninn._reads(manifest)) STORED;
COMMENT ON COLUMN muninn.readers.reads IS
    'How the reader reads, from its manifest: part of what it is, with its weights and its compute.';
ALTER TABLE muninn.readers DROP CONSTRAINT readers_seal_key;
ALTER TABLE muninn.readers
    ADD CONSTRAINT readers_seal_key UNIQUE NULLS NOT DISTINCT (model_sha, adapter_sha, heads_sha, compute, reads);

ALTER TABLE muninn.watches ADD COLUMN lexical regconfig;
COMMENT ON COLUMN muninn.watches.lexical IS
    'The text search configuration the watch is read lexically with (muninn.lexical()); NULL: not read lexically.';

ALTER TABLE muninn.sources
    ADD COLUMN lexemes  tsvector,
    ADD COLUMN lexeme_n int;
COMMENT ON COLUMN muninn.sources.lexemes IS
    'The lexical reading of the row''s current text (its first 131072 characters), written by the watch trigger with the text hash. NULL: the watch is not read lexically, or the row was not read lexically yet.';
CREATE INDEX sources_lexemes ON muninn.sources USING gin (lexemes);
-- Whether a watch has a row without its lexical reading must be instant: find_hybrid() asks it on
-- every question.
CREATE INDEX sources_lexemes_missing ON muninn.sources (watch) WHERE lexemes IS NULL;

-- How many rows of a watch carry each word, as of the last lexical_refresh().
CREATE TABLE muninn.lexstats (
    watch  int  NOT NULL REFERENCES muninn.watches(id) ON DELETE CASCADE,
    lexeme text NOT NULL,
    ndoc   int  NOT NULL CHECK (ndoc > 0),
    PRIMARY KEY (watch, lexeme)
);
CREATE TABLE muninn.lexdocs (
    watch        int PRIMARY KEY REFERENCES muninn.watches(id) ON DELETE CASCADE,
    n            bigint NOT NULL CHECK (n >= 0),
    avg_n        double precision NOT NULL,
    refreshed_at timestamptz NOT NULL
);
COMMENT ON TABLE muninn.lexstats IS
    'The weights of the lexical arm: rows of the watch that carry each word. Recomputed by lexical_refresh(); a word not counted yet weighs as the rarest.';
REVOKE ALL ON muninn.lexstats, muninn.lexdocs FROM PUBLIC;

-- ------------------------------------------------------------- the trigger --

-- A lexeme as a one-term tsquery, without parsing it again (it is already normalized).
CREATE FUNCTION muninn._term(p_lexeme text)
RETURNS tsquery
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
    SELECT ('''' || pg_catalog.replace(pg_catalog.replace(p_lexeme, '\', '\\'), '''', '''''') || '''')::pg_catalog.tsquery;
$$;

-- The text a lexical reading parses: the head of the row's text, so that no row, however long, can
-- make the write to its table fail on the size of a tsvector.
CREATE FUNCTION muninn._lexemes(p_config regconfig, p_body text)
RETURNS tsvector
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
    SELECT pg_catalog.to_tsvector(p_config, pg_catalog.left(coalesce(p_body, ''), 131072));
$$;

DROP FUNCTION muninn._note(int, text, bytea);
CREATE FUNCTION muninn._note(p_watch int, p_key text, p_hash bytea, p_body text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    cfg regconfig;
    lx  tsvector;
BEGIN
    IF pg_trigger_depth() = 0 THEN
        RAISE EXCEPTION 'muninn: _note() is called by a watch trigger, not directly';
    END IF;
    SELECT w.lexical INTO cfg FROM muninn.watches w WHERE w.id = p_watch;
    IF cfg IS NOT NULL THEN
        lx := muninn._lexemes(cfg, p_body);
    END IF;
    INSERT INTO muninn.sources AS s (watch, key, text_hash, lexemes, lexeme_n)
    VALUES (p_watch, p_key, p_hash, lx, length(lx))
    ON CONFLICT (watch, key) DO UPDATE
       SET text_hash = EXCLUDED.text_hash,
           lexemes = EXCLUDED.lexemes,
           lexeme_n = EXCLUDED.lexeme_n,
           changed_at = CASE WHEN s.text_hash IS DISTINCT FROM EXCLUDED.text_hash
                             THEN clock_timestamp() ELSE s.changed_at END;
    PERFORM pg_notify('muninn', p_watch::text);
END;
$$;

-- As in 0.1.0, and the text goes to _note() too, for the lexical reading.
CREATE OR REPLACE FUNCTION muninn._observe()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    old_key text;
    new_key text;
    body    text;
BEGIN
    IF TG_OP IN ('UPDATE', 'DELETE') THEN
        EXECUTE format('SELECT ($1).%I::text', TG_ARGV[1]) INTO old_key USING OLD;
    END IF;
    IF TG_OP IN ('INSERT', 'UPDATE') THEN
        EXECUTE format('SELECT r.%I::text, (%s)::text FROM (SELECT ($1).*) r', TG_ARGV[1], TG_ARGV[2])
           INTO new_key, body USING NEW;
    END IF;
    IF old_key IS NOT NULL AND old_key IS DISTINCT FROM new_key THEN
        PERFORM muninn._forget(TG_ARGV[0]::int, old_key);
    END IF;
    IF new_key IS NOT NULL THEN
        PERFORM muninn._note(TG_ARGV[0]::int, new_key,
                             sha256(convert_to(coalesce(body, ''), 'UTF8')), body);
    END IF;
    RETURN NULL;
END;
$$;

-- --------------------------------------------------------------- the admin --

-- The weights of the words, recounted from the lexical readings. Serialized per watch. Returns how
-- many rows were counted.
CREATE FUNCTION muninn.lexical_refresh(p_watch text)
RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    w muninn.watches := muninn._watch(p_watch);
    n bigint;
BEGIN
    IF w.lexical IS NULL THEN
        RAISE EXCEPTION 'muninn: watch % is not read lexically', p_watch
            USING HINT = 'muninn.lexical(watch, config) reads it.';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('muninn.lexstats'), w.id);
    DELETE FROM muninn.lexstats WHERE watch = w.id;
    INSERT INTO muninn.lexstats (watch, lexeme, ndoc)
    SELECT w.id, t.word, t.ndoc
      FROM ts_stat(format('SELECT lexemes FROM muninn.sources WHERE watch = %s AND lexemes IS NOT NULL', w.id)) t;
    INSERT INTO muninn.lexdocs AS d (watch, n, avg_n, refreshed_at)
    SELECT w.id, count(*), coalesce(avg(s.lexeme_n), 0), clock_timestamp()
      FROM muninn.sources s WHERE s.watch = w.id AND s.lexemes IS NOT NULL
    ON CONFLICT (watch) DO UPDATE SET n = EXCLUDED.n, avg_n = EXCLUDED.avg_n, refreshed_at = EXCLUDED.refreshed_at
    RETURNING d.n INTO n;
    RETURN n;
END;
$$;

-- What the reader process calls when its queue empties: refresh the weights if any row of the watch
-- changed, appeared or went away since they were counted. False, and nothing done, otherwise (and
-- always for a watch not read lexically).
CREATE FUNCTION muninn.lexical_maintain(p_watch text)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    w  muninn.watches := muninn._watch(p_watch);
    ld muninn.lexdocs;
BEGIN
    IF w.lexical IS NULL THEN
        RETURN false;
    END IF;
    SELECT * INTO ld FROM muninn.lexdocs d WHERE d.watch = w.id;
    IF FOUND AND NOT EXISTS (SELECT 1 FROM muninn.sources s WHERE s.watch = w.id AND s.changed_at > ld.refreshed_at)
       AND ld.n = (SELECT count(*) FROM muninn.sources s WHERE s.watch = w.id AND s.lexemes IS NOT NULL) THEN
        RETURN false;
    END IF;
    PERFORM muninn.lexical_refresh(p_watch);
    RETURN true;
END;
$$;

-- Read a watch lexically with a text search configuration, or stop (NULL). A DBA action, like
-- watch(), and it runs as its caller: the recipe is evaluated here, for the rows already in the table,
-- with the owner's rights. A row whose text changes meanwhile keeps the lexical reading its trigger
-- writes; one whose writer did not yet see the watch read lexically is left without one, and
-- find_hybrid() says so until this runs again. Returns how many rows were read lexically.
CREATE FUNCTION muninn.lexical(p_watch text, p_config regconfig)
RETURNS bigint
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    w    muninn.watches := muninn._watch(p_watch);
    k    text;
    body text;
    n    bigint := 0;
BEGIN
    IF NOT pg_has_role(current_user, (SELECT c.relowner FROM pg_class c WHERE c.oid = w.source), 'USAGE') THEN
        RAISE EXCEPTION 'muninn: only the owner of % may change how watch % is read', w.source, p_watch;
    END IF;
    UPDATE muninn.watches SET lexical = p_config WHERE id = w.id;
    IF p_config IS NULL THEN
        UPDATE muninn.sources SET lexemes = NULL, lexeme_n = NULL WHERE watch = w.id AND lexemes IS NOT NULL;
        DELETE FROM muninn.lexstats WHERE watch = w.id;
        DELETE FROM muninn.lexdocs WHERE watch = w.id;
        RETURN 0;
    END IF;
    FOR k, body IN EXECUTE format('SELECT r.%I::text, (%s)::text FROM %s r', w.key_col, w.recipe, w.source) LOOP
        UPDATE muninn.sources s
           SET lexemes = x.lx, lexeme_n = length(x.lx)
          FROM (SELECT muninn._lexemes(p_config, body) AS lx) x
         WHERE s.watch = w.id AND s.key = k AND s.text_hash = sha256(convert_to(coalesce(body, ''), 'UTF8'));
        IF FOUND THEN
            n := n + 1;
        END IF;
    END LOOP;
    PERFORM muninn.lexical_refresh(p_watch);
    RETURN n;
END;
$$;

-- -------------------------------------------------------------------- asking --

-- find(), and the question's words: the vector ranking of the binary sweep (m candidates, reranked by
-- the int8 code) and the lexical ranking (lm candidates), fused by reciprocal ranks. Each hit says
-- where it came from: its rank and score in each arm (NULL where that arm did not bring it); the
-- vector score is given for every hit.
CREATE FUNCTION muninn.find_hybrid(p_watch text, p_text text, p_q64 bigint, p_q smallint[], p_k int DEFAULT 10,
                                   p_partial boolean DEFAULT false, p_m int DEFAULT 200,
                                   p_q256 bit(256) DEFAULT NULL, p_lm int DEFAULT 200)
RETURNS TABLE (key text, score double precision, vector_score double precision, vector_rank int,
               lexical_score double precision, lexical_rank int, hamming int, state text,
               familiarity real, read_at timestamptz, truncated boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    w       muninn.watches := muninn._watch(p_watch);
    ld      muninn.lexdocs;
    dims    int;
    fresh   numeric;
    missing text;
    qnorm   double precision;
    terms   text[];
    idfs    double precision[];
BEGIN
    SELECT rd.dims INTO dims FROM muninn.readers rd WHERE rd.id = w.reader;
    IF p_q IS NULL OR cardinality(p_q) <> dims THEN
        RAISE EXCEPTION 'muninn: the question must be read by the watch''s reader (% dimensions)', dims;
    END IF;
    IF p_k NOT BETWEEN 1 AND 1000 OR p_m NOT BETWEEN p_k AND 100000 OR p_lm NOT BETWEEN p_k AND 100000 THEN
        RAISE EXCEPTION 'muninn: k must be in 1..1000, and m and lm in k..100000';
    END IF;
    IF w.lexical IS NULL THEN
        RAISE EXCEPTION 'muninn: watch % is not read lexically', p_watch
            USING HINT = 'muninn.lexical(watch, config) reads it; find() asks the readings alone.';
    END IF;
    SELECT * INTO ld FROM muninn.lexdocs d WHERE d.watch = w.id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'muninn: the words of watch % were never counted', p_watch
            USING HINT = 'muninn.lexical_refresh(watch) counts them.';
    END IF;

    SELECT coalesce(sum(c.share) FILTER (WHERE c.state IN ('fresh', 'doubtful')), 0),
           string_agg(format('%s %s%%', c.state, round(c.share * 100, 1)), ', ')
               FILTER (WHERE c.state IN ('stale', 'pending', 'failed') AND c.n > 0)
      INTO fresh, missing
      FROM muninn.coverage(p_watch) c;
    IF fresh < w.min_coverage AND NOT p_partial THEN
        RAISE EXCEPTION '%', format('muninn: watch %s covers %s%% of its rows and declared %s%%: %s',
            p_watch, round(fresh * 100, 1), round(w.min_coverage * 100, 1), coalesce(missing, 'nothing read yet'))
            USING HINT = 'Answering from what happens to be read would look like a full answer. Pass p_partial => true to accept it knowingly.';
    END IF;
    IF NOT p_partial AND EXISTS (SELECT 1 FROM muninn.sources s WHERE s.watch = w.id AND s.lexemes IS NULL) THEN
        RAISE EXCEPTION 'muninn: watch % has rows not read lexically', p_watch
            USING HINT = 'muninn.lexical(watch, config) reads them again. Pass p_partial => true to accept it knowingly.';
    END IF;

    -- The question's words, rarest first: at most ten, each carried by at most 5 % of the rows. A word
    -- not counted yet (no row had it at the last refresh) weighs as the rarest.
    SELECT array_agg(t.lexeme ORDER BY t.idf DESC, t.lexeme), array_agg(t.idf ORDER BY t.idf DESC, t.lexeme)
      INTO terms, idfs
      FROM (SELECT q.lexeme,
                   ln(1 + (ld.n - coalesce(st.ndoc, 0) + 0.5) / (coalesce(st.ndoc, 0) + 0.5)) AS idf
              FROM unnest(tsvector_to_array(muninn._lexemes(w.lexical, p_text))) q(lexeme)
              LEFT JOIN muninn.lexstats st ON st.watch = w.id AND st.lexeme = q.lexeme
             WHERE coalesce(st.ndoc, 0) <= greatest(1, 0.05 * ld.n)
             ORDER BY 2 DESC, 1
             LIMIT 10) t;

    SELECT sqrt(sum(x::float8 * x)) INTO qnorm FROM unnest(p_q) x;

    RETURN QUERY
    WITH sweep AS (
        SELECT r.key, r.text_hash, r.code,
               CASE WHEN p_q256 IS NOT NULL THEN bit_count(r.code256 # p_q256)
                    ELSE bit_count((r.code64 # p_q64)::bit(64)) END::int AS ham
          FROM muninn.readings r
         WHERE r.watch = w.id AND r.reader = w.reader AND r.failed IS NULL
           AND (p_q256 IS NULL OR r.code256 IS NOT NULL)
         ORDER BY ham, r.key
         LIMIT p_m
    ), vec AS (
        SELECT v.key, v.cos, row_number() OVER (ORDER BY v.cos DESC NULLS LAST, v.key)::int AS vr
          FROM (SELECT sw.key,
                       (SELECT sum(a::float8 * b) FROM unnest(sw.code, p_q) t(a, b))
                         / nullif((SELECT sqrt(sum(a::float8 * a)) FROM unnest(sw.code) a) * qnorm, 0) AS cos
                  FROM sweep sw
                  JOIN muninn.sources s ON s.watch = w.id AND s.key = sw.key AND s.text_hash = sw.text_hash) v
    ), lex AS (
        SELECT l.key, l.ls, row_number() OVER (ORDER BY l.ls DESC, l.key)::int AS lr
          FROM (SELECT x.key, sum(x.idf) * 2.2 / (1 + 1.2 * (0.25 + 0.75 * x.n / nullif(ld.avg_n, 0))) AS ls
                  FROM unnest(terms, idfs) t(lexeme, idf)
                  CROSS JOIN LATERAL (
                      SELECT s.key, coalesce(s.lexeme_n, 0)::float8 AS n, t.idf
                        FROM muninn.sources s
                        JOIN muninn.readings r ON r.watch = s.watch AND r.key = s.key AND r.reader = w.reader
                                              AND r.text_hash = s.text_hash AND r.failed IS NULL
                       WHERE s.watch = w.id AND s.lexemes @@ muninn._term(t.lexeme)) x
                 GROUP BY x.key, x.n) l
         ORDER BY l.ls DESC, l.key
         LIMIT p_lm
    ), fused AS (
        SELECT coalesce(v.key, l.key) AS key, v.cos, v.vr, l.ls, l.lr,
               (coalesce(1.0 / (60 + v.vr), 0) + coalesce(1.0 / (60 + l.lr), 0))::float8 AS rrf
          FROM vec v FULL JOIN lex l ON l.key = v.key
         ORDER BY 6 DESC, 1
         LIMIT p_k
    )
    SELECT f.key, f.rrf,
           coalesce(f.cos, (SELECT sum(a::float8 * b) FROM unnest(r.code, p_q) t(a, b))
                             / nullif((SELECT sqrt(sum(a::float8 * a)) FROM unnest(r.code) a) * qnorm, 0)),
           f.vr, f.ls, f.lr,
           CASE WHEN p_q256 IS NOT NULL THEN bit_count(r.code256 # p_q256)
                ELSE bit_count((r.code64 # p_q64)::bit(64)) END::int,
           CASE WHEN w.doubt_below IS NOT NULL AND r.familiarity < w.doubt_below THEN 'doubtful' ELSE 'fresh' END,
           r.familiarity, r.read_at, r.truncated
      FROM fused f
      JOIN muninn.readings r ON r.watch = w.id AND r.key = f.key AND r.reader = w.reader
     ORDER BY f.rrf DESC, f.key;
END;
$$;

-- ---------------------------------------------------------------- privileges --
REVOKE ALL ON FUNCTION muninn._note(int, text, bytea, text), muninn.lexical(text, regconfig),
    muninn.lexical_refresh(text), muninn.lexical_maintain(text),
    muninn.find_hybrid(text, text, bigint, smallint[], int, boolean, int, bit, int)
  FROM PUBLIC;
