-- Copyright 2026 Manuel Reyes Bravo
-- SPDX-License-Identifier: Apache-2.0

-- pg_phasevec 0.1.0
--
-- A reading is a claim: "this piece of this row means this, according to this reader, read from
-- this exact text, on this day". Vector stores keep the number and drop the claim, so they cannot
-- tell a fresh answer from a stale one, a row nobody read from an irrelevant one, or one model's
-- vectors from another's. This extension keeps the claim:
--
--   * a reader is a sealed model, identified by the sha256 of its weights; readings by different
--     readers are never compared;
--   * a watch declares what must be findable: a table, its key, and ONE named recipe (the SQL
--     expression whose text is read);
--   * every watched row's current text is hashed by a trigger in the same transaction that
--     changes it, so a reading of older text is stale at once, not months later;
--   * find() searches the readings that still hold, and refuses to answer when the watch's
--     coverage is below what it declared, instead of answering from whatever happens to be there.
--
-- There is no public vector type and no distance operator: callers declare and ask.
--
-- Security, by construction:
--   * the recipe runs inside the watch's trigger as whoever writes the table -- a trigger the
--     table's owner installed, like any other -- and never inside a SECURITY DEFINER function;
--   * the extension's own tables are written only by small SECURITY DEFINER functions that run no
--     caller code;
--   * creating a watch is a DBA action (INSERT on phasevec.watches is not granted to anyone).

\echo Use "CREATE EXTENSION pg_phasevec" to load this file. \quit

DO $$
DECLARE
    owner_name name;
BEGIN
    SELECT r.rolname INTO owner_name
      FROM pg_catalog.pg_namespace n JOIN pg_catalog.pg_roles r ON r.oid = n.nspowner
     WHERE n.nspname = 'phasevec';
    IF owner_name IS NOT NULL AND owner_name <> current_user
       AND NOT (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = owner_name) THEN
        RAISE EXCEPTION 'pg_phasevec: schema phasevec already exists and is owned by %, not by the installer', owner_name
            USING HINT = 'Its owner could replace the extension''s functions. Drop or rename that schema first.';
    END IF;
END $$;

-- ------------------------------------------------------------------ tables --

CREATE TABLE phasevec.readers (
    id            serial PRIMARY KEY,
    name          text NOT NULL UNIQUE CHECK (name <> ''),
    model_sha     text NOT NULL CHECK (model_sha ~ '^[0-9a-f]{64}$'),
    adapter_sha   text CHECK (adapter_sha ~ '^[0-9a-f]{64}$'),
    heads_sha     text CHECK (heads_sha ~ '^[0-9a-f]{64}$'),
    dims          int  NOT NULL CHECK (dims BETWEEN 1 AND 8192),
    manifest      jsonb NOT NULL DEFAULT '{}',
    registered_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    registered_by text NOT NULL DEFAULT current_user,
    UNIQUE NULLS NOT DISTINCT (model_sha, adapter_sha, heads_sha)
);
COMMENT ON TABLE phasevec.readers IS
    'Sealed readers: a model is identified by the sha256 of its weights (and of its adapter). Readings by different readers are never compared.';

CREATE TABLE phasevec.watches (
    id            serial PRIMARY KEY,
    name          text NOT NULL UNIQUE CHECK (name <> ''),
    source        regclass NOT NULL,
    key_col       name NOT NULL,
    recipe        text NOT NULL CHECK (recipe <> ''),
    reader        int  NOT NULL REFERENCES phasevec.readers(id),
    min_coverage  numeric NOT NULL DEFAULT 0.95 CHECK (min_coverage BETWEEN 0 AND 1),
    doubt_below   real,
    created_at    timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    created_by    text NOT NULL DEFAULT current_user
);
COMMENT ON TABLE phasevec.watches IS
    'What must be findable: a table, its key and one named recipe. find() refuses to answer below min_coverage.';

-- What each watched row says now: the hash of its recipe text, kept by the watch trigger.
CREATE TABLE phasevec.sources (
    watch      int  NOT NULL REFERENCES phasevec.watches(id) ON DELETE CASCADE,
    key        text NOT NULL,
    text_hash  bytea NOT NULL,
    changed_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    PRIMARY KEY (watch, key)
);

CREATE TABLE phasevec.readings (
    watch       int  NOT NULL REFERENCES phasevec.watches(id) ON DELETE CASCADE,
    key         text NOT NULL,
    reader      int  NOT NULL REFERENCES phasevec.readers(id),
    text_hash   bytea NOT NULL,
    code64      bigint,
    code        smallint[],
    familiarity real,
    failed      text,
    read_at     timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    PRIMARY KEY (watch, key, reader),
    CONSTRAINT a_reading_has_codes_or_a_failure
        CHECK ((failed IS NULL) = (code64 IS NOT NULL AND code IS NOT NULL))
);
COMMENT ON TABLE phasevec.readings IS
    'What a reader understood of a row: the hash of the exact text it read, its codes, and when.';

REVOKE ALL ON phasevec.readers, phasevec.watches, phasevec.sources, phasevec.readings FROM PUBLIC;

-- ------------------------------------------------------------------ states --

-- The seven states. `pending` has no reading by definition, so it is in coverage(), not here.
CREATE VIEW phasevec.reading_states AS
SELECT w.name AS watch, r.key, rd.name AS reader,
       CASE
           WHEN s.key IS NULL                  THEN 'orphan'
           WHEN r.reader <> w.reader           THEN 'foreign'
           WHEN r.failed IS NOT NULL           THEN 'failed'
           WHEN r.text_hash <> s.text_hash     THEN 'stale'
           WHEN w.doubt_below IS NOT NULL AND r.familiarity < w.doubt_below THEN 'doubtful'
           ELSE 'fresh'
       END AS state,
       r.read_at, s.changed_at, r.familiarity, r.failed
  FROM phasevec.readings r
  JOIN phasevec.watches w ON w.id = r.watch
  JOIN phasevec.readers rd ON rd.id = r.reader
  LEFT JOIN phasevec.sources s ON s.watch = r.watch AND s.key = r.key;
REVOKE ALL ON phasevec.reading_states FROM PUBLIC;

CREATE FUNCTION phasevec._watch(p_name text)
RETURNS phasevec.watches
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    w phasevec.watches;
BEGIN
    SELECT * INTO w FROM phasevec.watches WHERE name = p_name;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'phasevec: no watch named %', p_name;
    END IF;
    RETURN w;
END;
$$;

-- Every watched row in exactly one state for the watch's current reader, pending included.
CREATE FUNCTION phasevec.coverage(p_watch text)
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

CREATE VIEW phasevec.status AS
SELECT w.name AS watch, w.source, rd.name AS reader, w.min_coverage,
       (SELECT count(*) FROM phasevec.sources s WHERE s.watch = w.id) AS rows,
       (SELECT c.share FROM phasevec.coverage(w.name) c WHERE c.state = 'fresh') AS fresh,
       (SELECT c.share FROM phasevec.coverage(w.name) c WHERE c.state = 'stale') AS stale,
       (SELECT c.share FROM phasevec.coverage(w.name) c WHERE c.state = 'pending') AS pending,
       (SELECT max(r.read_at) FROM phasevec.readings r WHERE r.watch = w.id) AS last_read
  FROM phasevec.watches w JOIN phasevec.readers rd ON rd.id = w.reader;
REVOKE ALL ON phasevec.status FROM PUBLIC;

-- ------------------------------------------------------------- the trigger --

-- Writes what a row says now. Only from a trigger: called at top level it could forge a hash and
-- make a stale reading look fresh.
CREATE FUNCTION phasevec._note(p_watch int, p_key text, p_hash bytea)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF pg_trigger_depth() = 0 THEN
        RAISE EXCEPTION 'phasevec: _note() is called by a watch trigger, not directly';
    END IF;
    INSERT INTO phasevec.sources AS s (watch, key, text_hash) VALUES (p_watch, p_key, p_hash)
    ON CONFLICT (watch, key) DO UPDATE
       SET text_hash = EXCLUDED.text_hash,
           changed_at = CASE WHEN s.text_hash IS DISTINCT FROM EXCLUDED.text_hash
                             THEN clock_timestamp() ELSE s.changed_at END;
    PERFORM pg_notify('phasevec', p_watch::text);
END;
$$;

CREATE FUNCTION phasevec._forget(p_watch int, p_key text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF pg_trigger_depth() = 0 THEN
        RAISE EXCEPTION 'phasevec: _forget() is called by a watch trigger, not directly';
    END IF;
    DELETE FROM phasevec.sources WHERE watch = p_watch AND key = p_key;
END;
$$;

-- The watch trigger. Arguments: watch id, key column, recipe. It runs as whoever writes the table:
-- the recipe is the table owner's code, the same as any trigger the owner installs.
CREATE FUNCTION phasevec._observe()
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
        PERFORM phasevec._forget(TG_ARGV[0]::int, old_key);
    END IF;
    IF new_key IS NOT NULL THEN
        PERFORM phasevec._note(TG_ARGV[0]::int, new_key,
                             sha256(convert_to(coalesce(body, ''), 'UTF8')));
    END IF;
    RETURN NULL;
END;
$$;

-- --------------------------------------------------------------- the admin --

CREATE FUNCTION phasevec.reader_register(p_name text, p_model_sha text, p_dims int,
                                       p_adapter_sha text DEFAULT NULL, p_manifest jsonb DEFAULT '{}')
RETURNS int
LANGUAGE sql
SET search_path = pg_catalog, pg_temp
AS $$
    INSERT INTO phasevec.readers (name, model_sha, adapter_sha, dims, manifest)
    VALUES (p_name, lower(p_model_sha), lower(p_adapter_sha), p_dims, p_manifest)
    RETURNING id;
$$;

-- A reader trained against the vec contract arrives as its manifest (train_vec_branch.py export).
-- The manifest names the adapter and heads by sha256; the base model's sha256 is filled in by
-- whoever serves it (phasevec-reader --register --manifest hashes the GGUF it actually loaded), so a
-- manifest still carrying base_sha256 = null is refused: an unsealed base is not a reader.
CREATE FUNCTION phasevec.reader_register(p_manifest jsonb)
RETURNS int
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    hex  constant text := '^[0-9a-f]{64}$';
    dims int;
BEGIN
    IF jsonb_typeof(p_manifest) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'phasevec: a manifest is a JSON object';
    END IF;
    IF coalesce(p_manifest->>'reader', '') = '' OR coalesce(p_manifest->>'version', '') = '' THEN
        RAISE EXCEPTION 'phasevec: the manifest needs reader and version';
    END IF;
    IF coalesce(p_manifest->>'base_sha256', '') !~ hex THEN
        RAISE EXCEPTION 'phasevec: base_sha256 is not sealed'
            USING HINT = 'Register through phasevec-reader --register --manifest, which hashes the GGUF it serves.';
    END IF;
    IF coalesce(p_manifest->>'adapter_sha256', '') !~ hex THEN
        RAISE EXCEPTION 'phasevec: adapter_sha256 must be a sha256';
    END IF;
    IF p_manifest ? 'heads_sha256' AND coalesce(p_manifest->>'heads_sha256', '') !~ hex THEN
        RAISE EXCEPTION 'phasevec: heads_sha256 must be a sha256';
    END IF;
    IF coalesce(p_manifest->>'marker', '') = '' OR p_manifest->>'pooling' IS DISTINCT FROM 'none'
       OR p_manifest->>'read_at' IS DISTINCT FROM 'last_marker_token' THEN
        RAISE EXCEPTION 'phasevec: this manifest is not of the marker contract (marker, pooling none, read_at last_marker_token)';
    END IF;
    IF jsonb_typeof(p_manifest->'mrl_dims') IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'phasevec: the manifest needs mrl_dims';
    END IF;
    -- A reading keeps the 1024-dim prefix when the reader has one (the rerank code), else its widest.
    SELECT CASE WHEN bool_or(d::int = 1024) THEN 1024 ELSE max(d::int) END INTO dims
      FROM jsonb_array_elements_text(p_manifest->'mrl_dims') d;
    IF dims IS NULL OR dims < 64 OR NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text(p_manifest->'mrl_dims') d
                                                WHERE d::int = 64) THEN
        RAISE EXCEPTION 'phasevec: mrl_dims must include 64 (the binary code) and at least one prefix to keep';
    END IF;
    RETURN phasevec._reader_insert(
        (p_manifest->>'reader') || '-' || (p_manifest->>'version'),
        p_manifest->>'base_sha256', dims, p_manifest->>'adapter_sha256',
        p_manifest->>'heads_sha256', p_manifest);
END;
$$;

CREATE FUNCTION phasevec._reader_insert(p_name text, p_model_sha text, p_dims int, p_adapter_sha text,
                                      p_heads_sha text, p_manifest jsonb)
RETURNS int
LANGUAGE sql
SET search_path = pg_catalog, pg_temp
AS $$
    INSERT INTO phasevec.readers (name, model_sha, adapter_sha, heads_sha, dims, manifest)
    VALUES (p_name, lower(p_model_sha), lower(p_adapter_sha), lower(p_heads_sha), p_dims, p_manifest)
    RETURNING id;
$$;

-- Creating a watch installs a trigger on the table, so only the table's owner may do it, and it
-- writes phasevec.watches, which only the DBA is granted. Runs as its caller: the recipe is evaluated
-- here, for the rows already in the table, with the owner's rights and nobody else's.
CREATE FUNCTION phasevec.watch(p_name text, p_source regclass, p_key name, p_recipe text,
                             p_reader text, p_min_coverage numeric DEFAULT 0.95,
                             p_doubt_below real DEFAULT NULL)
RETURNS int
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    tbl_owner oid;
    rid       int;
    wid       int;
    k         text;
    body      text;
BEGIN
    SELECT c.relowner INTO tbl_owner FROM pg_class c WHERE c.oid = p_source AND c.relkind IN ('r', 'p');
    IF NOT FOUND THEN
        RAISE EXCEPTION 'phasevec: % is not a table', p_source;
    END IF;
    IF NOT pg_has_role(current_user, tbl_owner, 'USAGE') THEN
        RAISE EXCEPTION 'phasevec: a watch is a trigger on %, so only its owner may create one', p_source;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = p_source AND a.attname = p_key
                   AND a.attnum > 0 AND NOT a.attisdropped) THEN
        RAISE EXCEPTION 'phasevec: % has no column %', p_source, p_key;
    END IF;
    SELECT id INTO rid FROM phasevec.readers WHERE name = p_reader;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'phasevec: no reader named %', p_reader
            USING HINT = 'Register it with phasevec.reader_register(); nothing is read without a sealed reader.';
    END IF;
    -- The recipe must be an expression over the row, aliased r.
    EXECUTE format('SELECT (%s)::text FROM %s r LIMIT 0', p_recipe, p_source);

    INSERT INTO phasevec.watches (name, source, key_col, recipe, reader, min_coverage, doubt_below)
    VALUES (p_name, p_source, p_key, p_recipe, rid, p_min_coverage, p_doubt_below)
    RETURNING id INTO wid;

    EXECUTE format('CREATE TRIGGER %I AFTER INSERT OR UPDATE OR DELETE ON %s '
                   'FOR EACH ROW EXECUTE FUNCTION phasevec._observe(%L, %L, %L)',
                   'phasevec_watch_' || wid, p_source, wid, p_key, p_recipe);

    -- Every row already there is noted, so it is pending until read -- not invisible.
    FOR k, body IN EXECUTE format('SELECT r.%I::text, (%s)::text FROM %s r', p_key, p_recipe, p_source) LOOP
        INSERT INTO phasevec.sources (watch, key, text_hash)
        VALUES (wid, k, sha256(convert_to(coalesce(body, ''), 'UTF8')));
    END LOOP;
    RETURN wid;
END;
$$;

-- A new reader for a watch: every reading by the old one becomes foreign at once.
CREATE FUNCTION phasevec.reader_switch(p_watch text, p_reader text)
RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    rid int;
BEGIN
    SELECT id INTO rid FROM phasevec.readers WHERE name = p_reader;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'phasevec: no reader named %', p_reader;
    END IF;
    UPDATE phasevec.watches SET reader = rid WHERE name = p_watch;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'phasevec: no watch named %', p_watch;
    END IF;
END;
$$;

-- ---------------------------------------------------------- the reader side --

-- What the watch's reader still has to read: never read, read from older text, or read by another
-- reader. Runs as its caller: the recipe is evaluated with the reader role's rights on the table.
CREATE FUNCTION phasevec._todo(p_watch text, p_limit int)
RETURNS TABLE (key text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT s.key
      FROM phasevec._watch(p_watch) w
      JOIN phasevec.sources s ON s.watch = w.id
      LEFT JOIN phasevec.readings r ON r.watch = s.watch AND r.key = s.key AND r.reader = w.reader
     WHERE r.key IS NULL OR r.text_hash <> s.text_hash
     ORDER BY s.changed_at
     LIMIT p_limit;
$$;

CREATE FUNCTION phasevec.next(p_watch text, p_limit int DEFAULT 64)
RETURNS TABLE (key text, body text, text_hash bytea)
LANGUAGE plpgsql STABLE
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    w phasevec.watches := phasevec._watch(p_watch);
BEGIN
    RETURN QUERY EXECUTE format(
        'SELECT r.%1$I::text, (%2$s)::text, sha256(convert_to(coalesce((%2$s)::text, ''''), ''UTF8''))
           FROM %3$s r WHERE r.%1$I::text = ANY ($1)', w.key_col, w.recipe, w.source)
    USING ARRAY(SELECT t.key FROM phasevec._todo(p_watch, p_limit) t);
END;
$$;

-- What a reader process must prove before it writes: the sha256 of the weights it loaded. A process
-- that loaded other weights refuses to start, so nothing is recorded in a reader's name by a
-- different model.
CREATE FUNCTION phasevec.reader_seal(p_reader text)
RETURNS TABLE (model_sha text, adapter_sha text, dims int, heads_sha text, manifest jsonb)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT r.model_sha, r.adapter_sha, r.dims, r.heads_sha, r.manifest FROM phasevec.readers r WHERE r.name = p_reader;
$$;

-- A reading is accepted only if it is of the text the row says NOW, by the watch's reader.
CREATE FUNCTION phasevec.record(p_watch text, p_key text, p_reader text, p_text_hash bytea,
                              p_code64 bigint, p_code smallint[], p_familiarity real DEFAULT NULL)
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
    INSERT INTO phasevec.readings AS r (watch, key, reader, text_hash, code64, code, familiarity, failed, read_at)
    VALUES (w.id, p_key, rd.id, p_text_hash, p_code64, p_code, p_familiarity, NULL, clock_timestamp())
    ON CONFLICT (watch, key, reader) DO UPDATE
       SET text_hash = EXCLUDED.text_hash, code64 = EXCLUDED.code64, code = EXCLUDED.code,
           familiarity = EXCLUDED.familiarity, failed = NULL, read_at = EXCLUDED.read_at;
END;
$$;

CREATE FUNCTION phasevec.record_failure(p_watch text, p_key text, p_reader text, p_text_hash bytea, p_reason text)
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
       SET text_hash = EXCLUDED.text_hash, code64 = NULL, code = NULL, familiarity = NULL,
           failed = EXCLUDED.failed, read_at = EXCLUDED.read_at;
END;
$$;

-- ------------------------------------------------------------------- asking --

-- Exact scan of the 64-bit codes of the readings that still hold, then the best p_m reordered by
-- the full code. Below the watch's coverage it raises instead of answering, unless p_partial.
CREATE FUNCTION phasevec.find(p_watch text, p_q64 bigint, p_q smallint[], p_k int DEFAULT 10,
                            p_partial boolean DEFAULT false, p_m int DEFAULT 200)
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
    WITH cand AS (
        SELECT r.key, r.code, r.familiarity, r.read_at,
               bit_count((r.code64 # p_q64)::bit(64))::int AS ham
          FROM phasevec.readings r
          JOIN phasevec.sources s ON s.watch = r.watch AND s.key = r.key
         WHERE r.watch = w.id AND r.reader = w.reader
           AND r.failed IS NULL AND r.text_hash = s.text_hash
         ORDER BY ham, r.key
         LIMIT p_m
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

-- Rows like a given row: its own fresh reading is the question.
CREATE FUNCTION phasevec.alike(p_watch text, p_key text, p_k int DEFAULT 10, p_partial boolean DEFAULT false)
RETURNS TABLE (key text, score double precision, hamming int, state text, familiarity real, read_at timestamptz)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    w   phasevec.watches := phasevec._watch(p_watch);
    q64 bigint;
    q   smallint[];
BEGIN
    SELECT r.code64, r.code INTO q64, q
      FROM phasevec.readings r JOIN phasevec.sources s ON s.watch = r.watch AND s.key = r.key
     WHERE r.watch = w.id AND r.key = p_key AND r.reader = w.reader
       AND r.failed IS NULL AND r.text_hash = s.text_hash;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'phasevec: row % of watch % has no fresh reading to ask with', p_key, p_watch;
    END IF;
    RETURN QUERY SELECT f.* FROM phasevec.find(p_watch, q64, q, p_k + 1, p_partial) f WHERE f.key <> p_key LIMIT p_k;
END;
$$;

-- A dropped table takes its trigger with it; this takes its watch, so no watch is left pointing at a
-- dead oid and answering for rows that no longer exist.
CREATE FUNCTION phasevec._on_drop()
RETURNS event_trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    DELETE FROM phasevec.watches w
     WHERE NOT EXISTS (SELECT 1 FROM pg_class c WHERE c.oid = w.source);
END;
$$;
CREATE EVENT TRIGGER phasevec_watch_source_dropped ON sql_drop
    WHEN TAG IN ('DROP TABLE', 'DROP SCHEMA', 'DROP OWNED')
    EXECUTE FUNCTION phasevec._on_drop();

-- ---------------------------------------------------------------- privileges --
-- Readers and askers are granted by the DBA. Nothing is open by default.
REVOKE ALL ON FUNCTION phasevec._watch(text), phasevec._note(int, text, bytea), phasevec._forget(int, text),
    phasevec._todo(text, int), phasevec.reader_register(text, text, int, text, jsonb), phasevec.reader_register(jsonb),
    phasevec._reader_insert(text, text, int, text, text, jsonb),
    phasevec.watch(text, regclass, name, text, text, numeric, real), phasevec.reader_switch(text, text),
    phasevec.record(text, text, text, bytea, bigint, smallint[], real),
    phasevec.record_failure(text, text, text, bytea, text),
    phasevec.next(text, int), phasevec.coverage(text),
    phasevec.find(text, bigint, smallint[], int, boolean, int), phasevec.alike(text, text, int, boolean),
    phasevec._on_drop(), phasevec.reader_seal(text)
  FROM PUBLIC;
-- The watch trigger runs as whoever writes the table, so these two must be callable by anyone; they
-- refuse to run outside a trigger.
GRANT EXECUTE ON FUNCTION phasevec._observe(), phasevec._note(int, text, bytea), phasevec._forget(int, text) TO PUBLIC;
