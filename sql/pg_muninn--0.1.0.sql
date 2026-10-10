-- Copyright 2026 Manuel Reyes Bravo
-- SPDX-License-Identifier: Apache-2.0

-- pg_muninn 0.1.0
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
--   * creating a watch is a DBA action (INSERT on muninn.watches is not granted to anyone).

\echo Use "CREATE EXTENSION pg_muninn" to load this file. \quit

DO $$
DECLARE
    owner_name name;
BEGIN
    SELECT r.rolname INTO owner_name
      FROM pg_catalog.pg_namespace n JOIN pg_catalog.pg_roles r ON r.oid = n.nspowner
     WHERE n.nspname = 'muninn';
    IF owner_name IS NOT NULL AND owner_name <> current_user
       AND NOT (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = owner_name) THEN
        RAISE EXCEPTION 'pg_muninn: schema muninn already exists and is owned by %, not by the installer', owner_name
            USING HINT = 'Its owner could replace the extension''s functions. Drop or rename that schema first.';
    END IF;
END $$;

-- ------------------------------------------------------------------ tables --

CREATE TABLE muninn.readers (
    id            serial PRIMARY KEY,
    name          text NOT NULL UNIQUE CHECK (name <> ''),
    model_sha     text NOT NULL CHECK (model_sha ~ '^[0-9a-f]{64}$'),
    adapter_sha   text CHECK (adapter_sha ~ '^[0-9a-f]{64}$'),
    dims          int  NOT NULL CHECK (dims BETWEEN 1 AND 8192),
    manifest      jsonb NOT NULL DEFAULT '{}',
    registered_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    registered_by text NOT NULL DEFAULT current_user,
    UNIQUE (model_sha, adapter_sha)
);
COMMENT ON TABLE muninn.readers IS
    'Sealed readers: a model is identified by the sha256 of its weights (and of its adapter). Readings by different readers are never compared.';

CREATE TABLE muninn.watches (
    id            serial PRIMARY KEY,
    name          text NOT NULL UNIQUE CHECK (name <> ''),
    source        regclass NOT NULL,
    key_col       name NOT NULL,
    recipe        text NOT NULL CHECK (recipe <> ''),
    reader        int  NOT NULL REFERENCES muninn.readers(id),
    min_coverage  numeric NOT NULL DEFAULT 0.95 CHECK (min_coverage BETWEEN 0 AND 1),
    doubt_below   real,
    created_at    timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    created_by    text NOT NULL DEFAULT current_user
);
COMMENT ON TABLE muninn.watches IS
    'What must be findable: a table, its key and one named recipe. find() refuses to answer below min_coverage.';

-- What each watched row says now: the hash of its recipe text, kept by the watch trigger.
CREATE TABLE muninn.sources (
    watch      int  NOT NULL REFERENCES muninn.watches(id) ON DELETE CASCADE,
    key        text NOT NULL,
    text_hash  bytea NOT NULL,
    changed_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    PRIMARY KEY (watch, key)
);

CREATE TABLE muninn.readings (
    watch       int  NOT NULL REFERENCES muninn.watches(id) ON DELETE CASCADE,
    key         text NOT NULL,
    reader      int  NOT NULL REFERENCES muninn.readers(id),
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
COMMENT ON TABLE muninn.readings IS
    'What a reader understood of a row: the hash of the exact text it read, its codes, and when.';

REVOKE ALL ON muninn.readers, muninn.watches, muninn.sources, muninn.readings FROM PUBLIC;

-- ------------------------------------------------------------------ states --

-- The seven states. `pending` has no reading by definition, so it is in coverage(), not here.
CREATE VIEW muninn.reading_states AS
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
  FROM muninn.readings r
  JOIN muninn.watches w ON w.id = r.watch
  JOIN muninn.readers rd ON rd.id = r.reader
  LEFT JOIN muninn.sources s ON s.watch = r.watch AND s.key = r.key;
REVOKE ALL ON muninn.reading_states FROM PUBLIC;

CREATE FUNCTION muninn._watch(p_name text)
RETURNS muninn.watches
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    w muninn.watches;
BEGIN
    SELECT * INTO w FROM muninn.watches WHERE name = p_name;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'muninn: no watch named %', p_name;
    END IF;
    RETURN w;
END;
$$;

-- Every watched row in exactly one state for the watch's current reader, pending included.
CREATE FUNCTION muninn.coverage(p_watch text)
RETURNS TABLE (state text, n bigint, share numeric)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    WITH w AS (SELECT * FROM muninn._watch(p_watch)),
    per_row AS (
        SELECT CASE
                   WHEN r.key IS NULL                 THEN 'pending'
                   WHEN r.failed IS NOT NULL          THEN 'failed'
                   WHEN r.text_hash <> s.text_hash    THEN 'stale'
                   WHEN w.doubt_below IS NOT NULL AND r.familiarity < w.doubt_below THEN 'doubtful'
                   ELSE 'fresh'
               END AS state
          FROM w JOIN muninn.sources s ON s.watch = w.id
          LEFT JOIN muninn.readings r ON r.watch = s.watch AND r.key = s.key AND r.reader = w.reader
        UNION ALL
        SELECT 'foreign' FROM w JOIN muninn.readings r ON r.watch = w.id AND r.reader <> w.reader
        UNION ALL
        SELECT 'orphan' FROM w JOIN muninn.readings r ON r.watch = w.id AND r.reader = w.reader
         WHERE NOT EXISTS (SELECT 1 FROM muninn.sources s WHERE s.watch = r.watch AND s.key = r.key)
    ),
    total AS (SELECT count(*) AS t FROM w JOIN muninn.sources s ON s.watch = w.id)
    SELECT st.state, count(p.state),
           CASE WHEN (SELECT t FROM total) = 0 OR st.state IN ('foreign', 'orphan') THEN NULL
                ELSE round(count(p.state)::numeric / (SELECT t FROM total), 4) END
      FROM unnest(ARRAY['fresh','doubtful','stale','pending','failed','foreign','orphan']) WITH ORDINALITY st(state, o)
      LEFT JOIN per_row p ON p.state = st.state
     GROUP BY st.state, st.o
     ORDER BY st.o;
$$;

CREATE VIEW muninn.status AS
SELECT w.name AS watch, w.source, rd.name AS reader, w.min_coverage,
       (SELECT count(*) FROM muninn.sources s WHERE s.watch = w.id) AS rows,
       (SELECT c.share FROM muninn.coverage(w.name) c WHERE c.state = 'fresh') AS fresh,
       (SELECT c.share FROM muninn.coverage(w.name) c WHERE c.state = 'stale') AS stale,
       (SELECT c.share FROM muninn.coverage(w.name) c WHERE c.state = 'pending') AS pending,
       (SELECT max(r.read_at) FROM muninn.readings r WHERE r.watch = w.id) AS last_read
  FROM muninn.watches w JOIN muninn.readers rd ON rd.id = w.reader;
REVOKE ALL ON muninn.status FROM PUBLIC;

-- ------------------------------------------------------------- the trigger --

-- Writes what a row says now. Only from a trigger: called at top level it could forge a hash and
-- make a stale reading look fresh.
CREATE FUNCTION muninn._note(p_watch int, p_key text, p_hash bytea)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF pg_trigger_depth() = 0 THEN
        RAISE EXCEPTION 'muninn: _note() is called by a watch trigger, not directly';
    END IF;
    INSERT INTO muninn.sources AS s (watch, key, text_hash) VALUES (p_watch, p_key, p_hash)
    ON CONFLICT (watch, key) DO UPDATE
       SET text_hash = EXCLUDED.text_hash,
           changed_at = CASE WHEN s.text_hash IS DISTINCT FROM EXCLUDED.text_hash
                             THEN clock_timestamp() ELSE s.changed_at END;
    PERFORM pg_notify('muninn', p_watch::text);
END;
$$;

CREATE FUNCTION muninn._forget(p_watch int, p_key text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF pg_trigger_depth() = 0 THEN
        RAISE EXCEPTION 'muninn: _forget() is called by a watch trigger, not directly';
    END IF;
    DELETE FROM muninn.sources WHERE watch = p_watch AND key = p_key;
END;
$$;

-- The watch trigger. Arguments: watch id, key column, recipe. It runs as whoever writes the table:
-- the recipe is the table owner's code, the same as any trigger the owner installs.
CREATE FUNCTION muninn._observe()
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
                             sha256(convert_to(coalesce(body, ''), 'UTF8')));
    END IF;
    RETURN NULL;
END;
$$;

-- --------------------------------------------------------------- the admin --

CREATE FUNCTION muninn.reader_register(p_name text, p_model_sha text, p_dims int,
                                       p_adapter_sha text DEFAULT NULL, p_manifest jsonb DEFAULT '{}')
RETURNS int
LANGUAGE sql
SET search_path = pg_catalog, pg_temp
AS $$
    INSERT INTO muninn.readers (name, model_sha, adapter_sha, dims, manifest)
    VALUES (p_name, lower(p_model_sha), lower(p_adapter_sha), p_dims, p_manifest)
    RETURNING id;
$$;

-- Creating a watch installs a trigger on the table, so only the table's owner may do it, and it
-- writes muninn.watches, which only the DBA is granted. Runs as its caller: the recipe is evaluated
-- here, for the rows already in the table, with the owner's rights and nobody else's.
CREATE FUNCTION muninn.watch(p_name text, p_source regclass, p_key name, p_recipe text,
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
        RAISE EXCEPTION 'muninn: % is not a table', p_source;
    END IF;
    IF NOT pg_has_role(current_user, tbl_owner, 'USAGE') THEN
        RAISE EXCEPTION 'muninn: a watch is a trigger on %, so only its owner may create one', p_source;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = p_source AND a.attname = p_key
                   AND a.attnum > 0 AND NOT a.attisdropped) THEN
        RAISE EXCEPTION 'muninn: % has no column %', p_source, p_key;
    END IF;
    SELECT id INTO rid FROM muninn.readers WHERE name = p_reader;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'muninn: no reader named %', p_reader
            USING HINT = 'Register it with muninn.reader_register(); nothing is read without a sealed reader.';
    END IF;
    -- The recipe must be an expression over the row, aliased r.
    EXECUTE format('SELECT (%s)::text FROM %s r LIMIT 0', p_recipe, p_source);

    INSERT INTO muninn.watches (name, source, key_col, recipe, reader, min_coverage, doubt_below)
    VALUES (p_name, p_source, p_key, p_recipe, rid, p_min_coverage, p_doubt_below)
    RETURNING id INTO wid;

    EXECUTE format('CREATE TRIGGER %I AFTER INSERT OR UPDATE OR DELETE ON %s '
                   'FOR EACH ROW EXECUTE FUNCTION muninn._observe(%L, %L, %L)',
                   'muninn_watch_' || wid, p_source, wid, p_key, p_recipe);

    -- Every row already there is noted, so it is pending until read -- not invisible.
    FOR k, body IN EXECUTE format('SELECT r.%I::text, (%s)::text FROM %s r', p_key, p_recipe, p_source) LOOP
        INSERT INTO muninn.sources (watch, key, text_hash)
        VALUES (wid, k, sha256(convert_to(coalesce(body, ''), 'UTF8')));
    END LOOP;
    RETURN wid;
END;
$$;

-- A new reader for a watch: every reading by the old one becomes foreign at once.
CREATE FUNCTION muninn.reader_switch(p_watch text, p_reader text)
RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    rid int;
BEGIN
    SELECT id INTO rid FROM muninn.readers WHERE name = p_reader;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'muninn: no reader named %', p_reader;
    END IF;
    UPDATE muninn.watches SET reader = rid WHERE name = p_watch;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'muninn: no watch named %', p_watch;
    END IF;
END;
$$;

-- ---------------------------------------------------------- the reader side --

-- What the watch's reader still has to read: never read, read from older text, or read by another
-- reader. Runs as its caller: the recipe is evaluated with the reader role's rights on the table.
CREATE FUNCTION muninn._todo(p_watch text, p_limit int)
RETURNS TABLE (key text)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT s.key
      FROM muninn._watch(p_watch) w
      JOIN muninn.sources s ON s.watch = w.id
      LEFT JOIN muninn.readings r ON r.watch = s.watch AND r.key = s.key AND r.reader = w.reader
     WHERE r.key IS NULL OR r.text_hash <> s.text_hash
     ORDER BY s.changed_at
     LIMIT p_limit;
$$;

CREATE FUNCTION muninn.next(p_watch text, p_limit int DEFAULT 64)
RETURNS TABLE (key text, body text, text_hash bytea)
LANGUAGE plpgsql STABLE
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    w muninn.watches := muninn._watch(p_watch);
BEGIN
    RETURN QUERY EXECUTE format(
        'SELECT r.%1$I::text, (%2$s)::text, sha256(convert_to(coalesce((%2$s)::text, ''''), ''UTF8''))
           FROM %3$s r WHERE r.%1$I::text = ANY ($1)', w.key_col, w.recipe, w.source)
    USING ARRAY(SELECT t.key FROM muninn._todo(p_watch, p_limit) t);
END;
$$;

-- What a reader process must prove before it writes: the sha256 of the weights it loaded. A process
-- that loaded other weights refuses to start, so nothing is recorded in a reader's name by a
-- different model.
CREATE FUNCTION muninn.reader_seal(p_reader text)
RETURNS TABLE (model_sha text, adapter_sha text, dims int)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT r.model_sha, r.adapter_sha, r.dims FROM muninn.readers r WHERE r.name = p_reader;
$$;

-- A reading is accepted only if it is of the text the row says NOW, by the watch's reader.
CREATE FUNCTION muninn.record(p_watch text, p_key text, p_reader text, p_text_hash bytea,
                              p_code64 bigint, p_code smallint[], p_familiarity real DEFAULT NULL)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    w   muninn.watches := muninn._watch(p_watch);
    rd  muninn.readers;
    cur bytea;
BEGIN
    SELECT * INTO rd FROM muninn.readers WHERE name = p_reader;
    IF NOT FOUND OR rd.id <> w.reader THEN
        RAISE EXCEPTION 'muninn: watch % is read by reader #%, not by %', p_watch, w.reader, p_reader
            USING HINT = 'Readings by different readers are never mixed.';
    END IF;
    SELECT s.text_hash INTO cur FROM muninn.sources s WHERE s.watch = w.id AND s.key = p_key;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'muninn: watch % has no row %', p_watch, p_key;
    END IF;
    IF cur IS DISTINCT FROM p_text_hash THEN
        RAISE EXCEPTION 'muninn: row % of watch % changed since it was handed out; this reading would be stale', p_key, p_watch;
    END IF;
    IF p_code64 IS NULL OR p_code IS NULL OR cardinality(p_code) <> rd.dims THEN
        RAISE EXCEPTION 'muninn: reader % produces % dimensions, got %', p_reader, rd.dims, cardinality(p_code);
    END IF;
    IF EXISTS (SELECT 1 FROM unnest(p_code) x WHERE x NOT BETWEEN -128 AND 127) THEN
        RAISE EXCEPTION 'muninn: codes are int8, every value in -128..127';
    END IF;
    INSERT INTO muninn.readings AS r (watch, key, reader, text_hash, code64, code, familiarity, failed, read_at)
    VALUES (w.id, p_key, rd.id, p_text_hash, p_code64, p_code, p_familiarity, NULL, clock_timestamp())
    ON CONFLICT (watch, key, reader) DO UPDATE
       SET text_hash = EXCLUDED.text_hash, code64 = EXCLUDED.code64, code = EXCLUDED.code,
           familiarity = EXCLUDED.familiarity, failed = NULL, read_at = EXCLUDED.read_at;
END;
$$;

CREATE FUNCTION muninn.record_failure(p_watch text, p_key text, p_reader text, p_text_hash bytea, p_reason text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    w  muninn.watches := muninn._watch(p_watch);
    rd muninn.readers;
BEGIN
    SELECT * INTO rd FROM muninn.readers WHERE name = p_reader;
    IF NOT FOUND OR rd.id <> w.reader THEN
        RAISE EXCEPTION 'muninn: watch % is read by reader #%, not by %', p_watch, w.reader, p_reader;
    END IF;
    IF coalesce(p_reason, '') = '' THEN
        RAISE EXCEPTION 'muninn: a failed reading says why';
    END IF;
    INSERT INTO muninn.readings AS r (watch, key, reader, text_hash, failed, read_at)
    VALUES (w.id, p_key, rd.id, p_text_hash, p_reason, clock_timestamp())
    ON CONFLICT (watch, key, reader) DO UPDATE
       SET text_hash = EXCLUDED.text_hash, code64 = NULL, code = NULL, familiarity = NULL,
           failed = EXCLUDED.failed, read_at = EXCLUDED.read_at;
END;
$$;

-- ------------------------------------------------------------------- asking --

-- Exact scan of the 64-bit codes of the readings that still hold, then the best p_m reordered by
-- the full code. Below the watch's coverage it raises instead of answering, unless p_partial.
CREATE FUNCTION muninn.find(p_watch text, p_q64 bigint, p_q smallint[], p_k int DEFAULT 10,
                            p_partial boolean DEFAULT false, p_m int DEFAULT 200)
RETURNS TABLE (key text, score double precision, hamming int, state text, familiarity real, read_at timestamptz)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    w      muninn.watches := muninn._watch(p_watch);
    dims   int;
    fresh  numeric;
    missing text;
    qnorm  double precision;
BEGIN
    SELECT rd.dims INTO dims FROM muninn.readers rd WHERE rd.id = w.reader;
    IF p_q IS NULL OR cardinality(p_q) <> dims THEN
        RAISE EXCEPTION 'muninn: the question must be read by the watch''s reader (% dimensions)', dims;
    END IF;
    IF p_k NOT BETWEEN 1 AND 1000 OR p_m NOT BETWEEN p_k AND 100000 THEN
        RAISE EXCEPTION 'muninn: k must be in 1..1000 and m in k..100000';
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

    SELECT sqrt(sum(x::float8 * x)) INTO qnorm FROM unnest(p_q) x;

    RETURN QUERY
    WITH cand AS (
        SELECT r.key, r.code, r.familiarity, r.read_at,
               bit_count((r.code64 # p_q64)::bit(64))::int AS ham
          FROM muninn.readings r
          JOIN muninn.sources s ON s.watch = r.watch AND s.key = r.key
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
CREATE FUNCTION muninn.alike(p_watch text, p_key text, p_k int DEFAULT 10, p_partial boolean DEFAULT false)
RETURNS TABLE (key text, score double precision, hamming int, state text, familiarity real, read_at timestamptz)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    w   muninn.watches := muninn._watch(p_watch);
    q64 bigint;
    q   smallint[];
BEGIN
    SELECT r.code64, r.code INTO q64, q
      FROM muninn.readings r JOIN muninn.sources s ON s.watch = r.watch AND s.key = r.key
     WHERE r.watch = w.id AND r.key = p_key AND r.reader = w.reader
       AND r.failed IS NULL AND r.text_hash = s.text_hash;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'muninn: row % of watch % has no fresh reading to ask with', p_key, p_watch;
    END IF;
    RETURN QUERY SELECT f.* FROM muninn.find(p_watch, q64, q, p_k + 1, p_partial) f WHERE f.key <> p_key LIMIT p_k;
END;
$$;

-- A dropped table takes its trigger with it; this takes its watch, so no watch is left pointing at a
-- dead oid and answering for rows that no longer exist.
CREATE FUNCTION muninn._on_drop()
RETURNS event_trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    DELETE FROM muninn.watches w
     WHERE NOT EXISTS (SELECT 1 FROM pg_class c WHERE c.oid = w.source);
END;
$$;
CREATE EVENT TRIGGER muninn_watch_source_dropped ON sql_drop
    WHEN TAG IN ('DROP TABLE', 'DROP SCHEMA', 'DROP OWNED')
    EXECUTE FUNCTION muninn._on_drop();

-- ---------------------------------------------------------------- privileges --
-- Readers and askers are granted by the DBA. Nothing is open by default.
REVOKE ALL ON FUNCTION muninn._watch(text), muninn._note(int, text, bytea), muninn._forget(int, text),
    muninn._todo(text, int), muninn.reader_register(text, text, int, text, jsonb),
    muninn.watch(text, regclass, name, text, text, numeric, real), muninn.reader_switch(text, text),
    muninn.record(text, text, text, bytea, bigint, smallint[], real),
    muninn.record_failure(text, text, text, bytea, text),
    muninn.next(text, int), muninn.coverage(text),
    muninn.find(text, bigint, smallint[], int, boolean, int), muninn.alike(text, text, int, boolean),
    muninn._on_drop(), muninn.reader_seal(text)
  FROM PUBLIC;
-- The watch trigger runs as whoever writes the table, so these two must be callable by anyone; they
-- refuse to run outside a trigger.
GRANT EXECUTE ON FUNCTION muninn._observe(), muninn._note(int, text, bytea), muninn._forget(int, text) TO PUBLIC;
