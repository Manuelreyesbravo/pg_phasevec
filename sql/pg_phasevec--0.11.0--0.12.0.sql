-- pg_phasevec 0.12.0: exact search on the NPU (phasevec-npu).
--
-- phasevec-npu keeps a COPY of a watch's readings on the Ryzen AI NPU and sweeps all of them for up to 8
-- questions per pass (measured, sql/183-184: 1M readings in ~6 ms, top-10 identical to the exact one). The
-- copy is a photograph: this version is what keeps answers built on it exact and fresh.
--
--   phasevec.npu_snaps   one row per watch with a copy: its reader and the snapshot the copy was read in
--   phasevec.npu_dirty   readings recorded after it (the same trigger that feeds ivf_dirty), with their txid
--   phasevec.find_npu()  the copy's top-32 validated against the current readings and sources (a changed or
--                        deleted row never comes back), plus the dirty rows scored exactly; refuses instead
--                        of answering when fewer than k of the 32 are still current.
--
-- The server registers itself in two steps so that no reading falls between the copy and the dirty list:
-- npu_begin() (from then on, writes are listed), wait until every transaction older than that is over,
-- read under a REPEATABLE READ snapshot, npu_loaded() (forgets the dirty rows that snapshot already saw).

CREATE TABLE phasevec.npu_snaps (
    watch     int PRIMARY KEY REFERENCES phasevec.watches (id) ON DELETE CASCADE,
    reader    int NOT NULL,
    since     xid8 NOT NULL DEFAULT pg_catalog.pg_current_xact_id(),
    snap      pg_snapshot,
    loaded_at timestamptz,
    n         bigint
);
COMMENT ON TABLE phasevec.npu_snaps IS
    'Watches with a copy on the NPU (phasevec-npu): the reader it holds and the snapshot it was read in (NULL while loading).';

CREATE TABLE phasevec.npu_dirty (
    watch int NOT NULL,
    key   text NOT NULL,
    txid  xid8 NOT NULL DEFAULT pg_catalog.pg_current_xact_id(),
    PRIMARY KEY (watch, key)
);
COMMENT ON TABLE phasevec.npu_dirty IS
    'Readings recorded since a watch''s NPU copy was registered; find_npu scores them exactly next to the copy''s answer.';
REVOKE ALL ON phasevec.npu_snaps, phasevec.npu_dirty FROM PUBLIC;

CREATE OR REPLACE FUNCTION phasevec._ivf_dirty() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM phasevec.ivf_cents c WHERE c.watch = NEW.watch AND c.reader = NEW.reader) THEN
        INSERT INTO phasevec.ivf_dirty (watch, key) VALUES (NEW.watch, NEW.key)
            ON CONFLICT (watch, key) DO UPDATE SET txid = EXCLUDED.txid;
    END IF;
    IF EXISTS (SELECT 1 FROM phasevec.npu_snaps n WHERE n.watch = NEW.watch AND n.reader = NEW.reader) THEN
        INSERT INTO phasevec.npu_dirty (watch, key) VALUES (NEW.watch, NEW.key)
            ON CONFLICT (watch, key) DO UPDATE SET txid = EXCLUDED.txid;
    END IF;
    RETURN NULL;
END $$;

CREATE FUNCTION phasevec.npu_begin(p_watch text) RETURNS xid8
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    w phasevec.watches := phasevec._watch(p_watch);
BEGIN
    DELETE FROM phasevec.npu_dirty d WHERE d.watch = w.id;
    INSERT INTO phasevec.npu_snaps (watch, reader) VALUES (w.id, w.reader)
        ON CONFLICT (watch) DO UPDATE SET reader = EXCLUDED.reader, since = pg_catalog.pg_current_xact_id(),
                                          snap = NULL, loaded_at = NULL, n = NULL;
    RETURN pg_catalog.pg_current_xact_id();
END $$;
COMMENT ON FUNCTION phasevec.npu_begin(text) IS
    'phasevec-npu, step 1: from this commit on, readings of the watch are listed in npu_dirty. Returns the xid to wait past before reading.';

CREATE FUNCTION phasevec.npu_loaded(p_watch text, p_snap pg_snapshot, p_n bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    w phasevec.watches := phasevec._watch(p_watch);
BEGIN
    UPDATE phasevec.npu_snaps n SET snap = p_snap, loaded_at = clock_timestamp(), n = p_n WHERE n.watch = w.id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'phasevec: watch % did not begin an NPU copy', p_watch;
    END IF;
    DELETE FROM phasevec.npu_dirty d WHERE d.watch = w.id AND pg_catalog.pg_visible_in_snapshot(d.txid, p_snap);
END $$;
COMMENT ON FUNCTION phasevec.npu_loaded(text, pg_snapshot, bigint) IS
    'phasevec-npu, step 2: the copy was read in p_snap; the dirty rows that snapshot saw are in the copy and leave the list.';

CREATE FUNCTION phasevec.npu_end(p_watch text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    w phasevec.watches := phasevec._watch(p_watch);
BEGIN
    DELETE FROM phasevec.npu_snaps n WHERE n.watch = w.id;
    DELETE FROM phasevec.npu_dirty d WHERE d.watch = w.id;
END $$;
COMMENT ON FUNCTION phasevec.npu_end(text) IS 'phasevec-npu stops: no copy, writes are no longer listed.';

CREATE FUNCTION phasevec._npu_ask(text, text) RETURNS text
    AS 'MODULE_PATHNAME', 'phasevec_npu_ask' LANGUAGE C STRICT VOLATILE;
COMMENT ON FUNCTION phasevec._npu_ask(text, text) IS
    'One question to <phasevec.socket_dir>/<watch>.npu.sock: "k v0,...,v255"; returns the lines "key<TAB>score<TAB>hash" up to the blank one.';

CREATE FUNCTION phasevec.find_npu(p_watch text, p_q smallint[], p_k int DEFAULT 10, p_partial boolean DEFAULT false)
RETURNS TABLE (key text, score double precision, hamming int, state text, familiarity real, read_at timestamptz,
               truncated boolean)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    w       phasevec.watches := phasevec._watch(p_watch);
    ns      phasevec.npu_snaps;
    dims    int;
    fresh   numeric;
    missing text;
    qnorm   double precision;
    resp    text;
    ks      text[];
    hs      bytea[];
    ss      float8[];
    cands   int;
    vigentes int;
BEGIN
    SELECT rd.dims INTO dims FROM phasevec.readers rd WHERE rd.id = w.reader;
    IF p_q IS NULL OR cardinality(p_q) <> dims THEN
        RAISE EXCEPTION 'phasevec: the question must be read by the watch''s reader (% dimensions)', dims;
    END IF;
    IF p_k NOT BETWEEN 1 AND 32 THEN
        RAISE EXCEPTION 'phasevec: find_npu answers k in 1..32 (each NPU tile keeps its best 32)';
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
    SELECT * INTO ns FROM phasevec.npu_snaps x WHERE x.watch = w.id;
    IF NOT FOUND OR ns.snap IS NULL OR ns.reader <> w.reader THEN
        RAISE EXCEPTION 'phasevec: watch % has no NPU copy of its current reader', p_watch
            USING HINT = 'Start phasevec-npu for it, or use phasevec.find / find_ivf.';
    END IF;

    resp := phasevec._npu_ask(p_watch, '32 ' || array_to_string(p_q, ','));
    IF resp LIKE 'ERR%' THEN
        RAISE EXCEPTION 'phasevec: the NPU server answered: %', resp;
    END IF;
    SELECT sqrt(sum(x::float8 * x)) INTO qnorm FROM unnest(p_q) x;

    SELECT array_agg(split_part(l, E'\t', 1)), array_agg(decode(split_part(l, E'\t', 3), 'hex')),
           array_agg(split_part(l, E'\t', 2)::float8)
      INTO ks, hs, ss FROM string_to_table(resp, E'\n') l WHERE l <> '';
    cands := coalesce(cardinality(ks), 0);
    SELECT count(*) INTO vigentes
      FROM unnest(ks, hs) c(key, h)
      JOIN phasevec.readings r ON r.watch = w.id AND r.key = c.key AND r.reader = w.reader AND r.failed IS NULL AND r.text_hash = c.h
      JOIN phasevec.sources s ON s.watch = w.id AND s.key = c.key AND s.text_hash = c.h;
    -- exact iff k of the copy's 32 best are still current: every reading of the copy outside them scores no more
    IF cands = 32 AND vigentes < p_k THEN
        RAISE EXCEPTION 'phasevec: the NPU copy of % changed too much for an exact top-% (% of its 32 best still current)',
            p_watch, p_k, vigentes USING HINT = 'Restart phasevec-npu to take a new copy.';
    END IF;

    RETURN QUERY
    -- the copy's candidates still current keep the server's score: same hash = same reading = same code, and
    -- the server computes find's formula in double and prints it exactly (%.17g). Only the dirty rows are scored here.
    WITH todo AS (
        SELECT DISTINCT ON (u.key) u.* FROM (
            SELECT r.key, c.sc, r.familiarity, r.read_at, r.truncated
              FROM unnest(ks, hs, ss) c(key, h, sc)
              JOIN phasevec.readings r ON r.watch = w.id AND r.key = c.key AND r.reader = w.reader AND r.failed IS NULL AND r.text_hash = c.h
              JOIN phasevec.sources s ON s.watch = w.id AND s.key = c.key AND s.text_hash = c.h
            UNION ALL
            SELECT r.key,
                   (SELECT sum(a::float8 * b) FROM unnest(r.code, p_q) z(a, b))
                     / nullif((SELECT sqrt(sum(a::float8 * a)) FROM unnest(r.code) a) * qnorm, 0),
                   r.familiarity, r.read_at, r.truncated
              FROM phasevec.npu_dirty d
              JOIN phasevec.readings r ON r.watch = d.watch AND r.key = d.key AND r.reader = w.reader AND r.failed IS NULL
              JOIN phasevec.sources s ON s.watch = w.id AND s.key = r.key AND s.text_hash = r.text_hash
             WHERE d.watch = w.id
        ) u ORDER BY u.key
    )
    SELECT t.key,
           t.sc,
           NULL::int,
           CASE WHEN w.doubt_below IS NOT NULL AND t.familiarity < w.doubt_below THEN 'doubtful' ELSE 'fresh' END,
           t.familiarity, t.read_at, t.truncated
      FROM todo t
     ORDER BY 2 DESC NULLS LAST, t.key
     LIMIT p_k;
END $$;
COMMENT ON FUNCTION phasevec.find_npu(text, smallint[], int, boolean) IS
    'Exact top-k (k <= 32) of a watch from its NPU copy (phasevec-npu): validated against the current readings and sources, plus the readings recorded since the copy, scored exactly. Same columns as find (hamming NULL).';

REVOKE ALL ON FUNCTION phasevec.npu_begin(text), phasevec.npu_loaded(text, pg_snapshot, bigint),
                       phasevec.npu_end(text), phasevec._npu_ask(text, text) FROM PUBLIC;
