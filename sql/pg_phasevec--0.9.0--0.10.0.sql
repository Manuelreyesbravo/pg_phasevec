-- pg_phasevec 0.10.0: the coarse index keeps itself, and rebuilding it no longer stops the reader.
--
--   phasevec.ivf_maintain(watch)   rebuilds a watch's index when its delta (ivf_dirty, swept row by
--                                  row by every question) passes a threshold; nothing below it
--   phasevec.ivf_maintain_all()    the same for every watch with an index (a timer calls it)
--   phasevec.ivf_build(watch)      a REBUILD no longer locks phasevec.readings: until 0.9.0 it took a
--                                  SHARE lock for the whole build, so the reader waited to record (and,
--                                  being one thread, to answer: phasevec.search timed out meanwhile).
--                                  Now each delta row remembers its transaction, and the build empties
--                                  only the rows committed before it started reading; the rest stay,
--                                  at worst also indexed (a duplicate find_ivf already folds).
-- The lock stays for a FIRST build (or after reader_switch): no index of the watch's reader exists
-- yet, so nothing would put a reading recorded meanwhile in the delta.
-- The multi-watch reader (one process, one model, several watches) is in reader/, not in SQL.
\echo Use "ALTER EXTENSION pg_phasevec UPDATE TO '0.10.0'" to load this file. \quit

ALTER TABLE phasevec.ivf_dirty ADD COLUMN txid xid8 NOT NULL DEFAULT pg_catalog.pg_current_xact_id();
COMMENT ON COLUMN phasevec.ivf_dirty.txid IS
    'The transaction that recorded the reading: a rebuild empties only the rows committed before it read.';

-- A row read again keeps ONE delta row, now with the newer transaction: with the older one, a rebuild
-- that started before this reading could empty it without having indexed it.
CREATE OR REPLACE FUNCTION phasevec._ivf_dirty() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM phasevec.ivf_cents c WHERE c.watch = NEW.watch AND c.reader = NEW.reader) THEN
        INSERT INTO phasevec.ivf_dirty (watch, key) VALUES (NEW.watch, NEW.key)
            ON CONFLICT (watch, key) DO UPDATE SET txid = EXCLUDED.txid;
    END IF;
    RETURN NULL;
END $$;

CREATE FUNCTION phasevec._ivf_build(int, int, int, int, int, int, boolean, boolean) RETURNS int
    AS 'MODULE_PATHNAME', 'phasevec_ivf_build' LANGUAGE C STRICT VOLATILE;
-- the eighth argument keeps the delta (see ivf_build); the seven-argument form stays for old SQL

CREATE OR REPLACE FUNCTION phasevec.ivf_build(p_watch text, p_k int DEFAULT NULL, p_iters int DEFAULT 8,
                                              p_sample int DEFAULT 200000, p_soar boolean DEFAULT true)
RETURNS int LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    w     phasevec.watches := phasevec._watch(p_watch);
    dims  int;
    n     bigint;
    snap  pg_snapshot;
    lists int;
BEGIN
    -- a build is maintenance: the count deltas of a bulk load are folded first (0.7.0), or every
    -- find_ivf after it would sum them in coverage() (measured: ~25 ms per question at 100k)
    PERFORM phasevec.counts_compact(p_watch);
    -- one build of a watch at a time
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('phasevec.ivf_build'), w.id);
    IF EXISTS (SELECT 1 FROM phasevec.ivf_cents c WHERE c.watch = w.id AND c.reader = w.reader) THEN
        -- a rebuild: a reading recorded from now on lands in the delta (the trigger sees the index
        -- still in place). Taken BEFORE the build reads: what this snapshot sees, the build sees.
        snap := pg_catalog.pg_current_snapshot();
    ELSE
        LOCK TABLE phasevec.readings IN SHARE MODE;
    END IF;
    SELECT rd.dims INTO dims FROM phasevec.readers rd WHERE rd.id = w.reader;
    SELECT count(*) INTO n FROM phasevec.readings r WHERE r.watch = w.id AND r.reader = w.reader;
    lists := phasevec._ivf_build(w.id, w.reader, dims, coalesce(p_k, greatest(1, round(sqrt(n))::int)), p_iters,
                                 p_sample, p_soar, true);
    IF snap IS NULL THEN
        DELETE FROM phasevec.ivf_dirty d WHERE d.watch = w.id;
    ELSE
        DELETE FROM phasevec.ivf_dirty d WHERE d.watch = w.id AND pg_catalog.pg_visible_in_snapshot(d.txid, snap);
    END IF;
    RETURN lists;
END $$;

-- The delta in C (phasevec.ivf_delta): its best kk by the exact int8 cosine, each with the text hash its
-- code was read from. Until 0.9.0 every delta row was scored in SQL and offered as a candidate; now the
-- delta offers its best kk, as the lists do: a row among them found stale is dropped by the validation
-- below, exactly as a stale row of a list.
CREATE FUNCTION phasevec.ivf_delta(p_watch int, p_reader int, p_q256 bit(256), p_q smallint[], p_kk int)
RETURNS TABLE (key text, text_hash bytea, score double precision, hamming int)
    AS 'MODULE_PATHNAME', 'phasevec_ivf_delta' LANGUAGE C STRICT STABLE ROWS 50;

CREATE OR REPLACE FUNCTION phasevec._ivf_valid(w phasevec.watches, p_q256 bit(256), p_q smallint[], qnorm float8,
                         p_nprobe int, p_m int, kk int, p_k int)
RETURNS SETOF phasevec.ivf_hit LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    WITH c AS (
        SELECT s.key, s.text_hash, s.score, s.hamming FROM phasevec.ivf_sweep(w.id, p_q256, p_q, p_nprobe, p_m, kk) s
        UNION ALL
        SELECT x.key, x.text_hash, x.score, x.hamming FROM phasevec.ivf_delta(w.id, w.reader, p_q256, p_q, kk) x
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

-- The delta absorbed into the lists, without k-means (phasevec._ivf_absorb): what this snapshot sees
-- gets an ordinal after the index's, its nearest list and SOAR's second, and is appended to them; the
-- lists' older entries for those rows stay and are dropped by validation (their hash no longer matches).
-- Much cheaper than a build; the centroids do not move, so after enough is absorbed a build is due.
ALTER TABLE phasevec.ivf_cents ADD COLUMN absorbed int NOT NULL DEFAULT 0;
COMMENT ON COLUMN phasevec.ivf_cents.absorbed IS
    'Readings appended to the lists by ivf_absorb since the build (n counts them too); a build sets it back to 0.';
-- What absorb adds goes to chunks, one row per touched list, never rewriting a list (load_index joins
-- them; a build consolidates and deletes them). Rewriting the TOASTed lists cost 88-237 ms and 8-20 MB
-- of WAL for 50 readings (b_100k, 22-10).
CREATE TABLE phasevec.ivf_added (
    watch  int NOT NULL REFERENCES phasevec.watches(id) ON DELETE CASCADE,
    seq    bigserial,
    list   int NOT NULL,
    n      int NOT NULL,
    docs   bytea NOT NULL,
    keys   bytea NOT NULL,
    koff   bytea NOT NULL,
    hashes bytea NOT NULL,
    c256   bytea NOT NULL,
    c8     bytea NOT NULL,
    sn     int NOT NULL,
    sdocs  bytea NOT NULL,
    sc256  bytea NOT NULL,
    PRIMARY KEY (watch, seq)
);
COMMENT ON TABLE phasevec.ivf_added IS
    'Entries absorbed into a coarse index since its build: per touched list, the readings it is the first list of and its SOAR copies.';
CREATE FUNCTION phasevec._ivf_absorb(int, int, text) RETURNS int
    AS 'MODULE_PATHNAME', 'phasevec_ivf_absorb' LANGUAGE C STRICT VOLATILE;

CREATE FUNCTION phasevec.ivf_absorb(p_watch text) RETURNS int
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    w    phasevec.watches := phasevec._watch(p_watch);
    snap pg_snapshot;
    got  int;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('phasevec.ivf_build'), w.id);
    IF NOT EXISTS (SELECT 1 FROM phasevec.ivf_cents c WHERE c.watch = w.id AND c.reader = w.reader) THEN
        RAISE EXCEPTION 'phasevec: watch % has no coarse index for its reader to absorb into', p_watch
            USING HINT = 'Build it with phasevec.ivf_build(watch).';
    END IF;
    -- maintenance folds the count deltas first, as a build does: 5.000 changes leave 20.000 of them and
    -- coverage() sums them on every question (measured in b_100k: 2.28 ms against 0.85 folded)
    PERFORM phasevec.counts_compact(p_watch);
    snap := pg_catalog.pg_current_snapshot();
    got := phasevec._ivf_absorb(w.id, w.reader, snap::text);
    DELETE FROM phasevec.ivf_dirty d WHERE d.watch = w.id AND pg_catalog.pg_visible_in_snapshot(d.txid, snap);
    RETURN got;
END $$;
COMMENT ON FUNCTION phasevec.ivf_absorb(text) IS
    'Append the delta of a watch to its coarse index (nearest lists, no k-means); returns how many readings.';

-- The policy. Every question sweeps the whole delta (in C, ~4.4 us a row at 256 dimensions, measured
-- in b_100k): past p_absorb rows it is absorbed. The centroids do not follow what is absorbed, and the
-- stale entries it leaves are swept for nothing: once absorbed + delta reach p_frac of what the build
-- indexed, the index is built again. A watch whose index belongs to another reader (after reader_switch)
-- is rebuilt once the new reader covers min_coverage. A watch without an index is never given one:
-- whether a watch is worth an index is a decision, not maintenance.
CREATE FUNCTION phasevec.ivf_maintain(p_watch text, p_frac double precision DEFAULT 0.1, p_absorb int DEFAULT 50)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    w     phasevec.watches := phasevec._watch(p_watch);
    c     phasevec.ivf_cents;
    d     bigint;
    fresh numeric;
BEGIN
    -- under sustained writes the reader's queue may never empty, and nothing else would fold them
    PERFORM phasevec.counts_compact(p_watch);
    SELECT * INTO c FROM phasevec.ivf_cents x WHERE x.watch = w.id;
    IF NOT FOUND THEN
        RETURN 'none';
    END IF;
    IF c.reader <> w.reader THEN
        SELECT coalesce(sum(v.share) FILTER (WHERE v.state IN ('fresh', 'doubtful')), 0) INTO fresh
          FROM phasevec.coverage(p_watch) v;
        IF fresh < w.min_coverage THEN
            RETURN 'none';
        END IF;
        PERFORM phasevec.ivf_build(p_watch, NULL, 8, 200000, c.soar);
        RETURN 'rebuilt';
    END IF;
    SELECT count(*) INTO d FROM phasevec.ivf_dirty x WHERE x.watch = w.id;
    IF c.absorbed + d >= p_frac * (c.n - c.absorbed) THEN
        PERFORM phasevec.ivf_build(p_watch, NULL, 8, 200000, c.soar);
        RETURN 'rebuilt';
    END IF;
    IF d >= p_absorb THEN
        PERFORM phasevec.ivf_absorb(p_watch);
        RETURN 'absorbed';
    END IF;
    RETURN 'none';
END $$;
COMMENT ON FUNCTION phasevec.ivf_maintain(text, double precision, int) IS
    'Keep a watch''s coarse index: absorb its delta past p_absorb rows, rebuild once absorbed + delta reach p_frac of the build, or after a reader switch once covered. Returns rebuilt, absorbed or none.';

CREATE FUNCTION phasevec.ivf_maintain_all(p_frac double precision DEFAULT 0.1, p_absorb int DEFAULT 50)
RETURNS TABLE (watch text, action text, delta bigint, indexed int, ms numeric)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    r  record;
    t0 timestamptz;
BEGIN
    FOR r IN SELECT w.name, c.n FROM phasevec.ivf_cents c JOIN phasevec.watches w ON w.id = c.watch ORDER BY w.name LOOP
        watch := r.name;
        indexed := r.n;
        SELECT count(*) INTO delta FROM phasevec.ivf_dirty d JOIN phasevec.watches w ON w.id = d.watch WHERE w.name = r.name;
        t0 := clock_timestamp();
        action := phasevec.ivf_maintain(r.name, p_frac, p_absorb);
        ms := round(extract(epoch FROM clock_timestamp() - t0)::numeric * 1000, 1);
        RETURN NEXT;
    END LOOP;
END $$;
COMMENT ON FUNCTION phasevec.ivf_maintain_all(double precision, int) IS
    'phasevec.ivf_maintain for every watch with a coarse index; one row each: what was done, delta, indexed rows, time.';

-- find_ivf's work in C (phasevec._ivf_find): sweep, delta and validation in one call. The checks and the
-- coverage refusal stay here, the contract is find_ivf's of 0.8.0 unchanged (the regression suites
-- compare it with phasevec.find). Measured before (sql/174 and the probe of 22-10): with 16 clients
-- the sweep alone answered twice as many questions as find_ivf around it.
CREATE FUNCTION phasevec._ivf_find(p_watch int, p_reader int, p_q256 bit(256), p_q smallint[], p_nprobe int, p_m int,
                                   p_kk int, p_k int, p_doubt real)
RETURNS SETOF phasevec.ivf_hit
    AS 'MODULE_PATHNAME', 'phasevec_ivf_find' LANGUAGE C STABLE ROWS 10;
REVOKE ALL ON FUNCTION phasevec._ivf_find(int, int, bit(256), smallint[], int, int, int, int, real) FROM PUBLIC;

-- find_ivf itself in C (phasevec_find_ivf): the contract above, unchanged, with prepared plans. The
-- PL/pgSQL around the C cost a quarter of the throughput with 16 clients (probe of 22-10).
CREATE OR REPLACE FUNCTION phasevec.find_ivf(p_watch text, p_q64 bigint, p_q smallint[], p_k int DEFAULT 10,
                          p_partial boolean DEFAULT false, p_m int DEFAULT 200,
                          p_q256 bit(256) DEFAULT NULL, p_nprobe int DEFAULT 16)
RETURNS TABLE (key text, score double precision, hamming int, state text, familiarity real, read_at timestamptz,
               truncated boolean)
    AS 'MODULE_PATHNAME', 'phasevec_find_ivf' LANGUAGE C STABLE SECURITY DEFINER ROWS 10
    SET search_path = pg_catalog, pg_temp;

-- The audit of 22-10 (an independent review and an ASan stress test).
-- (1) A shared copy of an index is keyed by a GENERATION drawn by every build and absorb: the xmin of
--     ivf_cents, used until now, is the same for two changes in one transaction, and the second one's
--     copy was taken for the first's (its readings, already out of the delta, were never found).
CREATE SEQUENCE phasevec.ivf_gen;
ALTER TABLE phasevec.ivf_cents ADD COLUMN gen bigint NOT NULL DEFAULT nextval('phasevec.ivf_gen');
COMMENT ON COLUMN phasevec.ivf_cents.gen IS
    'The version of the index: drawn by every build and absorb, keys its shared copy in memory.';
-- (2) Two compactions at once folded the same deltas into a negative count (reproduced: 7 and 8 of
--     ~700-1400 changes failed with a_count_is_never_negative when counts_compact or ivf_build ran
--     beside a writer that compacts). Compactions take turns, and each one reads after the previous
--     one committed: the lock comes first, the DELETE (a new statement, a new snapshot) after.
CREATE OR REPLACE FUNCTION phasevec.counts_compact(p_watch text DEFAULT NULL)
RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    folded bigint;
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('phasevec.counts_compact'));
    WITH moved AS (
        DELETE FROM phasevec.count_deltas d
         WHERE p_watch IS NULL OR d.watch = (SELECT id FROM phasevec._watch(p_watch))
     RETURNING d.watch, d.state, d.d),
    s AS (SELECT watch, state, sum(d)::bigint AS d, count(*) AS rows FROM moved GROUP BY watch, state),
    u AS (UPDATE phasevec.counts c SET n = c.n + s.d FROM s
           WHERE c.watch = s.watch AND c.state = s.state AND s.d <> 0 RETURNING 1)
    SELECT coalesce(sum(rows), 0) INTO folded FROM s;
    RETURN folded;
END;
$$;
-- (3) The internal functions added in 0.10.0 are not for PUBLIC (the 7-argument _ivf_build was not either).
REVOKE ALL ON FUNCTION phasevec._ivf_build(int, int, int, int, int, int, boolean, boolean) FROM PUBLIC;
REVOKE ALL ON FUNCTION phasevec._ivf_absorb(int, int, text) FROM PUBLIC;
