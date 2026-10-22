-- pg_phasevec 0.7.0: coverage counts kept as DELTAS, so a bulk load is linear and writers do not queue.
--
-- Until 0.6.0 every change of a row's state did UPDATE phasevec.counts on ONE row per (watch, state).
-- Inside one transaction each of those updates walks the dead versions left by the ones before it:
-- a million rows in one COPY never finished (still in the triggers after 50 minutes, 2026-10-21,
-- Track B at 1M; 100k took 56 s). Between transactions the same row serialized every writer of a
-- watch behind one row lock.
--
-- Now a change appends a row to phasevec.count_deltas (no shared row, no lock, O(1)); the base counts
-- plus the deltas are the counts. phasevec.counts_compact() folds the deltas into the base: the reader
-- calls it when its queue drains, a bulk load calls it when it ends. Until then coverage() sums the
-- deltas too: always right, only slower while many are pending. coverage_check() still compares the
-- result with a full recount of the tables.
\echo Use "ALTER EXTENSION pg_phasevec UPDATE TO '0.7.0'" to load this file. \quit

CREATE TABLE phasevec.count_deltas (
    watch int    NOT NULL REFERENCES phasevec.watches(id) ON DELETE CASCADE,
    state text   NOT NULL CHECK (state IN ('fresh', 'doubtful', 'stale', 'pending', 'failed', 'foreign', 'orphan')),
    d     bigint NOT NULL
);
CREATE INDEX count_deltas_watch ON phasevec.count_deltas (watch);
COMMENT ON TABLE phasevec.count_deltas IS
    'Changes to phasevec.counts not folded in yet (phasevec.counts_compact). The counts are base + deltas.';
REVOKE ALL ON phasevec.count_deltas FROM PUBLIC;

CREATE OR REPLACE FUNCTION phasevec._refresh(p_watch int, p_key text)
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

    -- 0.7.0: a delta row, never an UPDATE of the one counts row (see the head of this file)
    INSERT INTO phasevec.count_deltas (watch, state, d)
    SELECT p_watch, x.state, sum(x.delta)::bigint
      FROM (VALUES (old_main, -1), (new_main, 1),
                   ('foreign', new_foreign - old_foreign),
                   ('orphan', new_orphan::int - old_orphan::int)) x(state, delta)
     WHERE x.state IS NOT NULL
     GROUP BY x.state
    HAVING sum(x.delta) <> 0;

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

CREATE OR REPLACE FUNCTION phasevec._recount(p_watch int)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    DELETE FROM phasevec.kstate WHERE watch = p_watch;
    DELETE FROM phasevec.count_deltas WHERE watch = p_watch;   -- the absolute counts replace them
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

-- Same answer as before: base counts plus the deltas not folded in yet.
CREATE OR REPLACE FUNCTION phasevec.coverage(p_watch text)
RETURNS TABLE (state text, n bigint, share numeric)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    WITH w AS (SELECT * FROM phasevec._watch(p_watch)),
    c AS (SELECT x.state, sum(x.n)::bigint AS n
            FROM (SELECT c.state, c.n FROM phasevec.counts c, w WHERE c.watch = w.id
                  UNION ALL
                  SELECT d.state, d.d FROM phasevec.count_deltas d, w WHERE d.watch = w.id) x
           GROUP BY x.state),
    total AS (SELECT coalesce(sum(n), 0) AS t FROM c WHERE state NOT IN ('foreign', 'orphan'))
    SELECT st.state, coalesce(c.n, 0),
           CASE WHEN (SELECT t FROM total) = 0 OR st.state IN ('foreign', 'orphan') THEN NULL
                ELSE round(coalesce(c.n, 0)::numeric / (SELECT t FROM total), 4) END
      FROM unnest(ARRAY['fresh','doubtful','stale','pending','failed','foreign','orphan']) WITH ORDINALITY st(state, o)
      LEFT JOIN c ON c.state = st.state
     ORDER BY st.o;
$$;

-- Folds the deltas of one watch (or of every watch) into the base counts, in one statement: the rows
-- it deletes are exactly the ones it adds, and deltas written meanwhile by other transactions are not
-- in its snapshot, so they stay for the next time. Returns how many delta rows it folded. The base
-- keeps its check: a count that would go negative fails here, loudly.
CREATE FUNCTION phasevec.counts_compact(p_watch text DEFAULT NULL)
RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    folded bigint;
BEGIN
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
COMMENT ON FUNCTION phasevec.counts_compact(text) IS
    'Folds the count deltas into the base counts. Call it after a bulk load; the reader calls it when its queue drains.';
