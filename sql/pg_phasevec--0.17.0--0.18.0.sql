-- pg_phasevec 0.17.0 -> 0.18.0: brief(), what a watch holds as still true, armed under a budget.
\echo Use "ALTER EXTENSION pg_phasevec UPDATE TO '0.18.0'" to load this file. \quit

-- Proven in yggdrasil (sql/201, sql/205, 31-10): a working state kept as a watch (pending items, decisions,
-- facts) is handed to a model as "what still holds", best first, inside a budget -- instead of a flat list that
-- keeps serving what was closed, refuted or went stale. brief() is that, for any watch.
--
-- Order: verified first, then net usefulness (helped - not_helped), then the most recently confirmed, then key.
-- Only what is still served: replaced, expired and refuted keys never come out. The budget counts the characters
-- of the lines; a line that does not fit is skipped and a shorter one after it may still fit.

-- Keys and truth only (like search(): no text), with the owner's rights: the watch tables are not public.
CREATE FUNCTION phasevec._brief_keys(p_watch text)
RETURNS TABLE (key text, verdict text, net_use bigint, seen timestamptz, src regclass, key_col name, recipe text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
    SELECT s.key, coalesce(phasevec._verdict(t), $q$unproven$q$),
           coalesce(u.helped, 0) - coalesce(u.not_helped, 0),
           coalesce(t.verified_at, t.changed_at), w.source, w.key_col, w.recipe
      FROM phasevec.watches w
      JOIN phasevec.sources s ON s.watch = w.id
      LEFT JOIN phasevec.truth t ON t.watch = w.id AND t.key = s.key
      LEFT JOIN phasevec.usefulness u ON u.watch = w.id AND u.key = s.key
     WHERE w.name = p_watch
       AND coalesce(phasevec._verdict(t), $q$unproven$q$) IN ($q$verified$q$, $q$unproven$q$)
     ORDER BY (coalesce(phasevec._verdict(t), $q$unproven$q$) = $q$verified$q$) DESC,
              coalesce(u.helped, 0) - coalesce(u.not_helped, 0) DESC,
              coalesce(t.verified_at, t.changed_at) DESC NULLS LAST, s.key
$f$;
REVOKE ALL ON FUNCTION phasevec._brief_keys(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION phasevec._brief_keys(text) TO PUBLIC;

-- The text comes from the watched table with the CALLER's rights: a brief never shows a row its caller could not
-- read. The line is the watch's own recipe over the row.
CREATE FUNCTION phasevec.brief(p_watch text, p_budget int DEFAULT 8000)
RETURNS TABLE (key text, verdict text, net_use bigint, line text)
LANGUAGE plpgsql STABLE AS $f$
DECLARE
    r    record;
    used int := 0;
BEGIN
    IF p_budget IS NULL OR p_budget < 1 THEN
        RAISE EXCEPTION $q$phasevec: a brief needs a positive budget$q$;
    END IF;
    FOR r IN SELECT * FROM phasevec._brief_keys(p_watch) LOOP
        EXECUTE pg_catalog.format($q$SELECT (%s)::text FROM %s r WHERE r.%I::text = $1$q$, r.recipe, r.src, r.key_col)
           INTO line USING r.key;
        CONTINUE WHEN line IS NULL OR used + pg_catalog.length(line) > p_budget;
        used := used + pg_catalog.length(line);
        key := r.key; verdict := r.verdict; net_use := r.net_use;
        RETURN NEXT;
    END LOOP;
END;
$f$;
COMMENT ON FUNCTION phasevec.brief(text, int) IS
    $q$What a watch holds as still true, best first (verified, useful, recent), inside a budget of characters. Text read with the caller's rights.$q$;
