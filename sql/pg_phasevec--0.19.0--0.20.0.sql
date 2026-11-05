-- pg_phasevec 0.19.0 -> 0.20.0: a verdict is about one claim (the text its author read, the proof, the author),
-- judged in one state under one clock, and the only door to it is a function that knows who calls it.
\echo Use "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" to load this file. \quit

-- Found by the public-readiness review of 2026-11-05, then by an adversarial review of the first cut of 0.20.0
-- (never released) that ran the attacks:
--
-- 1. A 'verified' truth survived any later edit of its row, and brief() served the new text as verified. The first
--    cut bound each verdict to phasevec.sources.text_hash, a cache only the watch trigger keeps: a table owner who
--    disabled the trigger, set session_replication_role = replica, truncated and inserted again, or rewrote the
--    column with DDL (ALTER COLUMN TYPE ... USING, RENAME plus ADD COLUMN DEFAULT) changed the text with the
--    verdict kept. And a proof that did not read the row verified whatever text a writer put there next.
--    Now the claim records what its author vouched for: assert() reads the row through the watch's recipe, with the
--    author's rights, and keeps its hash (asserted_for). verify() reads the live row, as the author, before and
--    after the proof: the text must be the asserted one, and the row must not move while the proof runs (under READ
--    COMMITTED each statement of a proof can see another snapshot: a text that changed and changed back passed).
--    brief() hashes the line it serves and serves it as 'verified' only if that is the text the verdict judged.
--    The cache is never evidence: a stale one only makes _verdict() say 'unproven'.
-- 2. verify() ran each proof with the rights of whoever called it (a confused deputy). A proof runs as its author
--    (src/phasevec_truth.c). The author is the role's OID, used only while that role still has the name it had (a
--    dropped author, or its name taken by another role, runs nothing). The verdict is bound to the author too: an
--    assert by another role while the proof runs leaves nothing recorded.
-- 3. verify() and verify_one() are C: they know their caller, check it, and write through internals that carry no
--    rights of their own (_truth_due, _truth_of, _truth_set run as whoever calls them, and only the owner can read
--    and write phasevec.truth). In the first cut a verifier needed EXECUTE on SECURITY DEFINER internals, and with
--    it forged 'verified' through _truth_set and listed every proof through _truth_due.
-- 4. The proof clock bounds the verdict: a proof that catches query_canceled runs on but is refuted for its time; a
--    proof cannot run another proof (a nested one reset the outer timer); a query_canceled a proof raises itself is
--    that proof's error (it aborted every verify() of the watch); a session advisory lock a proof takes is released.
--    A proof always has a clock (p_timeout_ms > 0): the cost cap is a planner estimate, not a bound.
-- 5. A proof that closed its own parenthesis made two statements and the second ran in the cost step, with no clock
--    and no cap. Fixed in the library, for every version of the SQL.
-- 6. _forget() was executable by PUBLIC behind a pg_trigger_depth() test that any user's own trigger passes, and in
--    the first cut _note() with a NULL hash did the same for whoever was granted _note(). _note() is C now and
--    refuses a caller that does not write the watch's own table; _forget() is the owner's.
-- 7. _brief_keys() is SECURITY DEFINER and was executable by PUBLIC: any role with USAGE on the schema read the
--    keys, verdicts, usefulness and recipes of every watch. It and brief() are granted together, by the owner.

ALTER TABLE phasevec.truth ADD COLUMN asserted_by name, ADD COLUMN asserted_by_oid oid,
                           ADD COLUMN asserted_for bytea, ADD COLUMN verified_for bytea;
COMMENT ON COLUMN phasevec.truth.asserted_by IS
    $q$The name of the role that asserted the proof, when it did (0.20.0). With asserted_by_oid: the proof runs as that role only while the OID still has this name.$q$;
COMMENT ON COLUMN phasevec.truth.asserted_by_oid IS
    $q$The role that asserted the proof (0.20.0): the proof runs with its rights. NULL for a proof asserted before 0.20.0, which does not run until asserted again (phasevec.adopt).$q$;
COMMENT ON COLUMN phasevec.truth.asserted_for IS
    $q$What the author vouched for (0.20.0): sha256 of the row's text, read through the recipe with the author's rights when it asserted. NULL when there was no row.$q$;
COMMENT ON COLUMN phasevec.truth.verified_for IS
    $q$What the verdict judged (0.20.0): sha256 of asserted_for, the proof and the author. A 'verified' that does not match the claim, or whose text is not the row's, reads 'unproven'.$q$;

-- A verdict judges (text, proof, author): fixed-size text hash, then the proof, then the author's OID.
CREATE FUNCTION phasevec._bind(p_text_hash bytea, p_proof text, p_author oid)
RETURNS bytea LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $f$
    SELECT sha256(p_text_hash || convert_to(coalesce(p_proof, $q$$q$), $q$UTF8$q$) || int8send(p_author::bigint))
$f$;

-- The truth a key has NOW. 'verified' only for the claim it judged, and only while the row's text, as the watch
-- trigger last saw it, is the asserted one. (brief() also checks the text it serves; verify() checks the live row.)
CREATE OR REPLACE FUNCTION phasevec._verdict(t phasevec.truth) RETURNS text
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    SELECT CASE WHEN t.verdict = $q$replaced$q$ THEN $q$replaced$q$
                WHEN t.expires_at IS NOT NULL AND t.expires_at <= now() THEN $q$expired$q$
                WHEN t.verdict = $q$verified$q$
                 AND (t.verified_for IS NULL
                      OR t.verified_for IS DISTINCT FROM phasevec._bind(t.asserted_for, t.proof, t.asserted_by_oid)
                      OR t.asserted_for IS DISTINCT FROM (SELECT s.text_hash FROM phasevec.sources s
                                                          WHERE s.watch = t.watch AND s.key = t.key))
                THEN $q$unproven$q$
                ELSE t.verdict END
$f$;

-- A row whose text changes away from what was judged loses its verdict, verified or refuted. Runs inside _note()
-- (as the owner).
CREATE FUNCTION phasevec._truth_text_changed() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $f$
BEGIN
    IF TG_OP = $q$UPDATE$q$ AND OLD.text_hash IS NOT DISTINCT FROM NEW.text_hash THEN
        RETURN NULL;
    END IF;
    UPDATE phasevec.truth t
       SET verdict = $q$unproven$q$, verified_at = NULL, verified_for = NULL, changed_at = now(),
           last_error = $q$the row's text changed after it was judged$q$
     WHERE t.watch = NEW.watch AND t.key = NEW.key AND t.verdict IN ($q$verified$q$, $q$refuted$q$)
       AND t.asserted_for IS DISTINCT FROM NEW.text_hash;
    RETURN NULL;
END;
$f$;
CREATE TRIGGER truth_text_changed AFTER INSERT OR UPDATE OF text_hash ON phasevec.sources
    FOR EACH ROW EXECUTE FUNCTION phasevec._truth_text_changed();

-- assert(): the same signature and grants; now C (src/phasevec_truth.c): it sees who calls it and reads the row
-- with that role's rights. It writes through _assert_set, as the owner.
CREATE FUNCTION phasevec._assert_set(p_watch text, p_key text, p_proof text, p_topic text, p_support jsonb,
                                     p_expires_at timestamptz, p_author oid, p_text_hash bytea)
RETURNS void LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $f$
DECLARE w phasevec.watches := phasevec._watch(p_watch);
BEGIN
    INSERT INTO phasevec.truth AS t (watch, key, proof, topic, support, expires_at,
                                     asserted_by, asserted_by_oid, asserted_for)
    VALUES (w.id, p_key, p_proof, p_topic, p_support, p_expires_at,
            pg_get_userbyid(p_author), p_author, p_text_hash)
    ON CONFLICT (watch, key) DO UPDATE
       SET proof = EXCLUDED.proof, topic = EXCLUDED.topic, support = EXCLUDED.support,
           expires_at = EXCLUDED.expires_at, asserted_by = EXCLUDED.asserted_by,
           asserted_by_oid = EXCLUDED.asserted_by_oid, asserted_for = EXCLUDED.asserted_for,
           verdict = CASE WHEN t.verdict = $q$replaced$q$ THEN t.verdict ELSE $q$unproven$q$ END,
           verified_at = NULL, verified_for = NULL, last_error = NULL, changed_at = now();
END;
$f$;
CREATE OR REPLACE FUNCTION phasevec.assert(p_watch text, p_key text, p_proof text DEFAULT NULL, p_topic text DEFAULT NULL,
                                           p_support jsonb DEFAULT NULL, p_expires_at timestamptz DEFAULT NULL)
RETURNS void AS $q$MODULE_PATHNAME$q$, $q$phasevec_assert$q$ LANGUAGE C VOLATILE;

-- refute(): as in 0.14.1, and the refutation is about the text it refuted (the asserted one, or the row's text as
-- the trigger last saw it when nothing was asserted): when that text changes, it is not refuted any more.
CREATE OR REPLACE FUNCTION phasevec.refute(p_watch text, p_key text, p_reason text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
DECLARE w phasevec.watches := phasevec._watch(p_watch);
BEGIN
    IF coalesce(btrim(p_reason), $q$$q$) = $q$$q$ THEN
        RAISE EXCEPTION $q$phasevec: a refutation says why$q$;
    END IF;
    INSERT INTO phasevec.truth AS t (watch, key, verdict, verified_at, last_error, asserted_for)
    VALUES (w.id, p_key, $q$refuted$q$, now(), p_reason,
            (SELECT s.text_hash FROM phasevec.sources s WHERE s.watch = w.id AND s.key = p_key))
    ON CONFLICT (watch, key) DO UPDATE
       SET verdict = $q$refuted$q$, verified_at = now(), last_error = p_reason, changed_at = now(),
           verified_for = phasevec._bind(t.asserted_for, t.proof, t.asserted_by_oid)
     WHERE t.verdict <> $q$replaced$q$;
END;
$f$;

-- The internals of verify() and verify_one() (src/phasevec_truth.c). They are not SECURITY DEFINER: they read and
-- write phasevec.truth, which only the owner can, so they work only when the C functions call them as the owner.
-- The C side passes the caller's OID, which a caller cannot choose.
--
-- The due proofs p_verifier may run, oldest first; a proof whose author is gone (no role with that OID and name)
-- is due for anyone: what verify() records for it is 'unproven'.
DROP FUNCTION phasevec._truth_due(int, int, interval);
CREATE FUNCTION phasevec._truth_due(p_watch int, p_n int, p_every interval, p_verifier oid)
RETURNS TABLE (key text, proof text, author oid, author_known boolean, asserted_for bytea)
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    SELECT t.key, t.proof, t.asserted_by_oid, r.oid IS NOT NULL, t.asserted_for
      FROM phasevec.truth t
      LEFT JOIN pg_catalog.pg_roles r ON r.oid = t.asserted_by_oid AND r.rolname = t.asserted_by
     WHERE t.watch = p_watch AND t.proof IS NOT NULL AND t.verdict <> $q$replaced$q$
       AND t.asserted_by_oid IS NOT NULL
       AND (t.verified_at IS NULL OR t.verified_at < now() - p_every)
       AND (r.oid IS NULL OR pg_catalog.pg_has_role(p_verifier, r.oid, $q$USAGE$q$))
     ORDER BY t.verified_at NULLS FIRST, t.key
     LIMIT p_n
$f$;

-- One key's claim (verify_one); no row when it has no proof or was replaced.
CREATE FUNCTION phasevec._truth_of(p_watch int, p_key text)
RETURNS TABLE (key text, proof text, author oid, author_known boolean, asserted_for bytea)
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    SELECT t.key, t.proof, t.asserted_by_oid, r.oid IS NOT NULL, t.asserted_for
      FROM phasevec.truth t
      LEFT JOIN pg_catalog.pg_roles r ON r.oid = t.asserted_by_oid AND r.rolname = t.asserted_by
     WHERE t.watch = p_watch AND t.key = p_key AND t.proof IS NOT NULL AND t.verdict <> $q$replaced$q$
$f$;

-- Record what a proof's run found, only for the claim it judged: the same proof, the same author, and (for a
-- verdict) the same asserted text. Anything else changed meanwhile: nothing is recorded. p_outcome NULL records
-- nothing (the row moved while the proof ran). Returns the verdict as it reads now.
DROP FUNCTION phasevec._truth_set(int, text, boolean, text);
CREATE FUNCTION phasevec._truth_set(p_watch int, p_key text, p_outcome text, p_error text, p_text_hash bytea,
                                    p_proof text, p_author oid)
RETURNS text LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $f$
DECLARE v text;
BEGIN
    IF p_outcome IS NOT NULL THEN
        UPDATE phasevec.truth t
           SET verdict = p_outcome, verified_at = now(), last_error = p_error,
               verified_for = CASE WHEN p_outcome IN ($q$verified$q$, $q$refuted$q$)
                                   THEN phasevec._bind(t.asserted_for, t.proof, t.asserted_by_oid) END
         WHERE t.watch = p_watch AND t.key = p_key AND t.verdict <> $q$replaced$q$
           AND t.proof IS NOT DISTINCT FROM p_proof AND t.asserted_by_oid IS NOT DISTINCT FROM p_author
           AND (p_outcome = $q$unproven$q$ OR t.asserted_for = p_text_hash);
    END IF;
    SELECT phasevec._verdict(t) INTO v FROM phasevec.truth t WHERE t.watch = p_watch AND t.key = p_key;
    RETURN v;
END;
$f$;

-- verify() and verify_one(): the same signatures and grants; now C. See src/phasevec_truth.c.
CREATE OR REPLACE FUNCTION phasevec.verify(p_watch text, p_n int DEFAULT 100,
                                           p_every interval DEFAULT interval $q$10 minutes$q$,
                                           p_budget interval DEFAULT interval $q$5 seconds$q$,
                                           p_timeout_ms int DEFAULT 2000, p_max_cost float8 DEFAULT 1e6)
RETURNS TABLE (key text, verdict text, error text)
AS $q$MODULE_PATHNAME$q$, $q$phasevec_verify$q$ LANGUAGE C VOLATILE;
CREATE OR REPLACE FUNCTION phasevec.verify_one(p_watch text, p_key text, p_timeout_ms int DEFAULT 2000,
                                               p_max_cost float8 DEFAULT 1e6)
RETURNS text AS $q$MODULE_PATHNAME$q$, $q$phasevec_verify_one$q$ LANGUAGE C VOLATILE;

DROP FUNCTION phasevec._prove_c(text, int, float8);

-- Proofs asserted before 0.20.0 have no author, and after a restore into another cluster (or a DROP ROLE) an author
-- OID may name no role, or another one. adopt() asserts every such proof of a watch again AS THE CALLER (it becomes
-- their author, and they are bound to the text the caller reads now). The owner runs it, as itself or after SET
-- ROLE to the role that should own them. Replaced keys are left as they are.
CREATE FUNCTION phasevec.adopt(p_watch text) RETURNS int
LANGUAGE plpgsql AS $f$
DECLARE
    w phasevec.watches := phasevec._watch(p_watch);
    t record;
    n int := 0;
BEGIN
    FOR t IN SELECT x.key, x.proof, x.topic, x.support, x.expires_at FROM phasevec.truth x
              WHERE x.watch = w.id AND x.proof IS NOT NULL AND x.verdict OPERATOR(pg_catalog.<>) $q$replaced$q$
                AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles r
                                 WHERE r.oid OPERATOR(pg_catalog.=) x.asserted_by_oid
                                   AND r.rolname OPERATOR(pg_catalog.=) x.asserted_by)
              ORDER BY x.key LOOP
        PERFORM phasevec.assert(p_watch, t.key, t.proof, t.topic, t.support, t.expires_at);
        n := n OPERATOR(pg_catalog.+) 1;
    END LOOP;
    RETURN n;
END;
$f$;
COMMENT ON FUNCTION phasevec.adopt(text) IS
    $q$Asserts again, as the caller, every proof of a watch whose author is unknown (asserted before 0.20.0) or gone. Owner only.$q$;

-- Verdicts reached before 0.20.0 were reached with the verifier's rights and about no claim: a 'verified' is not
-- carried over (back to unproven, with the reason in last_error). A 'refuted' stays refuted, about the row's text
-- as it is now. Their proofs have no author and do not run until asserted again (phasevec.adopt).
UPDATE phasevec.truth
   SET verdict = $q$unproven$q$, verified_at = NULL, changed_at = now(),
       last_error = $q$verified before 0.20.0, with the verifier's rights: not carried over$q$
 WHERE verdict = $q$verified$q$;
UPDATE phasevec.truth t SET asserted_for = s.text_hash
  FROM phasevec.sources s
 WHERE s.watch = t.watch AND s.key = t.key AND t.verdict = $q$refuted$q$;

-- 6. The watch trigger notes and forgets through _note(), now C: it passes its caller to _note_set, which refuses a
-- role that does not write the watch's table. A NULL hash forgets the key.
CREATE FUNCTION phasevec._note_set(p_watch int, p_key text, p_hash bytea, p_body text, p_writer oid)
RETURNS void LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    src regclass;
    cfg regconfig;
    lx  tsvector;
BEGIN
    IF pg_trigger_depth() = 0 THEN
        RAISE EXCEPTION 'phasevec: _note() is called by a watch trigger, not directly';
    END IF;
    SELECT w.source, w.lexical INTO src, cfg FROM phasevec.watches w WHERE w.id = p_watch;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'phasevec: no watch %', p_watch;
    END IF;
    IF NOT (has_table_privilege(p_writer, src, 'INSERT, UPDATE, DELETE')
            OR has_any_column_privilege(p_writer, src, 'INSERT, UPDATE')) THEN
        RAISE EXCEPTION 'phasevec: role % does not write %, so it may not note its rows',
            pg_get_userbyid(p_writer), src;
    END IF;
    IF p_hash IS NULL THEN
        DELETE FROM phasevec.sources WHERE watch = p_watch AND key = p_key;
        RETURN;
    END IF;
    IF cfg IS NOT NULL THEN
        lx := phasevec._lexemes(cfg, p_body);
    END IF;
    INSERT INTO phasevec.sources AS s (watch, key, text_hash, lexemes, lexeme_n)
    VALUES (p_watch, p_key, p_hash, lx, length(lx))
    ON CONFLICT (watch, key) DO UPDATE
       SET text_hash = EXCLUDED.text_hash,
           lexemes = EXCLUDED.lexemes,
           lexeme_n = EXCLUDED.lexeme_n,
           changed_at = CASE WHEN s.text_hash IS DISTINCT FROM EXCLUDED.text_hash
                             THEN clock_timestamp() ELSE s.changed_at END;
    PERFORM pg_notify('phasevec', p_watch::text);
END;
$$;
CREATE OR REPLACE FUNCTION phasevec._note(p_watch int, p_key text, p_hash bytea, p_body text)
RETURNS void AS $q$MODULE_PATHNAME$q$, $q$phasevec_note$q$ LANGUAGE C VOLATILE;

CREATE OR REPLACE FUNCTION phasevec._observe()
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
        PERFORM phasevec._note(TG_ARGV[0]::int, old_key, NULL, NULL);
    END IF;
    IF new_key IS NOT NULL THEN
        PERFORM phasevec._note(TG_ARGV[0]::int, new_key,
                             sha256(convert_to(coalesce(body, ''), 'UTF8')), body);
    END IF;
    RETURN NULL;
END;
$$;

-- 7. brief(): a key reads 'verified' only if the line served is the text the verdict judged, as it is read now with
-- the caller's rights. _brief_keys() gives, for a verified key, the hash of that text (judged).
DROP FUNCTION phasevec._brief_keys(text);
CREATE FUNCTION phasevec._brief_keys(p_watch text)
RETURNS TABLE (key text, verdict text, net_use bigint, seen timestamptz, src regclass, key_col name, recipe text,
               judged bytea)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
    SELECT s.key, coalesce(phasevec._verdict(t), $q$unproven$q$),
           coalesce(u.helped, 0) - coalesce(u.not_helped, 0),
           coalesce(t.verified_at, t.changed_at), w.source, w.key_col, w.recipe,
           CASE WHEN phasevec._verdict(t) = $q$verified$q$ THEN t.asserted_for END
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
CREATE OR REPLACE FUNCTION phasevec.brief(p_watch text, p_budget int DEFAULT 8000)
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
        EXIT WHEN used >= p_budget;   -- full: reading the rest of a large watch would serve nothing
        EXECUTE pg_catalog.format($q$SELECT (%s)::text FROM %s r WHERE r.%I::text = $1$q$, r.recipe, r.src, r.key_col)
           INTO line USING r.key;
        CONTINUE WHEN line IS NULL OR used + pg_catalog.length(line) > p_budget;
        used := used + pg_catalog.length(line);
        key := r.key; net_use := r.net_use;
        -- 0.20.0: the verdict is about a text; this is the text served
        verdict := CASE WHEN r.verdict = $q$verified$q$
                         AND r.judged IS DISTINCT FROM pg_catalog.sha256(pg_catalog.convert_to(line, $q$UTF8$q$))
                        THEN $q$unproven$q$ ELSE r.verdict END;
        RETURN NEXT;
    END LOOP;
END;
$f$;

-- ---------------------------------------------------------------- privileges --
-- New internals: the owner only (and they carry no rights of their own). A verifier other than the owner is
-- granted verify() or verify_one(), nothing else; it runs only the proofs whose author it may act as.
REVOKE ALL ON FUNCTION phasevec._bind(bytea, text, oid), phasevec._truth_text_changed(),
    phasevec._assert_set(text, text, text, text, jsonb, timestamptz, oid, bytea),
    phasevec._truth_due(int, int, interval, oid), phasevec._truth_of(int, text),
    phasevec._truth_set(int, text, text, text, bytea, text, oid),
    phasevec._note_set(int, text, bytea, text, oid), phasevec.adopt(text)
  FROM PUBLIC;
-- 6 and 7: closed to PUBLIC. brief() needs _brief_keys(), so whoever may brief gets both:
--   GRANT EXECUTE ON FUNCTION phasevec.brief(text, int), phasevec._brief_keys(text) TO <role>;
REVOKE ALL ON FUNCTION phasevec._forget(int, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION phasevec._brief_keys(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION phasevec.brief(text, int) FROM PUBLIC;
COMMENT ON FUNCTION phasevec._brief_keys(text) IS
    $q$Keys, verdicts, usefulness, recipe and judged text hash of a watch, with the owner's rights, for brief(). Not PUBLIC (0.20.0): granted with brief().$q$;
