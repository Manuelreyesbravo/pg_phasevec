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
--    keys, verdicts, usefulness and recipes of every watch. It is the owner's; brief() is granted by the owner.
--
-- Then a second adversarial review ran attacks against that second cut (also never released), and they come from
-- one root: phasevec ran code that was not its own (the recipe, the proof) in more than one way, and in some of them
-- with the rights or the settings of whoever happened to call it. Now there is one guard (src/phasevec_guard.c):
--
-- 8. brief() ran the recipe as its caller with full rights, outside the read-only, security-restricted guard of
--    assert() and verify(): a table owner swapped a column's type for one whose cast was its own code, and a
--    superuser reading the brief made it superuser. A recipe now renders as the table's OWNER (as PostgreSQL runs an
--    index expression in VACUUM or REINDEX), in the guard, everywhere: the watch trigger, assert, verify, brief,
--    next, lexical, audit_sample, watch. Who may read the text is the reader's own right (SELECT on the table; with
--    row-level security, the rows it sees, found as the reader).
-- 9. The text and the proof depended on the session's settings: a writer in another TimeZone (or DateStyle) made an
--    edited row print as the text its author had vouched for, and it was served 'verified'; a verifier in another
--    DateStyle read the author's '01/11/2026' as 11 January and recorded 'verified' for a row the proof, as written,
--    refutes. A recipe renders in pinned settings (DateStyle ISO, TimeZone UTC, extra_float_digits 1, bytea_output
--    hex, search_path pg_catalog, pg_temp, lc_* C, ...), so every reader reads one text; a claim records its
--    author's settings (truth.proof_env) and its proof runs with them, so it means what it meant to its author.
-- 10. A proof could change the verifier's session for good: set transaction_timeout and end the verifier's
--    connection with a FATAL before any verdict was written (every later verify() of the watch died the same way);
--    release the verifier's own session advisory locks; reseed its random(). In the guard the timeouts cannot be
--    changed, and the functions that change the session past a rollback cannot be called. A proof whose verifier's
--    session ends anyway is refuted by the next verify() of the watch, and not run again until asserted again.
-- 11. adopt() made its caller (usually the superuser owner) the author of any orphaned proof, unseen; a role could
--    orphan its own proof on purpose to have it adopted. adopt() now names the author, needs its privileges, works
--    granted and after SET ROLE, returns every proof with its former author, and makes a superuser the author of a
--    key only when that key is named.
-- 12. recall(), disputes(), replacement() and truth_coverage() showed every watch's keys, verdicts, topics, reasons
--    and support to any role with USAGE on the schema. They are one C door now: a watch is shown only to a role that
--    may SELECT its table (and with row-level security, only the keys of the rows it sees).
-- 13. _note() checked that its caller wrote the watched table at all: a writer limited by row-level security, or
--    with UPDATE on one unrelated column, forged, invented or forgot every key of the watch. The watch trigger is C
--    now and renders the row it fires for; _note() is gone.
--
-- Then a third adversarial review ran attacks against the third cut (ee1ec24, never released). The guard is now a
-- sealed room (src/phasevec_guard.c), and the doors compute over what their caller sees:
--
-- 14. A recipe had no subtransaction of its own: it read its caller's open cursor (a superuser's, over a table its
--    owner could not read) and NOTIFYed the rows out at the caller's COMMIT; a proof read, used up and printed its
--    verifier's open cursor. Each guard is a subtransaction, always rolled back; the session's cursors are frozen
--    while it runs; only a reviewed few commands and volatile system functions run in it.
-- 15. A claim recorded twelve named settings; every other one (text search configuration, timezone abbreviations,
--    transform_null_equals, row_security, a custom setting a policy reads) came from the verifier and decided the
--    verdict. A claim records every setting that changes meaning and is off its default; a proof and a recipe start
--    from the defaults.
-- 16. recall()'s disputed_by named keys of rows the caller does not see; replacement() followed a chain through such
--    a row and showed its reason. Each _door_* takes the caller's visible keys (p_visible) and computes over them.
-- 17. A verifier in REPEATABLE READ judged against its first snapshot and recorded the verdict as reached now. verify()
--    judges at READ COMMITTED, and verified_at is when the row was read (_truth_set's p_at).
-- 18. One ended verifier halted every claim that read alike, and past eight ended sessions a mark was dropped. The mark
--    names the claim's key (_truth_halted's p_key_hash); every mark is taken.
-- 19. After this update every write to a watched table from a session that loaded the library of 0.19.0 failed with
--    "could not find function". The trigger is in a library of its own that says to reconnect.
-- 20. A watch over a FORCE ROW LEVEL SECURITY table rendered nothing as its owner; a key column that is not unique let
--    a writer forget another's key. The owner renders without FORCE; watch() needs a unique key.

ALTER TABLE phasevec.truth ADD COLUMN asserted_by name, ADD COLUMN asserted_by_oid oid,
                           ADD COLUMN asserted_for bytea, ADD COLUMN verified_for bytea,
                           ADD COLUMN proof_env text[], ADD COLUMN halted boolean NOT NULL DEFAULT false;
COMMENT ON COLUMN phasevec.truth.asserted_by IS
    $q$The name of the role that asserted the proof, when it did (0.20.0). With asserted_by_oid: the proof runs as that role only while the OID still has this name.$q$;
COMMENT ON COLUMN phasevec.truth.asserted_by_oid IS
    $q$The role that asserted the proof (0.20.0): the proof runs with its rights. NULL for a proof asserted before 0.20.0, which does not run until asserted again (phasevec.adopt).$q$;
COMMENT ON COLUMN phasevec.truth.asserted_for IS
    $q$What the author vouched for (0.20.0): sha256 of the row's text as the recipe renders it (as the table's owner, in pinned settings) when it asserted. NULL when there was no row it could see.$q$;
COMMENT ON COLUMN phasevec.truth.verified_for IS
    $q$What the verdict judged (0.20.0): phasevec._bind of the claim (asserted_for, proof, author, proof_env). A 'verified' that does not match the claim, or whose text is not the row's, reads 'unproven'.$q$;
COMMENT ON COLUMN phasevec.truth.proof_env IS
    $q$The author's settings when it asserted ("name=value": DateStyle, TimeZone, search_path, ...): the proof runs with them (0.20.0).$q$;
COMMENT ON COLUMN phasevec.truth.halted IS
    $q$The verifier's session ended while this proof ran (0.20.0): it is refuted and not run by verify() again until asserted again.$q$;

-- A verdict judges (text, proof, author, the author's settings). Every part is framed, so no two claims read alike.
CREATE FUNCTION phasevec._bind(p_text_hash bytea, p_proof text, p_author oid, p_env text[])
RETURNS bytea LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $f$
    SELECT sha256(CASE WHEN p_text_hash IS NULL THEN $q$\x00$q$::bytea ELSE $q$\x01$q$::bytea || p_text_hash END
                  || int8send(coalesce(p_author, 0)::bigint)
                  || int4send(octet_length(convert_to(coalesce(p_proof, $q$$q$), $q$UTF8$q$)))
                  || convert_to(coalesce(p_proof, $q$$q$), $q$UTF8$q$)
                  || convert_to(coalesce(array_to_string(p_env, chr(10), $q$$q$), $q$$q$), $q$UTF8$q$))
$f$;

-- The truth a key has NOW. 'verified' only for the claim it judged, and only while the row's text, as the watch
-- trigger last saw it, is the asserted one. (brief() also checks the text it serves; verify() checks the live row.)
CREATE OR REPLACE FUNCTION phasevec._verdict(t phasevec.truth) RETURNS text
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    SELECT CASE WHEN t.verdict = $q$replaced$q$ THEN $q$replaced$q$
                WHEN t.expires_at IS NOT NULL AND t.expires_at <= now() THEN $q$expired$q$
                WHEN t.verdict = $q$verified$q$
                 AND (t.verified_for IS NULL
                      OR t.verified_for IS DISTINCT FROM phasevec._bind(t.asserted_for, t.proof, t.asserted_by_oid,
                                                                        t.proof_env)
                      OR t.asserted_for IS DISTINCT FROM (SELECT s.text_hash FROM phasevec.sources s
                                                          WHERE s.watch = t.watch AND s.key = t.key))
                THEN $q$unproven$q$
                ELSE t.verdict END
$f$;

-- A row whose text changes away from what was judged loses its verdict, verified or refuted. Runs inside the watch
-- trigger's write to phasevec.sources (as the owner).
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

-- assert(): the same signature and grants; now C (src/phasevec_truth.c): it sees who calls it, renders the row as
-- the table's owner in pinned settings, records the caller's settings, and writes through _assert_set, as the owner.
CREATE FUNCTION phasevec._assert_set(p_watch text, p_key text, p_proof text, p_topic text, p_support jsonb,
                                     p_expires_at timestamptz, p_author oid, p_text_hash bytea, p_env text[])
RETURNS void LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $f$
DECLARE w phasevec.watches := phasevec._watch(p_watch);
BEGIN
    INSERT INTO phasevec.truth AS t (watch, key, proof, topic, support, expires_at,
                                     asserted_by, asserted_by_oid, asserted_for, proof_env)
    VALUES (w.id, p_key, p_proof, p_topic, p_support, p_expires_at,
            pg_get_userbyid(p_author), p_author, p_text_hash, p_env)
    ON CONFLICT (watch, key) DO UPDATE
       SET proof = EXCLUDED.proof, topic = EXCLUDED.topic, support = EXCLUDED.support,
           expires_at = EXCLUDED.expires_at, asserted_by = EXCLUDED.asserted_by,
           asserted_by_oid = EXCLUDED.asserted_by_oid, asserted_for = EXCLUDED.asserted_for,
           proof_env = EXCLUDED.proof_env, halted = false,
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
           verified_for = phasevec._bind(t.asserted_for, t.proof, t.asserted_by_oid, t.proof_env)
     WHERE t.verdict <> $q$replaced$q$;
END;
$f$;

-- The internals of verify() and verify_one() (src/phasevec_truth.c). They are not SECURITY DEFINER: they read and
-- write phasevec.truth, which only the owner can, so they work only when the C functions call them as the owner.
-- The C side passes the caller's OID, which a caller cannot choose.
--
-- The due proofs p_verifier may run, oldest first; a proof whose author is gone (no role with that OID and name)
-- is due for anyone: what verify() records for it is 'unproven'. A halted claim is not due.
DROP FUNCTION phasevec._truth_due(int, int, interval);
CREATE FUNCTION phasevec._truth_due(p_watch int, p_n int, p_every interval, p_verifier oid)
RETURNS TABLE (key text, proof text, author oid, author_known boolean, asserted_for bytea, env text[], bind bytea)
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    SELECT t.key, t.proof, t.asserted_by_oid, r.oid IS NOT NULL, t.asserted_for, t.proof_env,
           phasevec._bind(t.asserted_for, t.proof, t.asserted_by_oid, t.proof_env)
      FROM phasevec.truth t
      LEFT JOIN pg_catalog.pg_roles r ON r.oid = t.asserted_by_oid AND r.rolname = t.asserted_by
     WHERE t.watch = p_watch AND t.proof IS NOT NULL AND t.verdict <> $q$replaced$q$
       AND t.asserted_by_oid IS NOT NULL AND NOT t.halted
       AND (t.verified_at IS NULL OR t.verified_at < now() - p_every)
       AND (r.oid IS NULL OR pg_catalog.pg_has_role(p_verifier, r.oid, $q$USAGE$q$))
     ORDER BY t.verified_at NULLS FIRST, t.key
     LIMIT p_n
$f$;

-- One key's claim (verify_one, which runs a halted claim too: it was asked for); no row when it has no proof or was
-- replaced.
CREATE FUNCTION phasevec._truth_of(p_watch int, p_key text)
RETURNS TABLE (key text, proof text, author oid, author_known boolean, asserted_for bytea, env text[], bind bytea)
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    SELECT t.key, t.proof, t.asserted_by_oid, r.oid IS NOT NULL, t.asserted_for, t.proof_env,
           phasevec._bind(t.asserted_for, t.proof, t.asserted_by_oid, t.proof_env)
      FROM phasevec.truth t
      LEFT JOIN pg_catalog.pg_roles r ON r.oid = t.asserted_by_oid AND r.rolname = t.asserted_by
     WHERE t.watch = p_watch AND t.key = p_key AND t.proof IS NOT NULL AND t.verdict <> $q$replaced$q$
$f$;

-- Record what a proof's run found, only for the claim it judged (p_bind: the same text, proof, author and settings).
-- Anything else changed meanwhile: nothing is recorded. p_outcome NULL records nothing (the row moved while the
-- proof ran). p_at: when the row was read for it, the state it judged (verified_at). Returns the verdict as it
-- reads now.
DROP FUNCTION phasevec._truth_set(int, text, boolean, text);
CREATE FUNCTION phasevec._truth_set(p_watch int, p_key text, p_outcome text, p_error text, p_bind bytea,
                                    p_at timestamptz)
RETURNS text LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $f$
DECLARE v text;
BEGIN
    IF p_outcome IS NOT NULL THEN
        UPDATE phasevec.truth t
           SET verdict = p_outcome, verified_at = coalesce(p_at, now()), last_error = p_error, halted = false,
               verified_for = CASE WHEN p_outcome IN ($q$verified$q$, $q$refuted$q$) THEN p_bind END
         WHERE t.watch = p_watch AND t.key = p_key AND t.verdict <> $q$replaced$q$
           AND phasevec._bind(t.asserted_for, t.proof, t.asserted_by_oid, t.proof_env) = p_bind;
    END IF;
    SELECT phasevec._verdict(t) INTO v FROM phasevec.truth t WHERE t.watch = p_watch AND t.key = p_key;
    RETURN v;
END;
$f$;

-- A claim whose verifier's session ended while its proof ran (src/phasevec_truth.c keeps the mark in shared memory;
-- the next verify() of the watch finds it): refuted, and not due again until asserted again. The mark names the
-- claim's key (p_key_hash, sha256 of it) and the claim (p_bind): in the third cut it named only the claim, and one
-- session that ended halted every key whose text, proof and author read alike.
CREATE FUNCTION phasevec._truth_halted(p_watch int, p_key_hash bytea, p_bind bytea)
RETURNS void LANGUAGE sql SET search_path = pg_catalog, pg_temp AS $f$
    UPDATE phasevec.truth t
       SET verdict = $q$refuted$q$, verified_at = now(), verified_for = p_bind, halted = true, changed_at = now(),
           last_error = $q$the verifier's session ended while this proof ran: not run again until it is asserted again$q$
     WHERE t.watch = p_watch AND t.verdict <> $q$replaced$q$
       AND sha256(convert_to(t.key, $q$UTF8$q$)) = p_key_hash
       AND phasevec._bind(t.asserted_for, t.proof, t.asserted_by_oid, t.proof_env) = p_bind
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
-- OID may name no role, or another one. adopt() asserts such proofs again in the name of the author it is given
-- (C, src/phasevec_truth.c): the caller must hold that role's privileges, every proof comes back with its former
-- author, and a superuser becomes the author only of the keys named in p_superuser_keys. Replaced keys are left.
CREATE FUNCTION phasevec.adopt(p_watch text, p_author regrole, p_keys text[] DEFAULT NULL,
                               p_superuser_keys text[] DEFAULT NULL)
RETURNS TABLE (key text, proof text, former_author text, adopted boolean, note text)
AS $q$MODULE_PATHNAME$q$, $q$phasevec_adopt$q$ LANGUAGE C VOLATILE;
COMMENT ON FUNCTION phasevec.adopt(text, regrole, text[], text[]) IS
    $q$Asserts again, in the name of p_author (the caller must hold its privileges), the proofs of a watch whose author is unknown (asserted before 0.20.0) or gone; returns each one. A superuser becomes the author only of keys named in p_superuser_keys. Owner only, or granted.$q$;

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

-- ------------------------------------------------------------------------------------------ rendering a row --
-- 8, 9, 13. One way to read a watched row's text: phasevec._render() (C), the recipe as the table's owner in the
-- guard and the pinned settings, for a caller that may SELECT the table (and its rows, with row-level security).
CREATE FUNCTION phasevec._render(p_watch text, p_keys text[])
RETURNS TABLE (key text, body text, text_hash bytea)
AS $q$MODULE_PATHNAME$q$, $q$phasevec_render$q$ LANGUAGE C STABLE;
COMMENT ON FUNCTION phasevec._render(text, text[]) IS
    $q$The rows of a watch (p_keys NULL: all) as its recipe renders them: as the table's owner, read-only and security-restricted, in pinned settings. For a caller that may SELECT the table (0.20.0).$q$;

-- The watch trigger's write, as the owner: notes a key's text (lexemes too), or with a NULL hash forgets the key.
CREATE FUNCTION phasevec._note_set(p_watch int, p_key text, p_hash bytea, p_body text)
RETURNS void LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    cfg regconfig;
    lx  tsvector;
BEGIN
    SELECT w.lexical INTO cfg FROM phasevec.watches w WHERE w.id = p_watch;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'phasevec: no watch %', p_watch;
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

-- The watch trigger: C. Same name, so every trigger already installed (phasevec_watch_<id>) keeps working. It is
-- declared in a library of its own (src/pg_phasevec_observe.c), which runs phasevec_observe from the session's
-- pg_phasevec library: a session that loaded the library of 0.19.0 or before, and wrote to a watched table after
-- this update, got "could not find function"; now it is told to reconnect (the write is refused, not let through).
CREATE OR REPLACE FUNCTION phasevec._observe() RETURNS trigger
AS $q$pg_phasevec_observe$q$, $q$phasevec_observe_entry$q$ LANGUAGE C;
DROP FUNCTION phasevec._note(int, text, bytea, text);

CREATE OR REPLACE FUNCTION phasevec.next(p_watch text, p_limit integer DEFAULT 64)
RETURNS TABLE(key text, body text, text_hash bytea)
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    SELECT x.key, x.body, x.text_hash
      FROM phasevec._render(p_watch, ARRAY(SELECT t.key FROM phasevec._todo(p_watch, p_limit) t)) x
$f$;

CREATE OR REPLACE FUNCTION phasevec.audit_sample(p_watch text, p_n integer)
RETURNS TABLE(key text, body text, text_hash bytea, code smallint[], code256 bit)
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $f$
DECLARE
    w phasevec.watches := phasevec._watch(p_watch);
BEGIN
    RETURN QUERY
    WITH cand AS (
        SELECT rd.key, rd.text_hash, rd.code, rd.code256
          FROM phasevec.readings rd
          JOIN phasevec.kstate k ON k.watch = rd.watch AND k.key = rd.key AND k.main IN ('fresh', 'doubtful')
         WHERE rd.watch = w.id AND rd.reader = w.reader AND rd.failed IS NULL)
    SELECT c.key, x.body, c.text_hash, c.code, c.code256
      FROM cand c
      JOIN phasevec._render(p_watch, ARRAY(SELECT cand.key FROM cand)) x ON x.key = c.key
     ORDER BY md5(c.key || clock_timestamp()::text) LIMIT p_n;
END;
$f$;

CREATE OR REPLACE FUNCTION phasevec.lexical(p_watch text, p_config regconfig)
RETURNS bigint LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $f$
DECLARE
    w    phasevec.watches := phasevec._watch(p_watch);
    x    record;
    n    bigint := 0;
BEGIN
    IF NOT pg_has_role(current_user, (SELECT c.relowner FROM pg_class c WHERE c.oid = w.source), 'USAGE') THEN
        RAISE EXCEPTION 'phasevec: only the owner of % may change how watch % is read', w.source, p_watch;
    END IF;
    UPDATE phasevec.watches SET lexical = p_config WHERE id = w.id;
    IF p_config IS NULL THEN
        UPDATE phasevec.sources SET lexemes = NULL, lexeme_n = NULL WHERE watch = w.id AND lexemes IS NOT NULL;
        DELETE FROM phasevec.lexstats WHERE watch = w.id;
        DELETE FROM phasevec.lexdocs WHERE watch = w.id;
        RETURN 0;
    END IF;
    FOR x IN SELECT r.key, r.body, r.text_hash FROM phasevec._render(p_watch, NULL) r LOOP
        UPDATE phasevec.sources s
           SET lexemes = l.lx, lexeme_n = length(l.lx)
          FROM (SELECT phasevec._lexemes(p_config, x.body) AS lx) l
         WHERE s.watch = w.id AND s.key = x.key AND s.text_hash = x.text_hash;
        IF FOUND THEN
            n := n + 1;
        END IF;
    END LOOP;
    PERFORM phasevec.lexical_refresh(p_watch);
    RETURN n;
END;
$f$;

CREATE OR REPLACE FUNCTION phasevec.watch(p_name text, p_source regclass, p_key name, p_recipe text, p_reader text,
                                          p_min_coverage numeric DEFAULT 0.95, p_doubt_below real DEFAULT NULL::real)
RETURNS integer LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $f$
DECLARE
    tbl_owner oid;
    rid       int;
    wid       int;
BEGIN
    SELECT c.relowner INTO tbl_owner FROM pg_class c WHERE c.oid = p_source AND c.relkind IN ('r', 'p');
    IF NOT FOUND THEN
        RAISE EXCEPTION 'phasevec: % is not a table', p_source;
    END IF;
    IF NOT pg_has_role(current_user, tbl_owner, 'USAGE') THEN
        RAISE EXCEPTION 'phasevec: a watch is a trigger on %, so only its owner may create one', p_source;
    END IF;
    -- A recipe never reads a temporary table (0.20.0): one is its session's, and a watch outlives the session.
    IF EXISTS (SELECT 1 FROM pg_class c WHERE c.oid = p_source AND c.relpersistence = 't') THEN
        RAISE EXCEPTION 'phasevec: % is a temporary table: a watch outlives its session', p_source;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = p_source AND a.attname = p_key
                   AND a.attnum > 0 AND NOT a.attisdropped) THEN
        RAISE EXCEPTION 'phasevec: % has no column %', p_source, p_key;
    END IF;
    -- A key names one row (0.20.0): with two rows under one key, a writer who could see and delete only its own
    -- forgot the other's, with its verdict.
    IF NOT EXISTS (SELECT 1 FROM pg_index i JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attname = p_key
                    WHERE i.indrelid = p_source AND i.indisunique AND i.indnkeyatts = 1
                      AND i.indkey[0] = a.attnum AND i.indpred IS NULL AND i.indexprs IS NULL) THEN
        RAISE EXCEPTION 'phasevec: % is not a key of %: a watch needs a column with a unique index of its own', p_key, p_source
            USING HINT = 'A PRIMARY KEY or a UNIQUE constraint on that column alone.';
    END IF;
    SELECT id INTO rid FROM phasevec.readers WHERE name = p_reader;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'phasevec: no reader named %', p_reader
            USING HINT = 'Register it with phasevec.reader_register(); nothing is read without a sealed reader.';
    END IF;

    INSERT INTO phasevec.watches (name, source, key_col, recipe, reader, min_coverage, doubt_below)
    VALUES (p_name, p_source, p_key, p_recipe, rid, p_min_coverage, p_doubt_below)
    RETURNING id INTO wid;
    -- The recipe must be an expression over the row, aliased r; it is read as every reader reads it (0.20.0).
    PERFORM 1 FROM phasevec._render(p_name, ARRAY[]::text[]);

    EXECUTE format('CREATE TRIGGER %I AFTER INSERT OR UPDATE OR DELETE ON %s '
                   'FOR EACH ROW EXECUTE FUNCTION phasevec._observe(%L, %L, %L)',
                   'phasevec_watch_' || wid, p_source, wid, p_key, p_recipe);

    -- Every row already there is noted, so it is pending until read -- not invisible.
    INSERT INTO phasevec.sources (watch, key, text_hash)
    SELECT wid, x.key, x.text_hash FROM phasevec._render(p_name, NULL) x;
    RETURN wid;
END;
$f$;

-- ---------------------------------------------------------------------------------- the doors to verdicts --
-- 7, 8. brief(): C. It shows a watch only to a role that may SELECT its table; each line is the row's text as the
-- recipe renders it (as the table's owner, in the guard); a key reads 'verified' only if that line is the text its
-- verdict judged. _brief_keys() is its internal, the owner's.
DROP FUNCTION phasevec._brief_keys(text);
CREATE FUNCTION phasevec._brief_keys(p_watch text)
RETURNS TABLE (key text, verdict text, net_use bigint, seen timestamptz, judged bytea)
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    SELECT s.key, coalesce(phasevec._verdict(t), $q$unproven$q$),
           coalesce(u.helped, 0) - coalesce(u.not_helped, 0),
           coalesce(t.verified_at, t.changed_at),
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
AS $q$MODULE_PATHNAME$q$, $q$phasevec_brief$q$ LANGUAGE C STABLE;

-- 12. recall(), disputes(), replacement(), truth_coverage(): the same signatures and grants, now one C door that
-- shows a watch only to a role that may SELECT its table, and runs the body (phasevec._door_<name>) as the owner.
-- p_visible (the last argument of each _door_*): the keys of the rows the caller sees when row-level security filters
-- them, NULL when it does not. The body computes over those keys only, so no field (disputed_by, a reason, a count)
-- carries a row the caller does not see.
CREATE FUNCTION phasevec._door_recall(p_watch text, p_question text, p_k int, p_partial boolean, p_visible text[])
RETURNS TABLE (key text, score double precision, adjusted double precision, verdict text, support jsonb,
               verified_at timestamptz, topic text, disputed_by text[], usefulness integer, state text)
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    WITH w AS (SELECT (phasevec._watch(p_watch)).id AS id),
    hits AS (SELECT * FROM phasevec.search(p_watch, p_question, least(p_k * 3, 1000), p_partial) x
              WHERE p_visible IS NULL OR x.key = ANY (p_visible)),
    th AS (SELECT h.key, t.topic AS tp, t.support AS sp, t.verified_at AS va,
                  coalesce(phasevec._verdict(t), $q$unproven$q$) AS v
             FROM hits h CROSS JOIN w LEFT JOIN phasevec.truth t ON t.watch = w.id AND t.key = h.key),
    vivas AS (SELECT t.topic, t.key, s.text_hash FROM phasevec.truth t CROSS JOIN w
                JOIN phasevec.sources s ON s.watch = t.watch AND s.key = t.key
               WHERE t.watch = w.id AND t.topic IN (SELECT th.tp FROM th WHERE th.tp IS NOT NULL)
                 AND (p_visible IS NULL OR t.key = ANY (p_visible))
                 AND phasevec._verdict(t) IN ($q$verified$q$, $q$unproven$q$)),
    disp AS (SELECT a.key, array_agg(b.key ORDER BY b.key) AS keys
               FROM vivas a JOIN vivas b ON b.topic = a.topic AND b.key <> a.key AND b.text_hash <> a.text_hash
              GROUP BY a.key)
    SELECT h.key, h.score,
           h.score * (1 + 0.1 * tanh(coalesce(us.helped - us.not_helped, 0) / 5.0)),
           CASE WHEN dp.keys IS NOT NULL THEN $q$disputed$q$ ELSE th.v END,
           th.sp, th.va, th.tp, dp.keys, coalesce(us.helped - us.not_helped, 0)::int, h.state
      FROM hits h
      JOIN th ON th.key = h.key
      CROSS JOIN w
      LEFT JOIN phasevec.usefulness us ON us.watch = w.id AND us.key = h.key
      LEFT JOIN disp dp ON dp.key = h.key
     ORDER BY 3 DESC NULLS LAST, (th.v = $q$verified$q$) DESC, h.key
     LIMIT p_k
$f$;
CREATE FUNCTION phasevec._door_disputes(p_watch text, p_visible text[])
RETURNS TABLE (topic text, key_a text, key_b text)
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    WITH vivas AS (
        SELECT t.topic, t.key, s.text_hash FROM phasevec.truth t
          JOIN phasevec.sources s ON s.watch = t.watch AND s.key = t.key
         WHERE t.watch = (phasevec._watch(p_watch)).id AND t.topic IS NOT NULL
           AND (p_visible IS NULL OR t.key = ANY (p_visible))
           AND phasevec._verdict(t) IN ($q$verified$q$, $q$unproven$q$))
    SELECT a.topic, a.key, b.key FROM vivas a JOIN vivas b ON b.topic = a.topic AND b.key > a.key
     WHERE a.text_hash <> b.text_hash
     ORDER BY 1, 2, 3
$f$;
-- A chain is followed only through rows the caller sees: it ends before the first one it does not.
CREATE FUNCTION phasevec._door_replacement(p_watch text, p_key text, p_visible text[])
RETURNS TABLE (step integer, key text, reason text)
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    WITH RECURSIVE c(step, key, reason, seen) AS (
        SELECT 0, p_key, NULL::text, ARRAY[p_key]
      UNION ALL
        SELECT c.step + 1, t.replaced_by, t.reason, c.seen || t.replaced_by
          FROM c JOIN phasevec.truth t ON t.watch = (phasevec._watch(p_watch)).id AND t.key = c.key
         WHERE t.verdict = $q$replaced$q$ AND c.step < 50 AND NOT t.replaced_by = ANY (c.seen)
           AND (p_visible IS NULL OR t.replaced_by = ANY (p_visible)))
    SELECT step, key, reason FROM c ORDER BY step
$f$;
CREATE FUNCTION phasevec._door_truth_coverage(p_watch text, p_visible text[])
RETURNS TABLE (verdict text, n bigint)
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    SELECT coalesce(phasevec._verdict(t), $q$unproven$q$) AS verdict, count(*)
      FROM phasevec.sources s
      LEFT JOIN phasevec.truth t ON t.watch = s.watch AND t.key = s.key
     WHERE s.watch = (phasevec._watch(p_watch)).id AND (p_visible IS NULL OR s.key = ANY (p_visible))
     GROUP BY 1 ORDER BY 1
$f$;
CREATE OR REPLACE FUNCTION phasevec.recall(p_watch text, p_question text, p_k int DEFAULT 10, p_partial boolean DEFAULT false)
RETURNS TABLE (key text, score double precision, adjusted double precision, verdict text, support jsonb,
               verified_at timestamptz, topic text, disputed_by text[], usefulness integer, state text)
AS $q$MODULE_PATHNAME$q$, $q$phasevec_door$q$ LANGUAGE C STABLE;
CREATE OR REPLACE FUNCTION phasevec.disputes(p_watch text)
RETURNS TABLE (topic text, key_a text, key_b text)
AS $q$MODULE_PATHNAME$q$, $q$phasevec_door$q$ LANGUAGE C STABLE;
CREATE OR REPLACE FUNCTION phasevec.replacement(p_watch text, p_key text)
RETURNS TABLE (step integer, key text, reason text)
AS $q$MODULE_PATHNAME$q$, $q$phasevec_door$q$ LANGUAGE C STABLE;
CREATE OR REPLACE FUNCTION phasevec.truth_coverage(p_watch text)
RETURNS TABLE (verdict text, n bigint)
AS $q$MODULE_PATHNAME$q$, $q$phasevec_door$q$ LANGUAGE C STABLE;

-- ---------------------------------------------------------------- privileges --
-- New internals: the owner only (and they carry no rights of their own). A verifier other than the owner is
-- granted verify() or verify_one(), nothing else; it runs only the proofs whose author it may act as. _render()
-- stays open: it checks its caller itself.
REVOKE ALL ON FUNCTION phasevec._bind(bytea, text, oid, text[]), phasevec._truth_text_changed(),
    phasevec._assert_set(text, text, text, text, jsonb, timestamptz, oid, bytea, text[]),
    phasevec._truth_due(int, int, interval, oid), phasevec._truth_of(int, text),
    phasevec._truth_set(int, text, text, text, bytea, timestamptz), phasevec._truth_halted(int, bytea, bytea),
    phasevec._note_set(int, text, bytea, text), phasevec.adopt(text, regrole, text[], text[]),
    phasevec._door_recall(text, text, int, boolean, text[]), phasevec._door_disputes(text, text[]),
    phasevec._door_replacement(text, text, text[]), phasevec._door_truth_coverage(text, text[])
  FROM PUBLIC;
-- 6 and 7: closed to PUBLIC. brief() calls _brief_keys() as the owner: whoever may brief is granted brief() only.
REVOKE ALL ON FUNCTION phasevec._forget(int, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION phasevec._brief_keys(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION phasevec.brief(text, int) FROM PUBLIC;
COMMENT ON FUNCTION phasevec._brief_keys(text) IS
    $q$Keys, verdicts, usefulness and judged text hash of a watch, for brief() (which runs it as the owner). The owner's only (0.20.0).$q$;

-- 9. Every row's text in the pinned settings: what the watch trigger noted before 0.20.0 was rendered in its
-- writer's settings. A text that now reads otherwise is noted again (its reading turns stale, its verdict unproven).
DO $d$
DECLARE
    w record;
    x record;
BEGIN
    FOR w IN SELECT id, name FROM phasevec.watches ORDER BY id LOOP
        FOR x IN SELECT r.key, r.body, r.text_hash FROM phasevec._render(w.name, NULL) r
                   JOIN phasevec.sources s ON s.watch = w.id AND s.key = r.key
                  WHERE s.text_hash IS DISTINCT FROM r.text_hash LOOP
            PERFORM phasevec._note_set(w.id, x.key, x.text_hash, x.body);
        END LOOP;
    END LOOP;
END
$d$;

-- A key names one row: watch() refuses a key column without a unique index of its own (0.20.0). A watch made before
-- keeps working, but with two rows under one key they share one verdict, and a writer who deletes its own row (one
-- row-level security lets it see) forgets the other's. Each such watch is named here.
DO $d$
DECLARE
    w record;
BEGIN
    FOR w IN SELECT x.name, x.source, x.key_col FROM phasevec.watches x
              WHERE NOT EXISTS (SELECT 1 FROM pg_index i
                                  JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attname = x.key_col
                                 WHERE i.indrelid = x.source AND i.indisunique AND i.indnkeyatts = 1
                                   AND i.indkey[0] = a.attnum AND i.indpred IS NULL AND i.indexprs IS NULL)
              ORDER BY x.id LOOP
        RAISE WARNING 'phasevec: watch % reads % by %, which is not unique there', w.name, w.source, w.key_col
            USING HINT = 'Add a UNIQUE constraint on that column alone: two rows under one key share one verdict.';
    END LOOP;
END
$d$;
