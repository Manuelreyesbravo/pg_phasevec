-- pg_phasevec 0.19.0 -> 0.20.0: a verdict is bound to what it judged, a proof runs as its author, and the
-- internal functions open to PUBLIC are closed.
\echo Use "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" to load this file. \quit

-- Found by the public-readiness review of 2026-11-05:
--
-- 1. A 'verified' truth survived any later edit of its row: nothing reset phasevec.truth when the text changed, and
--    brief() served the new text, read through the recipe, as verified. Now every verdict made by verify() or
--    refute() records what it judged (verified_for: sha256 of the row's text hash and the proof), a change of the
--    row's text sends the verdict back to 'unproven' and makes the proof due again (trigger on phasevec.sources), and
--    _verdict() never reports 'verified' for a binding that no longer matches (read-time check, so a race between a
--    proof and an edit cannot keep a stale verdict either).
-- 2. verify() ran each proof with the rights of whoever called verify(), not of whoever wrote it (a confused deputy:
--    a low-privilege asserter could read what the verifier can, through the verdict or the error text). assert() now
--    records its author (the caller's current user, taken in C: a SECURITY DEFINER function only sees its owner), and
--    a proof runs as its author, in a security-restricted operation, and only when the verifier already holds the
--    author's privileges. verify() skips the proofs whose author it cannot act as; verify_one() refuses them.
-- 3. A proof that closed its own parenthesis made two statements and the second ran in the cost step, with no
--    clock and no cap (src/phasevec_truth.c). Fixed in the library, for every version of the SQL.
-- 4. _forget() was executable by PUBLIC behind a pg_trigger_depth() test that any user's own trigger passes. The
--    watch trigger now forgets through _note() (a NULL hash), which only the writers of a watched table are granted
--    (since 0.6.0); _forget() is revoked from PUBLIC: only the extension's owner may call it.
-- 5. _brief_keys() is SECURITY DEFINER and was executable by PUBLIC, so any role with USAGE on the schema read the
--    keys, verdicts, usefulness and recipes of every watch. It is revoked from PUBLIC, and so is brief(): the owner
--    grants both to whoever may brief, as for find and search.

ALTER TABLE phasevec.truth ADD COLUMN asserted_by name, ADD COLUMN verified_for bytea;
COMMENT ON COLUMN phasevec.truth.asserted_by IS
    $q$The role that asserted the proof (0.20.0): the proof runs with its rights. NULL for a proof asserted before 0.20.0, which is not run until asserted again.$q$;
COMMENT ON COLUMN phasevec.truth.verified_for IS
    $q$What the verdict judged (0.20.0): sha256 of the row's text hash and the proof. A 'verified' that no longer matches is reported as 'unproven'.$q$;

-- What a verdict on (watch, key) judges now: the row's text, as phasevec.sources hashes it, and the proof.
-- NULL when the key has no row.
CREATE FUNCTION phasevec._binding(p_watch int, p_key text, p_proof text)
RETURNS bytea LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    SELECT sha256(s.text_hash || convert_to(coalesce(p_proof, $q$$q$), $q$UTF8$q$))
      FROM phasevec.sources s WHERE s.watch = p_watch AND s.key = p_key
$f$;

-- The truth a key has NOW: expiry and binding are compared at read time, so both are exact without any sweep.
CREATE OR REPLACE FUNCTION phasevec._verdict(t phasevec.truth) RETURNS text
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    SELECT CASE WHEN t.verdict = $q$replaced$q$ THEN $q$replaced$q$
                WHEN t.expires_at IS NOT NULL AND t.expires_at <= now() THEN $q$expired$q$
                WHEN t.verdict = $q$verified$q$
                 AND t.verified_for IS DISTINCT FROM phasevec._binding(t.watch, t.key, t.proof) THEN $q$unproven$q$
                ELSE t.verdict END
$f$;

-- A row whose text changes loses its verdict: verified or refuted, it was about another text. It goes back to
-- unproven and its proof is due at once. Runs inside _note() (the owner's rights).
CREATE FUNCTION phasevec._truth_text_changed() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $f$
BEGIN
    IF TG_OP = $q$UPDATE$q$ AND OLD.text_hash IS NOT DISTINCT FROM NEW.text_hash THEN
        RETURN NULL;
    END IF;
    UPDATE phasevec.truth t
       SET verdict = $q$unproven$q$, verified_at = NULL, verified_for = NULL, last_error = NULL, changed_at = now()
     WHERE t.watch = NEW.watch AND t.key = NEW.key AND t.verdict IN ($q$verified$q$, $q$refuted$q$)
       AND t.verified_for IS DISTINCT FROM sha256(NEW.text_hash || convert_to(coalesce(t.proof, $q$$q$), $q$UTF8$q$));
    RETURN NULL;
END;
$f$;
CREATE TRIGGER truth_text_changed AFTER INSERT OR UPDATE OF text_hash ON phasevec.sources
    FOR EACH ROW EXECUTE FUNCTION phasevec._truth_text_changed();

-- assert(): the same signature and grants; now in C, so it can see who calls it (src/phasevec_truth.c). It writes
-- through _assert_set, which only the owner may run.
CREATE FUNCTION phasevec._assert_set(p_watch text, p_key text, p_proof text, p_topic text, p_support jsonb,
                                     p_expires_at timestamptz, p_author oid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
DECLARE w phasevec.watches := phasevec._watch(p_watch);
BEGIN
    INSERT INTO phasevec.truth AS t (watch, key, proof, topic, support, expires_at, asserted_by)
    VALUES (w.id, p_key, p_proof, p_topic, p_support, p_expires_at, pg_get_userbyid(p_author))
    ON CONFLICT (watch, key) DO UPDATE
       SET proof = EXCLUDED.proof, topic = EXCLUDED.topic, support = EXCLUDED.support,
           expires_at = EXCLUDED.expires_at, asserted_by = EXCLUDED.asserted_by,
           verdict = CASE WHEN t.verdict = $q$replaced$q$ THEN t.verdict ELSE $q$unproven$q$ END,
           verified_at = NULL, verified_for = NULL, last_error = NULL, changed_at = now();
END;
$f$;
CREATE OR REPLACE FUNCTION phasevec.assert(p_watch text, p_key text, p_proof text DEFAULT NULL, p_topic text DEFAULT NULL,
                                           p_support jsonb DEFAULT NULL, p_expires_at timestamptz DEFAULT NULL)
RETURNS void AS $q$MODULE_PATHNAME$q$, $q$phasevec_assert$q$ LANGUAGE C VOLATILE;

-- refute(): as in 0.14.1, and the refutation is bound to the text it refuted.
CREATE OR REPLACE FUNCTION phasevec.refute(p_watch text, p_key text, p_reason text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
DECLARE w phasevec.watches := phasevec._watch(p_watch);
BEGIN
    IF coalesce(btrim(p_reason), $q$$q$) = $q$$q$ THEN
        RAISE EXCEPTION $q$phasevec: a refutation says why$q$;
    END IF;
    INSERT INTO phasevec.truth AS t (watch, key, verdict, verified_at, last_error, verified_for)
    VALUES (w.id, p_key, $q$refuted$q$, now(), p_reason, phasevec._binding(w.id, p_key, NULL))
    ON CONFLICT (watch, key) DO UPDATE
       SET verdict = $q$refuted$q$, verified_at = now(), last_error = p_reason, changed_at = now(),
           verified_for = phasevec._binding(w.id, p_key, t.proof)
     WHERE t.verdict <> $q$replaced$q$;
END;
$f$;

-- The proof runner: as its author (src/phasevec_truth.c). _prove_c, which ran proofs as the caller, goes.
CREATE FUNCTION phasevec._prove_as(p_proof text, p_timeout_ms int, p_max_cost float8, p_author name,
                                   OUT ok boolean, OUT err text)
RETURNS record AS $q$MODULE_PATHNAME$q$, $q$phasevec_prove_as$q$ LANGUAGE C STRICT VOLATILE;

-- The proofs that are due and that p_verifier may run (it holds their author's privileges), oldest first, with
-- what a verdict on each would judge now.
DROP FUNCTION phasevec._truth_due(int, int, interval);
CREATE FUNCTION phasevec._truth_due(p_watch int, p_n int, p_every interval, p_verifier name)
RETURNS TABLE (key text, proof text, author name, bound bytea)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
    SELECT t.key, t.proof, t.asserted_by, phasevec._binding(t.watch, t.key, t.proof)
      FROM phasevec.truth t
      JOIN pg_catalog.pg_roles r ON r.rolname = t.asserted_by
     WHERE t.watch = p_watch AND t.proof IS NOT NULL AND t.verdict <> $q$replaced$q$
       AND (t.verified_at IS NULL OR t.verified_at < now() - p_every)
       AND pg_catalog.pg_has_role(p_verifier, r.oid, $q$USAGE$q$)
     ORDER BY t.verified_at NULLS FIRST, t.key
     LIMIT p_n
$f$;

-- One key's proof, its author and its binding (verify_one); no row when it has no proof or was replaced.
CREATE FUNCTION phasevec._truth_of(p_watch int, p_key text)
RETURNS TABLE (proof text, author name, bound bytea)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
    SELECT t.proof, t.asserted_by, phasevec._binding(t.watch, t.key, t.proof)
      FROM phasevec.truth t
     WHERE t.watch = p_watch AND t.key = p_key AND t.proof IS NOT NULL AND t.verdict <> $q$replaced$q$
$f$;

-- Record a verdict, only if the row and the proof are still the ones it judged (p_bound). If either changed while
-- the proof ran, nothing is recorded: the change already sent the key back to unproven, and it is due again.
DROP FUNCTION phasevec._truth_set(int, text, boolean, text);
CREATE FUNCTION phasevec._truth_set(p_watch int, p_key text, p_ok boolean, p_error text, p_bound bytea)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
DECLARE v text;
BEGIN
    UPDATE phasevec.truth t
       SET verdict = CASE WHEN p_ok THEN $q$verified$q$ ELSE $q$refuted$q$ END,
           verified_at = now(), verified_for = p_bound, last_error = p_error
     WHERE t.watch = p_watch AND t.key = p_key AND t.verdict <> $q$replaced$q$
       AND p_bound IS NOT DISTINCT FROM phasevec._binding(t.watch, t.key, t.proof)
    RETURNING t.verdict INTO v;
    IF NOT FOUND THEN
        SELECT phasevec._verdict(t) INTO v FROM phasevec.truth t WHERE t.watch = p_watch AND t.key = p_key;
    END IF;
    RETURN v;
END;
$f$;

-- verify(): as in 0.14.2, with each proof run as its author. Runs the due proofs whose author the caller holds the
-- privileges of (a superuser: all of them); the others wait for a verifier that may run them. No pinned
-- search_path, on purpose: a proof resolves its names with the caller's path, as before. That path cannot lend
-- anything: the proof runs with its author's rights, which the caller already has.
CREATE OR REPLACE FUNCTION phasevec.verify(p_watch text, p_n int DEFAULT 100,
                                           p_every interval DEFAULT interval $q$10 minutes$q$,
                                           p_budget interval DEFAULT interval $q$5 seconds$q$,
                                           p_timeout_ms int DEFAULT 2000, p_max_cost float8 DEFAULT 1e6)
RETURNS TABLE (key text, verdict text, error text) LANGUAGE plpgsql AS $f$
DECLARE
    w   phasevec.watches := phasevec._watch(p_watch);
    d   record;
    r   record;
    t0  timestamptz := clock_timestamp();
BEGIN
    FOR d IN SELECT * FROM phasevec._truth_due(w.id, p_n, p_every, current_user) LOOP
        EXIT WHEN clock_timestamp() - t0 >= p_budget;
        r := phasevec._prove_as(d.proof, p_timeout_ms, p_max_cost, d.author);
        key := d.key;
        verdict := phasevec._truth_set(w.id, d.key, coalesce(r.ok, false), r.err, d.bound);
        error := r.err;
        RETURN NEXT;
    END LOOP;
END;
$f$;

-- verify_one(): one key, now or out of turn, as its author. NULL when the key has no proof or was replaced; an
-- error when its author is unknown or the caller may not act as it.
CREATE OR REPLACE FUNCTION phasevec.verify_one(p_watch text, p_key text, p_timeout_ms int DEFAULT 2000,
                                               p_max_cost float8 DEFAULT 1e6)
RETURNS text LANGUAGE plpgsql AS $f$
DECLARE
    w   phasevec.watches := phasevec._watch(p_watch);
    d   record;
    r   record;
BEGIN
    SELECT * INTO d FROM phasevec._truth_of(w.id, p_key);
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    IF d.author IS NULL THEN
        RAISE EXCEPTION $q$phasevec: the proof of key % has no author (asserted before 0.20.0): assert it again$q$, p_key;
    END IF;
    r := phasevec._prove_as(d.proof, p_timeout_ms, p_max_cost, d.author);
    RETURN phasevec._truth_set(w.id, p_key, coalesce(r.ok, false), r.err, d.bound);
END;
$f$;

DROP FUNCTION phasevec._prove_c(text, int, float8);

-- Verdicts reached before 0.20.0 were reached with the verifier's rights and bound to no text: a 'verified' is
-- not carried over (back to unproven, with the reason in last_error); a 'refuted' stays refuted, bound to the text
-- it has now. Their proofs have no author, so they do not run until asserted again or until the owner names the
-- author: UPDATE phasevec.truth SET asserted_by = '<role>' WHERE asserted_by IS NULL AND proof IS NOT NULL;
UPDATE phasevec.truth
   SET verdict = $q$unproven$q$, verified_at = NULL, changed_at = now(),
       last_error = $q$verified before 0.20.0, with the verifier's rights: not carried over$q$
 WHERE verdict = $q$verified$q$;
UPDATE phasevec.truth t SET verified_for = phasevec._binding(t.watch, t.key, t.proof) WHERE t.verdict = $q$refuted$q$;

-- 4. The watch trigger forgets through _note(): p_hash NULL deletes the key's source row.
CREATE OR REPLACE FUNCTION phasevec._note(p_watch int, p_key text, p_hash bytea, p_body text)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    cfg regconfig;
    lx  tsvector;
BEGIN
    IF pg_trigger_depth() = 0 THEN
        RAISE EXCEPTION 'phasevec: _note() is called by a watch trigger, not directly';
    END IF;
    IF p_hash IS NULL THEN
        DELETE FROM phasevec.sources WHERE watch = p_watch AND key = p_key;
        RETURN;
    END IF;
    SELECT w.lexical INTO cfg FROM phasevec.watches w WHERE w.id = p_watch;
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

-- ---------------------------------------------------------------- privileges --
-- New internals: the owner only. A verifier other than the owner is granted verify() (or verify_one()) together
-- with _truth_due, _truth_of, _truth_set and _prove_as; it runs only the proofs whose author it may act as.
REVOKE ALL ON FUNCTION phasevec._binding(int, text, text), phasevec._truth_text_changed(),
    phasevec._assert_set(text, text, text, text, jsonb, timestamptz, oid),
    phasevec._prove_as(text, int, float8, name), phasevec._truth_due(int, int, interval, name),
    phasevec._truth_of(int, text), phasevec._truth_set(int, text, boolean, text, bytea)
  FROM PUBLIC;
-- 4 and 5: closed to PUBLIC. brief() needs _brief_keys(), so whoever may brief gets both:
--   GRANT EXECUTE ON FUNCTION phasevec.brief(text, int), phasevec._brief_keys(text) TO <role>;
REVOKE ALL ON FUNCTION phasevec._forget(int, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION phasevec._brief_keys(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION phasevec.brief(text, int) FROM PUBLIC;
COMMENT ON FUNCTION phasevec._brief_keys(text) IS
    $q$Keys, verdicts, usefulness and recipe of a watch, with the owner's rights, for brief(). Not PUBLIC (0.20.0): granted with brief().$q$;
