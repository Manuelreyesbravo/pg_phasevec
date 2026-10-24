-- pg_phasevec 0.14.0: memory that knows what is still true (the v1 of the verifiable memory).
--
-- A reading says what a sealed reader understood of a row and whether it matches the text. It cannot say whether
-- what the text claims is still TRUE: a resolved task, a corrected decision, a re-measured number keep their text
-- and keep being served as fresh. Truth is a second axis, kept apart from the seven reading states (kstate, counts,
-- coverage and the queue do not change):
--
--   phasevec.truth   per key: an optional proof (SQL returning a boolean), its support (references to show), a
--                    topic (two current rows with the same topic and different text are in dispute), an expiry,
--                    and what replaced it. Its truth is replaced > expired > refuted > verified > unproven.
--   searches         find, alike, find_hybrid, find_npu, find_ivf (C) and _ivf_valid never serve a replaced,
--                    expired or refuted key; their signatures do not change.
--   verify()         runs the proofs that are due, each read-only and in a subtransaction that is always rolled
--                    back, with the caller rights; a proof that errs refutes its row.
--   recall()         search() plus truth, support, disputes and learned usefulness (phasevec.uses).

CREATE TABLE phasevec.truth (
    watch           int  NOT NULL REFERENCES phasevec.watches (id) ON DELETE CASCADE,
    key             text NOT NULL,
    proof           text,
    support         jsonb,
    topic           text,
    expires_at      timestamptz,
    replaced_by     text,
    reason          text,
    verdict         text NOT NULL DEFAULT $q$unproven$q$
                    CHECK (verdict IN ($q$verified$q$, $q$unproven$q$, $q$refuted$q$, $q$replaced$q$)),
    verified_at     timestamptz,
    last_error      text,
    changed_at      timestamptz NOT NULL DEFAULT pg_catalog.now(),
    PRIMARY KEY (watch, key),
    CHECK ((verdict = $q$replaced$q$) = (replaced_by IS NOT NULL))
);
CREATE INDEX truth_topic ON phasevec.truth (watch, topic) WHERE topic IS NOT NULL;
COMMENT ON TABLE phasevec.truth IS
    $q$What a watched row claims and whether it still holds: proof, support, topic, expiry, replacement. Kept apart from the reading states.$q$;

CREATE TABLE phasevec.uses (
    watch   int  NOT NULL REFERENCES phasevec.watches (id) ON DELETE CASCADE,
    key     text NOT NULL,
    at      timestamptz NOT NULL DEFAULT pg_catalog.now(),
    outcome smallint NOT NULL CHECK (outcome IN (-1, 0, 1))
);
CREATE INDEX uses_key ON phasevec.uses (watch, key);
COMMENT ON TABLE phasevec.uses IS
    $q$Learned usefulness: a row was brought (0), helped the work that followed (1) or did not (-1).$q$;

-- The truth a key has NOW (expiry is compared at read time, so it is exact without any sweep).
CREATE FUNCTION phasevec._verdict(t phasevec.truth) RETURNS text
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    SELECT CASE WHEN t.verdict = $q$replaced$q$ THEN $q$replaced$q$
                WHEN t.expires_at IS NOT NULL AND t.expires_at <= now() THEN $q$expired$q$
                ELSE t.verdict END
$f$;

-- Say what a row claims: its proof, topic, support and expiry. A new proof makes the row unproven until verified.
CREATE FUNCTION phasevec.assert(p_watch text, p_key text, p_proof text DEFAULT NULL, p_topic text DEFAULT NULL,
                                p_support jsonb DEFAULT NULL, p_expires_at timestamptz DEFAULT NULL)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
DECLARE w phasevec.watches := phasevec._watch(p_watch);
BEGIN
    INSERT INTO phasevec.truth AS t (watch, key, proof, topic, support, expires_at)
    VALUES (w.id, p_key, p_proof, p_topic, p_support, p_expires_at)
    ON CONFLICT (watch, key) DO UPDATE
       SET proof = EXCLUDED.proof, topic = EXCLUDED.topic, support = EXCLUDED.support, expires_at = EXCLUDED.expires_at,
           verdict = CASE WHEN t.verdict = $q$replaced$q$ THEN t.verdict ELSE $q$unproven$q$ END,
           verified_at = NULL, last_error = NULL, changed_at = now();
END;
$f$;

-- Say that a row was replaced by another of the same watch, and why. The old row is never served again until
-- unsuperseded; its history stays.
CREATE FUNCTION phasevec.supersede(p_watch text, p_old text, p_new text, p_reason text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
DECLARE w phasevec.watches := phasevec._watch(p_watch);
BEGIN
    IF p_old = p_new THEN
        RAISE EXCEPTION $q$phasevec: a row cannot replace itself$q$;
    END IF;
    IF coalesce(btrim(p_reason), $q$$q$) = $q$$q$ THEN
        RAISE EXCEPTION $q$phasevec: a replacement says why$q$;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM phasevec.sources s WHERE s.watch = w.id AND s.key = p_new) THEN
        RAISE EXCEPTION $q$phasevec: row % of watch % does not exist: it cannot replace anything$q$, p_new, p_watch;
    END IF;
    INSERT INTO phasevec.truth AS t (watch, key, replaced_by, reason, verdict)
    VALUES (w.id, p_old, p_new, p_reason, $q$replaced$q$)
    ON CONFLICT (watch, key) DO UPDATE
       SET replaced_by = p_new, reason = p_reason, verdict = $q$replaced$q$, changed_at = now();
END;
$f$;

CREATE FUNCTION phasevec.unsupersede(p_watch text, p_key text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
DECLARE w phasevec.watches := phasevec._watch(p_watch);
BEGIN
    UPDATE phasevec.truth SET replaced_by = NULL, reason = NULL, verdict = $q$unproven$q$, verified_at = NULL,
                              changed_at = now()
     WHERE watch = w.id AND key = p_key AND verdict = $q$replaced$q$;
END;
$f$;

-- The proofs that are due, oldest first (the reader process calls verify() when its queue empties).
CREATE FUNCTION phasevec._truth_due(p_watch int, p_n int, p_every interval)
RETURNS TABLE (key text, proof text) LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
    SELECT t.key, t.proof FROM phasevec.truth t
     WHERE t.watch = p_watch AND t.proof IS NOT NULL AND t.verdict <> $q$replaced$q$
       AND (t.verified_at IS NULL OR t.verified_at < now() - p_every)
     ORDER BY t.verified_at NULLS FIRST, t.key
     LIMIT p_n
$f$;

CREATE FUNCTION phasevec._truth_set(p_watch int, p_key text, p_ok boolean, p_error text)
RETURNS text LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
    UPDATE phasevec.truth
       SET verdict = CASE WHEN p_ok THEN $q$verified$q$ ELSE $q$refuted$q$ END,
           verified_at = now(), last_error = p_error
     WHERE watch = p_watch AND key = p_key AND verdict <> $q$replaced$q$
    RETURNING verdict
$f$;

-- Run the proofs that are due with the CALLER rights. Each runs read-only inside a subtransaction that is always
-- rolled back (the result travels in the exception), so a proof can read anything the caller can and change nothing.
-- A proof that returns false, NULL, or errs refutes its row; the error is kept.
-- No pinned search_path, on purpose: the proofs are the caller code and resolve names as the caller does (with a
-- pinned one, found by the test, a proof could not see the tables it was written to check). Everything this function
-- calls itself is schema-qualified. Write proofs schema-qualified when they must not depend on the caller.
CREATE FUNCTION phasevec.verify(p_watch text, p_n int DEFAULT 100, p_every interval DEFAULT interval $q$10 minutes$q$)
RETURNS TABLE (key text, verdict text, error text) LANGUAGE plpgsql AS $f$
DECLARE
    w   phasevec.watches := phasevec._watch(p_watch);
    d   record;
    ok  boolean;
    err text;
    msg text;
BEGIN
    FOR d IN SELECT * FROM phasevec._truth_due(w.id, p_n, p_every) LOOP
        ok := NULL; err := NULL;
        BEGIN
            PERFORM set_config($q$transaction_read_only$q$, $q$on$q$, true);
            EXECUTE format($q$SELECT (%s)::boolean$q$, d.proof) INTO ok;
            RAISE EXCEPTION USING ERRCODE = $q$PVTRU$q$, MESSAGE = coalesce(ok::text, $q$null$q$);
        EXCEPTION
            WHEN SQLSTATE $q$PVTRU$q$ THEN
                GET STACKED DIAGNOSTICS msg = MESSAGE_TEXT;
                ok := CASE msg WHEN $q$true$q$ THEN true WHEN $q$false$q$ THEN false ELSE NULL END;
                IF ok IS NULL THEN err := $q$the proof returned NULL$q$; END IF;
            WHEN OTHERS THEN
                GET STACKED DIAGNOSTICS msg = MESSAGE_TEXT;
                ok := false; err := msg;
        END;
        key := d.key;
        verdict := phasevec._truth_set(w.id, d.key, coalesce(ok, false), err);
        error := err;
        RETURN NEXT;
    END LOOP;
END;
$f$;

-- Truth coverage of a watch: every current source row once, by its truth now (rows without a truth row are unproven).
CREATE FUNCTION phasevec.truth_coverage(p_watch text)
RETURNS TABLE (verdict text, n bigint) LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
    SELECT coalesce(phasevec._verdict(t), $q$unproven$q$) AS verdict, count(*)
      FROM phasevec.sources s
      LEFT JOIN phasevec.truth t ON t.watch = s.watch AND t.key = s.key
     WHERE s.watch = (phasevec._watch(p_watch)).id
     GROUP BY 1 ORDER BY 1
$f$;

-- Pairs of CURRENT rows (verified or unproven) that claim the same topic with different text.
CREATE FUNCTION phasevec.disputes(p_watch text)
RETURNS TABLE (topic text, key_a text, key_b text) LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
    WITH vivas AS (
        SELECT t.topic, t.key, s.text_hash FROM phasevec.truth t
          JOIN phasevec.sources s ON s.watch = t.watch AND s.key = t.key
         WHERE t.watch = (phasevec._watch(p_watch)).id AND t.topic IS NOT NULL
           AND phasevec._verdict(t) IN ($q$verified$q$, $q$unproven$q$))
    SELECT a.topic, a.key, b.key FROM vivas a JOIN vivas b ON b.topic = a.topic AND b.key > a.key
     WHERE a.text_hash <> b.text_hash
     ORDER BY 1, 2, 3
$f$;

-- The chain of replacements from a key to the row that holds now (at most 50 steps; a cycle stops).
CREATE FUNCTION phasevec.replacement(p_watch text, p_key text)
RETURNS TABLE (step int, key text, reason text) LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
    WITH RECURSIVE c(step, key, reason, seen) AS (
        SELECT 0, p_key, NULL::text, ARRAY[p_key]
      UNION ALL
        SELECT c.step + 1, t.replaced_by, t.reason, c.seen || t.replaced_by
          FROM c JOIN phasevec.truth t ON t.watch = (phasevec._watch(p_watch)).id AND t.key = c.key
         WHERE t.verdict = $q$replaced$q$ AND c.step < 50 AND NOT t.replaced_by = ANY (c.seen))
    SELECT step, key, reason FROM c ORDER BY step
$f$;

CREATE FUNCTION phasevec.note_use(p_watch text, p_key text, p_outcome smallint)
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
    INSERT INTO phasevec.uses (watch, key, outcome) VALUES ((phasevec._watch(p_watch)).id, p_key, p_outcome)
$f$;

-- search() with what a reader of the answer needs to trust it: its truth now, its support, when it was verified,
-- its topic and the current rows that dispute it, and how useful it proved (net uses). Ordered by the score
-- nudged by usefulness (x (1 + 0.1 tanh(net/5))): usefulness breaks near-ties, it does not overrule similarity.
CREATE FUNCTION phasevec.recall(p_watch text, p_question text, p_k int DEFAULT 10, p_partial boolean DEFAULT false)
RETURNS TABLE (key text, score double precision, adjusted double precision, verdict text, support jsonb,
               verified_at timestamptz, topic text, disputed_by text[], usefulness int, state text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
    WITH w AS (SELECT (phasevec._watch(p_watch)).id AS id),
    hits AS (SELECT * FROM phasevec.search(p_watch, p_question, least(p_k * 3, 1000), p_partial)),
    u AS (SELECT us.key, sum(us.outcome)::int AS net FROM phasevec.uses us, w WHERE us.watch = w.id
           AND us.key IN (SELECT h.key FROM hits h) GROUP BY us.key)
    SELECT h.key, h.score,
           h.score * (1 + 0.1 * tanh(coalesce(u.net, 0) / 5.0)),
           CASE WHEN d.keys IS NOT NULL THEN $q$disputed$q$ ELSE coalesce(phasevec._verdict(t), $q$unproven$q$) END,
           t.support, t.verified_at, t.topic, d.keys, coalesce(u.net, 0), h.state
      FROM hits h
      CROSS JOIN w
      LEFT JOIN phasevec.truth t ON t.watch = w.id AND t.key = h.key
      LEFT JOIN u ON u.key = h.key
      LEFT JOIN LATERAL (
          SELECT array_agg(x.key_b ORDER BY x.key_b) AS keys FROM (
              SELECT CASE WHEN dp.key_a = h.key THEN dp.key_b ELSE dp.key_a END AS key_b
                FROM phasevec.disputes(p_watch) dp WHERE h.key IN (dp.key_a, dp.key_b)) x) d ON true
     ORDER BY 3 DESC NULLS LAST, (coalesce(phasevec._verdict(t), $q$unproven$q$) = $q$verified$q$) DESC, h.key
     LIMIT p_k
$f$;

REVOKE ALL ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION phasevec.supersede(text, text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION phasevec.unsupersede(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION phasevec._truth_due(int, int, interval) FROM PUBLIC;
REVOKE ALL ON FUNCTION phasevec._truth_set(int, text, boolean, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION phasevec.verify(text, int, interval) FROM PUBLIC;
REVOKE ALL ON FUNCTION phasevec.note_use(text, text, smallint) FROM PUBLIC;


-- The searches, copied unchanged from their latest version except for the truth filter wherever they
-- require a live reading: a replaced, expired or refuted key is never served. Signatures do not change.

-- find: from sql/pg_phasevec--0.4.0--0.5.0.sql, + truth filter (1)
CREATE OR REPLACE FUNCTION phasevec.find(p_watch text, p_q64 bigint, p_q smallint[], p_k int DEFAULT 10,
                            p_partial boolean DEFAULT false, p_m int DEFAULT 200,
                            p_q256 bit(256) DEFAULT NULL)
RETURNS TABLE (key text, score double precision, hamming int, state text, familiarity real, read_at timestamptz,
               truncated boolean)
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
    WITH sweep AS (
        SELECT r.key, r.text_hash, r.code, r.familiarity, r.read_at, r.truncated,
               CASE WHEN p_q256 IS NOT NULL THEN bit_count(r.code256 # p_q256)
                    ELSE bit_count((r.code64 # p_q64)::bit(64)) END::int AS ham
          FROM phasevec.readings r
         WHERE r.watch = w.id AND r.reader = w.reader AND r.failed IS NULL AND NOT EXISTS (SELECT 1 FROM phasevec.truth tr WHERE tr.watch = r.watch AND tr.key = r.key AND (tr.verdict IN ($q$replaced$q$, $q$refuted$q$) OR tr.expires_at <= now()))
           AND (p_q256 IS NULL OR r.code256 IS NOT NULL)
         ORDER BY ham, r.key
         LIMIT p_m
    ), cand AS (
        SELECT sw.* FROM sweep sw
          JOIN phasevec.sources s ON s.watch = w.id AND s.key = sw.key AND s.text_hash = sw.text_hash
    )
    SELECT c.key,
           (SELECT sum(a::float8 * b) FROM unnest(c.code, p_q) t(a, b))
             / nullif((SELECT sqrt(sum(a::float8 * a)) FROM unnest(c.code) a) * qnorm, 0),
           c.ham,
           CASE WHEN w.doubt_below IS NOT NULL AND c.familiarity < w.doubt_below THEN 'doubtful' ELSE 'fresh' END,
           c.familiarity, c.read_at, c.truncated
      FROM cand c
     ORDER BY 2 DESC NULLS LAST, c.key
     LIMIT p_k;
END;
$$;

-- find_hybrid: from sql/pg_phasevec--0.5.0--0.6.0.sql, + truth filter (2)
CREATE OR REPLACE FUNCTION phasevec.find_hybrid(p_watch text, p_text text, p_q64 bigint, p_q smallint[], p_k int DEFAULT 10,
                                   p_partial boolean DEFAULT false, p_m int DEFAULT 200,
                                   p_q256 bit(256) DEFAULT NULL, p_lm int DEFAULT 200)
RETURNS TABLE (key text, score double precision, vector_score double precision, vector_rank int,
               lexical_score double precision, lexical_rank int, hamming int, state text,
               familiarity real, read_at timestamptz, truncated boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    w       phasevec.watches := phasevec._watch(p_watch);
    ld      phasevec.lexdocs;
    dims    int;
    fresh   numeric;
    missing text;
    qnorm   double precision;
    terms   text[];
    idfs    double precision[];
BEGIN
    SELECT rd.dims INTO dims FROM phasevec.readers rd WHERE rd.id = w.reader;
    IF p_q IS NULL OR cardinality(p_q) <> dims THEN
        RAISE EXCEPTION 'phasevec: the question must be read by the watch''s reader (% dimensions)', dims;
    END IF;
    -- k may exceed either arm: asking for k = m + lm returns every candidate of both, with its ranks
    -- (the union a reranker reads).
    IF p_k NOT BETWEEN 1 AND 1000 OR p_m NOT BETWEEN 1 AND 100000 OR p_lm NOT BETWEEN 1 AND 100000 THEN
        RAISE EXCEPTION 'phasevec: k must be in 1..1000, and m and lm in 1..100000';
    END IF;
    IF w.lexical IS NULL THEN
        RAISE EXCEPTION 'phasevec: watch % is not read lexically', p_watch
            USING HINT = 'phasevec.lexical(watch, config) reads it; find() asks the readings alone.';
    END IF;
    SELECT * INTO ld FROM phasevec.lexdocs d WHERE d.watch = w.id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'phasevec: the words of watch % were never counted', p_watch
            USING HINT = 'phasevec.lexical_refresh(watch) counts them.';
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
    IF NOT p_partial AND EXISTS (SELECT 1 FROM phasevec.sources s WHERE s.watch = w.id AND s.lexemes IS NULL) THEN
        RAISE EXCEPTION 'phasevec: watch % has rows not read lexically', p_watch
            USING HINT = 'phasevec.lexical(watch, config) reads them again. Pass p_partial => true to accept it knowingly.';
    END IF;

    -- The question's words, rarest first: at most ten, each carried by at most 5 % of the rows. A word
    -- not counted yet (no row had it at the last refresh) weighs as the rarest.
    SELECT array_agg(t.lexeme ORDER BY t.idf DESC, t.lexeme), array_agg(t.idf ORDER BY t.idf DESC, t.lexeme)
      INTO terms, idfs
      FROM (SELECT q.lexeme,
                   ln(1 + (ld.n - coalesce(st.ndoc, 0) + 0.5) / (coalesce(st.ndoc, 0) + 0.5)) AS idf
              FROM unnest(tsvector_to_array(phasevec._lexemes(w.lexical, p_text))) q(lexeme)
              LEFT JOIN phasevec.lexstats st ON st.watch = w.id AND st.lexeme = q.lexeme
             WHERE coalesce(st.ndoc, 0) <= greatest(1, 0.05 * ld.n)
             ORDER BY 2 DESC, 1
             LIMIT 10) t;

    SELECT sqrt(sum(x::float8 * x)) INTO qnorm FROM unnest(p_q) x;

    RETURN QUERY
    WITH sweep AS (
        SELECT r.key, r.text_hash, r.code,
               CASE WHEN p_q256 IS NOT NULL THEN bit_count(r.code256 # p_q256)
                    ELSE bit_count((r.code64 # p_q64)::bit(64)) END::int AS ham
          FROM phasevec.readings r
         WHERE r.watch = w.id AND r.reader = w.reader AND r.failed IS NULL AND NOT EXISTS (SELECT 1 FROM phasevec.truth tr WHERE tr.watch = r.watch AND tr.key = r.key AND (tr.verdict IN ($q$replaced$q$, $q$refuted$q$) OR tr.expires_at <= now()))
           AND (p_q256 IS NULL OR r.code256 IS NOT NULL)
         ORDER BY ham, r.key
         LIMIT p_m
    ), vec AS (
        SELECT v.key, v.cos, row_number() OVER (ORDER BY v.cos DESC NULLS LAST, v.key)::int AS vr
          FROM (SELECT sw.key,
                       (SELECT sum(a::float8 * b) FROM unnest(sw.code, p_q) t(a, b))
                         / nullif((SELECT sqrt(sum(a::float8 * a)) FROM unnest(sw.code) a) * qnorm, 0) AS cos
                  FROM sweep sw
                  JOIN phasevec.sources s ON s.watch = w.id AND s.key = sw.key AND s.text_hash = sw.text_hash) v
    ), lex AS (
        SELECT l.key, l.ls, row_number() OVER (ORDER BY l.ls DESC, l.key)::int AS lr
          FROM (SELECT x.key, sum(x.idf) * 2.2 / (1 + 1.2 * (0.25 + 0.75 * x.n / nullif(ld.avg_n, 0))) AS ls
                  FROM unnest(terms, idfs) t(lexeme, idf)
                  CROSS JOIN LATERAL (
                      SELECT s.key, coalesce(s.lexeme_n, 0)::float8 AS n, t.idf
                        FROM phasevec.sources s
                        JOIN phasevec.readings r ON r.watch = s.watch AND r.key = s.key AND r.reader = w.reader
                                              AND r.text_hash = s.text_hash AND r.failed IS NULL AND NOT EXISTS (SELECT 1 FROM phasevec.truth tr WHERE tr.watch = r.watch AND tr.key = r.key AND (tr.verdict IN ($q$replaced$q$, $q$refuted$q$) OR tr.expires_at <= now()))
                       WHERE s.watch = w.id AND s.lexemes @@ phasevec._term(t.lexeme)) x
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
      JOIN phasevec.readings r ON r.watch = w.id AND r.key = f.key AND r.reader = w.reader
     ORDER BY f.rrf DESC, f.key;
END;
$$;

-- find_npu: from sql/pg_phasevec--0.11.0--0.12.0.sql, + truth filter (3)
CREATE OR REPLACE FUNCTION phasevec.find_npu(p_watch text, p_q smallint[], p_k int DEFAULT 10, p_partial boolean DEFAULT false)
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
      JOIN phasevec.readings r ON r.watch = w.id AND r.key = c.key AND r.reader = w.reader AND r.failed IS NULL AND NOT EXISTS (SELECT 1 FROM phasevec.truth tr WHERE tr.watch = r.watch AND tr.key = r.key AND (tr.verdict IN ($q$replaced$q$, $q$refuted$q$) OR tr.expires_at <= now())) AND r.text_hash = c.h
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
              JOIN phasevec.readings r ON r.watch = w.id AND r.key = c.key AND r.reader = w.reader AND r.failed IS NULL AND NOT EXISTS (SELECT 1 FROM phasevec.truth tr WHERE tr.watch = r.watch AND tr.key = r.key AND (tr.verdict IN ($q$replaced$q$, $q$refuted$q$) OR tr.expires_at <= now())) AND r.text_hash = c.h
              JOIN phasevec.sources s ON s.watch = w.id AND s.key = c.key AND s.text_hash = c.h
            UNION ALL
            SELECT r.key,
                   (SELECT sum(a::float8 * b) FROM unnest(r.code, p_q) z(a, b))
                     / nullif((SELECT sqrt(sum(a::float8 * a)) FROM unnest(r.code) a) * qnorm, 0),
                   r.familiarity, r.read_at, r.truncated
              FROM phasevec.npu_dirty d
              JOIN phasevec.readings r ON r.watch = d.watch AND r.key = d.key AND r.reader = w.reader AND r.failed IS NULL AND NOT EXISTS (SELECT 1 FROM phasevec.truth tr WHERE tr.watch = r.watch AND tr.key = r.key AND (tr.verdict IN ($q$replaced$q$, $q$refuted$q$) OR tr.expires_at <= now()))
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

-- _ivf_valid: from sql/pg_phasevec--0.9.0--0.10.0.sql, + truth filter (1)
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
                                AND r.failed IS NULL AND NOT EXISTS (SELECT 1 FROM phasevec.truth tr WHERE tr.watch = r.watch AND tr.key = r.key AND (tr.verdict IN ($q$replaced$q$, $q$refuted$q$) OR tr.expires_at <= now())) AND r.text_hash = c.text_hash
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
