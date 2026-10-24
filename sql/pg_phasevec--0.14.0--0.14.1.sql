-- pg_phasevec 0.14.1: the verifiable memory does not overflow.
--
--  * verify() has a budget: it stops starting new proofs once the pass took p_budget. A proof cannot be cut from
--    inside a function (statement_timeout is armed per top-level statement), so verify_one() proves ONE key per
--    call: a caller that sets statement_timeout around it cuts a slow proof, and refute() records why.
--  * usefulness is three counters per key, not one row per use (phasevec.uses grew without bound).
--  * recall() computes the disputes once per question, only for the topics of its hits.

-- One proof, read-only, in a subtransaction always rolled back, with the caller rights and search_path.
CREATE FUNCTION phasevec._prove(p_proof text, OUT ok boolean, OUT err text) LANGUAGE plpgsql AS $f$
DECLARE msg text;
BEGIN
    ok := NULL; err := NULL;
    BEGIN
        PERFORM set_config($q$transaction_read_only$q$, $q$on$q$, true);
        EXECUTE format($q$SELECT (%s)::boolean$q$, p_proof) INTO ok;
        RAISE EXCEPTION USING ERRCODE = $q$PVTRU$q$, MESSAGE = coalesce(ok::text, $q$null$q$);
    EXCEPTION
        WHEN SQLSTATE $q$PVTRU$q$ THEN
            GET STACKED DIAGNOSTICS msg = MESSAGE_TEXT;
            ok := CASE msg WHEN $q$true$q$ THEN true WHEN $q$false$q$ THEN false ELSE NULL END;
            IF ok IS NULL THEN err := $q$the proof returned NULL$q$; END IF;
        WHEN query_canceled THEN
            RAISE;
        WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS msg = MESSAGE_TEXT;
            ok := false; err := msg;
    END;
END;
$f$;

DROP FUNCTION phasevec.verify(text, int, interval);
-- The proofs that are due, oldest first, until p_n of them or until the pass took p_budget (checked between
-- proofs). No pinned search_path, on purpose: proofs are the caller code (see 0.14.0).
CREATE FUNCTION phasevec.verify(p_watch text, p_n int DEFAULT 100, p_every interval DEFAULT interval $q$10 minutes$q$,
                                p_budget interval DEFAULT interval $q$5 seconds$q$)
RETURNS TABLE (key text, verdict text, error text) LANGUAGE plpgsql AS $f$
DECLARE
    w   phasevec.watches := phasevec._watch(p_watch);
    d   record;
    r   record;
    t0  timestamptz := clock_timestamp();
BEGIN
    FOR d IN SELECT * FROM phasevec._truth_due(w.id, p_n, p_every) LOOP
        EXIT WHEN clock_timestamp() - t0 >= p_budget;
        r := phasevec._prove(d.proof);
        key := d.key;
        verdict := phasevec._truth_set(w.id, d.key, coalesce(r.ok, false), r.err);
        error := r.err;
        RETURN NEXT;
    END LOOP;
END;
$f$;

-- One key: for a caller that bounds each proof with statement_timeout (a canceled proof is an error to the caller,
-- which then calls refute()). NULL when the key has no proof or was replaced.
CREATE FUNCTION phasevec.verify_one(p_watch text, p_key text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE
    w   phasevec.watches := phasevec._watch(p_watch);
    pr  text;
    r   record;
BEGIN
    SELECT t.proof INTO pr FROM phasevec.truth t
     WHERE t.watch = w.id AND t.key = p_key AND t.proof IS NOT NULL AND t.verdict <> $q$replaced$q$;
    IF pr IS NULL THEN
        RETURN NULL;
    END IF;
    r := phasevec._prove(pr);
    RETURN phasevec._truth_set(w.id, p_key, coalesce(r.ok, false), r.err);
END;
$f$;

-- Refute a key with a reason (a proof cut by its time limit, or a correction without a replacement row).
CREATE FUNCTION phasevec.refute(p_watch text, p_key text, p_reason text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
DECLARE w phasevec.watches := phasevec._watch(p_watch);
BEGIN
    IF coalesce(btrim(p_reason), $q$$q$) = $q$$q$ THEN
        RAISE EXCEPTION $q$phasevec: a refutation says why$q$;
    END IF;
    INSERT INTO phasevec.truth AS t (watch, key, verdict, verified_at, last_error)
    VALUES (w.id, p_key, $q$refuted$q$, now(), p_reason)
    ON CONFLICT (watch, key) DO UPDATE
       SET verdict = $q$refuted$q$, verified_at = now(), last_error = p_reason, changed_at = now()
     WHERE t.verdict <> $q$replaced$q$;
END;
$f$;

-- Usefulness as three counters per key.
CREATE TABLE phasevec.usefulness (
    watch       int  NOT NULL REFERENCES phasevec.watches (id) ON DELETE CASCADE,
    key         text NOT NULL,
    helped      bigint NOT NULL DEFAULT 0,
    not_helped  bigint NOT NULL DEFAULT 0,
    brought     bigint NOT NULL DEFAULT 0,
    last_at     timestamptz NOT NULL DEFAULT pg_catalog.now(),
    PRIMARY KEY (watch, key)
);
COMMENT ON TABLE phasevec.usefulness IS
    $q$Learned usefulness, as counters: how often a row helped the work that followed, did not, or was only brought.$q$;
INSERT INTO phasevec.usefulness (watch, key, helped, not_helped, brought, last_at)
SELECT watch, key, count(*) FILTER (WHERE outcome = 1), count(*) FILTER (WHERE outcome = -1),
       count(*) FILTER (WHERE outcome = 0), max(at)
  FROM phasevec.uses GROUP BY watch, key;
DROP TABLE phasevec.uses;

CREATE OR REPLACE FUNCTION phasevec.note_use(p_watch text, p_key text, p_outcome smallint)
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
    INSERT INTO phasevec.usefulness AS u (watch, key, helped, not_helped, brought)
    VALUES ((phasevec._watch(p_watch)).id, p_key, (p_outcome = 1)::int, (p_outcome = -1)::int, (p_outcome = 0)::int)
    ON CONFLICT (watch, key) DO UPDATE
       SET helped = u.helped + EXCLUDED.helped, not_helped = u.not_helped + EXCLUDED.not_helped,
           brought = u.brought + EXCLUDED.brought, last_at = now()
$f$;

-- recall(): the disputes once per question, only for the topics among its hits; usefulness from the counters.
CREATE OR REPLACE FUNCTION phasevec.recall(p_watch text, p_question text, p_k int DEFAULT 10, p_partial boolean DEFAULT false)
RETURNS TABLE (key text, score double precision, adjusted double precision, verdict text, support jsonb,
               verified_at timestamptz, topic text, disputed_by text[], usefulness int, state text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
    WITH w AS (SELECT (phasevec._watch(p_watch)).id AS id),
    hits AS (SELECT * FROM phasevec.search(p_watch, p_question, least(p_k * 3, 1000), p_partial)),
    th AS (SELECT h.key, t.topic AS tp, t.support AS sp, t.verified_at AS va,
                  coalesce(phasevec._verdict(t), $q$unproven$q$) AS v
             FROM hits h CROSS JOIN w LEFT JOIN phasevec.truth t ON t.watch = w.id AND t.key = h.key),
    vivas AS (SELECT t.topic, t.key, s.text_hash FROM phasevec.truth t CROSS JOIN w
                JOIN phasevec.sources s ON s.watch = t.watch AND s.key = t.key
               WHERE t.watch = w.id AND t.topic IN (SELECT th.tp FROM th WHERE th.tp IS NOT NULL)
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

REVOKE ALL ON FUNCTION phasevec._prove(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION phasevec.verify(text, int, interval, interval) FROM PUBLIC;
REVOKE ALL ON FUNCTION phasevec.verify_one(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION phasevec.refute(text, text, text) FROM PUBLIC;
