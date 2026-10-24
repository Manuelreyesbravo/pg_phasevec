-- pg_phasevec 0.14.2: every proof runs with its own clock (src/phasevec_truth.c).
--
-- 0.14.1 could not cut one slow proof from inside verify() (statement_timeout is armed per top-level statement), so
-- it asked the caller to prove key by key. Now the proof runs in C, in a subtransaction always rolled back, read-only,
-- with a timer of its own: verify() cuts each slow proof itself and goes on with the next. Before running, the
-- planner estimates the proof; one above p_max_cost is refuted without running. A cancel that is not ours (the
-- caller statement_timeout, a user cancel) is thrown again as always.

CREATE FUNCTION phasevec._prove_c(p_proof text, p_timeout_ms int, p_max_cost float8, OUT ok boolean, OUT err text)
RETURNS record AS $q$MODULE_PATHNAME$q$, $q$phasevec_prove$q$ LANGUAGE C STRICT VOLATILE;

DROP FUNCTION phasevec.verify(text, int, interval, interval);
DROP FUNCTION phasevec.verify_one(text, text);
DROP FUNCTION phasevec._prove(text);

-- The proofs that are due, oldest first, until p_n of them or until the pass took p_budget; each one cut at
-- p_timeout_ms and refused above p_max_cost (planner units). No pinned search_path: proofs are the caller code.
CREATE FUNCTION phasevec.verify(p_watch text, p_n int DEFAULT 100, p_every interval DEFAULT interval $q$10 minutes$q$,
                                p_budget interval DEFAULT interval $q$5 seconds$q$, p_timeout_ms int DEFAULT 2000,
                                p_max_cost float8 DEFAULT 1e6)
RETURNS TABLE (key text, verdict text, error text) LANGUAGE plpgsql AS $f$
DECLARE
    w   phasevec.watches := phasevec._watch(p_watch);
    d   record;
    r   record;
    t0  timestamptz := clock_timestamp();
BEGIN
    FOR d IN SELECT * FROM phasevec._truth_due(w.id, p_n, p_every) LOOP
        EXIT WHEN clock_timestamp() - t0 >= p_budget;
        r := phasevec._prove_c(d.proof, p_timeout_ms, p_max_cost);
        key := d.key;
        verdict := phasevec._truth_set(w.id, d.key, coalesce(r.ok, false), r.err);
        error := r.err;
        RETURN NEXT;
    END LOOP;
END;
$f$;

-- One key, now or out of turn. NULL when the key has no proof or was replaced.
CREATE FUNCTION phasevec.verify_one(p_watch text, p_key text, p_timeout_ms int DEFAULT 2000, p_max_cost float8 DEFAULT 1e6)
RETURNS text LANGUAGE plpgsql AS $f$
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
    r := phasevec._prove_c(pr, p_timeout_ms, p_max_cost);
    RETURN phasevec._truth_set(w.id, p_key, coalesce(r.ok, false), r.err);
END;
$f$;

REVOKE ALL ON FUNCTION phasevec._prove_c(text, int, float8) FROM PUBLIC;
REVOKE ALL ON FUNCTION phasevec.verify(text, int, interval, interval, int, float8) FROM PUBLIC;
REVOKE ALL ON FUNCTION phasevec.verify_one(text, text, int, float8) FROM PUBLIC;
