-- pg_phasevec 0.9.0: phasevec.search(watch, question, k) — the search as one SQL call, the database
-- in the middle. Until now a question was read only by talking to the reader's socket, so whoever
-- asked had to reach that socket; a sandboxed caller (yggdrasil's acts, under Landlock) cannot, and
-- should not. Now the database asks the watch's sealed reader for the question's codes (phasevec._ask,
-- a superuser-set socket path) and runs find_ivf (or find, without an index) itself, in the CALLER's
-- snapshot: the validation against phasevec.sources is the caller's transaction, as with find.
\echo Use "ALTER EXTENSION pg_phasevec UPDATE TO '0.9.0'" to load this file. \quit

CREATE FUNCTION phasevec._ask(p_watch text, p_request text) RETURNS text
    AS 'MODULE_PATHNAME', 'phasevec_ask' LANGUAGE C STRICT VOLATILE;
REVOKE ALL ON FUNCTION phasevec._ask(text, text) FROM PUBLIC;
COMMENT ON FUNCTION phasevec._ask(text, text) IS
    'One JSON line to the reader of a watch (<phasevec.socket_dir>/<watch>.sock), one line back. Internal: use phasevec.search().';

-- The search by question. The reader that read the question must be the watch's (its seal: same
-- weights, compute and reads): its codes are then comparable with the watch's readings; a different
-- one is refused, never mixed. The rest is find_ivf's (or find's) contract, unchanged.
CREATE FUNCTION phasevec.search(p_watch text, p_question text, p_k int DEFAULT 10, p_partial boolean DEFAULT false,
                                p_m int DEFAULT 200, p_nprobe int DEFAULT 16)
RETURNS TABLE (key text, score double precision, hamming int, state text, familiarity real, read_at timestamptz,
               truncated boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    w       phasevec.watches := phasevec._watch(p_watch);
    wreader text;
    a       jsonb;
BEGIN
    IF p_question IS NULL OR btrim(p_question) = '' THEN
        RAISE EXCEPTION 'phasevec: the question is empty';
    END IF;
    SELECT rd.name INTO wreader FROM phasevec.readers rd WHERE rd.id = w.reader;
    a := phasevec._ask(p_watch, jsonb_build_object('q', p_question, 'encode', true)::text)::jsonb;
    IF a ? 'error' THEN
        RAISE EXCEPTION 'phasevec: the reader of watch % refused the question: %', p_watch, a->>'error';
    END IF;
    IF a->>'reader' IS DISTINCT FROM wreader THEN
        RAISE EXCEPTION 'phasevec: the question was read by %, the watch % is read by %: not comparable',
            coalesce(a->>'reader', '(none)'), p_watch, wreader
            USING HINT = 'The socket of this watch is served by another reader: restart the watch''s reader.';
    END IF;
    IF EXISTS (SELECT 1 FROM phasevec.ivf_cents c WHERE c.watch = w.id AND c.reader = w.reader) THEN
        RETURN QUERY SELECT * FROM phasevec.find_ivf(p_watch, (a->>'code64')::bigint, (a->>'code')::smallint[], p_k,
                                                     p_partial, p_m, (a->>'code256')::bit(256), p_nprobe);
    ELSE
        RETURN QUERY SELECT * FROM phasevec.find(p_watch, (a->>'code64')::bigint, (a->>'code')::smallint[], p_k,
                                                 p_partial, p_m, (a->>'code256')::bit(256));
    END IF;
END;
$$;
COMMENT ON FUNCTION phasevec.search(text, text, int, boolean, int, int) IS
    'Search a watch by a question in words: the watch''s sealed reader reads it, find_ivf (or find) answers in the caller''s snapshot.';
