-- 0.20.0 (seventeenth review): a claim's identity is injective over everything that changes what its proof means; a
-- proof's session has only the settings its author could set itself, and only what the author's SESSION had (not the
-- SET clause of a function it was inside); a refuted claim is retired.
\set VERBOSITY terse

CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register($n$r1$n$, repeat($h$a$h$, 64), 4) > 0 AS r1;
CREATE TABLE notes17 (id int PRIMARY KEY, body text);
INSERT INTO notes17 SELECT g, $t$note $t$ || g FROM generate_series(1, 9) g;
SELECT phasevec.watch($w$notes17$w$, $w$notes17$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) > 0 AS watch;
CREATE ROLE pv17_au;
GRANT USAGE ON SCHEMA phasevec TO pv17_au;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz) TO pv17_au;
GRANT SELECT ON notes17 TO pv17_au;
CREATE FUNCTION public.pv17_one() RETURNS int LANGUAGE sql AS $f$ SELECT 1 $f$;

-- (a) VI-1. Two settings, and one whose value holds a newline and reads as both: two claims, two identities. In the
-- sixteenth cut the settings were joined with a newline, and a verdict judged for one was recorded for the other.
SELECT phasevec._bind(sha256($b$t$b$), $p$p$p$, 10, ARRAY[$e$x.a=1$e$, $e$x.b=2$e$])
       = phasevec._bind(sha256($b$t$b$), $p$p$p$, 10, ARRAY[E'x.a=1\nx.b=2']) AS env_items_collide;
-- and no other part runs into the next: a proof that ends as the settings begin, NULL against empty
SELECT phasevec._bind(NULL, $p$p$p$, 10, ARRAY[$e$x=1$e$]) = phasevec._bind(NULL, E'p\n', 10, ARRAY[$e$x=1$e$])
       AS proof_into_env,
       phasevec._bind(NULL, NULL, 10, NULL) = phasevec._bind(NULL, $p$$p$, 10, $a${}$a$::text[]) AS null_as_empty,
       phasevec._bind(NULL, $p$p$p$, NULL, NULL) = phasevec._bind(NULL, $p$p$p$, 0, NULL) AS null_author_as_0,
       phasevec._bind(NULL, $p$p$p$, 10, ARRAY[NULL]::text[]) = phasevec._bind(NULL, $p$p$p$, 10, ARRAY[$e$$e$])
       AS null_item_as_empty;

-- (b) VI-2. A superuser-only setting (PGC_SUSET) of a library the author's session had not loaded yet: the author
-- names it as a placeholder, which PostgreSQL drops (a WARNING) when the library loads. In the sixteenth cut it was
-- recorded before assert() loaded PL/pgSQL and set in the proof's session as SUSET: key 1 was verified.
\c -
SET client_min_messages = error;
SET ROLE pv17_au;
SET plpgsql.variable_conflict = $v$use_variable$v$;
SELECT phasevec.assert($w$notes17$w$, $k$1$k$, $p$current_setting('plpgsql.variable_conflict', true) = 'use_variable'$p$);
RESET ROLE;
RESET client_min_messages;
-- a superuser's session SET a superuser-only setting and called a SECURITY DEFINER function of the author: the
-- author could not set it, and its proof does not have it (in the sixteenth cut key 2 was verified)
CREATE FUNCTION public.pv17_assert_as_au(p_key text, p_proof text) RETURNS void LANGUAGE sql SECURITY DEFINER
    AS $f$ SELECT phasevec.assert('notes17', p_key, p_proof) $f$;
ALTER FUNCTION public.pv17_assert_as_au(text, text) OWNER TO pv17_au;
\c -
SET session_replication_role = replica;
SELECT public.pv17_assert_as_au($k$2$k$, $p$current_setting('session_replication_role') = 'replica'$p$);
RESET session_replication_role;
-- a hand-written setting the author may not set is not set in its proof's session either (key 3), and (twentieth
-- review, RT20P-ENV-1) the proof is not judged without it: 'unproven' (until then it ran without it: 'refuted')
SET ROLE pv17_au;
SELECT phasevec.assert($w$notes17$w$, $k$3$k$, $p$current_setting('session_replication_role') = 'replica'$p$);
RESET ROLE;
UPDATE phasevec.truth SET proof_env = proof_env || $e$session_replication_role=replica$e$::text WHERE key = $k$3$k$;
SELECT key, array(SELECT e FROM unnest(proof_env) e WHERE e NOT LIKE $l$application_name=%$l$) AS env
  FROM phasevec.truth WHERE key IN ($k$1$k$, $k$2$k$, $k$3$k$) ORDER BY key;
SET client_min_messages = error;
SELECT key, verdict FROM phasevec.verify($w$notes17$w$, 10, $e$0$e$) WHERE key IN ($k$1$k$, $k$2$k$, $k$3$k$) ORDER BY key;
RESET client_min_messages;

-- (c) MIND-ENV-1, as the nineteenth review (R19-PRIV-1) settled it: a claim records the settings in effect where
-- assert() was called, as its author had them there; the SET clause of the author's own function is the author's.
-- Key 4 is asserted by the author's session; key 5 through a SECURITY DEFINER function of the author with SET
-- search_path = pg_catalog, pg_temp (yggdrasil's _afirmar): it records that search_path and its proof means what it
-- means inside that function, where pv17_one() is not found: refuted (in the seventeenth and eighteenth cuts the
-- clause was read past, and a caller without the author's rights chose the search_path of the author's proof:
-- truth_review19b plays that, and the adopted copy of a wrapper's claim). Key 6: a SET inside such a function is the
-- author's too: recorded.
CREATE FUNCTION public.pv17_afirmar(p_key text, p_proof text) RETURNS void LANGUAGE sql SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp AS $f$ SELECT phasevec.assert('notes17', p_key, p_proof) $f$;
ALTER FUNCTION public.pv17_afirmar(text, text) OWNER TO pv17_au;
CREATE FUNCTION public.pv17_afirmar_set(p_key text, p_proof text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp AS $f$
BEGIN
    PERFORM pg_catalog.set_config('extra_float_digits', '2', false);
    PERFORM pg_catalog.set_config('search_path', 'public', false);
    PERFORM phasevec.assert('notes17', p_key, p_proof);
END
$f$;
ALTER FUNCTION public.pv17_afirmar_set(text, text) OWNER TO pv17_au;
\c -
SET ROLE pv17_au;
SELECT phasevec.assert($w$notes17$w$, $k$4$k$, $p$pv17_one() = 1$p$);
RESET ROLE;
SELECT public.pv17_afirmar($k$5$k$, $p$pv17_one() = 1$p$);
SELECT public.pv17_afirmar_set($k$6$k$, $p$pv17_one() = 1 AND current_setting('extra_float_digits') = '2'$p$);
SHOW search_path;
RESET search_path;
RESET extra_float_digits;
SELECT key, array(SELECT e FROM unnest(proof_env) e WHERE e NOT LIKE $l$application_name=%$l$) AS env
  FROM phasevec.truth WHERE key IN ($k$4$k$, $k$5$k$, $k$6$k$) ORDER BY key;
SELECT key, verdict FROM phasevec.verify($w$notes17$w$, 10, $e$0$e$) WHERE key IN ($k$4$k$, $k$5$k$, $k$6$k$) ORDER BY key;

-- (d) MIND-REFUTE-1. A refuted claim is retired: no verify(), verify_one() or adopt() judges it again. In the
-- sixteenth cut key 7 (true proof, refuted by hand) was verified again by the next verify(), and adopt() asserted it
-- again; key 8 keeps its proof and is judged as before.
SET ROLE pv17_au;
SELECT phasevec.assert($w$notes17$w$, $k$7$k$, $p$true$p$);
SELECT phasevec.assert($w$notes17$w$, $k$8$k$, $p$true$p$);
RESET ROLE;
SELECT key, verdict FROM phasevec.verify($w$notes17$w$, 10, $e$0$e$) WHERE key IN ($k$7$k$, $k$8$k$) ORDER BY key;
SELECT phasevec.refute($w$notes17$w$, $k$7$k$, $r$the file is gone$r$);
SELECT key, verdict, proof IS NULL AS retired, phasevec._verdict(t) FROM phasevec.truth t
 WHERE key IN ($k$7$k$, $k$8$k$) ORDER BY key;
SELECT key, verdict FROM phasevec.verify($w$notes17$w$, 10, $e$0$e$) WHERE key IN ($k$7$k$, $k$8$k$) ORDER BY key;
SELECT phasevec.verify_one($w$notes17$w$, $k$7$k$, 5000) AS verify_one_7;
-- its author is gone: adopt() asserts again the proofs of an unknown author, not a retired claim
UPDATE phasevec.truth SET asserted_by_oid = NULL WHERE key IN ($k$7$k$, $k$8$k$);
SELECT key, adopted FROM phasevec.adopt($w$notes17$w$, $r$pv17_au$r$, ARRAY[$k$7$k$, $k$8$k$]) ORDER BY key;
SELECT key, verdict, phasevec._verdict(t) FROM phasevec.truth t WHERE key IN ($k$7$k$, $k$8$k$) ORDER BY key;
-- an assert() makes it a claim again
SET ROLE pv17_au;
SELECT phasevec.assert($w$notes17$w$, $k$7$k$, $p$true$p$);
RESET ROLE;
SELECT key, verdict FROM phasevec.verify($w$notes17$w$, 10, $e$0$e$) WHERE key = $k$7$k$;

DROP TABLE notes17;
DROP EXTENSION pg_phasevec;
DROP FUNCTION public.pv17_one(), public.pv17_assert_as_au(text, text), public.pv17_afirmar(text, text),
    public.pv17_afirmar_set(text, text);
DROP OWNED BY pv17_au;
DROP ROLE pv17_au;
