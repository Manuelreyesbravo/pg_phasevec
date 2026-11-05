-- 0.20.0: a proof runs as its author. Up to 0.19.0 it ran with the rights of whoever called verify(): a
-- low-privilege asserter could make a privileged verifier read for it (a confused deputy), here through the error.
\set VERBOSITY terse

CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register($n$r1$n$, repeat($h$a$h$, 64), 4) > 0 AS r1;
CREATE TABLE notes (id int PRIMARY KEY, body text);
INSERT INTO notes VALUES (1, $t$a claim$t$), (2, $t$another claim$t$), (3, $t$a third one$t$);
SELECT phasevec.watch($w$notes$w$, $w$notes$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) > 0 AS watch;
CREATE SCHEMA pv_private;
CREATE TABLE pv_private.secret (v text);
INSERT INTO pv_private.secret VALUES ($s$hunter2$s$);
CREATE TABLE pv_shared (n int);
INSERT INTO pv_shared VALUES (7);

CREATE ROLE pv_author;
GRANT USAGE ON SCHEMA phasevec TO pv_author;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz) TO pv_author;
GRANT SELECT ON pv_shared TO pv_author;

-- the author says two things: one it can check, one that reads what only the verifier can
SET ROLE pv_author;
SELECT phasevec.assert($w$notes$w$, $k$1$k$, $p$(SELECT n FROM public.pv_shared) = 7$p$);
SELECT phasevec.assert($w$notes$w$, $k$2$k$, $p$(SELECT v FROM pv_private.secret LIMIT 1)::int = 0$p$);
RESET ROLE;
SELECT key, asserted_by FROM phasevec.truth ORDER BY key;

-- the superuser verifies: each proof runs as pv_author, so the secret stays out of the error and the verdict
SELECT key, verdict, error FROM phasevec.verify($w$notes$w$) ORDER BY key;
SELECT key, verdict, last_error FROM phasevec.truth ORDER BY key;

-- the author is the caller's current user, also inside a SECURITY DEFINER function of someone else
CREATE FUNCTION pv_author_says(p text) RETURNS void LANGUAGE sql SECURITY DEFINER
    AS $f$ SELECT phasevec.assert('notes', '3', p) $f$;
ALTER FUNCTION pv_author_says(text) OWNER TO pv_author;
SELECT pv_author_says($p$true$p$);
SELECT key, asserted_by FROM phasevec.truth WHERE key = $k$3$k$;

-- a verifier that does not hold the author's privileges runs none of its proofs: it cannot lend itself rights it
-- does not have, nor borrow the author's
CREATE ROLE pv_verifier;
GRANT USAGE ON SCHEMA phasevec TO pv_verifier;
GRANT EXECUTE ON FUNCTION phasevec._watch(text), phasevec.verify(text, int, interval, interval, int, float8),
                          phasevec.verify_one(text, text, int, float8),
                          phasevec._truth_due(int, int, interval, name), phasevec._truth_of(int, text),
                          phasevec._truth_set(int, text, boolean, text, bytea),
                          phasevec._prove_as(text, int, float8, name) TO pv_verifier;
SET ROLE pv_verifier;
SELECT count(*) AS run FROM phasevec.verify($w$notes$w$, p_every => interval $i$0$i$);
SELECT phasevec.verify_one($w$notes$w$, $k$3$k$);
SELECT * FROM phasevec._prove_as($p$true$p$, 1000, 1e6, $r$pv_author$r$);
RESET ROLE;
-- once it is a member of the author, it may
GRANT pv_author TO pv_verifier;
SET ROLE pv_verifier;
SELECT key, verdict FROM phasevec.verify($w$notes$w$, p_every => interval $i$0$i$) ORDER BY key;
RESET ROLE;

-- the proof runs in a security-restricted operation: it cannot change role, even to one its author may use
CREATE ROLE pv_other;
GRANT pv_other TO pv_author;
SET ROLE pv_author;
SELECT phasevec.assert($w$notes$w$, $k$3$k$, $p$set_config('role', 'pv_other', true) IS NOT NULL$p$);
RESET ROLE;
SELECT phasevec.verify_one($w$notes$w$, $k$3$k$);
SELECT last_error FROM phasevec.truth WHERE key = $k$3$k$;

DROP FUNCTION pv_author_says(text);
DROP TABLE notes, pv_shared;
DROP SCHEMA pv_private CASCADE;
DROP EXTENSION pg_phasevec;
DROP OWNED BY pv_verifier, pv_author, pv_other;
DROP ROLE pv_verifier;
DROP ROLE pv_author;
DROP ROLE pv_other;
