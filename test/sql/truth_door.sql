-- 0.20.0 (second cut): verify() and verify_one() are the only door to a verdict, and a proof runs as the role that
-- asserted it, by OID. In the first cut a verifier needed EXECUTE on the SECURITY DEFINER internals, and with them
-- it forged 'verified' (_truth_set) and listed every proof and author (_truth_due with another verifier's name);
-- and the author was a role NAME, so a dropped author's proof ran as whatever role took the name next.
\set VERBOSITY terse

CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register($n$r1$n$, repeat($h$a$h$, 64), 4) > 0 AS r1;
CREATE TABLE notes (id int PRIMARY KEY, body text);
INSERT INTO notes VALUES (1, $t$a claim$t$), (2, $t$another claim$t$);
SELECT phasevec.watch($w$notes$w$, $w$notes$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) > 0 AS watch;
CREATE SCHEMA pv_private;
CREATE TABLE pv_private.secret (v text);
INSERT INTO pv_private.secret VALUES ($s$hunter2$s$);
CREATE ROLE pv_admin;
GRANT USAGE ON SCHEMA pv_private TO pv_admin;
GRANT SELECT ON pv_private.secret TO pv_admin;
CREATE ROLE pv_verifier;
CREATE ROLE pv_low;
GRANT USAGE ON SCHEMA phasevec TO pv_admin, pv_verifier, pv_low;
GRANT SELECT ON notes TO pv_admin, pv_low;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz) TO pv_admin, pv_low;
GRANT EXECUTE ON FUNCTION phasevec.verify(text, int, interval, interval, int, float8),
                          phasevec.verify_one(text, text, int, float8) TO pv_verifier;
SELECT id AS notes_id FROM phasevec.watches WHERE name = $w$notes$w$ \gset
SELECT current_user AS su \gset

-- (a) a verifier that may not act as the author cannot forge its verdict nor read its proof
SET ROLE pv_admin;
SELECT phasevec.assert($w$notes$w$, $k$1$k$, $p$(SELECT v FROM pv_private.secret) = 'wrong'$p$);
RESET ROLE;
-- the first cut's documented grants, where they still exist
DO $d$
DECLARE f regprocedure;
BEGIN
    FOR f IN SELECT p.oid::regprocedure FROM pg_proc p
              WHERE p.pronamespace = $n$phasevec$n$::regnamespace
                AND p.proname IN ($f$_watch$f$, $f$_truth_due$f$, $f$_truth_of$f$, $f$_truth_set$f$, $f$_prove_as$f$) LOOP
        EXECUTE format($g$GRANT EXECUTE ON FUNCTION %s TO pv_verifier$g$, f);
    END LOOP;
END $d$;
SET ROLE pv_verifier;
SELECT phasevec.verify_one($w$notes$w$, $k$1$k$);
SELECT key, proof, author FROM phasevec._truth_due(:notes_id, 100, interval $i$0$i$, :'su'::name);
SELECT phasevec._truth_set(:notes_id, $k$1$k$, true, NULL,
       (SELECT bound FROM phasevec._truth_of(:notes_id, $k$1$k$))) AS forged;
-- the internals of this version, even granted, write and read nothing: they carry no rights of their own
SELECT key FROM phasevec._truth_due(:notes_id, 100, interval $i$0$i$, $r$pv_admin$r$::regrole::oid);
SELECT phasevec._truth_set(:notes_id, $k$1$k$, $v$verified$v$, NULL, NULL, NULL, NULL);
RESET ROLE;
SELECT key, verdict, phasevec._verdict(t) AS now FROM phasevec.truth t WHERE key = $k$1$k$;
SELECT phasevec.verify_one($w$notes$w$, $k$1$k$) AS real_verdict;

-- (b) the author is a role, not a name: dropped, and its name given to another role, its proof runs as no one
SET ROLE pv_low;
SELECT phasevec.assert($w$notes$w$, $k$2$k$, $p$(SELECT v FROM pv_private.secret) = 'hunter2'$p$);
RESET ROLE;
SELECT phasevec.verify_one($w$notes$w$, $k$2$k$);
DROP OWNED BY pv_low;
DROP ROLE pv_low;
SELECT key, asserted_by FROM phasevec.truth WHERE key = $k$2$k$;
ALTER ROLE pv_admin RENAME TO pv_low;
SELECT phasevec.verify_one($w$notes$w$, $k$2$k$);
SELECT key, verdict, last_error FROM phasevec.truth WHERE key = $k$2$k$;
ALTER ROLE pv_low RENAME TO pv_admin;
-- the owner adopts it: asserted again as the owner, about the text it reads now
SELECT phasevec.adopt($w$notes$w$) AS adopted;
SELECT key, asserted_by = current_user AS by_owner, phasevec.verify_one($w$notes$w$, key) FROM phasevec.truth WHERE key = $k$2$k$;

DROP TABLE notes;
DROP SCHEMA pv_private CASCADE;
DROP EXTENSION pg_phasevec;
DROP OWNED BY pv_admin, pv_verifier;
DROP ROLE pv_admin;
DROP ROLE pv_verifier;
