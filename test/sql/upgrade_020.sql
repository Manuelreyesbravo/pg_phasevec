-- 0.19.0 -> 0.20.0 on a database in use: verdicts reached the old way are not carried over as verified, proofs
-- wait for an author, grants the DBA gave are kept, PUBLIC loses the internals, and the dump marks do not change.
\set VERBOSITY terse

CREATE EXTENSION pg_phasevec VERSION $v$0.19.0$v$;
SELECT phasevec.reader_register($n$r1$n$, repeat($h$a$h$, 64), 4) > 0 AS r1;
CREATE TABLE notes (id int PRIMARY KEY, body text);
INSERT INTO notes VALUES (1, $t$holds$t$), (2, $t$does not hold$t$), (3, $t$replaced$t$), (4, $t$plain$t$);
SELECT phasevec.watch($w$notes$w$, $w$notes$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) > 0 AS watch;
SELECT phasevec.assert($w$notes$w$, $k$1$k$, $p$SELECT true$p$);
SELECT phasevec.assert($w$notes$w$, $k$2$k$, $p$SELECT false$p$);
SELECT phasevec.supersede($w$notes$w$, $k$3$k$, $k$4$k$, $m$newer$m$);
SELECT key, verdict FROM phasevec.verify($w$notes$w$) ORDER BY key;
CREATE ROLE pv_up_asker;
GRANT USAGE ON SCHEMA phasevec TO pv_up_asker;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz) TO pv_up_asker;
GRANT SELECT ON notes TO pv_up_asker;

ALTER EXTENSION pg_phasevec UPDATE TO $v$0.20.0$v$;
SELECT extversion FROM pg_extension WHERE extname = $e$pg_phasevec$e$;

-- the verified key is unproven, with the reason; the refuted one stays refuted, about its text as it is now
SELECT key, verdict, asserted_by, asserted_for IS NOT NULL AS about_text, last_error FROM phasevec.truth ORDER BY key;
-- proofs without an author do not run
SELECT count(*) AS run FROM phasevec.verify($w$notes$w$, p_every => interval $i$0$i$);
SELECT phasevec.verify_one($w$notes$w$, $k$1$k$);
-- naming an author by hand is not enough: a claim is also the text its author read
UPDATE phasevec.truth SET asserted_by = current_user WHERE asserted_by IS NULL AND proof IS NOT NULL;
SELECT count(*) AS run FROM phasevec.verify($w$notes$w$, p_every => interval $i$0$i$);
-- adopt() names their author; granted, the author adopts them itself (every proof comes back); then they run as
-- it, bound
GRANT EXECUTE ON FUNCTION phasevec.adopt(text, regrole, text[], text[]) TO pv_up_asker;
SET ROLE pv_up_asker;
SELECT key, proof, adopted, note FROM phasevec.adopt($w$notes$w$, $r$pv_up_asker$r$) ORDER BY key;
RESET ROLE;
SELECT key, verdict FROM phasevec.verify($w$notes$w$, p_every => interval $i$0$i$) ORDER BY key;
SELECT key, verdict, asserted_by, verified_for IS NOT NULL AS bound FROM phasevec.truth ORDER BY key;

-- the grant on assert() survives its new body; the internals are closed to PUBLIC
SELECT has_function_privilege($r$pv_up_asker$r$, $f$phasevec.assert(text, text, text, text, jsonb, timestamptz)$f$, $x$EXECUTE$x$) AS asker_asserts,
       has_function_privilege($r$public$r$, $f$phasevec.assert(text, text, text, text, jsonb, timestamptz)$f$, $x$EXECUTE$x$) AS public_asserts,
       has_function_privilege($r$public$r$, $f$phasevec._forget(int, text)$f$, $x$EXECUTE$x$) AS public_forget,
       has_function_privilege($r$public$r$, $f$phasevec._brief_keys(text)$f$, $x$EXECUTE$x$) AS public_brief_keys;
SET ROLE pv_up_asker;
SELECT phasevec.assert($w$notes$w$, $k$4$k$, $p$SELECT true$p$);
RESET ROLE;
SELECT key, asserted_by FROM phasevec.truth WHERE key = $k$4$k$;

-- the watch trigger installed by 0.19.0 still notes and forgets
UPDATE notes SET body = $t$holds, said again$t$ WHERE id = 1;
SELECT t.key, phasevec._verdict(t) AS verdict FROM phasevec.truth t WHERE t.key = $k$1$k$;
DELETE FROM notes WHERE id = 2;
SELECT key FROM phasevec.sources ORDER BY key;

-- pg_dump still carries the same tables (the new columns travel with phasevec.truth)
SELECT array_length(extconfig, 1) AS marked FROM pg_extension WHERE extname = $e$pg_phasevec$e$;

DROP TABLE notes;
DROP EXTENSION pg_phasevec;
DROP OWNED BY pv_up_asker;
DROP ROLE pv_up_asker;
