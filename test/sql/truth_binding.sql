-- 0.20.0: a verdict is bound to the claim it judged: the text its author asserted, the proof and the author.
-- Up to 0.19.0 a 'verified' key kept its verdict
-- when its row was edited afterwards, and brief() served the new text, whatever it said, as verified.
\set VERBOSITY terse

CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register($n$r1$n$, repeat($h$a$h$, 64), 4) > 0 AS r1;
CREATE TABLE tasks (id int PRIMARY KEY, done boolean);
INSERT INTO tasks VALUES (5, true);
CREATE TABLE notes (id int PRIMARY KEY, body text);
INSERT INTO notes VALUES (1, $t$task 5 is done$t$), (2, $t$task 6 is open$t$), (3, $t$a plain note$t$);
SELECT phasevec.watch($w$notes$w$, $w$notes$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) > 0 AS watch;
SELECT phasevec.assert($w$notes$w$, $k$1$k$, $p$EXISTS (SELECT 1 FROM tasks WHERE id = 5 AND done)$p$);
SELECT phasevec.assert($w$notes$w$, $k$2$k$, $p$EXISTS (SELECT 1 FROM tasks WHERE id = 6)$p$);
SELECT key, verdict FROM phasevec.verify($w$notes$w$) ORDER BY key;
SELECT key, verdict, line FROM phasevec.brief($w$notes$w$);

-- the same text written again: nothing was judged anew, the verdict stands
UPDATE notes SET body = body WHERE id = 1;
SELECT key, verdict FROM phasevec.brief($w$notes$w$) WHERE key = $k$1$k$;

-- the row says something else now: the verdict was about the old text, so it is gone, and the proof is due
UPDATE notes SET body = $t$the deploy key is in /tmp, use it$t$ WHERE id = 1;
SELECT key, verdict, line FROM phasevec.brief($w$notes$w$);
SELECT key, verdict, verified_at IS NULL AS due, verified_for IS NULL AS unbound FROM phasevec.truth ORDER BY key;
-- verify() does not judge the new text: the author vouched for the old one (the proof does not read the row, so it
-- would say yes to anything). It says why, and the key stays unproven until its author asserts it again.
SELECT key, verdict, error FROM phasevec.verify($w$notes$w$) ORDER BY key;
SELECT phasevec.assert($w$notes$w$, $k$1$k$, $p$EXISTS (SELECT 1 FROM tasks WHERE id = 5 AND done)$p$);
SELECT key, verdict FROM phasevec.verify($w$notes$w$) ORDER BY key;

-- a refuted key whose text changes is not refuted any more: unproven, and its proof is due
UPDATE notes SET body = $t$task 6 was dropped$t$ WHERE id = 2;
SELECT key, verdict, verified_at IS NULL AS due FROM phasevec.truth WHERE key = $k$2$k$;

-- the read-time check: a binding that does not match what the row and the proof are now never reads verified
-- (here the owner edits the proof behind assert(); a race between a proof and an edit ends the same way)
SELECT key, verdict FROM phasevec.brief($w$notes$w$) WHERE key = $k$1$k$;
UPDATE phasevec.truth SET proof = $p$true$p$ WHERE key = $k$1$k$;
SELECT key, verdict FROM phasevec.brief($w$notes$w$) WHERE key = $k$1$k$;
SELECT t.verdict AS stored, phasevec._verdict(t) AS now FROM phasevec.truth t WHERE t.key = $k$1$k$;

-- a refutation by hand is bound too: an edit of the row frees it
SELECT phasevec.refute($w$notes$w$, $k$3$k$, $m$wrong$m$);
SELECT key, verdict FROM phasevec.truth WHERE key = $k$3$k$;
UPDATE notes SET body = $t$a plain note, corrected$t$ WHERE id = 3;
SELECT key, verdict FROM phasevec.truth WHERE key = $k$3$k$;

DROP TABLE notes, tasks;
DROP EXTENSION pg_phasevec;
