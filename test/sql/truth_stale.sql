-- 0.20.0 (sixth review): a row edited and put back. verify() wrote 'unproven' over the verdict of a claim whose row
-- said something else when it looked, and that verdict stayed when the row was put back: a writer that edited a row
-- for a moment, while a routine verify() ran, erased a refutation (or a verification) until the claim was due again
-- (p_every). The lazy read (_verdict) said 'refuted' again as soon as the text was back. Now verify() leaves the
-- verdict bound to the text it judged, records that it looked (looked_at), and the claim is not due again for that
-- same text until p_every: both reads agree.
\set VERBOSITY terse

CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register($n$r1$n$, repeat($h$a$h$, 64), 4) > 0 AS r1;
CREATE TABLE notes (id int PRIMARY KEY, body text);
INSERT INTO notes SELECT g, $t$claim $t$ || g FROM generate_series(1, 5) g;
SELECT phasevec.watch($w$notes$w$, $w$notes$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) > 0 AS watch;
SELECT phasevec.assert($w$notes$w$, $k$3$k$, $p$false$p$), phasevec.assert($w$notes$w$, $k$4$k$, $p$false$p$),
       phasevec.assert($w$notes$w$, $k$5$k$, $p$true$p$);
SELECT key, verdict FROM phasevec.verify($w$notes$w$, 10, interval '0') ORDER BY key;
-- a writer edits the rows; a routine verify() (every day) runs meanwhile
UPDATE notes SET body = body || $t$ (edited)$t$ WHERE id IN (3, 4, 5);
SELECT key, verdict, error FROM phasevec.verify($w$notes$w$, 10, interval '1 day') ORDER BY key;
SELECT key, verdict, phasevec._verdict(t), looked_at IS NOT NULL AS looked FROM phasevec.truth t ORDER BY key;
-- looked at once for that text: not due again for it
SELECT count(*) AS due FROM phasevec.verify($w$notes$w$, 10, interval '1 day');
-- edited again: due again
UPDATE notes SET body = body || $t$+$t$ WHERE id = 5;
SELECT key, verdict FROM phasevec.verify($w$notes$w$, 10, interval '1 day') ORDER BY key;
-- put back: the verdicts read as they were, written and read alike, and none is due
UPDATE notes SET body = replace(replace(body, $t$ (edited)+$t$, $t$$t$), $t$ (edited)$t$, $t$$t$) WHERE id IN (3, 4, 5);
SELECT key, verdict, phasevec._verdict(t) FROM phasevec.truth t ORDER BY key;
SELECT count(*) AS due FROM phasevec.verify($w$notes$w$, 10, interval '1 day');
SELECT key, verdict FROM phasevec.brief($w$notes$w$) ORDER BY key;
-- the row gone: the same. (twenty-eighth review, RT28PA-REUSE-1) Back under its key, it is another
-- row: the refutation was about the one deleted, and reads 'unproven' (until then 'refuted').
DELETE FROM notes WHERE id = 3;
SELECT key, verdict, error FROM phasevec.verify($w$notes$w$, 10, interval '1 day') ORDER BY key;
INSERT INTO notes VALUES (3, $t$claim 3$t$);
SELECT key, verdict, phasevec._verdict(t) FROM phasevec.truth t WHERE key = $k$3$k$;
-- asserted again: due, and judged
SELECT phasevec.assert($w$notes$w$, $k$4$k$, $p$true$p$);
SELECT key, verdict FROM phasevec.verify($w$notes$w$, 10, interval '1 day') ORDER BY key;

DROP TABLE notes;
DROP EXTENSION pg_phasevec;
