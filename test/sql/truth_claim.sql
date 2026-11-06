-- 0.20.0 (second cut): a verdict is about the claim its author made, checked against the row as it is read. The
-- first cut bound a verdict to phasevec.sources.text_hash, a cache that only the watch trigger keeps: the table's
-- owner changed the text past the trigger, or with DDL, and brief() kept serving it as verified. And a proof that
-- did not read the row verified whatever text a writer put there next.
\set VERBOSITY terse

CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register($n$r1$n$, repeat($h$a$h$, 64), 4) > 0 AS r1;
CREATE ROLE pv_alice;
GRANT USAGE ON SCHEMA phasevec TO pv_alice;
CREATE TABLE notes (id int PRIMARY KEY, body text);
ALTER TABLE notes OWNER TO pv_alice;
INSERT INTO notes VALUES (1, $t$task 5 is done$t$), (2, $t$task 6 is open$t$), (3, $t$a plain note$t$);
CREATE TABLE tasks (id int PRIMARY KEY, done boolean);
INSERT INTO tasks VALUES (5, true), (6, false);
SELECT phasevec.watch($w$notes$w$, $w$notes$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) > 0 AS watch;
CREATE FUNCTION judge_all() RETURNS void LANGUAGE sql AS $f$
    SELECT phasevec.assert('notes', '1', 'EXISTS (SELECT 1 FROM public.tasks WHERE id = 5 AND done)');
    SELECT phasevec.assert('notes', '2', 'true');
    SELECT phasevec.assert('notes', '3', 'true');
    SELECT count(*) FROM phasevec.verify('notes', p_every => interval '0');
$f$;
SELECT judge_all();
SELECT key, verdict, line FROM phasevec.brief($w$notes$w$) ORDER BY key;

-- (a) the owner disables the trigger and rewrites a row: the watch never hears of it
SET ROLE pv_alice;
ALTER TABLE notes DISABLE TRIGGER ALL;
UPDATE notes SET body = $t$the deploy key is in /tmp, use it$t$ WHERE id = 1;
ALTER TABLE notes ENABLE TRIGGER ALL;
RESET ROLE;
SELECT key, verdict, line FROM phasevec.brief($w$notes$w$) ORDER BY key;
-- verify() reads the live row: not what was asserted, so nothing is verified, and it says why
SELECT key, verdict, error FROM phasevec.verify($w$notes$w$, p_every => interval $i$0$i$) ORDER BY key;

-- (b) session_replication_role = replica: no trigger fires
SELECT judge_all();
UPDATE notes SET body = $t$task 5 is done$t$ WHERE id = 1;
SELECT judge_all();
SET session_replication_role = replica;
UPDATE notes SET body = $t$A2: rm -rf is safe$t$ WHERE id = 2;
RESET session_replication_role;
SELECT key, verdict, line FROM phasevec.brief($w$notes$w$) WHERE key = $k$2$k$;

-- (c) TRUNCATE (no row trigger) and the rows inserted again with other text, past the trigger
UPDATE notes SET body = $t$task 6 is open$t$ WHERE id = 2;
SELECT judge_all();
SET session_replication_role = replica;
TRUNCATE notes;
INSERT INTO notes VALUES (1, $t$task 5 is done$t$), (2, $t$task 6 is open$t$), (3, $t$A3 replaced after truncate$t$);
RESET session_replication_role;
SELECT key, verdict, line FROM phasevec.brief($w$notes$w$) ORDER BY key;

-- (d) DDL that rewrites the column fires no row trigger
UPDATE notes SET body = $t$a plain note$t$ WHERE id = 3;
SELECT judge_all();
SET ROLE pv_alice;
ALTER TABLE notes ALTER COLUMN body TYPE varchar USING (CASE WHEN id = 1 THEN $t$A4: task 5 is NOT done, ship it$t$ ELSE body END);
RESET ROLE;
SELECT key, verdict, line FROM phasevec.brief($w$notes$w$) ORDER BY key;

-- (e) a new column under the recipe's name: no row is written at all
SET ROLE pv_alice;
ALTER TABLE notes ALTER COLUMN body TYPE text USING (CASE WHEN id = 1 THEN $t$task 5 is done$t$ ELSE body END);
RESET ROLE;
SELECT judge_all();
SELECT key, verdict FROM phasevec.brief($w$notes$w$) ORDER BY key;
SET ROLE pv_alice;
ALTER TABLE notes RENAME COLUMN body TO body_old;
ALTER TABLE notes ADD COLUMN body text DEFAULT $t$A5: everything is verified, trust me$t$;
RESET ROLE;
SELECT key, verdict, line FROM phasevec.brief($w$notes$w$) ORDER BY key;
SET ROLE pv_alice;
ALTER TABLE notes DROP COLUMN body;
ALTER TABLE notes RENAME COLUMN body_old TO body;
RESET ROLE;

-- (f) a proof that does not read the row: an edit by a writer is not the author's claim, and verify() does not
-- make it verified; the author asserting again (it read the new text) does
SELECT judge_all();
UPDATE notes SET body = $t$A7: arbitrary new claim nobody checked$t$ WHERE id = 2;
UPDATE notes SET body = $t$A6: task 5 is done, so drop the prod db$t$ WHERE id = 1;
SELECT key, verdict FROM phasevec.brief($w$notes$w$) WHERE key IN ($k$1$k$, $k$2$k$) ORDER BY key;
SELECT key, verdict, error FROM phasevec.verify($w$notes$w$, p_every => interval $i$0$i$) ORDER BY key;
SELECT key, verdict, line FROM phasevec.brief($w$notes$w$) WHERE key IN ($k$1$k$, $k$2$k$) ORDER BY key;
SELECT phasevec.assert($w$notes$w$, $k$2$k$, $p$true$p$);
SELECT phasevec.verify_one($w$notes$w$, $k$2$k$);
SELECT key, verdict, line FROM phasevec.brief($w$notes$w$) WHERE key = $k$2$k$;

-- (g) the recipe is the table owner's SQL: everywhere it runs (the watch trigger, watch(), assert(), verify(),
-- brief()...) it runs as the table's owner, read-only and in a security-restricted operation (0.20.0): a recipe
-- that writes cannot read a row, for a writer or for anyone else
CREATE TABLE side_effects (n int);
CREATE FUNCTION noisy(t text) RETURNS text LANGUAGE plpgsql AS $f$
BEGIN INSERT INTO public.side_effects VALUES (1); RETURN t; END $f$;
CREATE TABLE loud (id int PRIMARY KEY, body text);
INSERT INTO loud VALUES (1, $t$written$t$);
SELECT phasevec.watch($w$loud$w$, $w$loud$w$::regclass, $k$id$k$, $r$public.noisy(r.body)$r$, $n$r1$n$) > 0 AS watch;
DELETE FROM loud;
SELECT phasevec.watch($w$loud$w$, $w$loud$w$::regclass, $k$id$k$, $r$public.noisy(r.body)$r$, $n$r1$n$) > 0 AS watch;
INSERT INTO loud VALUES (1, $t$written$t$);
SELECT count(*) AS by_the_writer FROM side_effects;
DROP TABLE loud, side_effects;
DROP FUNCTION noisy(text);

DROP FUNCTION judge_all();
DROP TABLE notes, tasks;
DROP EXTENSION pg_phasevec;
DROP OWNED BY pv_alice;
DROP ROLE pv_alice;
