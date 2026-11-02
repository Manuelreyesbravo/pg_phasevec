-- 0.18.0: brief() hands what still holds, best first, inside a budget; never what was replaced, refuted or
-- expired; the text with the caller's rights.
\set VERBOSITY terse

CREATE EXTENSION pg_phasevec VERSION $v$0.17.0$v$;
ALTER EXTENSION pg_phasevec UPDATE TO $v$0.18.0$v$;
SELECT extversion FROM pg_extension WHERE extname = $e$pg_phasevec$e$;
SELECT phasevec.reader_register($n$r1$n$, repeat($h$a$h$, 64), 4) > 0 AS r1;
CREATE TABLE work (id int PRIMARY KEY, body text);
INSERT INTO work VALUES
  (1, $t$open: fix the planner regression$t$),
  (2, $t$closed: the planner regression was fixed in 4a1b$t$),
  (3, $t$open: its proof still holds$t$),
  (4, $t$open: its proof says it is done$t$),
  (5, $t$open: nobody touched it for a month$t$),
  (6, repeat($t$a long note $t$, 20)),
  (7, $t$open: plain, nothing said$t$);
SELECT phasevec.watch($w$work$w$, $w$work$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) > 0 AS watch;

-- control: nothing said about truth, everything comes out
SELECT count(*) AS all_served FROM phasevec.brief($w$work$w$);

SELECT phasevec.supersede($w$work$w$, $k$1$k$, $k$2$k$, $m$closed$m$);
SELECT phasevec.assert($w$work$w$, $k$3$k$, $p$SELECT true$p$);
SELECT phasevec.assert($w$work$w$, $k$4$k$, $p$SELECT false$p$);
SELECT phasevec.assert($w$work$w$, $k$5$k$, p_expires_at => now() - interval $i$1 day$i$);
SELECT key, verdict FROM phasevec.verify($w$work$w$) ORDER BY key;
SELECT phasevec.note_use($w$work$w$, $k$2$k$, 1::smallint), phasevec.note_use($w$work$w$, $k$2$k$, 1::smallint);

-- served: verified first, then the useful one, then the rest; never 1 (replaced), 4 (refuted), 5 (expired)
SELECT key, verdict, net_use, left(line, 40) AS line FROM phasevec.brief($w$work$w$);

-- the budget: the long note does not fit, the short ones after it still do
SELECT string_agg(key, $s$,$s$) AS keys, sum(length(line)) AS chars FROM phasevec.brief($w$work$w$, 120);

-- the text is read with the caller's rights
CREATE ROLE brief_stranger;
GRANT USAGE ON SCHEMA phasevec TO brief_stranger;   -- as any user of the extension
SET ROLE brief_stranger;
SELECT count(*) FROM phasevec.brief($w$work$w$);
RESET ROLE;
GRANT SELECT ON work TO brief_stranger;
SET ROLE brief_stranger;
SELECT count(*) AS served_to_a_reader FROM phasevec.brief($w$work$w$);
RESET ROLE;
DROP OWNED BY brief_stranger;
DROP ROLE brief_stranger;

-- a brief needs a budget
SELECT * FROM phasevec.brief($w$work$w$, 0);

DROP TABLE work;
DROP EXTENSION pg_phasevec;
