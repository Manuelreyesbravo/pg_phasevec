-- 0.20.0 (fifth review): the watch trigger keeps its plan per session, and that plan reads the row by column number.
-- In the fifth cut (ce02558) nothing told it that the table's columns had changed: a session that wrote before a
-- RENAME, a DROP and ADD COLUMN or an ALTER COLUMN TYPE went on hashing the old column (a changed row stayed fresh,
-- next() handed out nothing, find() served the old reading), or failed every later write with "attribute N has wrong
-- type", until it reconnected. Every write below comes from the session that wrote before the DDL.
\set VERBOSITY terse

CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register($n$r1$n$, repeat($h$a$h$, 64), 4) > 0 AS r1;
-- does phasevec.sources hold, for every row, the hash of the text the recipe renders now?
CREATE FUNCTION pv_noted(p_watch text) RETURNS TABLE (key text, noted boolean) LANGUAGE sql AS $f$
    SELECT r.key, s.text_hash IS NOT DISTINCT FROM r.text_hash
      FROM phasevec._render(p_watch, NULL) r
      LEFT JOIN phasevec.sources s ON s.watch = (SELECT id FROM phasevec.watches WHERE name = p_watch) AND s.key = r.key
     ORDER BY r.key
$f$;

-- (1) a column renamed away and another renamed into its place
CREATE TABLE docs (id int PRIMARY KEY, body text, other text);
SELECT phasevec.watch($w$docs$w$, $w$docs$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) > 0 AS watch;
INSERT INTO docs VALUES (1, $t$apple$t$, $t$zzz$t$);
SELECT count(phasevec.record($w$docs$w$, n.key, $n$r1$n$, n.text_hash, 1, $v${1,1,1,1}$v$::smallint[]))
  FROM phasevec.next($w$docs$w$) n;
ALTER TABLE docs RENAME COLUMN body TO old_body;
ALTER TABLE docs RENAME COLUMN other TO body;
UPDATE docs SET body = $t$completely different text$t$ WHERE id = 1;
SELECT * FROM pv_noted($w$docs$w$);
SELECT key, state FROM phasevec.reading_states WHERE watch = $w$docs$w$;
SELECT count(*) AS to_read FROM phasevec.next($w$docs$w$);
UPDATE docs SET old_body = $t$x$t$ WHERE id = 1;
SELECT * FROM pv_noted($w$docs$w$);

-- (2) the column dropped and added again (a new column number)
CREATE TABLE d2 (id int PRIMARY KEY, body text);
SELECT phasevec.watch($w$d2$w$, $w$d2$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) > 0 AS watch;
INSERT INTO d2 VALUES (1, $t$one$t$);
ALTER TABLE d2 DROP COLUMN body;
ALTER TABLE d2 ADD COLUMN body text;
INSERT INTO d2 VALUES (2, $t$two$t$);
UPDATE d2 SET body = $t$one again$t$ WHERE id = 1;
SELECT * FROM pv_noted($w$d2$w$);

-- (3) the column's type changed: every write of this session failed until it reconnected
CREATE TABLE d3 (id int PRIMARY KEY, body text, n text);
SELECT phasevec.watch($w$d3$w$, $w$d3$w$::regclass, $k$id$k$, $r$r.body || ' #' || r.n$r$, $n$r1$n$) > 0 AS watch;
INSERT INTO d3 VALUES (1, $t$one$t$, $t$1$t$);
ALTER TABLE d3 ALTER COLUMN body TYPE varchar(50);
INSERT INTO d3 VALUES (2, $t$two$t$, $t$2$t$);
ALTER TABLE d3 ALTER COLUMN n TYPE int USING n::int;
INSERT INTO d3 VALUES (3, $t$three$t$, 3);
UPDATE d3 SET n = n + 10 WHERE id = 1;
SELECT * FROM pv_noted($w$d3$w$);

-- (4) a partition attached with its columns in another order (a row type of its own, read by name)
CREATE TABLE parts (id int, body text, tag text) PARTITION BY RANGE (id);
CREATE TABLE parts_1 PARTITION OF parts FOR VALUES FROM (0) TO (100);
ALTER TABLE parts ADD PRIMARY KEY (id);
SELECT phasevec.watch($w$parts$w$, $w$parts$w$::regclass, $k$id$k$, $r$r.body || ' / ' || r.tag$r$, $n$r1$n$) > 0 AS watch;
INSERT INTO parts VALUES (1, $t$first$t$, $t$a$t$);
CREATE TABLE parts_2 (tag text, extra int, body text, id int NOT NULL);
ALTER TABLE parts_2 DROP COLUMN extra;
ALTER TABLE parts ATTACH PARTITION parts_2 FOR VALUES FROM (100) TO (200);
INSERT INTO parts VALUES (101, $t$second$t$, $t$b$t$);
UPDATE parts SET tag = $t$c$t$ WHERE id = 1;
-- and the first partition's columns renamed under the session's plan
ALTER TABLE parts RENAME COLUMN tag TO tag_old;
ALTER TABLE parts ADD COLUMN tag text DEFAULT $t$new$t$;
UPDATE parts SET body = body || $t$!$t$;
SELECT * FROM pv_noted($w$parts$w$);

DROP TABLE docs, d2, d3, parts;
DROP FUNCTION pv_noted(text);
DROP EXTENSION pg_phasevec;
