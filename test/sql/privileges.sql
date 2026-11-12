-- 0.20.0: no internal function of the extension is open to PUBLIC. Up to 0.19.0 _forget() (SECURITY DEFINER,
-- guarded only by pg_trigger_depth(), which any user's own trigger passes) and _brief_keys() (SECURITY DEFINER,
-- every watch's keys, verdicts, usefulness and recipe) were executable by PUBLIC.
\set VERBOSITY terse

CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register($n$r1$n$, repeat($h$a$h$, 64), 4) > 0 AS r1;
CREATE TABLE docs (id int PRIMARY KEY, body text);
INSERT INTO docs VALUES (1, $t$one$t$), (2, $t$two$t$), (3, $t$three$t$);
SELECT phasevec.watch($w$docs$w$, $w$docs$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) > 0 AS watch;

-- the SECURITY DEFINER functions still executable by PUBLIC: only the search surface, open since 0.16.0 to
-- whoever the owner gives USAGE on the schema (security.sql); no internal one (package review: not
-- the renamed 0.14 find_ivf, _find_ivf_hide, either)
SELECT p.oid::regprocedure AS open_to_public
  FROM pg_proc p JOIN pg_depend d ON d.classid = $c$pg_proc$c$::regclass AND d.objid = p.oid AND d.deptype = $d$e$d$
  JOIN pg_extension e ON e.oid = d.refobjid AND e.extname = $e$pg_phasevec$e$
 WHERE p.prosecdef AND has_function_privilege($r$public$r$, p.oid, $x$EXECUTE$x$)
 ORDER BY 1::text;
SELECT has_function_privilege($r$public$r$, $f$phasevec._forget(int, text)$f$, $x$EXECUTE$x$) AS forget,
       has_function_privilege($r$public$r$, $f$phasevec._brief_keys(text)$f$, $x$EXECUTE$x$) AS brief_keys,
       has_function_privilege($r$public$r$, $f$phasevec.brief(text, int)$f$, $x$EXECUTE$x$) AS brief;

-- a role with nothing but USAGE on the schema, as the owner gives to whoever uses the extension
CREATE ROLE pv_stranger;
GRANT USAGE ON SCHEMA phasevec TO pv_stranger;
SELECT id AS docs_id FROM phasevec.watches WHERE name = $w$docs$w$ \gset
SET ROLE pv_stranger;
-- it cannot read the keys and verdicts of a watch
SELECT count(*) FROM phasevec._brief_keys($w$docs$w$);
-- nor make another watch forget a key from a trigger of its own
CREATE TEMP TABLE pv_t (x int);
SELECT format($f$CREATE FUNCTION pg_temp.pv_forget() RETURNS trigger LANGUAGE plpgsql AS $b$
    BEGIN PERFORM phasevec._forget(%s, '1'); RETURN NULL; END $b$$f$, :docs_id) \gexec
CREATE TRIGGER pv_forget AFTER INSERT ON pv_t FOR EACH ROW EXECUTE FUNCTION pg_temp.pv_forget();
INSERT INTO pv_t VALUES (1);
RESET ROLE;
SELECT key FROM phasevec.sources ORDER BY key;

-- a writer of the watched table adds, moves and forgets rows with no grant of phasevec's: the watch trigger is C
-- and renders the row it fires for (0.20.0)
CREATE ROLE pv_writer;
GRANT USAGE ON SCHEMA phasevec TO pv_writer;
GRANT SELECT, INSERT, UPDATE, DELETE ON docs TO pv_writer;
SET ROLE pv_writer;
INSERT INTO docs VALUES (4, $t$four$t$);
UPDATE docs SET id = 20 WHERE id = 2;
DELETE FROM docs WHERE id = 3;
RESET ROLE;
SELECT key FROM phasevec.sources ORDER BY key;

-- 0.20.0: a writer of one watched table cannot touch another watch's sources. In the first cut the watch trigger
-- forgot through _note() (a NULL hash), so whoever was granted _note() for one table forgot, rewrote and invented
-- the keys of every other watch from a trigger of its own. _note() is gone; the watch trigger itself, put on another
-- table with that watch's id, refuses.
CREATE TABLE b_secret (id int PRIMARY KEY, body text);
INSERT INTO b_secret VALUES (1, $t$b one$t$), (2, $t$b two$t$);
SELECT phasevec.watch($w$b$w$, $w$b_secret$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) AS b_id \gset
SET ROLE pv_writer;
CREATE TEMP TABLE pv_t2 (x int);
SELECT format($f$CREATE TRIGGER pv_hit AFTER INSERT ON pv_t2 FOR EACH ROW EXECUTE FUNCTION phasevec._observe(%L)$f$,
              :b_id) \gexec
INSERT INTO pv_t2 VALUES (1);
RESET ROLE;
SELECT s.key, s.text_hash = sha256(convert_to(b.body, $u$UTF8$u$)) AS matches_the_table
  FROM phasevec.sources s LEFT JOIN b_secret b ON b.id::text = s.key
 WHERE s.watch = :b_id ORDER BY s.key;
DROP TABLE pv_t2;
DROP TABLE b_secret;

-- whoever the owner lets brief is granted brief() (it calls _brief_keys() as the owner), and reads only a watch
-- whose table it may SELECT
GRANT EXECUTE ON FUNCTION phasevec.brief(text, int) TO pv_stranger;
SET ROLE pv_stranger;
SELECT count(*) AS without_select FROM phasevec.brief($w$docs$w$);
RESET ROLE;
GRANT SELECT ON docs TO pv_stranger;
SET ROLE pv_stranger;
SELECT key, line FROM phasevec.brief($w$docs$w$) ORDER BY key;
RESET ROLE;

DROP TABLE pv_t;
DROP FUNCTION pg_temp.pv_forget();
DROP TABLE docs;
DROP EXTENSION pg_phasevec;
DROP OWNED BY pv_stranger, pv_writer;
DROP ROLE pv_stranger;
DROP ROLE pv_writer;
