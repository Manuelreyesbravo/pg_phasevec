-- 0.20.0 (fifth review): the verifier's session objects decided a proof. The fifth cut (ce02558) refused a temporary
-- table or function, by the kind of range-table entry it came in: a temporary view (a subquery entry since PostgreSQL
-- 16), type, domain, operator or collation went through, and verify() recorded, brief() served, 'verified' for claims
-- the author's own objects refute. Now what a query in the guard uses is walked, as PostgreSQL walks a view's query
-- to decide whether the view is temporary, and a temporary object is refused, however the query names it: directly,
-- inside a SQL function the planner would inline (its body was parsed with no hook and folded to a constant), or in a
-- plan the verifier's session made before the guard ran (a function with its own search_path keeps one), or in a
-- SQL function body kept parsed (BEGIN ATOMIC), which is planned with no parse. (Eighth review: a proof runs in a
-- session of its own, which has none of the verifier's objects; the walk still guards a recipe, which renders in the
-- session that reads or writes the row.)
\set VERBOSITY terse

CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register($n$r1$n$, repeat($h$a$h$, 64), 4) > 0 AS r1;
CREATE TABLE notes (id int PRIMARY KEY, body text);
INSERT INTO notes SELECT g, $t$claim $t$ || g FROM generate_series(1, 11) g;
SELECT phasevec.watch($w$notes$w$, $w$notes$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) > 0 AS watch;
-- the author's own objects, in public, say no
CREATE TABLE stock (item text, qty int);
INSERT INTO stock VALUES ($i$widget$i$, 0);
SET check_function_bodies = off;
-- SQL bodies that name the session's temporary objects (inlined by the planner when it may)
CREATE FUNCTION pv_tt_cmp() RETURNS boolean LANGUAGE sql STABLE AS $f$ SELECT 'b'::pg_temp.e < 'a'::pg_temp.e $f$;
-- a PL/pgSQL function with its own search_path: the same inside the guard and out, so a plan made out is kept
CREATE FUNCTION pv_tt_kept() RETURNS boolean LANGUAGE plpgsql SET search_path = pg_temp, public AS $f$
BEGIN
    RETURN 'b'::e < 'a'::e;
END $f$;
RESET check_function_bodies;
CREATE ROLE pv_tt_author;
GRANT USAGE ON SCHEMA phasevec TO pv_tt_author;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz) TO pv_tt_author;
GRANT SELECT ON notes, stock TO pv_tt_author;
SET ROLE pv_tt_author;
SELECT phasevec.assert($w$notes$w$, $k$1$k$, $p$(SELECT qty FROM pg_temp.sv WHERE item = 'widget') > 0$p$);
SELECT phasevec.assert($w$notes$w$, $k$2$k$, $p$(SELECT count(*) FROM pg_temp.sv2) = 0$p$);
SELECT phasevec.assert($w$notes$w$, $k$3$k$, $p$'b'::pg_temp.e < 'a'::pg_temp.e$p$);
SELECT phasevec.assert($w$notes$w$, $k$4$k$, $p$(-1)::pg_temp.d IS NOT NULL$p$);
SELECT phasevec.assert($w$notes$w$, $k$5$k$, $p$NOT (1 OPERATOR(pg_temp.<) 2)$p$);
SELECT phasevec.assert($w$notes$w$, $k$6$k$, $p$NOT ('a' < 'B' COLLATE pg_temp.ci)$p$);
SELECT phasevec.assert($w$notes$w$, $k$7$k$, $p$'pg_temp.sv'::regclass IS NOT NULL$p$);
SELECT phasevec.assert($w$notes$w$, $k$8$k$, $p$public.pv_tt_cmp()$p$);
SELECT phasevec.assert($w$notes$w$, $k$9$k$, $p$public.pv_tt_kept()$p$);
SELECT phasevec.assert($w$notes$w$, $k$10$k$, $p$(SELECT qty FROM public.stock WHERE item = 'widget') = 0$p$);
SELECT phasevec.assert($w$notes$w$, $k$11$k$, $p$public.pv_tt_atomic()$p$);
RESET ROLE;

-- control: none of these objects exist; every claim but 10 is refuted (11 names a function that does not exist)
BEGIN;
SELECT key, verdict FROM phasevec.verify($w$notes$w$, p_every => interval '0') ORDER BY key::int;
ROLLBACK;

-- the verifier makes them, in its own session, and grants them to the author
CREATE TEMP VIEW sv AS SELECT $i$widget$i$::text AS item, 99 AS qty;
CREATE TEMP VIEW sv2 AS SELECT * FROM public.notes WHERE false;
GRANT SELECT ON pg_temp.sv, pg_temp.sv2 TO pv_tt_author;
CREATE TYPE pg_temp.e AS ENUM ($l$b$l$, $l$a$l$);
CREATE DOMAIN pg_temp.d AS int;
CREATE OPERATOR pg_temp.< (LEFTARG = int, RIGHTARG = int, FUNCTION = int4gt);
CREATE COLLATION pg_temp.ci FROM "C";
-- a SQL function written BEGIN ATOMIC names its objects by OID, kept parsed: it is planned with no parse
SET client_min_messages = warning;   -- PostgreSQL 19 says it is "effectively temporary"; 18 does not
CREATE FUNCTION public.pv_tt_atomic() RETURNS boolean LANGUAGE sql STABLE
BEGIN ATOMIC SELECT 'b'::pg_temp.e < 'a'::pg_temp.e; END;
RESET client_min_messages;
GRANT EXECUTE ON FUNCTION public.pv_tt_atomic() TO pv_tt_author;
-- the verifier runs the function first: its plan is made out of the guard, with the temporary type in it, folded
SELECT public.pv_tt_kept() AS kept_out;
SELECT public.pv_tt_kept() AS kept_out;
-- (eighth review) the proofs run in a session of their own (a new session of their author): the verifier's objects
-- are not there to be found, and every claim reads as the control's (11 calls a function whose body names the
-- verifier's temporary type by OID: another session's, refused)
SELECT key, verdict, regexp_replace(error, $r$pg_temp_[0-9]+$r$, $r$pg_temp_N$r$) AS error
  FROM phasevec.verify($w$notes$w$, p_every => interval '0') ORDER BY key::int;
SELECT key, verdict FROM phasevec.brief($w$notes$w$) WHERE verdict = $v$verified$v$ ORDER BY key::int;

-- out of the guard the verifier uses its objects as before
SELECT qty FROM sv;
SELECT 'b'::pg_temp.e < 'a'::pg_temp.e AS out_of_guard;

-- (sixth review) verify() refused to run in a session with temporary objects (truth_lookup); (eighth review) its
-- session is not where proofs run. Dropped, they leave behind the plan the verifier's session made of pv_tt_kept()
-- with the temporary enum folded in, which is the verifier's session's: every claim reads as the control's.
DISCARD TEMP;
SELECT key, verdict, error FROM phasevec.verify($w$notes$w$, p_every => interval '0') ORDER BY key::int;

-- a recipe does not read a writer's temporary objects either: here a function the recipe calls searches pg_temp first
-- (its owner's mistake), and a writer's temporary type named like the owner's would decide the text the watch trigger
-- notes. The write is refused rather than noted with a text no other session renders.
CREATE TYPE mood AS ENUM ($l$calm$l$);
CREATE FUNCTION pv_tt_label(t text) RETURNS text LANGUAGE sql STABLE SET search_path = pg_temp, public
    AS $f$ SELECT t || ' ' || enum_range(NULL::mood)::text $f$;
CREATE TABLE moods (id int PRIMARY KEY, body text);
SELECT phasevec.watch($w$moods$w$, $w$moods$w$::regclass, $k$id$k$, $r$public.pv_tt_label(r.body)$r$, $n$r1$n$) > 0 AS watch;
CREATE TYPE pg_temp.mood AS ENUM ($l$furious$l$);
INSERT INTO moods VALUES (1, $t$today$t$);
DISCARD TEMP;
INSERT INTO moods VALUES (1, $t$today$t$) ON CONFLICT DO NOTHING;
SELECT r.key, r.body, s.text_hash = r.text_hash AS noted
  FROM phasevec._render($w$moods$w$, NULL) r
  JOIN phasevec.sources s ON s.watch = (SELECT id FROM phasevec.watches WHERE name = $w$moods$w$) AND s.key = r.key;

DROP TABLE notes, stock, moods;
DROP FUNCTION pv_tt_cmp(), pv_tt_kept(), pv_tt_label(text);
DROP FUNCTION IF EXISTS pv_tt_atomic();
DROP TYPE mood;
DROP EXTENSION pg_phasevec;
DROP OWNED BY pv_tt_author CASCADE;
DROP ROLE pv_tt_author;
