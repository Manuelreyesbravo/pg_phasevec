-- 0.20.0 (sixth review): names looked up while the code runs. The walk of what a query names (truth_temp) did not
-- see the RETURNING type of JSON_VALUE and JSON_QUERY (with NULL ON ERROR it is in no other node), nor, on
-- PostgreSQL 18, a regconfig or regdictionary constant; and no walk sees a name looked up while the query runs:
-- to_regclass('pg_temp.v'), pg_input_is_valid(text, 'pg_temp.d'), to_regtypemod, a cast of text to regclass,
-- set_config('default_text_search_config', 'pg_temp.cfg'). Each found the verifier's temporary objects, and
-- verify() recorded, brief() served, 'verified'. Now a verdict is judged only in a session with no temporary object
-- (there is nothing to find), and the walk sees the RETURNING type and those constants (a recipe runs in the
-- writer's session, which may have them).
\set VERBOSITY terse

CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register($n$r1$n$, repeat($h$a$h$, 64), 4) > 0 AS r1;
CREATE TABLE notes (id int PRIMARY KEY, body text);
INSERT INTO notes SELECT g, $t$claim $t$ || g FROM generate_series(1, 14) g;
SELECT phasevec.watch($w$notes$w$, $w$notes$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) > 0 AS watch;
CREATE ROLE pv_tl_author;
GRANT USAGE ON SCHEMA phasevec TO pv_tl_author;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz) TO pv_tl_author;
GRANT SELECT ON notes TO pv_tl_author;
SET ROLE pv_tl_author;
SELECT phasevec.assert($w$notes$w$, $k$1$k$, $p$JSON_VALUE('"b"', '$' RETURNING pg_temp.e) < JSON_VALUE('"a"', '$' RETURNING pg_temp.e)$p$);
SELECT phasevec.assert($w$notes$w$, $k$2$k$, $p$JSON_VALUE('{"a":-1}', '$.a' RETURNING pg_temp.d NULL ON ERROR) IS NULL$p$);
SELECT phasevec.assert($w$notes$w$, $k$3$k$, $p$JSON_QUERY('[1]', '$' RETURNING pg_temp.dj NULL ON ERROR) IS NULL$p$);
SELECT phasevec.assert($w$notes$w$, $k$4$k$, $p$to_regclass('pg_temp.sv') IS NOT NULL$p$);
SELECT phasevec.assert($w$notes$w$, $k$5$k$, $p$NOT pg_input_is_valid('-1', 'pg_temp.d')$p$);
SELECT phasevec.assert($w$notes$w$, $k$6$k$, $p$(SELECT set_config('default_text_search_config', 'pg_temp.cfg', true)) IS NOT NULL AND to_tsvector('the cats') = to_tsvector('simple', 'the cats')$p$);
SELECT phasevec.assert($w$notes$w$, $k$7$k$, $p$pg_input_is_valid('b', 'pg_temp.e')$p$);
SELECT phasevec.assert($w$notes$w$, $k$8$k$, $p$to_regtypemod('pg_temp.d') IS NOT NULL$p$);
SELECT phasevec.assert($w$notes$w$, $k$9$k$, $p$(SELECT ('pg_temp.' || 'sv')::regclass IS NOT NULL)$p$);
SELECT phasevec.assert($w$notes$w$, $k$10$k$, $p$(SELECT ('{"r":"pg_temp.sv"}'::json ->> 'r')::regclass IS NOT NULL)$p$);
SELECT phasevec.assert($w$notes$w$, $k$11$k$, $p$to_tsvector('pg_temp.cfg', 'the cats') = to_tsvector('simple', 'the cats')$p$);
SELECT phasevec.assert($w$notes$w$, $k$12$k$, $p$ts_lexize('pg_temp.dict', 'the') IS NULL$p$);
SELECT phasevec.assert($w$notes$w$, $k$13$k$, $p$true$p$);
RESET ROLE;

-- control: none of these objects exist; every claim but 13 is refuted
BEGIN;
SELECT key, verdict FROM phasevec.verify($w$notes$w$, p_every => interval '0') ORDER BY key::int;
ROLLBACK;

-- the verifier makes them in its own session
CREATE TEMP VIEW sv AS SELECT $i$widget$i$::text AS item, 99 AS qty;
CREATE TYPE pg_temp.e AS ENUM ($l$b$l$, $l$a$l$);
CREATE DOMAIN pg_temp.d AS int CHECK (VALUE > 0);
CREATE DOMAIN pg_temp.dj AS jsonb CHECK (jsonb_typeof(VALUE) = 'string');
CREATE TEXT SEARCH CONFIGURATION pg_temp.cfg (COPY = simple);
CREATE TEXT SEARCH DICTIONARY pg_temp.dict (TEMPLATE = simple, ACCEPT = false);
GRANT SELECT ON pg_temp.sv TO pv_tl_author;
-- nothing is judged in this session; nothing is recorded, nothing is served
SELECT key, verdict FROM phasevec.verify($w$notes$w$, p_every => interval '0') ORDER BY key::int;
SELECT phasevec.verify_one($w$notes$w$, $k$1$k$);
SELECT count(*) AS judged FROM phasevec.truth WHERE verdict <> $v$unproven$v$;
SELECT key, verdict FROM phasevec.brief($w$notes$w$) WHERE verdict = $v$verified$v$ ORDER BY key::int;
-- in a transaction that made one and dropped it, neither (the schema is empty again)
BEGIN;
CREATE TEMP TABLE pv_tl_scratch (x int);
SELECT count(*) FROM phasevec.verify($w$notes$w$, p_every => interval '0');
ROLLBACK;
-- emptied, the same session judges as the control did
DISCARD TEMP;
SELECT key, verdict FROM phasevec.verify($w$notes$w$, p_every => interval '0') ORDER BY key::int;
SELECT key, verdict FROM phasevec.brief($w$notes$w$) WHERE verdict = $v$verified$v$ ORDER BY key::int;

-- A recipe runs in the writer's session, which may have temporary objects: what it names is walked. Here the
-- functions it calls name pg_temp (their owner's mistake): the writer's temporary enum (the RETURNING type of
-- JSON_VALUE ... NULL ON ERROR) or text search configuration (a regconfig constant: on PostgreSQL 18 the walk did
-- not look at it) would decide the text noted. The write is refused.
CREATE FUNCTION pv_tl_try(q text) RETURNS text LANGUAGE plpgsql AS $f$
BEGIN
    EXECUTE q;
    RETURN $o$ok$o$;
EXCEPTION WHEN OTHERS THEN
    RETURN regexp_replace(SQLERRM, $x$pg_temp_[0-9]+$x$, $x$pg_temp_N$x$, $x$g$x$);
END $f$;
CREATE TYPE tone AS ENUM ($l$calm$l$);
SET check_function_bodies = off;
CREATE FUNCTION pv_tl_json(t text) RETURNS text LANGUAGE sql STABLE SET search_path = pg_temp, public
    AS $f$ SELECT t || ' ' || coalesce(JSON_VALUE('"loud"', '$' RETURNING tone NULL ON ERROR)::text, '-') $f$;
CREATE FUNCTION pv_tl_ts(t text) RETURNS text LANGUAGE sql STABLE SET search_path = pg_temp, public
    AS $f$ SELECT to_tsvector('pg_temp.tcfg', t)::text $f$;
RESET check_function_bodies;
CREATE TABLE tones (id int PRIMARY KEY, body text);
CREATE TABLE stems (id int PRIMARY KEY, body text);
SELECT phasevec.watch($w$tones$w$, $w$tones$w$::regclass, $k$id$k$, $r$public.pv_tl_json(r.body)$r$, $n$r1$n$) > 0 AS watch;
SELECT phasevec.watch($w$stems$w$, $w$stems$w$::regclass, $k$id$k$, $r$public.pv_tl_ts(r.body)$r$, $n$r1$n$) > 0 AS watch;
CREATE TYPE pg_temp.tone AS ENUM ($l$loud$l$);
CREATE TEXT SEARCH CONFIGURATION pg_temp.tcfg (COPY = simple);
SELECT pv_tl_try($q$INSERT INTO tones VALUES (1, 'today')$q$) AS json_returning;
SELECT pv_tl_try($q$INSERT INTO stems VALUES (1, 'the cats')$q$) AS regconfig;
-- the session's temporary schema named by its own name: refused too
DO $d$ BEGIN
    EXECUTE format($f$CREATE FUNCTION pv_tl_named(t text) RETURNS text LANGUAGE sql STABLE
        AS $b$ SELECT t || coalesce(to_regclass(%L)::text, '-') $b$$f$, pg_my_temp_schema()::regnamespace || '.sv');
END $d$;
CREATE TEMP VIEW sv AS SELECT 1 AS x;
CREATE TABLE named (id int PRIMARY KEY, body text);
SELECT phasevec.watch($w$named$w$, $w$named$w$::regclass, $k$id$k$, $r$public.pv_tl_named(r.body)$r$, $n$r1$n$) > 0 AS watch;
SELECT pv_tl_try($q$INSERT INTO named VALUES (1, 'x')$q$) AS schema_named;
DISCARD TEMP;
INSERT INTO tones VALUES (1, $t$today$t$);
SELECT key, body FROM phasevec._render($w$tones$w$, NULL);

-- A statement the client sends is planned for itself: it does not make the next watched write throw away the
-- session's cached plans. Until the sixth review a statement on a temporary table did, and the watch trigger's
-- plans and every prepared statement of the session were made again at each write (5.5 times the latency).
CREATE FUNCTION pv_tl_noisy(i int) RETURNS int LANGUAGE plpgsql IMMUTABLE AS $f$
BEGIN
    RAISE NOTICE 'planned';
    RETURN i;
END $f$;
SET plan_cache_mode = force_generic_plan;
PREPARE pv_tl_q AS SELECT pv_tl_noisy(1) AS planned_once;
EXECUTE pv_tl_q;
EXECUTE pv_tl_q;
CREATE TEMP TABLE pv_tl_tt (x int);
INSERT INTO pv_tl_tt VALUES (1);
UPDATE notes SET body = body WHERE id = 1;
EXECUTE pv_tl_q;
DEALLOCATE pv_tl_q;
RESET plan_cache_mode;
DISCARD TEMP;

DROP TABLE notes, tones, stems, named;
DROP FUNCTION pv_tl_try(text), pv_tl_json(text), pv_tl_ts(text), pv_tl_named(text), pv_tl_noisy(int);
DROP TYPE tone;
DROP EXTENSION pg_phasevec;
DROP OWNED BY pv_tl_author CASCADE;
DROP ROLE pv_tl_author;
