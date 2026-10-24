-- 0.14.0: memory that knows what is still true. A replaced, expired or refuted row is never served by find, alike,
-- find_hybrid or find_ivf; truth does not touch the queue nor the reading coverage; unsuperseding restores; expiry
-- is exact; verify() refutes and verifies again; a proof cannot write; disputes come in pairs. Each with its control.
\set VERBOSITY terse

CREATE EXTENSION pg_phasevec VERSION $v$0.13.0$v$;
SELECT phasevec.reader_register($n$r1$n$, repeat($h$a$h$, 64), 4) > 0 AS r1;
CREATE TABLE docs (id int PRIMARY KEY, body text);
INSERT INTO docs VALUES (1, $t$the deployed version of pg_phasevec is 0.12.0$t$),
                        (2, $t$the deployed version of pg_phasevec is 0.13.0$t$),
                        (3, $t$cherry tart recipe$t$), (4, $t$date palm notes$t$);
SELECT phasevec.watch($w$docs$w$, $w$docs$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) > 0 AS watch;
CREATE FUNCTION pg_temp.code(k text) RETURNS smallint[] LANGUAGE sql AS $f$
    SELECT CASE k WHEN $k$1$k$ THEN ARRAY[100,0,0,0] WHEN $k$2$k$ THEN ARRAY[95,5,0,0]
                  WHEN $k$3$k$ THEN ARRAY[0,0,100,0] ELSE ARRAY[0,0,0,100] END::smallint[] $f$;
SELECT count(phasevec.record($w$docs$w$, n.key, $n$r1$n$, n.text_hash, 1, pg_temp.code(n.key))) AS recorded
  FROM phasevec.next($w$docs$w$) n;

ALTER EXTENSION pg_phasevec UPDATE TO $v$0.14.0$v$;
SELECT extversion FROM pg_extension WHERE extname = $e$pg_phasevec$e$;

-- ------------------------------------------------ control: nothing said about truth, everything served
SELECT key FROM phasevec.find($w$docs$w$, 1, ARRAY[100,0,0,0]::smallint[], 2);
SELECT verdict, n FROM phasevec.truth_coverage($w$docs$w$);

-- ------------------------------------------------ replaced: never served, history kept
SELECT phasevec.supersede($w$docs$w$, $k$1$k$, $k$2$k$, $m$deployed 0.13.0 on 2026-10-24$m$);
SELECT key FROM phasevec.find($w$docs$w$, 1, ARRAY[100,0,0,0]::smallint[], 2);
SELECT key FROM phasevec.alike($w$docs$w$, $k$2$k$, 3);
SELECT step, key, reason FROM phasevec.replacement($w$docs$w$, $k$1$k$);
-- the reading axis does not move: same coverage, nothing back in the queue, counts agree with a recount
SELECT state, n FROM phasevec.coverage($w$docs$w$) WHERE n > 0;
SELECT count(*) AS to_read FROM phasevec.next($w$docs$w$);
SELECT count(*) AS mismatches FROM phasevec.coverage_check($w$docs$w$);
-- a replacement must exist, must not be itself and must say why
SELECT phasevec.supersede($w$docs$w$, $k$3$k$, $k$99$k$, $m$typo$m$);
SELECT phasevec.supersede($w$docs$w$, $k$3$k$, $k$3$k$, $m$self$m$);
SELECT phasevec.supersede($w$docs$w$, $k$3$k$, $k$4$k$, $m$ $m$);
-- unsuperseding restores it
SELECT phasevec.unsupersede($w$docs$w$, $k$1$k$);
SELECT key FROM phasevec.find($w$docs$w$, 1, ARRAY[100,0,0,0]::smallint[], 2);

-- ------------------------------------------------ expired: exact at read time, no sweep
SELECT phasevec.assert($w$docs$w$, $k$3$k$, p_expires_at => now() - interval $i$1 minute$i$);
SELECT key FROM phasevec.find($w$docs$w$, 1, ARRAY[0,0,100,0]::smallint[], 1);
SELECT phasevec.assert($w$docs$w$, $k$3$k$, p_expires_at => now() + interval $i$1 hour$i$);
SELECT key FROM phasevec.find($w$docs$w$, 1, ARRAY[0,0,100,0]::smallint[], 1);

-- ------------------------------------------------ proofs: verify refutes and verifies again
CREATE TABLE world (v int);
INSERT INTO world VALUES (1);
SELECT phasevec.assert($w$docs$w$, $k$4$k$, $p$SELECT v = 1 FROM world$p$, NULL, $s${"measured": "world.v"}$s$::jsonb);
SELECT key, verdict, error FROM phasevec.verify($w$docs$w$, 10, interval $i$0$i$);
SELECT key FROM phasevec.find($w$docs$w$, 1, ARRAY[0,0,0,100]::smallint[], 1);
UPDATE world SET v = 2;
SELECT key, verdict, error FROM phasevec.verify($w$docs$w$, 10, interval $i$0$i$);
SELECT key FROM phasevec.find($w$docs$w$, 1, ARRAY[0,0,0,100]::smallint[], 1);
UPDATE world SET v = 1;
SELECT key, verdict FROM phasevec.verify($w$docs$w$, 10, interval $i$0$i$);
SELECT key FROM phasevec.find($w$docs$w$, 1, ARRAY[0,0,0,100]::smallint[], 1);
-- not due yet: nothing re-run
SELECT count(*) AS rerun FROM phasevec.verify($w$docs$w$, 10);
-- a proof cannot write: it is refuted with the error and the world is untouched
CREATE FUNCTION writes() RETURNS boolean LANGUAGE sql AS $f$ INSERT INTO world VALUES (9); SELECT true $f$;
SELECT phasevec.assert($w$docs$w$, $k$4$k$, $p$SELECT writes()$p$);
SELECT key, verdict, error FROM phasevec.verify($w$docs$w$, 10, interval $i$0$i$);
SELECT count(*) AS rows_in_world FROM world;
-- a proof that answers NULL refutes, and says so
SELECT phasevec.assert($w$docs$w$, $k$4$k$, $p$SELECT NULL::boolean$p$);
SELECT key, verdict, error FROM phasevec.verify($w$docs$w$, 10, interval $i$0$i$);
SELECT verdict, n FROM phasevec.truth_coverage($w$docs$w$);

-- ------------------------------------------------ disputes: two current rows, same topic, different text
SELECT phasevec.assert($w$docs$w$, $k$1$k$, NULL, $c$pg_phasevec.deployed$c$);
SELECT phasevec.assert($w$docs$w$, $k$2$k$, NULL, $c$pg_phasevec.deployed$c$);
SELECT * FROM phasevec.disputes($w$docs$w$);
SELECT phasevec.supersede($w$docs$w$, $k$1$k$, $k$2$k$, $m$deployed 0.13.0$m$);
SELECT count(*) AS disputes_after FROM phasevec.disputes($w$docs$w$);

-- ------------------------------------------------ find_hybrid: neither arm serves a replaced row
SELECT phasevec.lexical($w$docs$w$, $l$english$l$) AS read_lexically;
SELECT phasevec.lexical_maintain($w$docs$w$) AS maintained;
SELECT key FROM phasevec.find_hybrid($w$docs$w$, $q$deployed version pg_phasevec$q$, 1, ARRAY[100,0,0,0]::smallint[], 4, false, 100, NULL, 4) ORDER BY key;
SELECT phasevec.unsupersede($w$docs$w$, $k$1$k$);
SELECT key FROM phasevec.find_hybrid($w$docs$w$, $q$deployed version pg_phasevec$q$, 1, ARRAY[100,0,0,0]::smallint[], 4, false, 100, NULL, 4) ORDER BY key;

-- ------------------------------------------------ uses are noted
SELECT phasevec.note_use($w$docs$w$, $k$2$k$, 1::smallint), phasevec.note_use($w$docs$w$, $k$2$k$, 1::smallint);
SELECT key, sum(outcome) AS net FROM phasevec.uses GROUP BY key;

-- ------------------------------------------------ find_ivf (C): the same, with the coarse index
SELECT phasevec.reader_register($n$r256$n$, repeat($h$b$h$, 64), 256) > 0 AS r256;
CREATE TABLE big (id int PRIMARY KEY, body text);
INSERT INTO big SELECT g, $t$doc $t$ || g FROM generate_series(1, 300) g;
SELECT phasevec.watch($w$big$w$, $w$big$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r256$n$) > 0 AS watch;
CREATE FUNCTION pg_temp.code_of(g int) RETURNS smallint[] LANGUAGE sql IMMUTABLE AS $f$
    SELECT array(SELECT (((g * 31 + j * 17 * (g % 7 + 1) + (g / 13) * j) % 255) - 127)::smallint
                   FROM generate_series(1, 256) j) $f$;
CREATE FUNCTION pg_temp.signs_of(c smallint[]) RETURNS bit(256) LANGUAGE sql IMMUTABLE AS $f$
    SELECT string_agg(CASE WHEN x > 0 THEN $b$1$b$ ELSE $b$0$b$ END, $b$$b$ ORDER BY o)::bit(256)
      FROM unnest(c) WITH ORDINALITY u(x, o) $f$;
SELECT count(phasevec.record($w$big$w$, s.key, $n$r256$n$, s.text_hash, 0::bigint, pg_temp.code_of(s.key::int), NULL,
                             pg_temp.signs_of(pg_temp.code_of(s.key::int))))
  FROM phasevec.sources s WHERE s.watch = (SELECT id FROM phasevec.watches WHERE name = $w$big$w$);
SELECT phasevec.ivf_build($w$big$w$) > 0 AS built;
SELECT key FROM phasevec.find_ivf($w$big$w$, 0, pg_temp.code_of(100), 1, false, 300, pg_temp.signs_of(pg_temp.code_of(100)), 1000);
SELECT phasevec.supersede($w$big$w$, $k$100$k$, $k$101$k$, $m$test$m$);
SELECT count(*) FILTER (WHERE key = $k$100$k$) AS replaced_served
  FROM phasevec.find_ivf($w$big$w$, 0, pg_temp.code_of(100), 10, false, 300, pg_temp.signs_of(pg_temp.code_of(100)), 1000);
-- same answer as find, which filters in SQL
SELECT (SELECT array_agg(key ORDER BY score DESC, key) FROM phasevec.find($w$big$w$, 0, pg_temp.code_of(100), 10, false, 300, pg_temp.signs_of(pg_temp.code_of(100))))
     = (SELECT array_agg(key ORDER BY score DESC, key) FROM phasevec.find_ivf($w$big$w$, 0, pg_temp.code_of(100), 10, false, 300, pg_temp.signs_of(pg_temp.code_of(100)), 1000))
       AS same_as_find;

DROP TABLE big;
DROP FUNCTION writes();
DROP TABLE world;
DROP TABLE docs;
DROP EXTENSION pg_phasevec;
