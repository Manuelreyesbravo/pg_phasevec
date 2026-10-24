-- 0.14.2: every proof runs with its own clock. One verify() call cuts a slow proof at its limit and goes on with the
-- next; the caller is not canceled afterwards; a cancel that is not ours (statement_timeout) still cancels the whole
-- statement; a proof the planner estimates above the limit is refused unrun; read-only, NULL and errors as before.
\set VERBOSITY terse

CREATE EXTENSION pg_phasevec VERSION $v$0.14.1$v$;
SELECT phasevec.reader_register($n$r1$n$, repeat($h$a$h$, 64), 4) > 0 AS r1;
CREATE TABLE docs (id int PRIMARY KEY, body text);
INSERT INTO docs VALUES (1, $t$one$t$), (2, $t$two$t$), (3, $t$three$t$), (4, $t$four$t$);
SELECT phasevec.watch($w$docs$w$, $w$docs$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) > 0 AS watch;
CREATE FUNCTION pg_temp.code(k text) RETURNS smallint[] LANGUAGE sql AS $f$
    SELECT CASE k WHEN $k$1$k$ THEN ARRAY[100,0,0,0] WHEN $k$2$k$ THEN ARRAY[0,100,0,0]
                  WHEN $k$3$k$ THEN ARRAY[0,0,100,0] ELSE ARRAY[0,0,0,100] END::smallint[] $f$;
SELECT count(phasevec.record($w$docs$w$, n.key, $n$r1$n$, n.text_hash, 1, pg_temp.code(n.key))) AS recorded
  FROM phasevec.next($w$docs$w$) n;
ALTER EXTENSION pg_phasevec UPDATE TO $v$0.14.2$v$;
SELECT extversion FROM pg_extension WHERE extname = $e$pg_phasevec$e$;

-- ------------------------------------------------ one call: the slow proof is cut, the fast one still proved
SELECT phasevec.assert($w$docs$w$, $k$3$k$, $p$(SELECT true FROM pg_sleep(3))$p$);
SELECT phasevec.assert($w$docs$w$, $k$2$k$, $p$SELECT 1 + 1 = 2$p$);
CREATE FUNCTION pg_temp.timed() RETURNS TABLE (key text, verdict text, error text, under_2s boolean)
LANGUAGE plpgsql AS $f$
DECLARE t0 timestamptz := clock_timestamp();
BEGIN
    RETURN QUERY SELECT v.key, v.verdict, v.error, clock_timestamp() - t0 < interval $i$2 seconds$i$
                   FROM phasevec.verify($w$docs$w$, 10, interval $i$0$i$, interval $i$10 seconds$i$, 300) v ORDER BY v.key;
END $f$;
SELECT * FROM pg_temp.timed();
-- the caller was not canceled by the timer
SELECT 1 AS still_alive;
SELECT key FROM phasevec.find($w$docs$w$, 1, ARRAY[0,0,100,0]::smallint[], 1);

-- ------------------------------------------------ a cancel that is not ours cancels the whole statement
SET statement_timeout = 300;
SELECT * FROM phasevec.verify($w$docs$w$, 10, interval $i$0$i$, interval $i$10 seconds$i$, 5000);
RESET statement_timeout;
SELECT 1 AS alive_after_cancel;

-- ------------------------------------------------ the planner estimate refuses a proof that would be expensive
CREATE TABLE big AS SELECT g FROM generate_series(1, 100000) g;
ANALYZE big;
SELECT phasevec.assert($w$docs$w$, $k$4$k$, $p$SELECT count(*) > 0 FROM big$p$);
SELECT phasevec.verify_one($w$docs$w$, $k$4$k$, 2000, 10) AS over_cost;
SELECT last_error LIKE $l$the proof is estimated at % above the limit of 10: not run$l$ AS said_why FROM phasevec.truth WHERE key = $k$4$k$;
SELECT phasevec.verify_one($w$docs$w$, $k$4$k$) AS within_default_cost;

-- ------------------------------------------------ read-only, NULL and errors, as in 0.14.0
CREATE TABLE world (v int);
CREATE FUNCTION writes() RETURNS boolean LANGUAGE sql AS $f$ INSERT INTO world VALUES (9); SELECT true $f$;
SELECT phasevec.assert($w$docs$w$, $k$1$k$, $p$SELECT writes()$p$);
SELECT phasevec.verify_one($w$docs$w$, $k$1$k$);
SELECT last_error FROM phasevec.truth WHERE key = $k$1$k$;
SELECT count(*) AS rows_in_world FROM world;
SELECT phasevec.assert($w$docs$w$, $k$1$k$, $p$SELECT NULL::boolean$p$);
SELECT phasevec.verify_one($w$docs$w$, $k$1$k$);
SELECT last_error FROM phasevec.truth WHERE key = $k$1$k$;
SELECT phasevec.assert($w$docs$w$, $k$1$k$, $p$SELECT no_such_column FROM docs$p$);
SELECT phasevec.verify_one($w$docs$w$, $k$1$k$);
SELECT last_error FROM phasevec.truth WHERE key = $k$1$k$;
SELECT phasevec.assert($w$docs$w$, $k$1$k$, $p$SELECT true$p$);
SELECT phasevec.verify_one($w$docs$w$, $k$1$k$) AS proved_again;

DROP FUNCTION writes();
DROP TABLE world;
DROP TABLE big;
DROP TABLE docs;
DROP EXTENSION pg_phasevec;
