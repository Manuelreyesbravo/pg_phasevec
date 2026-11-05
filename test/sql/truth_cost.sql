-- 0.20.0: the cost cap and the proof clock hold for every proof. Up to 0.19.0 a proof that closed its own
-- parenthesis made two statements: the cost step EXPLAINed the first and RAN the second, with no clock, read no
-- cost from it, and let it through the cap.
\set VERBOSITY terse

CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register($n$r1$n$, repeat($h$a$h$, 64), 4) > 0 AS r1;
CREATE TABLE notes (id int PRIMARY KEY, body text);
INSERT INTO notes VALUES (1, $t$one$t$), (2, $t$two$t$), (3, $t$three$t$), (4, $t$four$t$);
SELECT phasevec.watch($w$notes$w$, $w$notes$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) > 0 AS watch;
-- verify() with a 300 ms clock, and whether the whole pass stayed well under one second
CREATE FUNCTION timed_verify() RETURNS TABLE (key text, verdict text, error text, quick boolean)
LANGUAGE plpgsql AS $f$
DECLARE t0 timestamptz := clock_timestamp();
BEGIN
    RETURN QUERY SELECT v.key, v.verdict, v.error, clock_timestamp() - t0 < interval '1 second'
                   FROM phasevec.verify('notes', p_timeout_ms => 300) v ORDER BY v.key;
END $f$;
-- planning folds an immutable function with constant arguments: it runs during the cost step
CREATE FUNCTION slow_constant(int) RETURNS boolean LANGUAGE sql IMMUTABLE AS $f$ SELECT pg_sleep($1) IS NOT NULL $f$;

-- a proof that is two statements is refused before anything runs
SELECT phasevec.assert($w$notes$w$, $k$1$k$, $p$true); SELECT (pg_sleep(2) IS NULL$p$);
-- a single statement that is far too expensive is refused by the cap, as before
SELECT phasevec.assert($w$notes$w$, $k$2$k$,
    $p$true) FROM generate_series(1, 100000000) a, generate_series(1, 100000000) b WHERE (true$p$);
-- the clock covers the cost step: a proof that is slow to plan is cut at 300 ms
SELECT phasevec.assert($w$notes$w$, $k$3$k$, $p$public.slow_constant(2)$p$);
-- a plain proof still runs
SELECT phasevec.assert($w$notes$w$, $k$4$k$, $p$(SELECT count(*) FROM public.notes) = 4$p$);
SELECT * FROM timed_verify();

DROP FUNCTION timed_verify(), slow_constant(int);
DROP TABLE notes;
DROP EXTENSION pg_phasevec;
