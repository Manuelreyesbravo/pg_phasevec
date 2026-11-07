-- 0.20.0 (twenty-third review). RT23P-UPD-3: a recipe's own RAISE of one of the codes phasevec keeps for the
-- server's errors (55P03 lock_not_available, 40001, 57014, ...) was taken for the server's: the update retried it as a
-- lock failure and blamed "another session". It now comes out of the recipe's guard as the recipe's own error
-- (P0001, its code in the DETAIL), for a reader and a writer alike; an error of the recipe's data keeps its code; and
-- an error of its own that a recipe raises after it caught one of the server's comes out as the server's. What the
-- update does with them needs a 0.19.0 cluster: test/upgrade_writers.sh, cases 8 to 10.
\set VERBOSITY terse

CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register($n$r1$n$, repeat($h$a$h$, 64), 4) > 0 AS r1;
CREATE TABLE r23_slow (on_ boolean, busy boolean);
INSERT INTO r23_slow VALUES (false, false);
CREATE FUNCTION r23_label(id int) RETURNS text LANGUAGE plpgsql STABLE AS $f$
BEGIN
    IF id = 1 THEN
        RAISE EXCEPTION 'busy, says the recipe' USING ERRCODE = 'lock_not_available', DETAIL = 'its own detail';
    ELSIF id = 2 THEN
        RAISE EXCEPTION 'conflict, says the recipe' USING ERRCODE = 'serialization_failure';
    ELSIF id = 3 THEN
        RAISE EXCEPTION 'canceled, says the recipe' USING ERRCODE = 'query_canceled';
    ELSIF id = 4 THEN
        RETURN (1 / 0)::text;
    ELSIF id = 5 THEN
        BEGIN
            RAISE EXCEPTION 'inner' USING ERRCODE = 'lock_not_available';
        EXCEPTION WHEN lock_not_available THEN
            RAISE;
        END;
    ELSIF id = 7 AND (SELECT s.busy FROM public.r23_slow s) THEN
        RAISE EXCEPTION 'busy row, says the recipe' USING ERRCODE = 'lock_not_available';
    ELSIF id = 6 AND (SELECT s.on_ FROM public.r23_slow s) THEN
        BEGIN
            PERFORM pg_sleep(1);
        EXCEPTION WHEN query_canceled THEN
            RAISE EXCEPTION 'no label, says the recipe' USING ERRCODE = 'no_data_found';
        END;
    END IF;
    RETURN 'label ' || id;
END
$f$;
CREATE FUNCTION r23_try(q text) RETURNS text LANGUAGE plpgsql AS $f$
DECLARE
    c text;
    m text;
    d text;
BEGIN
    EXECUTE q;
    RETURN 'ok';
EXCEPTION WHEN OTHERS THEN
    GET STACKED DIAGNOSTICS c = RETURNED_SQLSTATE, m = MESSAGE_TEXT, d = PG_EXCEPTION_DETAIL;
    RETURN c || ': ' || m || coalesce(' [the recipe raised '
                                      || substring(d FROM 'SQLSTATE ([0-9A-Z]{5}), a code phasevec keeps') || ']', '')
             || CASE WHEN d LIKE 'its own detail%' THEN ' [its own detail kept]' ELSE '' END;
END
$f$;
CREATE TABLE r23_mem (id int PRIMARY KEY, body text);
INSERT INTO r23_mem VALUES (6, $t$six$t$), (7, $t$seven$t$);
SELECT phasevec.watch($w$r23_mem$w$, $w$r23_mem$w$::regclass, $k$id$k$, $r$r.body || ' / ' || public.r23_label(r.id)$r$,
                      $n$r1$n$) > 0 AS watch;

-- a recipe's own RAISE of a server's code: its own error (P0001), for a writer and for a reader
SELECT k, r23_try(format($q$INSERT INTO r23_mem VALUES (%s, 'x')$q$, k)) FROM generate_series(1, 5) k ORDER BY k;
SELECT count(*) AS rows_kept FROM r23_mem;
SELECT r23_try($q$UPDATE r23_mem SET id = 1 WHERE id = 7$q$) AS writer;
UPDATE r23_slow SET busy = true;
SELECT r23_try($q$SELECT * FROM phasevec.brief('r23_mem', 1000)$q$) AS reader;
SELECT r23_try($q$SELECT * FROM phasevec._render('r23_mem', NULL)$q$) AS reader;
UPDATE r23_slow SET busy = false;
SELECT key, body FROM phasevec._render($w$r23_mem$w$, NULL) ORDER BY key;

-- an error of its own raised after the recipe caught one of the server's (a statement_timeout): the server's (57014,
-- which an EXCEPTION WHEN OTHERS does not catch), and the writer notes nothing
UPDATE r23_slow SET on_ = true;
SET statement_timeout = $t$200ms$t$;
SELECT r23_try($q$SELECT * FROM phasevec._render('r23_mem', ARRAY['6'])$q$) AS reader;
SELECT r23_try($q$UPDATE r23_mem SET body = 'seis' WHERE id = 6$q$) AS writer;
RESET statement_timeout;
SELECT body FROM r23_mem WHERE id = 6;
UPDATE r23_slow SET on_ = false;
SELECT key, body FROM phasevec._render($w$r23_mem$w$, NULL) ORDER BY key;

DROP TABLE r23_mem, r23_slow;
DROP FUNCTION r23_label(int);
DROP FUNCTION r23_try(text);
DROP EXTENSION pg_phasevec;
