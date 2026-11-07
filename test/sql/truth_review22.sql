-- 0.20.0 (twenty-second review). RT22P-UPD-1: a recipe that reads through a function of its own with an EXCEPTION
-- clause caught the update's lock failure (its lock_timeout of 1 ms) and rendered its fallback text, which the update
-- noted for every row and bound the claims it retired to. A render now ends with an error that is not the recipe's
-- own (a lock another session holds, a cancel, the server short of a resource) even when the recipe catches it. The
-- lock case needs a second session: test/upgrade_writers.sh, cases 6 and 7. Here: a statement_timeout the recipe
-- catches, and what stays the recipe's own (an error of its data, a RAISE of its own).
\set VERBOSITY terse

CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register($n$r1$n$, repeat($h$a$h$, 64), 4) > 0 AS r1;
CREATE TABLE r22_slow (on_ boolean);
INSERT INTO r22_slow VALUES (false);
CREATE FUNCTION r22_label(id int) RETURNS text LANGUAGE plpgsql STABLE AS $f$
BEGIN
    IF id = 1 AND (SELECT s.on_ FROM public.r22_slow s) THEN
        PERFORM pg_sleep(1);
    END IF;
    IF id = 2 THEN
        RETURN (1 / 0)::text;
    END IF;
    IF id = 3 THEN
        RAISE EXCEPTION 'busy, says the recipe' USING ERRCODE = 'lock_not_available';
    END IF;
    RETURN 'label ' || id;
EXCEPTION
    WHEN query_canceled THEN RETURN '(cut short)';
    WHEN OTHERS THEN RETURN '(fallback ' || SQLSTATE || ')';
END
$f$;
CREATE TABLE r22_mem (id int PRIMARY KEY, body text);
INSERT INTO r22_mem VALUES (1, $t$one$t$), (2, $t$two$t$), (3, $t$three$t$);
SELECT phasevec.watch($w$r22_mem$w$, $w$r22_mem$w$::regclass, $k$id$k$, $r$r.body || ' / ' || public.r22_label(r.id)$r$,
                      $n$r1$n$) > 0 AS watch;

-- an error of the recipe's data, and a RAISE of its own (even of a lock's code), caught by it: its text, as before
SELECT key, body FROM phasevec._render($w$r22_mem$w$, NULL) ORDER BY key;
SELECT count(*) AS noted_as_rendered FROM phasevec.sources s JOIN phasevec._render($w$r22_mem$w$, NULL) r
    ON r.key = s.key AND r.text_hash = s.text_hash;

-- a statement_timeout the recipe catches: no text, for a reader and for a writer (which notes nothing)
UPDATE r22_slow SET on_ = true;
CREATE TEMP TABLE r22_noted AS SELECT s.key, s.text_hash FROM phasevec.sources s;
SET statement_timeout = $t$200ms$t$;
SELECT key, body FROM phasevec._render($w$r22_mem$w$, NULL) ORDER BY key;
SELECT key, line FROM phasevec.brief($w$r22_mem$w$, 1000) ORDER BY key;
UPDATE r22_mem SET body = $t$uno$t$ WHERE id = 1;
RESET statement_timeout;
SELECT body FROM r22_mem WHERE id = 1;
SELECT count(*) AS changed FROM phasevec.sources s JOIN r22_noted n ON n.key = s.key WHERE n.text_hash <> s.text_hash;
UPDATE r22_slow SET on_ = false;
UPDATE r22_mem SET body = $t$uno$t$ WHERE id = 1;
SELECT key, body FROM phasevec._render($w$r22_mem$w$, ARRAY[$k$1$k$]);

DROP TABLE r22_mem, r22_slow;
DROP FUNCTION r22_label(int);
DROP EXTENSION pg_phasevec;
