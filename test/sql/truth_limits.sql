-- 0.14.1: the verifiable memory does not overflow. Uses become counters (the log is folded and dropped); verify()
-- stops at its budget; verify_one() proves one key so the caller can bound it with statement_timeout, and refute()
-- records a proof cut for being slow, which is then never served.
\set VERBOSITY terse

CREATE EXTENSION pg_phasevec VERSION $v$0.14.0$v$;
SELECT phasevec.reader_register($n$r1$n$, repeat($h$a$h$, 64), 4) > 0 AS r1;
CREATE TABLE docs (id int PRIMARY KEY, body text);
INSERT INTO docs VALUES (1, $t$one$t$), (2, $t$two$t$), (3, $t$three$t$), (4, $t$four$t$);
SELECT phasevec.watch($w$docs$w$, $w$docs$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) > 0 AS watch;
CREATE FUNCTION pg_temp.code(k text) RETURNS smallint[] LANGUAGE sql AS $f$
    SELECT CASE k WHEN $k$1$k$ THEN ARRAY[100,0,0,0] WHEN $k$2$k$ THEN ARRAY[0,100,0,0]
                  WHEN $k$3$k$ THEN ARRAY[0,0,100,0] ELSE ARRAY[0,0,0,100] END::smallint[] $f$;
SELECT count(phasevec.record($w$docs$w$, n.key, $n$r1$n$, n.text_hash, 1, pg_temp.code(n.key))) AS recorded
  FROM phasevec.next($w$docs$w$) n;
-- three uses logged one row each in 0.14.0
SELECT phasevec.note_use($w$docs$w$, $k$2$k$, 1::smallint), phasevec.note_use($w$docs$w$, $k$2$k$, 1::smallint),
       phasevec.note_use($w$docs$w$, $k$2$k$, -1::smallint);
SELECT count(*) AS logged FROM phasevec.uses;

ALTER EXTENSION pg_phasevec UPDATE TO $v$0.14.1$v$;
SELECT extversion FROM pg_extension WHERE extname = $e$pg_phasevec$e$;

-- ------------------------------------------------ uses folded into counters, the log is gone
SELECT to_regclass($r$phasevec.uses$r$) IS NULL AS log_dropped;
SELECT key, helped, not_helped, brought FROM phasevec.usefulness;
SELECT phasevec.note_use($w$docs$w$, $k$2$k$, 1::smallint), phasevec.note_use($w$docs$w$, $k$3$k$, 0::smallint);
SELECT key, helped, not_helped, brought FROM phasevec.usefulness ORDER BY key;
SELECT count(*) AS rows_for_five_uses FROM phasevec.usefulness;

-- ------------------------------------------------ the budget stops the pass between proofs
SELECT phasevec.assert($w$docs$w$, k, $p$(SELECT true FROM pg_sleep(0.3))$p$) FROM unnest(ARRAY[$k$1$k$, $k$2$k$, $k$3$k$]) k;
SELECT count(*) AS proved_within_budget FROM phasevec.verify($w$docs$w$, 10, interval $i$0$i$, interval $i$0.45 seconds$i$);
SELECT count(*) AS proved_next_pass FROM phasevec.verify($w$docs$w$, 10, interval $i$1 hour$i$, interval $i$10 seconds$i$);
SELECT verdict, n FROM phasevec.truth_coverage($w$docs$w$);

-- ------------------------------------------------ one key per call: the caller bounds it, refute() records why
SELECT phasevec.verify_one($w$docs$w$, $k$1$k$) AS no_longer_due_but_proved;
SELECT phasevec.verify_one($w$docs$w$, $k$4$k$) AS without_proof;
SELECT phasevec.assert($w$docs$w$, $k$4$k$, $p$(SELECT true FROM pg_sleep(2))$p$);
SET statement_timeout = 200;
SELECT phasevec.verify_one($w$docs$w$, $k$4$k$);
RESET statement_timeout;
SELECT phasevec.refute($w$docs$w$, $k$4$k$, $m$proof over 200 ms$m$);
SELECT phasevec.refute($w$docs$w$, $k$4$k$, $m$ $m$);
SELECT key, verdict, last_error FROM phasevec.truth WHERE key = $k$4$k$;
SELECT key FROM phasevec.find($w$docs$w$, 1, ARRAY[0,0,0,100]::smallint[], 1);
-- refute does not overrule a replacement
SELECT phasevec.supersede($w$docs$w$, $k$3$k$, $k$2$k$, $m$merged$m$);
SELECT phasevec.refute($w$docs$w$, $k$3$k$, $m$late$m$);
SELECT verdict FROM phasevec.truth WHERE key = $k$3$k$;

DROP TABLE docs;
DROP EXTENSION pg_phasevec;
