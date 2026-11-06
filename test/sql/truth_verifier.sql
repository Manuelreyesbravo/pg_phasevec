-- 0.20.0 (ninth review): a verdict is about a committed state that does not depend on its verifier's transaction, and
-- a verifier never waits without its deadlines.
-- 1. A verifier with an uncommitted write that refutes the claims: the proofs judged the committed state before it,
--    and the 'verified' they reached committed together with the write that refutes it (no committed state ever made
--    it true). verify() and verify_one() refuse a transaction that has written (it has a transaction id).
-- 2. A verdict is committed by the proof's own session as it is reached: the verifier's transaction does not carry it
--    (a ROLLBACK of the verifier keeps it), and a verifier writes nothing, so it may verify again in the same transaction.
-- 3. A claim larger than the queue between verifier and worker (64 kB) blocked the verifier inside shm_mq_send with no
--    deadline: behind a proof that catches query_canceled, the clock plus 5 s never ended that proof's worker, and the
--    call waited for as long as the proof ran. Sends do not block now: the call waits under its deadlines.
-- 4. The same claim, verified in a transaction holding DDL on the watched table: the worker waited for the lock while
--    the verifier waited, sending, for the worker; nothing ended it. Such a transaction is refused now.
\set VERBOSITY terse

CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register($n$r1$n$, repeat($h$a$h$, 64), 4) > 0 AS r1;
CREATE TABLE notes (id int PRIMARY KEY, body text);
INSERT INTO notes SELECT g, $t$note $t$ || g FROM generate_series(1, 4) g;
SELECT phasevec.watch($w$v1$w$, $w$notes$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) > 0 AS v1;
SELECT phasevec.watch($w$v2$w$, $w$notes$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) > 0 AS v2;
CREATE TABLE invoices (id int, overdue boolean);
INSERT INTO invoices VALUES (1, false), (2, false);
SELECT phasevec.assert($w$v1$w$, k::text, $p$NOT EXISTS (SELECT 1 FROM public.invoices WHERE overdue)$p$)
  FROM generate_series(1, 2) k;

-- 1. The verifier makes an invoice overdue and verifies before it commits: refused, by verify() and by verify_one().
BEGIN;
UPDATE invoices SET overdue = true WHERE id = 1;
SELECT key, verdict FROM phasevec.verify($w$v1$w$, p_every => interval '0') ORDER BY key;
COMMIT;
BEGIN;
UPDATE invoices SET overdue = true WHERE id = 1;
SELECT phasevec.verify_one($w$v1$w$, $k$1$k$);
COMMIT;
-- what was committed, and what the claims say about it: nothing judged a state that never was
SELECT count(*) FILTER (WHERE overdue) AS overdue FROM invoices;
SELECT t.key, phasevec._verdict(t) AS verdict FROM phasevec.truth t JOIN phasevec.watches w ON w.id = t.watch
 WHERE w.name = $w$v1$w$ ORDER BY t.key;
-- DDL takes a transaction id too: refused before any proof waits for its lock
BEGIN;
CREATE INDEX ON invoices (overdue);
SELECT phasevec.verify_one($w$v1$w$, $k$1$k$);
ROLLBACK;

-- 2. Verdicts are committed as they are reached, by the proofs' sessions: a verifier's ROLLBACK keeps them, and a
-- verifier may verify again in one transaction or one statement.
UPDATE invoices SET overdue = false;
BEGIN;
SELECT key, verdict FROM phasevec.verify($w$v1$w$, p_every => interval '0') ORDER BY key;
ROLLBACK;
SELECT t.key, phasevec._verdict(t) AS verdict FROM phasevec.truth t JOIN phasevec.watches w ON w.id = t.watch
 WHERE w.name = $w$v1$w$ ORDER BY t.key;
BEGIN;
SELECT count(*) AS judged FROM phasevec.verify($w$v1$w$, p_every => interval '0');
SELECT count(*) AS judged FROM phasevec.verify($w$v1$w$, p_every => interval '0');
COMMIT;
SELECT phasevec.verify_one($w$v1$w$, $k$1$k$) AS one, phasevec.verify_one($w$v1$w$, $k$2$k$) AS two;
-- the verifier's transaction got no transaction id from any of it
BEGIN;
SELECT count(*) AS judged FROM phasevec.verify($w$v1$w$, p_every => interval '0');
SELECT pg_current_xact_id_if_assigned() IS NULL AS no_xid;
COMMIT;

-- 3. A proof that catches query_canceled (it runs for a minute) and, sent behind it, a claim of 70 kB. The clock and
-- 5 s more end the first one's worker; the second is judged in a new one.
CREATE FUNCTION public.stubborn() RETURNS boolean LANGUAGE plpgsql AS $f$
BEGIN
    FOR i IN 1..600 LOOP
        BEGIN
            PERFORM pg_sleep(0.1);
        EXCEPTION WHEN query_canceled THEN NULL;
        END;
    END LOOP;
    RETURN true;
END $f$;
SELECT phasevec.assert($w$v2$w$, $k$1$k$, $p$public.stubborn()$p$);
SELECT phasevec.assert($w$v2$w$, $k$2$k$, format($p$length(%L) = 70000$p$, repeat($x$x$x$, 70000)));
SET statement_timeout = '25s';
SELECT key, verdict, error FROM phasevec.verify($w$v2$w$, p_every => interval '0', p_budget => interval '30 seconds',
                                                p_timeout_ms => 300) ORDER BY key;
RESET statement_timeout;
SELECT t.key, phasevec._verdict(t) AS verdict, t.halted FROM phasevec.truth t JOIN phasevec.watches w ON w.id = t.watch
 WHERE w.name = $w$v2$w$ ORDER BY t.key;

-- 4. The 70 kB claim, in a transaction with DDL on the watched table: refused, not a wait with no end.
SET statement_timeout = '15s';
BEGIN;
ALTER TABLE notes ADD COLUMN z int;
SELECT phasevec.verify_one($w$v2$w$, $k$2$k$);
ROLLBACK;
RESET statement_timeout;
SELECT phasevec.verify_one($w$v2$w$, $k$2$k$);
