-- 0.20.0 (tenth and eleventh reviews): verdicts move forward in time; a verdict serves only while it is fresh; and a
-- claim's turn is spent by every attempt. (The races themselves: test/truth_order.sh, test/truth_unjudged.sh,
-- test/truth_liveness.sh.)
-- 1. _truth_set records a judgment only if no verdict of the claim was read after it: in the ninth cut verify_one()
--    wrote a 'verified' it read before a verify() read and recorded 'refuted'. An interruption is not a verdict: it
--    stops nothing from being recorded.
-- 2. A halt is recorded only if no verdict was read after its proof began.
-- 3. The horizon (eleventh review): a verdict of a proof reads 'unproven' past verified_at + watches.max_age, whatever
--    kept it from being judged again; _truth_tried records why a claim was not judged and leaves its verdict as it
--    was. And the turn: _truth_due takes the oldest attempt first (a claim never tried, from when it was asserted); an
--    assert does not give a claim a new turn.
\set VERBOSITY terse

CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register($n$r1$n$, repeat($h$a$h$, 64), 4) > 0 AS r1;
CREATE TABLE notes (id int PRIMARY KEY, body text);
INSERT INTO notes SELECT g, $t$note $t$ || g FROM generate_series(1, 6) g;
SELECT phasevec.watch($w$o1$w$, $w$notes$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) > 0 AS o1;
SELECT count(phasevec.assert($w$o1$w$, k::text, $p$true$p$)) FROM generate_series(1, 5) k;
CREATE FUNCTION pv_o_set(k text, v text, at timestamptz) RETURNS text LANGUAGE sql AS $f$
    SELECT phasevec._truth_set(t.watch, t.key, v, v, phasevec._bind(t.asserted_for, t.proof,
                               t.asserted_by_oid, t.proof_env), at)
      FROM phasevec.truth t WHERE t.key = k $f$;
CREATE FUNCTION pv_o_tried(k text, why text, interrupted boolean) RETURNS text LANGUAGE sql AS $f$
    SELECT phasevec._truth_tried(t.watch, t.key, why, interrupted) FROM phasevec.truth t WHERE t.key = k $f$;
CREATE FUNCTION pv_o_show(k text) RETURNS TABLE (verdict text, reads text, last_error text, interrupted boolean,
                                                 tried boolean, why text)
LANGUAGE sql AS $f$
    SELECT t.verdict, phasevec._verdict(t), t.last_error, t.interrupted_at IS NOT NULL, a.attempted_at IS NOT NULL,
           a.why
      FROM phasevec.truth t LEFT JOIN phasevec.attempts a ON a.watch = t.watch AND a.key = t.key
     WHERE t.key = k $f$;
CREATE FUNCTION pv_o_due() RETURNS SETOF text LANGUAGE sql AS $f$
    SELECT key FROM phasevec._truth_due((SELECT id FROM phasevec.watches WHERE name = $w$o1$w$), 10, interval '0',
                                        (SELECT oid FROM pg_roles WHERE rolname = current_user)) $f$;

-- 1. A 'refuted' read at 00:00:10 is recorded; a 'verified' read at 00:00:05 is not; one read at 00:00:20 is. Read
-- now, months later, all of them are past their horizon (an hour): 'unproven'.
SELECT pv_o_set($k$1$k$, $v$refuted$v$, $t$2026-01-01 00:00:10+00$t$);
SELECT pv_o_set($k$1$k$, $v$verified$v$, $t$2026-01-01 00:00:05+00$t$);
SELECT * FROM pv_o_show($k$1$k$);
SELECT pv_o_set($k$1$k$, $v$verified$v$, $t$2026-01-01 00:00:20+00$t$);
SELECT * FROM pv_o_show($k$1$k$);
-- an interruption recorded now: the verdict is as it was, and a judgment read after the last one is recorded
SELECT pv_o_tried($k$1$k$, $w$interrupted: by another process$w$, true);
SELECT * FROM pv_o_show($k$1$k$);
SELECT pv_o_set($k$1$k$, $v$refuted$v$, $t$2026-01-01 00:00:30+00$t$);
SELECT * FROM pv_o_show($k$1$k$);
SELECT pv_o_set($k$1$k$, $v$refuted$v$, clock_timestamp());
SELECT * FROM pv_o_show($k$1$k$);

-- 2. A halt whose proof began before the verdict was read: not recorded (0); one that began after: recorded (1). A
-- halted claim is not judged again: its 'refuted' has no horizon.
SELECT pv_o_set($k$2$k$, $v$verified$v$, now() + interval '1 minute');
SELECT phasevec._truth_halted(t.watch, sha256(convert_to(t.key, $e$UTF8$e$)),
                              phasevec._bind(t.asserted_for, t.proof, t.asserted_by_oid, t.proof_env),
                              (SELECT oid FROM pg_roles WHERE rolname = current_user), now() + s.after) AS halted
  FROM phasevec.truth t, (VALUES (interval '50 seconds'), (interval '70 seconds')) s(after)
 WHERE t.key = $k$2$k$;
UPDATE phasevec.truth SET verified_at = now() - interval '1 day' WHERE key = $k$2$k$;
SELECT verdict, halted, phasevec._verdict(t) AS reads FROM phasevec.truth t WHERE key = $k$2$k$;

-- 3. The horizon. Claim 3 verified now; not judged since (its session did not start): its verdict stands, fresh.
SELECT pv_o_set($k$3$k$, $v$verified$v$, clock_timestamp());
SELECT pv_o_tried($k$3$k$, $w$not judged: its session did not start$w$, false);
SELECT * FROM pv_o_show($k$3$k$);
-- the watch's horizon is a minute; the verdict was judged two minutes ago: 'unproven', whatever kept it
UPDATE phasevec.watches SET max_age = interval '1 minute' WHERE name = $w$o1$w$;
UPDATE phasevec.truth SET verified_at = now() - interval '2 minutes' WHERE key = $k$3$k$;
SELECT * FROM pv_o_show($k$3$k$);
-- a refuted one too; a refute() of a key with no proof has nothing that judges it again: no horizon
SELECT pv_o_set($k$5$k$, $v$refuted$v$, now() - interval '2 minutes');
SELECT phasevec.refute($w$o1$w$, $k$6$k$, $r$by hand$r$);
UPDATE phasevec.truth SET verified_at = now() - interval '2 minutes' WHERE key = $k$6$k$;
SELECT key, verdict, phasevec._verdict(t) AS reads FROM phasevec.truth t WHERE key IN ($k$5$k$, $k$6$k$) ORDER BY key;
-- a horizon is above zero
UPDATE phasevec.watches SET max_age = interval '0' WHERE name = $w$o1$w$;
UPDATE phasevec.watches SET max_age = interval '1 hour' WHERE name = $w$o1$w$;

-- 4. The turn. Every claim due (p_every 0; 2 is halted): those never tried first, by when they were asserted, then
-- those tried, oldest attempt first. Claim 3 was tried above; 1 too (the interruption).
SELECT * FROM pv_o_due();
-- 4 is tried now: it goes behind 1 and 3
SELECT phasevec._truth_attempt(t.watch, t.key) FROM phasevec.truth t WHERE key = $k$4$k$;
SELECT * FROM pv_o_due();
-- an attempt clears why the last one did not judge it
SELECT phasevec._truth_attempt(t.watch, t.key) FROM phasevec.truth t WHERE key = $k$3$k$;
SELECT * FROM pv_o_show($k$3$k$);
-- an assert does not give a claim a new turn: 4 stays where it was, and its verdict is 'unproven' until judged
SELECT phasevec.assert($w$o1$w$, $k$4$k$, $p$1 = 1$p$);
SELECT * FROM pv_o_due();
SELECT * FROM pv_o_show($k$4$k$);
-- only the owner records, and only the owner reads the turns
SELECT has_function_privilege($r$public$r$, $f$phasevec._truth_tried(int, text, text, boolean)$f$, $p$EXECUTE$p$) AS tried_public,
       has_function_privilege($r$public$r$, $f$phasevec._truth_attempt(int, text)$f$, $p$EXECUTE$p$) AS attempt_public,
       has_table_privilege($r$public$r$, $t$phasevec.attempts$t$, $p$SELECT$p$) AS attempts_public;

DROP FUNCTION pv_o_set(text, text, timestamptz);
DROP FUNCTION pv_o_tried(text, text, boolean);
DROP FUNCTION pv_o_show(text);
DROP FUNCTION pv_o_due();
DROP TABLE notes;
DROP EXTENSION pg_phasevec;
