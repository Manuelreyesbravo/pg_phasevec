-- 0.20.0 (tenth review): verdicts move forward in time, and a claim that cannot be judged for its author's sake keeps
-- its verdict only while it is fresh. (The races themselves: test/truth_order.sh, test/truth_unjudged.sh.)
-- 1. _truth_set records a judgment only if no verdict (and no interruption) of the claim was read after it: in the
--    ninth cut verify_one() wrote a 'verified' it read before a verify() read and recorded 'refuted'.
-- 2. A halt is recorded only if no verdict was read after its proof began.
-- 3. _truth_unjudged: the claim stays due, keeps its verdict until unjudged_until, then reads 'unproven'; it waits
--    behind the claims judged since (tried_at), and a verdict or an assert clears the marks.
\set VERBOSITY terse

CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register($n$r1$n$, repeat($h$a$h$, 64), 4) > 0 AS r1;
CREATE TABLE notes (id int PRIMARY KEY, body text);
INSERT INTO notes SELECT g, $t$note $t$ || g FROM generate_series(1, 4) g;
SELECT phasevec.watch($w$o1$w$, $w$notes$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) > 0 AS o1;
SELECT count(phasevec.assert($w$o1$w$, k::text, $p$true$p$)) FROM generate_series(1, 4) k;
CREATE FUNCTION pv_o_set(k text, v text, at timestamptz) RETURNS text LANGUAGE sql AS $f$
    SELECT phasevec._truth_set(t.watch, t.key, v, v, phasevec._bind(t.asserted_for, t.proof,
                               t.asserted_by_oid, t.proof_env), at)
      FROM phasevec.truth t WHERE t.key = k $f$;
CREATE FUNCTION pv_o_show(k text) RETURNS TABLE (verdict text, reads text, last_error text, interrupted boolean,
                                                 unjudged boolean, tried boolean)
LANGUAGE sql AS $f$
    SELECT t.verdict, phasevec._verdict(t), t.last_error, t.interrupted_at IS NOT NULL, t.unjudged_at IS NOT NULL,
           t.tried_at IS NOT NULL
      FROM phasevec.truth t WHERE t.key = k $f$;

-- 1. A 'refuted' read at 00:00:10 is recorded; a 'verified' read at 00:00:05 is not; one read at 00:00:20 is.
SELECT pv_o_set($k$1$k$, $v$refuted$v$, $t$2026-01-01 00:00:10+00$t$);
SELECT pv_o_set($k$1$k$, $v$verified$v$, $t$2026-01-01 00:00:05+00$t$);
SELECT * FROM pv_o_show($k$1$k$);
SELECT pv_o_set($k$1$k$, $v$verified$v$, $t$2026-01-01 00:00:20+00$t$);
SELECT * FROM pv_o_show($k$1$k$);
-- an interruption recorded now: a judgment read before it is not recorded, one read after it is
SELECT phasevec._truth_interrupted(t.watch, t.key, phasevec._bind(t.asserted_for, t.proof, t.asserted_by_oid,
                                   t.proof_env), $w$interrupted$w$)
  FROM phasevec.truth t WHERE t.key = $k$1$k$;
SELECT pv_o_set($k$1$k$, $v$refuted$v$, $t$2026-01-01 00:00:30+00$t$);
SELECT * FROM pv_o_show($k$1$k$);
SELECT pv_o_set($k$1$k$, $v$refuted$v$, clock_timestamp() + interval '1 second');
SELECT * FROM pv_o_show($k$1$k$);

-- 2. A halt whose proof began before the verdict was read: not recorded (0); one that began after: recorded (1).
SELECT pv_o_set($k$2$k$, $v$verified$v$, now() + interval '1 minute');
SELECT phasevec._truth_halted(t.watch, sha256(convert_to(t.key, $e$UTF8$e$)),
                              phasevec._bind(t.asserted_for, t.proof, t.asserted_by_oid, t.proof_env),
                              (SELECT oid FROM pg_roles WHERE rolname = current_user), now() + s.after) AS halted
  FROM phasevec.truth t, (VALUES (interval '50 seconds'), (interval '70 seconds')) s(after)
 WHERE t.key = $k$2$k$;
SELECT verdict, halted FROM phasevec.truth WHERE key = $k$2$k$;

-- 3. Claims 3 and 4 verified; 3 cannot be judged: it keeps its verdict while fresh, then reads 'unproven'.
SELECT pv_o_set($k$3$k$, $v$verified$v$, $t$2026-01-01 00:02:00+00$t$);
SELECT pv_o_set($k$4$k$, $v$verified$v$, $t$2026-01-01 00:02:01+00$t$);
SELECT phasevec._truth_unjudged(t.watch, t.key, phasevec._bind(t.asserted_for, t.proof, t.asserted_by_oid,
                                t.proof_env), $w$its session did not start$w$, interval '1 hour')
  FROM phasevec.truth t WHERE t.key = $k$3$k$;
SELECT * FROM pv_o_show($k$3$k$);
-- a second attempt keeps when it began, and the time the verdict stands
UPDATE phasevec.truth SET unjudged_at = unjudged_at - interval '1 minute' WHERE key = $k$3$k$;
SELECT phasevec._truth_unjudged(t.watch, t.key, phasevec._bind(t.asserted_for, t.proof, t.asserted_by_oid,
                                t.proof_env), $w$again$w$, interval '0')
  FROM phasevec.truth t WHERE t.key = $k$3$k$;
SELECT unjudged_why, unjudged_at < tried_at AS began_before, unjudged_until > now() AS fresh
  FROM phasevec.truth WHERE key = $k$3$k$;
-- the hour is over
UPDATE phasevec.truth SET unjudged_until = now() - interval '1 second' WHERE key = $k$3$k$;
SELECT * FROM pv_o_show($k$3$k$);
-- every claim due: 3, tried last, comes after 4, whose verdict is older than its attempt
SELECT key FROM phasevec._truth_due((SELECT id FROM phasevec.watches WHERE name = $w$o1$w$), 10, interval '0',
                                    (SELECT oid FROM pg_roles WHERE rolname = current_user))
 WHERE key IN ($k$3$k$, $k$4$k$);
-- a verdict clears the marks
SELECT pv_o_set($k$3$k$, $v$refuted$v$, clock_timestamp());
SELECT * FROM pv_o_show($k$3$k$);
-- and so does an assert
SELECT phasevec._truth_unjudged(t.watch, t.key, phasevec._bind(t.asserted_for, t.proof, t.asserted_by_oid,
                                t.proof_env), $w$once more$w$, interval '0')
  FROM phasevec.truth t WHERE t.key = $k$4$k$;
SELECT phasevec.assert($w$o1$w$, $k$4$k$, $p$true$p$);
SELECT * FROM pv_o_show($k$4$k$);
-- only the owner records: _truth_unjudged is closed to PUBLIC
SELECT has_function_privilege($r$public$r$, $f$phasevec._truth_unjudged(int, text, bytea, text, interval)$f$,
                              $p$EXECUTE$p$) AS public_may;

DROP FUNCTION pv_o_set(text, text, timestamptz);
DROP FUNCTION pv_o_show(text);
DROP TABLE notes;
DROP EXTENSION pg_phasevec;
