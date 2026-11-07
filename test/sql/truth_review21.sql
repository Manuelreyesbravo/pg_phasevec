-- 0.20.0 (twenty-first review). RT21M-1: the update retired the claims refute() refuted under 0.19.0 against the
-- text 0.19.0 noted (rendered in its writer's settings), then noted every row again in the pinned settings; with a
-- recipe that prints a timestamptz (this suite's TimeZone is PST8PDT, the pinned one UTC) every retired claim read
-- 'unproven' and brief() served it. Now they are bound to the text as the update renders it. And watch_truncate():
-- what a role other than the owner needs to be granted to make a watch's TRUNCATE trigger.
\set VERBOSITY terse

CREATE EXTENSION pg_phasevec VERSION $v$0.19.0$v$;
SELECT phasevec.reader_register($n$r1$n$, repeat($h$a$h$, 64), 4) > 0 AS r1;
CREATE TABLE r21_mem (id int PRIMARY KEY, body text, at timestamptz);
INSERT INTO r21_mem VALUES (1, $t$old memory$t$, $d$2026-11-01 13:00:00+00$d$),
                           (2, $t$current memory$t$, $d$2026-11-01 13:00:00+00$d$),
                           (3, $t$another$t$, $d$2026-11-01 13:00:00+00$d$),
                           (4, $t$replaced$t$, $d$2026-11-01 13:00:00+00$d$),
                           (5, $t$its replacement$t$, $d$2026-11-01 13:00:00+00$d$);
SELECT phasevec.watch($w$r21_mem$w$, $w$r21_mem$w$::regclass, $k$id$k$, $r$r.body || ' @ ' || r.at$r$, $n$r1$n$) > 0 AS watch;
SELECT phasevec.assert($w$r21_mem$w$, $k$1$k$, $p$SELECT true$p$);
SELECT phasevec.assert($w$r21_mem$w$, $k$2$k$, $p$SELECT true$p$);
SELECT phasevec.refute($w$r21_mem$w$, $k$1$k$, $m$deleted$m$);
SELECT phasevec.refute($w$r21_mem$w$, $k$3$k$, $m$deleted$m$);
SELECT phasevec.refute($w$r21_mem$w$, $k$4$k$, $m$deleted$m$);
SELECT phasevec.supersede($w$r21_mem$w$, $k$4$k$, $k$5$k$, $m$newer$m$);
CREATE TEMP TABLE r21_noted AS SELECT s.key, s.text_hash FROM phasevec.sources s;

-- the update's own lock_timeout (1 ms where it reads a watch) ends with it, in the caller's transaction too
BEGIN;
SET LOCAL lock_timeout = $t$7s$t$;
ALTER EXTENSION pg_phasevec UPDATE TO $v$0.20.0$v$;
SHOW lock_timeout;
COMMIT;
SHOW lock_timeout;

-- the update's helpers are gone with it
SELECT count(*) AS helpers FROM pg_proc WHERE proname = $f$_update_step$f$;
-- 0.19.0 noted each text in this session's settings, the update in the pinned ones: every row is noted again
SELECT count(*) AS noted_again FROM phasevec.sources s JOIN r21_noted n ON n.key = s.key WHERE n.text_hash <> s.text_hash;
-- what refute() retired stays retired, and refuted; the rest as before
SELECT t.key, t.verdict, phasevec._verdict(t) AS served, t.retired_at IS NOT NULL AS retired
  FROM phasevec.truth t ORDER BY t.key;
SELECT key, verdict FROM phasevec.brief($w$r21_mem$w$) ORDER BY key;
SELECT verdict, n FROM phasevec.truth_coverage($w$r21_mem$w$) ORDER BY verdict;
-- the replaced claim retired behind its replacement reads refuted when it comes back
SELECT phasevec.unsupersede($w$r21_mem$w$, $k$4$k$);
SELECT t.key, phasevec._verdict(t) AS served FROM phasevec.truth t WHERE t.key = $k$4$k$;

-- watch_truncate(): its owner, or a role granted it, EXECUTE on _truncate_trigger() and SELECT (id, name, source) on
-- phasevec.watches; the caller must also own the table
CREATE ROLE pv_r21_owner;
GRANT USAGE ON SCHEMA phasevec TO pv_r21_owner;
CREATE TABLE r21_t (id int PRIMARY KEY, body text);
ALTER TABLE r21_t OWNER TO pv_r21_owner;
SELECT phasevec.watch($w$r21_t$w$, $w$r21_t$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) > 0 AS watch;
DO $x$
BEGIN
    EXECUTE format($q$DROP TRIGGER %I ON r21_t$q$,
                   (SELECT $q$phasevec_watch_$q$ || w.id || $q$_truncate$q$ FROM phasevec.watches w WHERE w.name = $q$r21_t$q$));
END
$x$;
GRANT EXECUTE ON FUNCTION phasevec.watch_truncate(text) TO pv_r21_owner;
SET ROLE pv_r21_owner;
SELECT phasevec.watch_truncate($w$r21_t$w$);
RESET ROLE;
GRANT EXECUTE ON FUNCTION phasevec._truncate_trigger(int, boolean) TO pv_r21_owner;
GRANT SELECT (id, name, source) ON phasevec.watches TO pv_r21_owner;
SET ROLE pv_r21_owner;
SELECT phasevec.watch_truncate($w$r21_t$w$) AS made;
SELECT phasevec.watch_truncate($w$r21_t$w$) AS made_again;
RESET ROLE;
CREATE ROLE pv_r21_other;
GRANT pv_r21_owner TO pv_r21_other WITH INHERIT FALSE;
GRANT USAGE ON SCHEMA phasevec TO pv_r21_other;
GRANT EXECUTE ON FUNCTION phasevec.watch_truncate(text), phasevec._truncate_trigger(int, boolean) TO pv_r21_other;
GRANT SELECT (id, name, source) ON phasevec.watches TO pv_r21_other;
SET ROLE pv_r21_other;
SELECT phasevec.watch_truncate($w$r21_t$w$);
RESET ROLE;

DROP TABLE r21_mem, r21_t;
DROP EXTENSION pg_phasevec;
DROP OWNED BY pv_r21_owner, pv_r21_other;
DROP ROLE pv_r21_other;
DROP ROLE pv_r21_owner;
