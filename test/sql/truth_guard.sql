-- 0.20.0: everything phasevec runs that is not its own (a watch's recipe, a proof) goes through one guard
-- (src/phasevec_guard.c). Each block is an attack an adversarial review ran against the second cut of 0.20.0
-- (e39829f, never released); there each one worked.
\set VERBOSITY terse

CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register($n$r1$n$, repeat($h$a$h$, 64), 4) > 0 AS r1;
CREATE TABLE notes (id int PRIMARY KEY, body text);
INSERT INTO notes SELECT g, $t$note $t$ || g FROM generate_series(1, 8) g;
SELECT phasevec.watch($w$notes$w$, $w$notes$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) > 0 AS watch;
CREATE ROLE pv_g_author;
GRANT USAGE ON SCHEMA phasevec TO pv_g_author;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz) TO pv_g_author;
GRANT SELECT ON notes TO pv_g_author;

-- (1) brief() ran the recipe as its caller, with full rights: the table's owner swapped a column's type for one
-- whose cast to text is its own code, and a superuser reading the brief made the owner superuser. The recipe runs
-- as the table's owner now, read-only, everywhere.
CREATE ROLE pv_g_bob;
GRANT CREATE ON SCHEMA public TO pv_g_bob;
SET ROLE pv_g_bob;
CREATE TABLE bobdocs (id int PRIMARY KEY, body text);
INSERT INTO bobdocs VALUES (1, $t$hello$t$);
GRANT SELECT ON bobdocs TO PUBLIC;
RESET ROLE;
SELECT phasevec.watch($w$bobdocs$w$, $w$bobdocs$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) > 0 AS watch;
SELECT phasevec.assert($w$bobdocs$w$, $k$1$k$, $p$true$p$);
SELECT key, verdict FROM phasevec.verify($w$bobdocs$w$, p_every => interval $i$0$i$);
SET ROLE pv_g_bob;
CREATE TYPE public.pv_g_btext AS (v text);
CREATE FUNCTION public.pv_g_btext_out(b public.pv_g_btext) RETURNS text LANGUAGE plpgsql VOLATILE AS $f$
BEGIN
    RAISE NOTICE 'the cast runs as %', current_user;
    IF (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user) THEN
        EXECUTE 'ALTER ROLE pv_g_bob SUPERUSER';
    END IF;
    RETURN b.v;
END $f$;
CREATE CAST (public.pv_g_btext AS text) WITH FUNCTION public.pv_g_btext_out(public.pv_g_btext);
ALTER TABLE bobdocs DISABLE TRIGGER USER;
ALTER TABLE bobdocs ALTER COLUMN body TYPE public.pv_g_btext USING ROW(body)::public.pv_g_btext;
ALTER TABLE bobdocs ENABLE TRIGGER USER;
RESET ROLE;
SELECT key, verdict, line FROM phasevec.brief($w$bobdocs$w$);
SELECT rolsuper AS bob_became_superuser FROM pg_roles WHERE rolname = $r$pv_g_bob$r$;
-- the owner's code that writes cannot do it from a recipe, for anyone
SET ROLE pv_g_bob;
CREATE OR REPLACE FUNCTION public.pv_g_btext_out(b public.pv_g_btext) RETURNS text LANGUAGE plpgsql VOLATILE AS $f$
BEGIN CREATE TABLE public.pv_g_planted (x int); RETURN b.v; END $f$;
RESET ROLE;
SELECT key, line FROM phasevec.brief($w$bobdocs$w$);
SELECT to_regclass($r$public.pv_g_planted$r$) IS NULL AS nothing_planted;

-- (2) a proof released the verifier session's own advisory locks, reseeded its random(), or signalled its backend:
-- none of it is undone by a rollback. A guarded proof cannot call those functions.
SET ROLE pv_g_author;
SELECT phasevec.assert($w$notes$w$, $k$5$k$, $p$pg_advisory_unlock(777)$p$);
SELECT phasevec.assert($w$notes$w$, $k$6$k$, $p$pg_advisory_unlock_all() IS NULL$p$);
SELECT phasevec.assert($w$notes$w$, $k$7$k$, $p$setseed(0.42) IS NULL$p$);
SELECT phasevec.assert($w$notes$w$, $k$8$k$, $p$pg_cancel_backend(pg_backend_pid())$p$);
RESET ROLE;
SELECT setseed(0.9);
SELECT random() AS after_seed \gset
SELECT pg_advisory_lock(777), pg_advisory_lock(888);
SELECT setseed(0.9);
SELECT key, verdict, error FROM phasevec.verify($w$notes$w$, 100, interval $i$0$i$, interval $i$1 hour$i$, 1000, 1e6)
 WHERE key IN ($k$5$k$, $k$6$k$, $k$7$k$, $k$8$k$) ORDER BY key;
SELECT random() = :after_seed AS seed_kept;
SELECT objid FROM pg_locks WHERE locktype = $l$advisory$l$ AND pid = pg_backend_pid() ORDER BY objid;
SELECT pg_advisory_unlock_all();
-- the guard ends with the proof: the verifier itself calls them as before
SELECT pg_advisory_lock(999), pg_advisory_unlock(999) AS unlocked;

-- (3) a row's text and a proof's meaning depended on the session's settings. A writer in another TimeZone edited
-- a row so that it printed as the asserted text, and brief() served it 'verified'; a verifier in another DateStyle
-- read the author's '01/11/2026' as 11 January and recorded 'verified' for a date the proof, as its author wrote it,
-- refutes. A recipe renders in pinned settings (TimeZone UTC, DateStyle ISO, ...); a proof runs in its author's.
CREATE ROLE pv_g_writer;
GRANT USAGE ON SCHEMA phasevec TO pv_g_writer;
-- what the second cut's watch trigger needed of a writer (it called _note() as the writer)
DO $d$ BEGIN
    IF to_regprocedure($f$phasevec._note(int, text, bytea, text)$f$) IS NOT NULL THEN
        GRANT EXECUTE ON FUNCTION phasevec._note(int, text, bytea, text) TO pv_g_writer;
    END IF;
END $d$;
CREATE TABLE events (id int PRIMARY KEY, title text, due timestamptz);
GRANT SELECT ON events TO pv_g_author;
GRANT SELECT, UPDATE ON events TO pv_g_writer;
SET TimeZone = $z$America/Santiago$z$;
INSERT INTO events VALUES (1, $t$release freeze starts$t$, $d$2026-11-20 10:00-03$d$);
SELECT phasevec.watch($w$ev$w$, $w$events$w$::regclass, $k$id$k$,
                      $r$r.title || ' at ' || to_char(r.due, 'YYYY-MM-DD HH24:MI')$r$, $n$r1$n$) > 0 AS watch;
SET ROLE pv_g_author;
SELECT phasevec.assert($w$ev$w$, $k$1$k$, $p$(SELECT due >= '2026-11-20 09:00-03' FROM public.events WHERE id = 1)$p$);
RESET ROLE;
SELECT key, verdict FROM phasevec.verify($w$ev$w$, p_every => interval $i$0$i$);
SELECT key, verdict, line FROM phasevec.brief($w$ev$w$);
SET ROLE pv_g_writer;
SET TimeZone = $z$UTC$z$;
UPDATE events SET due = $d$2026-11-20 10:00+00$d$ WHERE id = 1;
RESET ROLE;
SELECT key, verdict, line FROM phasevec.brief($w$ev$w$);
SET TimeZone = $z$America/Santiago$z$;
SELECT key, verdict, line FROM phasevec.brief($w$ev$w$);
SELECT key, verdict, error FROM phasevec.verify($w$ev$w$, p_every => interval $i$0$i$);
RESET TimeZone;

CREATE TABLE deadlines (id int PRIMARY KEY, what text, due date);
GRANT SELECT ON deadlines TO pv_g_author;
GRANT SELECT, UPDATE ON deadlines TO pv_g_writer;
INSERT INTO deadlines VALUES (1, $t$patch deadline$t$, $d$2026-11-05$d$);
SELECT phasevec.watch($w$dl$w$, $w$deadlines$w$::regclass, $k$id$k$, $r$r.what$r$, $n$r1$n$) > 0 AS watch;
SET ROLE pv_g_author;
SET DateStyle = $s$SQL, DMY$s$;
-- the deadline is not before 1 November (in the author's day/month order)
SELECT phasevec.assert($w$dl$w$, $k$1$k$, $p$(SELECT due >= '01/11/2026' FROM public.deadlines WHERE id = 1)$p$);
RESET DateStyle;
RESET ROLE;
SELECT key, x FROM phasevec.truth t, unnest(t.proof_env) x
 WHERE t.watch = (SELECT id FROM phasevec.watches WHERE name = $w$dl$w$) AND x LIKE $l$DateStyle=%$l$;
SET DateStyle = $s$SQL, MDY$s$;
SELECT key, verdict FROM phasevec.verify($w$dl$w$, p_every => interval $i$0$i$);
SET ROLE pv_g_writer;
UPDATE deadlines SET due = $d$2026-05-11$d$ WHERE id = 1;   -- 11 May
RESET ROLE;
SELECT key, verdict FROM phasevec.verify($w$dl$w$, p_every => interval $i$0$i$);
RESET DateStyle;

-- (4) adopt() made its caller (the superuser owner) the author of any orphaned proof, unseen; a role could orphan
-- its own proof on purpose to have it adopted; and adopt() could not be granted nor run after SET ROLE. It names
-- the author now, needs that author's privileges, returns every proof, and makes a superuser the author of a key
-- only when that key is named.
CREATE ROLE pv_g_throwaway;
GRANT USAGE ON SCHEMA phasevec TO pv_g_throwaway;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz) TO pv_g_throwaway;
GRANT SELECT ON notes TO pv_g_throwaway;
SET ROLE pv_g_throwaway;
SELECT phasevec.assert($w$notes$w$, $k$4$k$, $p$(SELECT count(*) FROM pg_catalog.pg_authid) > 0$p$);
RESET ROLE;
ALTER ROLE pv_g_throwaway RENAME TO pv_g_throwaway2;
SELECT phasevec.adopt($w$notes$w$);
SELECT key, proof, former_author, adopted, note FROM phasevec.adopt($w$notes$w$, current_user::regrole);
SELECT key, asserted_by IS NULL OR asserted_by <> current_user AS not_the_superusers FROM phasevec.truth
 WHERE key = $k$4$k$ AND watch = (SELECT id FROM phasevec.watches WHERE name = $w$notes$w$);
CREATE ROLE pv_g_ops;
GRANT USAGE ON SCHEMA phasevec TO pv_g_ops;
GRANT SELECT ON notes TO pv_g_ops;
GRANT EXECUTE ON FUNCTION phasevec.adopt(text, regrole, text[], text[]) TO pv_g_ops;
SET ROLE pv_g_ops;
SELECT key FROM phasevec.adopt($w$notes$w$, $r$pv_g_author$r$);
SELECT key, proof, former_author, adopted, note FROM phasevec.adopt($w$notes$w$, $r$pv_g_ops$r$, ARRAY[$k$4$k$]);
RESET ROLE;
SELECT key, verdict, error FROM phasevec.verify($w$notes$w$, p_every => interval $i$0$i$) WHERE key = $k$4$k$;

-- (5) _note() checked only that its caller wrote the watched table at all: a writer limited by row-level security,
-- or holding UPDATE on one column, forged, invented and forgot the keys of every row. It is gone; the watch trigger
-- renders the row it fires for, and belongs to its watch's table only.
CREATE TABLE tnotes (id int PRIMARY KEY, tenant name, body text, tags text);
INSERT INTO tnotes VALUES (1, $t$pv_g_tenant_a$t$, $t$a row of a$t$, $t$$t$), (2, $t$pv_g_tenant_b$t$, $t$b says this$t$, $t$$t$);
SELECT phasevec.watch($w$tnotes$w$, $w$tnotes$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) AS tid \gset
ALTER TABLE tnotes ENABLE ROW LEVEL SECURITY;
CREATE POLICY own ON tnotes USING (tenant = current_user) WITH CHECK (tenant = current_user);
CREATE ROLE pv_g_tenant_a;
GRANT USAGE ON SCHEMA phasevec TO pv_g_tenant_a;
GRANT SELECT, INSERT, UPDATE, DELETE ON tnotes TO pv_g_tenant_a;
GRANT CREATE ON SCHEMA public TO pv_g_tenant_a;
CREATE ROLE pv_g_tagger;
GRANT USAGE ON SCHEMA phasevec TO pv_g_tagger;
GRANT UPDATE (tags) ON tnotes TO pv_g_tagger;
-- as the second cut's watch trigger needed (it called _note() as the writer)
DO $d$ BEGIN
    IF to_regprocedure($f$phasevec._note(int, text, bytea, text)$f$) IS NOT NULL THEN
        GRANT EXECUTE ON FUNCTION phasevec._note(int, text, bytea, text) TO pv_g_tenant_a, pv_g_tagger;
    END IF;
END $d$;
SET ROLE pv_g_tenant_a;
UPDATE tnotes SET body = $t$b is wrong$t$ WHERE id = 2;
CREATE TABLE a_scratch (x int);
SELECT format($f$CREATE FUNCTION a_forge() RETURNS trigger LANGUAGE plpgsql AS $b$ BEGIN
    PERFORM phasevec._note(%s, '2', sha256('forged'::bytea), 'forged');
    PERFORM phasevec._note(%s, '777', sha256('invented'::bytea), 'invented');
    RETURN NULL; END $b$$f$, :tid, :tid) \gexec
CREATE TRIGGER a_forge AFTER INSERT ON a_scratch FOR EACH ROW EXECUTE FUNCTION a_forge();
INSERT INTO a_scratch VALUES (1);
DROP TRIGGER a_forge ON a_scratch;
SELECT format($f$CREATE TRIGGER a_observe AFTER INSERT ON a_scratch FOR EACH ROW EXECUTE FUNCTION phasevec._observe(%L)$f$, :tid) \gexec
INSERT INTO a_scratch VALUES (2);
UPDATE tnotes SET body = $t$a row of a, edited$t$ WHERE id = 1;
RESET ROLE;
SET ROLE pv_g_tagger;
CREATE TEMP TABLE t_scratch (x int);
SELECT format($f$CREATE FUNCTION pg_temp.t_forget() RETURNS trigger LANGUAGE plpgsql AS $b$ BEGIN
    PERFORM phasevec._note(%s, '1', NULL, NULL); RETURN NULL; END $b$$f$, :tid) \gexec
CREATE TRIGGER t_forget AFTER INSERT ON t_scratch FOR EACH ROW EXECUTE FUNCTION pg_temp.t_forget();
INSERT INTO t_scratch VALUES (1);
RESET ROLE;
SELECT s.key, s.text_hash = sha256(convert_to(t.body, $u$UTF8$u$)) AS the_rows_text
  FROM phasevec.sources s LEFT JOIN tnotes t ON t.id::text = s.key
 WHERE s.watch = :tid ORDER BY s.key;
-- the trigger fires on a partition of a watched partitioned table: that is its watch's table too
CREATE TABLE parted (id int PRIMARY KEY, body text) PARTITION BY RANGE (id);
CREATE TABLE parted_low PARTITION OF parted FOR VALUES FROM (0) TO (100);
SELECT phasevec.watch($w$parted$w$, $w$parted$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) AS pid \gset
INSERT INTO parted VALUES (1, $t$in a partition$t$);
UPDATE parted SET id = 2 WHERE id = 1;
SELECT key FROM phasevec.sources WHERE watch = :pid;

-- (6) recall(), disputes(), replacement() and truth_coverage() gave any role with USAGE on the schema the keys,
-- verdicts, topics and reasons of every watch. A watch is shown only to a role that may SELECT its table; with
-- row-level security, only the keys of the rows it sees (and no count over all of them).
SELECT phasevec.assert($w$notes$w$, $k$1$k$, NULL, $t$colour$t$);
SELECT phasevec.assert($w$notes$w$, $k$2$k$, NULL, $t$colour$t$);
SELECT phasevec.supersede($w$notes$w$, $k$3$k$, $k$2$k$, $t$newer$t$);
CREATE ROLE pv_g_nobody;
GRANT USAGE ON SCHEMA phasevec TO pv_g_nobody;
SET ROLE pv_g_nobody;
SELECT count(*) AS recall FROM phasevec.recall($w$notes$w$, $q$any question$q$);
SELECT * FROM phasevec.disputes($w$notes$w$);
SELECT * FROM phasevec.replacement($w$notes$w$, $k$3$k$);
SELECT * FROM phasevec.truth_coverage($w$notes$w$);
RESET ROLE;
GRANT SELECT ON notes TO pv_g_nobody;
SET ROLE pv_g_nobody;
SELECT * FROM phasevec.disputes($w$notes$w$);
SELECT * FROM phasevec.replacement($w$notes$w$, $k$3$k$);
SELECT * FROM phasevec.truth_coverage($w$notes$w$);
RESET ROLE;
SELECT phasevec.supersede($w$tnotes$w$, $k$2$k$, $k$1$k$, $t$merged$t$);
GRANT EXECUTE ON FUNCTION phasevec.brief(text, int) TO pv_g_tenant_a;
SET ROLE pv_g_tenant_a;
SELECT * FROM phasevec.replacement($w$tnotes$w$, $k$2$k$);
SELECT * FROM phasevec.replacement($w$tnotes$w$, $k$1$k$);
SELECT * FROM phasevec.disputes($w$tnotes$w$);
SELECT * FROM phasevec.truth_coverage($w$tnotes$w$);
SELECT key, line FROM phasevec.brief($w$tnotes$w$);
RESET ROLE;

-- (7) a proof set transaction_timeout and ended the verifier's connection with a FATAL before any verdict was
-- written: every later verify() of the watch died the same way, and the other keys were never judged. A guarded
-- proof cannot change the session's timeouts, by set_config(), SET, or a function's SET clause.
CREATE FUNCTION pv_g_armed() RETURNS boolean LANGUAGE sql SET transaction_timeout = 50 AS $f$ SELECT pg_sleep(0.3) IS NOT NULL $f$;
CREATE FUNCTION pv_g_set() RETURNS boolean LANGUAGE plpgsql AS $f$ BEGIN SET LOCAL idle_session_timeout = 50; RETURN true; END $f$;
GRANT EXECUTE ON FUNCTION pv_g_armed(), pv_g_set() TO pv_g_author;
SET ROLE pv_g_author;
SELECT phasevec.assert($w$notes$w$, $k$5$k$, $p$set_config('transaction_timeout', '50', true) IS NOT NULL AND pg_sleep(0.3) IS NOT NULL$p$);
SELECT phasevec.assert($w$notes$w$, $k$6$k$, $p$public.pv_g_armed()$p$);
SELECT phasevec.assert($w$notes$w$, $k$7$k$, $p$public.pv_g_set()$p$);
SELECT phasevec.assert($w$notes$w$, $k$8$k$, $p$true$p$);
RESET ROLE;
SELECT key, verdict, error FROM phasevec.verify($w$notes$w$, 100, interval $i$0$i$, interval $i$1 hour$i$, 1000, 1e6)
 WHERE key IN ($k$5$k$, $k$6$k$, $k$7$k$, $k$8$k$) ORDER BY key;
SELECT key, verdict, error FROM phasevec.verify($w$notes$w$, 100, interval $i$0$i$, interval $i$1 hour$i$, 1000, 1e6)
 WHERE key IN ($k$5$k$, $k$6$k$, $k$7$k$, $k$8$k$) ORDER BY key;
SELECT current_setting($s$transaction_timeout$s$) AS transaction_timeout, current_setting($s$idle_session_timeout$s$) AS idle_session_timeout;

DROP TABLE notes, bobdocs, events, deadlines, tnotes, a_scratch, parted;
DROP FUNCTION pv_g_armed(), pv_g_set();
DROP EXTENSION pg_phasevec;
DROP OWNED BY pv_g_author, pv_g_bob, pv_g_writer, pv_g_throwaway2, pv_g_ops, pv_g_tenant_a, pv_g_tagger, pv_g_nobody CASCADE;
DROP ROLE pv_g_author, pv_g_bob, pv_g_writer, pv_g_throwaway2, pv_g_ops, pv_g_tenant_a, pv_g_tagger, pv_g_nobody;
