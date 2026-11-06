-- 0.20.0 (eighth review): a proof does not run in its verifier's session. It ran there, in a subtransaction of the
-- verifier's transaction, and four reviews in a row found one more piece of that session that decided verdicts. Now
-- each proof runs in a session of its own: a background worker connected as its author (a new session of the author:
-- its session_user, the configuration every new session of it has), with what the author's session had changed on top,
-- reading only what is committed.
-- 1. the verifier's own uncommitted writes and DDL: the proof judged them, and the verdict committed after they were
--    undone; a lock the verifier's transaction holds on what the proof reads is an error, not a wait forever.
-- 2. the verifier's session_user (SET SESSION AUTHORIZATION) and application_name decided verdicts.
-- 3. a proof that made a custom placeholder (set_config) kept every later claim of its verify() from being judged, in
--    every new session while it was asserted again between runs: it came first each time.
-- 4. after ALTER DATABASE ... SET app.x, every new session has the placeholder: no session judged the claims asserted
--    before, and they held the head of the due queue. The configuration is what a new session of the author has.
\set VERBOSITY terse

CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register($n$r1$n$, repeat($h$a$h$, 64), 4) > 0 AS r1;
CREATE TABLE notes (id int PRIMARY KEY, body text);
INSERT INTO notes SELECT g, $t$note $t$ || g FROM generate_series(1, 9) g;
SELECT phasevec.watch($w$h1$w$, $w$notes$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) > 0 AS h1;
SELECT phasevec.watch($w$m1$w$, $w$notes$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) > 0 AS m1;
SELECT phasevec.watch($w$m2$w$, $w$notes$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) > 0 AS m2;
SELECT phasevec.watch($w$m3$w$, $w$notes$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) > 0 AS m3;
CREATE TABLE invoices (id int, tenant text, overdue boolean);
INSERT INTO invoices VALUES (1, $t$acme$t$, true), (2, $t$acme$t$, false);
CREATE FUNCTION public.overdue_count() RETURNS bigint LANGUAGE sql STABLE
    AS $f$SELECT count(*) FROM public.invoices WHERE overdue$f$;
CREATE TABLE logins (id int, tenant text, overdue boolean);
INSERT INTO logins VALUES (1, $t$pv_os_a$t$, true), (2, $t$pv_os_v$t$, false);
ALTER TABLE logins ENABLE ROW LEVEL SECURITY;
CREATE POLICY by_login ON logins USING (tenant = session_user::text);
CREATE ROLE pv_os_a LOGIN;
CREATE ROLE pv_os_v LOGIN;
GRANT pv_os_a TO pv_os_v;
GRANT USAGE ON SCHEMA phasevec TO pv_os_a, pv_os_v;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz) TO pv_os_a;
GRANT EXECUTE ON FUNCTION phasevec.verify(text, integer, interval, interval, integer, double precision),
                          phasevec.verify_one(text, text, integer, double precision) TO pv_os_v;
GRANT SELECT ON notes, invoices, logins TO pv_os_a, pv_os_v;
\c -
SET ROLE pv_os_a;
SELECT phasevec.assert($w$h1$w$, $k$1$k$, $p$NOT EXISTS (SELECT 1 FROM public.invoices WHERE overdue)$p$);
SELECT phasevec.assert($w$h1$w$, $k$2$k$, $p$public.overdue_count() = 0$p$);
SELECT phasevec.assert($w$h1$w$, $k$3$k$, $p$NOT EXISTS (SELECT 1 FROM public.invoices WHERE overdue)$p$);
SELECT phasevec.assert($w$h1$w$, $k$4$k$, $p$(SELECT true FROM pg_advisory_xact_lock_shared(4242))$p$);
RESET ROLE;

-- 1. The verifier deletes the overdue invoice, verifies, and puts it back before COMMIT: the proof judges what is
-- committed (one overdue invoice), not the state no other session ever saw. (Ninth review: a transaction that has
-- written may not verify at all; the proofs could not see its writes, and judged the state they replace.)
BEGIN;
DELETE FROM invoices WHERE overdue;
SELECT key, verdict, error FROM phasevec.verify($w$h1$w$, p_every => interval '0') WHERE key = '1';
INSERT INTO invoices VALUES (1, $t$acme$t$, true);
COMMIT;
-- DDL not committed: the function the proof calls, replaced and put back in the verifier's transaction
BEGIN;
CREATE OR REPLACE FUNCTION public.overdue_count() RETURNS bigint LANGUAGE sql STABLE AS $f$SELECT 0::bigint$f$;
SELECT phasevec.verify_one($w$h1$w$, $k$2$k$);
CREATE OR REPLACE FUNCTION public.overdue_count() RETURNS bigint LANGUAGE sql STABLE
    AS $f$SELECT count(*) FROM public.invoices WHERE overdue$f$;
COMMIT;
-- what was committed: one overdue invoice, and both claims refuted
SELECT count(*) FILTER (WHERE overdue) AS overdue FROM invoices;
SELECT key, verdict FROM phasevec.verify($w$h1$w$, p_every => interval '0') WHERE key IN ('1', '2') ORDER BY key;
SELECT t.key, phasevec._verdict(t) AS verdict FROM phasevec.truth t JOIN phasevec.watches w ON w.id = t.watch
 WHERE w.name = $w$h1$w$ AND t.key IN ($k$1$k$, $k$2$k$) ORDER BY t.key;
-- a lock this transaction holds on what the proof reads (row-level security switched on, no policy: the author would
-- see nothing): the proof would wait for it as long as verify_one() waits for the proof. DDL gives the transaction an
-- id: refused before any proof runs (ninth review).
BEGIN;
ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
SELECT phasevec.verify_one($w$h1$w$, $k$3$k$);
ROLLBACK;
SELECT t.key, phasevec._verdict(t) AS verdict FROM phasevec.truth t JOIN phasevec.watches w ON w.id = t.watch
 WHERE w.name = $w$h1$w$ AND t.key = $k$3$k$;
-- a lock with no transaction id (a session's advisory lock) that the proof waits for: an error, not a wait
SELECT pg_advisory_lock(4242);
SELECT phasevec.verify_one($w$h1$w$, $k$4$k$);
SELECT pg_advisory_unlock(4242);
SELECT phasevec.verify_one($w$h1$w$, $k$4$k$);

-- 2. session_user and application_name are the author's session's, not the verifier's.
\c -
SET application_name = $a$app_a$a$;
SET SESSION AUTHORIZATION pv_os_a;
SELECT phasevec.assert($w$m1$w$, $k$1$k$, $p$NOT EXISTS (SELECT 1 FROM public.logins WHERE overdue)$p$);
SELECT phasevec.assert($w$m1$w$, $k$2$k$, $p$session_user = 'pv_os_a'$p$);
SELECT phasevec.assert($w$m1$w$, $k$3$k$, $p$current_setting('application_name') = 'app_a'$p$);
-- the author sees its one overdue login
SELECT count(*) AS overdue FROM logins WHERE overdue;
RESET SESSION AUTHORIZATION;
-- what the claim records of the author's session: what it changed (its application_name), not its identity
SELECT t.key, array(SELECT e FROM unnest(t.proof_env) e WHERE e LIKE $l$application_name=%$l$) AS app
  FROM phasevec.truth t JOIN phasevec.watches w ON w.id = t.watch WHERE w.name = $w$m1$w$ ORDER BY t.key;
\c -
SET application_name = $a$app_v$a$;
SET SESSION AUTHORIZATION pv_os_v;
SELECT phasevec.verify_one($w$m1$w$, $k$1$k$) AS login_policy,
       phasevec.verify_one($w$m1$w$, $k$2$k$) AS session_user,
       phasevec.verify_one($w$m1$w$, $k$3$k$) AS application_name;
RESET SESSION AUTHORIZATION;

-- 3. All four claims judged once; then key 1 is asserted again (a writer edited its row) with a proof that makes a
-- placeholder: never judged since, it comes first. The data behind 2-4 changes; each run, in a new session, judges them.
CREATE TABLE flags (id int PRIMARY KEY, done boolean);
INSERT INTO flags SELECT g, false FROM generate_series(1, 4) g;
GRANT SELECT ON flags TO pv_os_a;
SET ROLE pv_os_a;
SELECT phasevec.assert($w$m2$w$, $k$1$k$, $p$true$p$);
SELECT phasevec.assert($w$m2$w$, k::text, format($p$NOT EXISTS (SELECT 1 FROM public.flags WHERE id = %s AND done)$p$, k))
  FROM generate_series(2, 4) k;
RESET ROLE;
SELECT key, verdict, error FROM phasevec.verify($w$m2$w$, p_every => interval '0');
UPDATE flags SET done = true WHERE id BETWEEN 2 AND 4;
UPDATE notes SET body = body || $t$ (edited)$t$ WHERE id = 1;
SET ROLE pv_os_a;
SELECT phasevec.assert($w$m2$w$, $k$1$k$, $p$set_config('app.trace', 'on', true) IS NOT NULL$p$);
RESET ROLE;
\c -
SELECT key, verdict, error FROM phasevec.verify($w$m2$w$, p_every => interval '0');
-- asserted again before the next run (by a writer's session that never verified), which is in a new session too
\c -
UPDATE notes SET body = body || $t$ (edited)$t$ WHERE id = 1;
SET ROLE pv_os_a;
SELECT phasevec.assert($w$m2$w$, $k$1$k$, $p$set_config('app.trace', 'on', true) IS NOT NULL $p$);
RESET ROLE;
\c -
SELECT key, verdict, error FROM phasevec.verify($w$m2$w$, p_every => interval '0');

-- 4. Claims asserted before a database-level custom setting: judged, in the configuration a new session of their author
-- has now (the setting is there, as it is in every session of the author from now on).
SET ROLE pv_os_a;
SELECT phasevec.assert($w$m3$w$, k::text, $p$true$p$) FROM generate_series(2, 4) k;
SELECT phasevec.assert($w$m3$w$, $k$5$k$, $p$current_setting('app.modo', true) = 'normal'$p$);
RESET ROLE;
SELECT current_database() AS db \gset
ALTER DATABASE :"db" SET app.modo = 'normal';
\c -
SELECT current_setting($s$app.modo$s$, true) AS modo;
SELECT key, verdict, error FROM phasevec.verify($w$m3$w$, p_every => interval '0');
-- a claim asserted after it, and p_n 1: nothing holds the head of the queue
SET ROLE pv_os_a;
SELECT phasevec.assert($w$m3$w$, $k$6$k$, $p$true$p$);
RESET ROLE;
-- a claim records what its author's session changed, not what the configuration gave it: no app.modo
SELECT t.key, array(SELECT e FROM unnest(t.proof_env) e WHERE e LIKE $l$app.%$l$) AS app
  FROM phasevec.truth t JOIN phasevec.watches w ON w.id = t.watch WHERE w.name = $w$m3$w$ AND t.key = $k$6$k$;
\c -
SELECT key, verdict, error FROM phasevec.verify($w$m3$w$, 1, interval '1 hour');
ALTER DATABASE :"db" RESET app.modo;

DROP TABLE notes, invoices, logins, flags;
DROP FUNCTION public.overdue_count();
DROP EXTENSION pg_phasevec;
DROP OWNED BY pv_os_a, pv_os_v CASCADE;
DROP ROLE pv_os_a, pv_os_v;
