-- 0.20.0 (seventh review): a custom placeholder (app.tenant, a custom setting no library defines) once a session has
-- it stays in it: a rollback takes back its value, not it, and current_setting('app.tenant', true) then reads '' where
-- it read NULL. The guard set every custom setting "to its default", which for a placeholder read as '': it did not tell
-- one that exists from one that does not. An author whose proof only called set_config, judged first in the same
-- verify(), decided a later author's verdict through the row-level security policy it ran under; and a verifier's
-- pooled connection that once ran SET LOCAL app.tenant recorded verdicts the persistent state refutes. Now a claim
-- records which placeholders its author's session had. (Eighth review: it is judged in a session of its own, a new
-- session of its author that has only those; a session where an earlier proof made another one is not reused.)
\set VERBOSITY terse

CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register($n$r1$n$, repeat($h$a$h$, 64), 4) > 0 AS r1;
CREATE TABLE notes (id int PRIMARY KEY, body text);
INSERT INTO notes SELECT g, $t$note $t$ || g FROM generate_series(1, 6) g;
SELECT phasevec.watch($w$notes$w$, $w$notes$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) > 0 AS watch;
CREATE TABLE invoices (id int, tenant text, overdue boolean);
INSERT INTO invoices VALUES (1, $t$acme$t$, true), (2, $t$acme$t$, false), (3, $t$zeta$t$, false);
ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON invoices
    USING (current_setting($s$app.tenant$s$, true) IS NULL OR tenant = current_setting($s$app.tenant$s$, true));
CREATE ROLE pv_ph_a;
CREATE ROLE pv_ph_b;
GRANT USAGE ON SCHEMA phasevec TO pv_ph_a, pv_ph_b;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz) TO pv_ph_a, pv_ph_b;
GRANT SELECT ON notes TO pv_ph_a, pv_ph_b;
GRANT UPDATE ON notes TO pv_ph_a, pv_ph_b;
GRANT SELECT ON invoices TO pv_ph_b;
GRANT UPDATE ON invoices TO pv_ph_b;
-- the author asserts from a session with no placeholder
\c -
SET ROLE pv_ph_a;
SELECT phasevec.assert($w$notes$w$, $k$1$k$, $p$set_config('app.tenant', 'acme', true) = 'acme'$p$);
RESET ROLE;
SET ROLE pv_ph_b;
SELECT phasevec.assert($w$notes$w$, $k$2$k$, $p$NOT EXISTS (SELECT 1 FROM public.invoices WHERE overdue)$p$);
SELECT phasevec.assert($w$notes$w$, $k$3$k$, $p$current_setting('app.tenant', true) IS NULL$p$);
RESET ROLE;
-- one that once named it, and rolled back: it has it, with no value
\c -
BEGIN;
SELECT set_config($s$app.tenant$s$, $v$x$v$, true) IS NOT NULL AS made;
ROLLBACK;
SET ROLE pv_ph_b;
SELECT phasevec.assert($w$notes$w$, $k$4$k$, $p$current_setting('app.tenant', true) = ''$p$);
RESET ROLE;
-- one that set it for the session: it has it, with a value
\c -
SET app.tenant = $v$zeta$v$;
SET ROLE pv_ph_b;
SELECT phasevec.assert($w$notes$w$, $k$5$k$, $p$NOT EXISTS (SELECT 1 FROM public.invoices WHERE overdue)$p$);
RESET ROLE;
-- what each recorded of app.*: nothing (absent), '' (present, no value), 'zeta'
SELECT key, array(SELECT e FROM unnest(proof_env) e WHERE e LIKE $l$app.%$l$) AS app
  FROM phasevec.truth ORDER BY key::int;

-- 1. A routine verify(): key 1's proof makes the placeholder in the session it runs in; 2 and 3, whose author did not
-- have it, are judged in a new one (2 refuted: the policy shows acme's overdue invoice). 4 and 5 run last, where the
-- placeholder their authors had is made (it reads '' to 4, 'zeta' to 5).
\c -
SELECT key, verdict, error FROM phasevec.verify($w$notes$w$, p_every => interval '0');
SELECT key, verdict FROM phasevec.brief($w$notes$w$) ORDER BY key::int;
-- again, from a new session: the same
\c -
SELECT key, verdict, error FROM phasevec.verify($w$notes$w$, p_every => interval '0');
SELECT key, verdict FROM phasevec.brief($w$notes$w$) ORDER BY key::int;

-- 2. A pooled verifier connection that once ran SET LOCAL app.tenant: its placeholder is its own and decides nothing
-- (the seventh cut judged there only the claims whose authors had it).
\c -
BEGIN;
SET LOCAL app.tenant = $v$zeta$v$;
COMMIT;
SELECT current_setting($s$app.tenant$s$, true) IS NULL AS absent;
SELECT key, verdict, error FROM phasevec.verify($w$notes$w$, p_every => interval '0');
SELECT phasevec.verify_one($w$notes$w$, $k$2$k$);
SELECT phasevec.verify_one($w$notes$w$, $k$5$k$);
SELECT key, verdict FROM phasevec.brief($w$notes$w$) ORDER BY key::int;
-- the persistent state, as the author reads it from a new session: one overdue invoice
\c -
SET ROLE pv_ph_b;
SELECT count(*) FILTER (WHERE overdue) AS overdue FROM invoices;
RESET ROLE;

DROP TABLE notes, invoices;
DROP EXTENSION pg_phasevec;
DROP OWNED BY pv_ph_a, pv_ph_b CASCADE;
DROP ROLE pv_ph_a, pv_ph_b;
