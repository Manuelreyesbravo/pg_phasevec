-- 0.20.0 (seventeenth review): a key names a row byte for byte, whatever the key column's collation. In the sixteenth
-- cut a key column with a nondeterministic (case-insensitive) collation, and a unique index declared COLLATE "C", held
-- 'alice' and 'ALICE' as two rows; a reader that row-level security showed only 'alice' had _render() show it 'ALICE'
-- too, with its text, and _verdict() served the hidden row's verdict (an oracle on its text). Needs ICU: a build
-- without it has no nondeterministic collation (truth_collation_1.out).
\set VERBOSITY terse
SELECT setting !~ '--without-icu' AS icu FROM pg_config WHERE name = 'CONFIGURE' \gset
\if :icu
CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register($n$r1$n$, repeat($h$a$h$, 64), 4) > 0 AS r1;
CREATE COLLATION pv17_ci (provider = icu, locale = 'und-u-ks-level2', deterministic = false);
CREATE ROLE pv17c_a;
CREATE ROLE pv17c_b;
GRANT USAGE ON SCHEMA phasevec TO pv17c_a;
CREATE TABLE notesc (k text COLLATE pv17_ci NOT NULL, tenant name NOT NULL, body text);
CREATE UNIQUE INDEX notesc_k ON notesc (k COLLATE "C");
INSERT INTO notesc VALUES ($k$alice$k$, $t$pv17c_a$t$, $b$public note$b$), ($k$ALICE$k$, $t$pv17c_b$t$, $b$salary is 91000$b$),
                          ($k$carol$k$, $t$pv17c_b$t$, $b$hidden too$b$);
ALTER TABLE notesc ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON notesc FOR SELECT USING (tenant = current_user);
GRANT SELECT ON notesc TO pv17c_a, pv17c_b;
GRANT EXECUTE ON FUNCTION phasevec.brief(text, int) TO pv17c_a;
SELECT phasevec.watch($w$wc$w$, $t$notesc$t$::regclass, $k$k$k$, $r$r.body$r$, $n$r1$n$) > 0 AS watch;
SELECT id AS wc_id FROM phasevec.watches WHERE name = $w$wc$w$ \gset
SELECT phasevec.refute($w$wc$w$, $k$ALICE$k$, $r$x$r$);
SELECT phasevec.refute($w$wc$w$, $k$carol$k$, $r$x$r$);
-- a claim names one row: 'alice' is not 'ALICE', and 'Alice' is no row
SELECT phasevec.assert($w$wc$w$, $k$alice$k$, $p$true$p$);
SELECT phasevec.assert($w$wc$w$, $k$Alice$k$, $p$true$p$);
SELECT key, verdict FROM phasevec.verify($w$wc$w$, 10, $e$0$e$) ORDER BY key COLLATE "C";
SET ROLE pv17c_a;
SELECT k, body FROM notesc;
SELECT key, body FROM phasevec._render($w$wc$w$, NULL) ORDER BY key COLLATE "C";
SELECT key, body FROM phasevec._render($w$wc$w$, ARRAY[$k$ALICE$k$]) ORDER BY key COLLATE "C";
-- a forged row is no oracle: the hidden key's verdict is not shown, whatever text is guessed
SELECT g.key, g.guess, phasevec._verdict(ROW(:wc_id, g.key, NULL, NULL, NULL, NULL, NULL, NULL, 'refuted', NULL, NULL,
           now(), NULL, NULL, sha256(convert_to(g.guess, 'UTF8')), NULL, NULL, false, NULL, NULL, NULL, NULL)::phasevec.truth)
  FROM (VALUES ($k$ALICE$k$, $g$salary is 90000$g$), ($k$ALICE$k$, $g$salary is 91000$g$), ($k$carol$k$, $g$hidden too$g$)) g(key, guess);
RESET ROLE;
GRANT SELECT ON phasevec.truth TO pv17c_a;
SET ROLE pv17c_a;
SELECT key, phasevec._verdict(t) FROM phasevec.truth t ORDER BY key COLLATE "C";
SELECT key, verdict FROM phasevec.brief($w$wc$w$, 1000) ORDER BY key COLLATE "C";
RESET ROLE;
DROP TABLE notesc;
DROP EXTENSION pg_phasevec;
DROP COLLATION pv17_ci;
DROP OWNED BY pv17c_a, pv17c_b;
DROP ROLE pv17c_a;
DROP ROLE pv17c_b;
\else
\echo 'no ICU in this build: no nondeterministic collation'
\endif
