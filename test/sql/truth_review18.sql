-- 0.20.0 (eighteenth review): a retired claim stays retired on every path (the update from 0.19.0, refute() of a
-- replaced claim, supersede() and unsupersede() around a retired one); a key names at most one row of everything
-- phasevec reads (a plain table outside any inheritance tree, by an immediate unique btree index), checked by watch()
-- and again by every read.
\set VERBOSITY terse

-- (a) R18-VI-1, PRIV-3, CLD-1. Claims refuted under 0.19.0, by refute() and by their proofs, through the update and
-- adopt(). In the seventeenth cut key 1 (refute(): "deleted by its owner", its proof still true) was adopted and
-- served 'verified'.
CREATE EXTENSION pg_phasevec VERSION $v$0.19.0$v$;
SELECT phasevec.reader_register($n$r1$n$, repeat($h$a$h$, 64), 4) > 0 AS r1;
CREATE TABLE mem18 (id int PRIMARY KEY, body text);
INSERT INTO mem18 SELECT g, $t$memory $t$ || g FROM generate_series(1, 9) g;
SELECT phasevec.watch($w$mem18$w$, $w$mem18$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) > 0 AS watch;
SELECT phasevec.assert($w$mem18$w$, k::text, p) FROM (VALUES (1, $p$SELECT true$p$), (2, $p$SELECT true$p$),
       (3, $p$SELECT false$p$), (4, $p$SELECT 1/0 = 1$p$), (5, $p$SELECT true$p$), (8, $p$SELECT true$p$)) v(k, p);
SELECT phasevec.assert($w$mem18$w$, $k$7$k$, NULL);
SELECT key, verdict FROM phasevec.verify($w$mem18$w$) ORDER BY key;
SELECT phasevec.refute($w$mem18$w$, $k$1$k$, $r$deleted by its owner$r$);
SELECT phasevec.refute($w$mem18$w$, $k$5$k$, $r$deleted by its owner$r$);
SELECT phasevec.supersede($w$mem18$w$, $k$5$k$, $k$6$k$, $r$a newer one$r$);
SELECT phasevec.refute($w$mem18$w$, $k$9$k$, $r$never asserted$r$);
ALTER EXTENSION pg_phasevec UPDATE TO $v$0.20.0$v$;
-- 1, 5 (behind its replacement) and 9 are retired; 3 (its proof's false) and 4 (its proof's error) keep their proofs
SELECT key, verdict, phasevec._claim_state(t) AS state, phasevec._verdict(t) FROM phasevec.truth t ORDER BY key;
CREATE ROLE pv18_au;
GRANT USAGE ON SCHEMA phasevec TO pv18_au;
GRANT SELECT ON mem18 TO pv18_au;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz),
                          phasevec.adopt(text, regrole, text[], text[]) TO pv18_au;
SET ROLE pv18_au;
SELECT key, adopted FROM phasevec.adopt($w$mem18$w$, $r$pv18_au$r$) ORDER BY key;
RESET ROLE;
SELECT key, verdict FROM phasevec.verify($w$mem18$w$, p_every => interval $i$0$i$) ORDER BY key;
SELECT key, phasevec._verdict(t) FROM phasevec.truth t ORDER BY key;
SELECT phasevec.unsupersede($w$mem18$w$, $k$5$k$);
SELECT key, phasevec._verdict(t), phasevec._claim_state(t) AS state FROM phasevec.truth t WHERE key = $k$5$k$;
GRANT EXECUTE ON FUNCTION phasevec.brief(text, int) TO pv18_au;
SET ROLE pv18_au;
SELECT key, verdict FROM phasevec.brief($w$mem18$w$, 100000) ORDER BY key;
RESET ROLE;

-- (b) MIND18-1. refute() of a claim with no text recorded (asserted before 0.20.0, never adopted; or with no proof)
-- reads 'refuted': it is about the row's text when it was refuted. In the seventeenth cut they read 'unproven', and
-- yggdrasil served every memory deleted after the update.
UPDATE phasevec.truth SET asserted_for = NULL, asserted_by_oid = NULL WHERE key = $k$8$k$;
SELECT phasevec.refute($w$mem18$w$, $k$7$k$, $r$deleted after the update$r$);
SELECT phasevec.refute($w$mem18$w$, $k$8$k$, $r$deleted after the update$r$);
SELECT key, phasevec._verdict(t), phasevec._claim_state(t) AS state FROM phasevec.truth t
 WHERE key IN ($k$7$k$, $k$8$k$) ORDER BY key;
-- its text changes: the refutation was about the old one
UPDATE mem18 SET body = $t$memory 8, written again$t$ WHERE id = 8;
SELECT key, phasevec._verdict(t), phasevec._claim_state(t) AS state FROM phasevec.truth t WHERE key = $k$8$k$;
DROP TABLE mem18;
DROP EXTENSION pg_phasevec;

-- (c) R18-VI-2, VI-3. refute() of a replaced claim retires it behind its replacement; unsupersede() shows a retired
-- claim 'refuted' again. In the seventeenth cut refute() of key 1 (replaced) did nothing and key 1 came back
-- 'verified'; key 3 (retired, then superseded and unsuperseded) read 'unproven' for good.
CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register($n$r1$n$, repeat($h$a$h$, 64), 4) > 0 AS r1;
CREATE TABLE mem18 (id int PRIMARY KEY, body text);
INSERT INTO mem18 SELECT g, $t$memory $t$ || g FROM generate_series(1, 4) g;
SELECT phasevec.watch($w$mem18$w$, $w$mem18$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) > 0 AS watch;
SELECT phasevec.assert($w$mem18$w$, k::text, $p$SELECT true$p$) FROM generate_series(1, 4) k;
SELECT count(*) FILTER (WHERE verdict = $v$verified$v$) AS verified FROM phasevec.verify($w$mem18$w$, p_every => interval $i$0$i$);
SELECT phasevec.supersede($w$mem18$w$, $k$1$k$, $k$2$k$, $r$newer$r$);
SELECT phasevec.refute($w$mem18$w$, $k$1$k$, $r$deleted$r$);
SELECT key, verdict, phasevec._claim_state(t) AS state, last_error FROM phasevec.truth t WHERE key = $k$1$k$;
SELECT phasevec.unsupersede($w$mem18$w$, $k$1$k$);
SELECT phasevec.refute($w$mem18$w$, $k$3$k$, $r$deleted$r$);
SELECT phasevec.supersede($w$mem18$w$, $k$3$k$, $k$2$k$, $r$newer$r$);
SELECT phasevec.unsupersede($w$mem18$w$, $k$3$k$);
SELECT key, verdict FROM phasevec.verify($w$mem18$w$, p_every => interval $i$0$i$) ORDER BY key;
SELECT phasevec.verify_one($w$mem18$w$, $k$1$k$) AS verify_one_1;
SELECT key, verdict, phasevec._verdict(t), phasevec._claim_state(t) AS state FROM phasevec.truth t ORDER BY key;
SELECT key, verdict FROM phasevec.brief($w$mem18$w$, 100000) ORDER BY key;
-- retired means no proof: the table says so too
UPDATE phasevec.truth SET proof = $p$SELECT true$p$ WHERE key = $k$1$k$;
-- an assert() is the only way back
SELECT phasevec.assert($w$mem18$w$, $k$3$k$, $p$SELECT true$p$);
SELECT key, verdict FROM phasevec.verify($w$mem18$w$, p_every => interval $i$0$i$) ORDER BY key;
DROP TABLE mem18;

-- (d) R18-PRIV-1, PRIV-2. What watch() reads by key: a plain table outside any inheritance tree, by a unique btree
-- index of its own enforced at once.
CREATE TABLE k18_ok (k int PRIMARY KEY, body text);
CREATE TABLE k18_deferred (k int NOT NULL, body text, CONSTRAINT k18_deferred_k UNIQUE (k) DEFERRABLE INITIALLY DEFERRED);
CREATE TABLE k18_deferrable (k int NOT NULL, body text, CONSTRAINT k18_deferrable_k UNIQUE (k) DEFERRABLE);
CREATE TABLE k18_hash (k int NOT NULL, body text);
CREATE UNIQUE INDEX ON k18_hash (k) INCLUDE (body);
CREATE TABLE k18_parent (k int PRIMARY KEY, body text);
CREATE TABLE k18_child () INHERITS (k18_parent);
ALTER TABLE k18_child ADD PRIMARY KEY (k);
CREATE TABLE k18_parted (k int PRIMARY KEY, body text) PARTITION BY RANGE (k);
CREATE TABLE k18_part PARTITION OF k18_parted FOR VALUES FROM (0) TO (100);
CREATE TABLE k18_two (k int, j int, body text, PRIMARY KEY (k, j));
CREATE TABLE k18_expr (k text, body text);
CREATE UNIQUE INDEX ON k18_expr (lower(k));
SELECT c, phasevec._key_shape(c::regclass, $k$k$k$) AS why
  FROM unnest(ARRAY[$t$k18_ok$t$, $t$k18_deferred$t$, $t$k18_deferrable$t$, $t$k18_hash$t$, $t$k18_parent$t$,
                    $t$k18_child$t$, $t$k18_parted$t$, $t$k18_part$t$, $t$k18_two$t$, $t$k18_expr$t$]) c;
SELECT phasevec.watch($w$k18d$w$, $w$k18_deferred$w$::regclass, $k$k$k$, $r$r.body$r$, $n$r1$n$);
SELECT phasevec.watch($w$k18p$w$, $w$k18_parent$w$::regclass, $k$k$k$, $r$r.body$r$, $n$r1$n$);
SELECT phasevec.watch($w$k18c$w$, $w$k18_child$w$::regclass, $k$k$k$, $r$r.body$r$, $n$r1$n$);
SELECT phasevec.watch($w$k18t$w$, $w$k18_parted$w$::regclass, $k$k$k$, $r$r.body$r$, $n$r1$n$);
SELECT phasevec.watch($w$k18q$w$, $w$k18_part$w$::regclass, $k$k$k$, $r$r.body$r$, $n$r1$n$);

-- (e) The same, after watch(): every read checks it again and refuses. PRIV-1's attack: a writer limited by row-level
-- security inserts, in its own transaction, a row under the key of one it cannot see; in the seventeenth cut a
-- DEFERRABLE key let it, and _render() showed it the hidden row.
CREATE TABLE notes18 (k int NOT NULL, tenant name NOT NULL DEFAULT current_user, body text,
                      CONSTRAINT notes18_k UNIQUE (k));
ALTER TABLE notes18 ENABLE ROW LEVEL SECURITY;
CREATE POLICY own ON notes18 USING (tenant = current_user) WITH CHECK (tenant = current_user);
CREATE ROLE pv18_a;
CREATE ROLE pv18_b;
GRANT USAGE ON SCHEMA phasevec TO pv18_a, pv18_b;
GRANT SELECT, INSERT ON notes18 TO pv18_a, pv18_b;
GRANT SELECT ON phasevec.truth TO pv18_a;
INSERT INTO notes18 VALUES (1, $r$pv18_a$r$, $t$a public note of a$t$), (2, $r$pv18_b$r$, $t$SECRET of b$t$);
SELECT phasevec.watch($w$notes18$w$, $w$notes18$w$::regclass, $k$k$k$, $r$r.body$r$, $n$r1$n$) > 0 AS watch;
SELECT phasevec.assert($w$notes18$w$, $k$2$k$, $p$SELECT true$p$);
SELECT count(*) FROM phasevec.verify($w$notes18$w$, p_every => interval $i$0$i$);
ALTER TABLE notes18 DROP CONSTRAINT notes18_k;
ALTER TABLE notes18 ADD CONSTRAINT notes18_k UNIQUE (k) DEFERRABLE INITIALLY DEFERRED;
SET ROLE pv18_a;
BEGIN;
INSERT INTO notes18 VALUES (2, $r$pv18_a$r$, $t$mine$t$);
SELECT key, body FROM phasevec._render($w$notes18$w$, ARRAY[$k$2$k$]);
ROLLBACK;
BEGIN;
INSERT INTO notes18 VALUES (2, $r$pv18_a$r$, $t$mine$t$);
SELECT t.key, phasevec._verdict(t) FROM phasevec.truth t WHERE t.key = $k$2$k$;
ROLLBACK;
RESET ROLE;
SELECT count(*) FROM phasevec.verify($w$notes18$w$, p_every => interval $i$0$i$);
SELECT phasevec.verify_one($w$notes18$w$, $k$2$k$);
SELECT phasevec.assert($w$notes18$w$, $k$1$k$, $p$SELECT true$p$);
-- the key is enforced at once again: it reads
ALTER TABLE notes18 DROP CONSTRAINT notes18_k;
ALTER TABLE notes18 ADD CONSTRAINT notes18_k UNIQUE (k);
SELECT key, body FROM phasevec._render($w$notes18$w$, ARRAY[$k$2$k$]);
-- PRIV-2's attack: a row an inheritance child holds under a key the parent's index does not cover. In the
-- seventeenth cut _render() showed pv18_a pv18_b's secret, kept in a child.
CREATE TABLE notes18_archive () INHERITS (notes18);
GRANT INSERT ON notes18_archive TO pv18_b;
SET ROLE pv18_b;
INSERT INTO notes18_archive VALUES (3, $r$pv18_b$r$, $t$SECRET of b, archived$t$);
RESET ROLE;
SET ROLE pv18_a;
INSERT INTO notes18 VALUES (3, $r$pv18_a$r$, $t$mine$t$);
SELECT key, body FROM phasevec._render($w$notes18$w$, ARRAY[$k$3$k$]);
SELECT key, body FROM phasevec._render($w$notes18$w$, NULL);
RESET ROLE;
SELECT count(*) FROM phasevec.verify($w$notes18$w$, p_every => interval $i$0$i$);
-- the child goes: it reads again (relhassubclass is still set until VACUUM: the children are listed)
DROP TABLE notes18_archive;
SET ROLE pv18_a;
SELECT key, body FROM phasevec._render($w$notes18$w$, NULL) ORDER BY key;
RESET ROLE;
-- a write is never refused for the shape of its table: its readers are
CREATE TABLE notes18_more () INHERITS (notes18);
INSERT INTO notes18 VALUES (4, current_user, $t$a write while a child exists$t$);
SELECT key FROM phasevec.sources WHERE watch = (SELECT id FROM phasevec.watches WHERE name = $w$notes18$w$) ORDER BY key;
DROP TABLE notes18_more;

DROP TABLE notes18, k18_ok, k18_deferred, k18_deferrable, k18_hash, k18_child, k18_parent, k18_parted, k18_two, k18_expr;
DROP EXTENSION pg_phasevec;
DROP OWNED BY pv18_au, pv18_a, pv18_b;
DROP ROLE pv18_au, pv18_a, pv18_b;
