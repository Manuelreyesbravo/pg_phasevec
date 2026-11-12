-- 0.20.0 (nineteenth review, second pass: the review's lenses and the fuzzer). One file for what one session shows:
-- (a) R19-PRIV-1, (b) the same rule against MIND-ENV-1, (c) R19-F8, (d) R19-F9, (e) R19-PRIV-2. The races (R19-F7,
-- R19-F10, RT19-CRASH-1) are in test/truth_adopt_race.sh and test/truth_drop_race.sh.
\set VERBOSITY terse
CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register($n$r1$n$, repeat($h$a$h$, 64), 4) > 0 AS r1;
CREATE TABLE n19b (id int PRIMARY KEY, body text);
INSERT INTO n19b SELECT g, $t$note $t$ || g FROM generate_series(1, 9) g;
SELECT phasevec.watch($w$n19b$w$, $w$n19b$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) > 0 AS watch;
CREATE ROLE pv19b_au;
CREATE ROLE pv19b_mal;
CREATE ROLE pv19b_wr;
CREATE ROLE pv19b_nobody;
GRANT USAGE ON SCHEMA phasevec TO pv19b_au, pv19b_mal, pv19b_wr, pv19b_nobody;
GRANT SELECT ON n19b TO pv19b_au;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz) TO pv19b_au;
GRANT EXECUTE ON FUNCTION phasevec.adopt(text, regrole, text[], text[]) TO pv19b_au;
-- (twenty-sixth review) adopting changes claims: a steward of the watch's adopts
SELECT phasevec.steward($w$n19b$w$, $r$pv19b_au$r$);

-- (a) R19-PRIV-1. The author's SECURITY DEFINER wrapper, hardened (SET search_path), with a fixed proof that names
-- '>' unqualified. A caller without the author's rights sets its own search_path (its schema first, with an operator
-- '>' for bigint and int) and other settings, and calls it (key 1); and calls an unhardened wrapper of the author
-- through its own function with a SET clause (key 2). In the eighteenth cut key 1 recorded the caller's search_path:
-- the proof ran the caller's operator as the author ("the caller's operator ran as pv19b_au") and was refuted, and
-- the operator decided the verdict. Now a claim records what was in effect where assert() was called, as the author
-- had it: the wrapper's SET clause is the author's; what a role without the author's privileges set is not recorded.
CREATE SCHEMA app19b AUTHORIZATION pv19b_au;
CREATE FUNCTION app19b.vouch(k int) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
    SET search_path = pg_catalog, public AS $f$
BEGIN
    PERFORM phasevec.assert('n19b', k::text, format('SELECT count(*) > 0 FROM public.n19b WHERE id = %s', k));
END
$f$;
CREATE FUNCTION app19b.vouch_bare(k int) RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $f$
BEGIN
    PERFORM phasevec.assert('n19b', k::text, format('SELECT count(*) > 0 FROM public.n19b WHERE id = %s', k));
END
$f$;
ALTER FUNCTION app19b.vouch(int) OWNER TO pv19b_au;
ALTER FUNCTION app19b.vouch_bare(int) OWNER TO pv19b_au;
GRANT USAGE ON SCHEMA app19b TO pv19b_mal;
GRANT EXECUTE ON FUNCTION app19b.vouch(int), app19b.vouch_bare(int) TO pv19b_mal;
CREATE SCHEMA evil19b AUTHORIZATION pv19b_mal;
SET ROLE pv19b_mal;
CREATE FUNCTION evil19b.gt(bigint, int) RETURNS boolean LANGUAGE plpgsql AS $f$
BEGIN
    RAISE EXCEPTION 'the caller''s operator ran as %', current_user;
END
$f$;
CREATE OPERATOR evil19b.> (LEFTARG = bigint, RIGHTARG = int, FUNCTION = evil19b.gt);
CREATE FUNCTION evil19b.via(k int) RETURNS void LANGUAGE sql
    SET search_path = evil19b, pg_catalog SET extra_float_digits = 3 AS $f$ SELECT app19b.vouch_bare(k) $f$;
SET search_path = evil19b, pg_catalog;
SET IntervalStyle = sql_standard;
SET app.tenant = 'mallory';
RESET app.made19b;
SELECT app19b.vouch(1);
SELECT evil19b.via(2);
RESET ROLE;
RESET search_path;
RESET IntervalStyle;
SELECT key, array(SELECT e FROM unnest(proof_env) e
                   WHERE e ~ '^(search_path|IntervalStyle|extra_float_digits|app\.)') AS env
  FROM phasevec.truth WHERE key IN ($k$1$k$, $k$2$k$) ORDER BY key;
SELECT key, verdict, error FROM phasevec.verify($w$n19b$w$, 10, $e$0$e$) WHERE key IN ($k$1$k$, $k$2$k$) ORDER BY key;

-- (b) MIND-ENV-1 under the same rule. A wrapper of the author with SET search_path (an author's wrapper, here with
-- the schema its proofs name) asserts key 3, called by a superuser's session whose own search_path is another. Key 4
-- is the same claim from before 0.20.0 (no author, no settings), adopted through the author's wrapper of adopt() with
-- the same SET clause; key 5 the same, adopted by the author's own session in the same search_path. All three record
-- the same settings and mean the same: verified. (In the eighteenth cut each recorded the calling session's
-- search_path, public, where one() is not found: all three refuted.)
CREATE SCHEMA lib19b;
CREATE FUNCTION lib19b.one() RETURNS int LANGUAGE sql IMMUTABLE AS $f$ SELECT 1 $f$;
GRANT USAGE ON SCHEMA lib19b TO pv19b_au;
CREATE FUNCTION app19b.afirmar(k text, p text) RETURNS void LANGUAGE sql SECURITY DEFINER
    SET search_path = pg_catalog, lib19b, pg_temp AS $f$ SELECT phasevec.assert('n19b', k, p) $f$;
CREATE FUNCTION app19b.adoptar(k text) RETURNS SETOF text LANGUAGE sql SECURITY DEFINER
    SET search_path = pg_catalog, lib19b, pg_temp
    AS $f$ SELECT a.key FROM phasevec.adopt('n19b', 'pv19b_au', ARRAY[k]) a WHERE a.adopted $f$;
ALTER FUNCTION app19b.afirmar(text, text) OWNER TO pv19b_au;
ALTER FUNCTION app19b.adoptar(text) OWNER TO pv19b_au;
SET search_path = public;
SELECT app19b.afirmar(k, $p$one() = 1$p$) FROM unnest(ARRAY[$k$3$k$, $k$4$k$, $k$5$k$]) k;
UPDATE phasevec.truth SET asserted_by_oid = NULL, asserted_by = NULL, proof_env = NULL
 WHERE key IN ($k$4$k$, $k$5$k$);
SELECT app19b.adoptar($k$4$k$);
SET ROLE pv19b_au;
SET search_path = pg_catalog, lib19b, pg_temp;
SELECT key, adopted FROM phasevec.adopt($w$n19b$w$, $r$pv19b_au$r$, ARRAY[$k$5$k$]);
RESET ROLE;
RESET search_path;
SELECT key, array(SELECT e FROM unnest(proof_env) e WHERE e ~ '^search_path') AS env,
       asserted_by FROM phasevec.truth WHERE key IN ($k$3$k$, $k$4$k$, $k$5$k$) ORDER BY key;
SELECT count(DISTINCT proof_env) AS envs FROM phasevec.truth WHERE key IN ($k$3$k$, $k$4$k$, $k$5$k$);
SELECT key, verdict FROM phasevec.verify($w$n19b$w$, 10, $e$0$e$) WHERE key IN ($k$3$k$, $k$4$k$, $k$5$k$) ORDER BY key;

-- (c) R19-F8. A claim in each state, superseded and unsuperseded, comes back in the same state, with the verdict
-- that state has: halted (key 6, its proof ended its session) reads 'refuted' as of its halt; retired (key 7)
-- 'refuted'; judged (key 8) 'unproven' and due at once, and verify() judges it again. In the eighteenth cut key 6
-- came back 'unproven' for good (verify() does not run a halted claim) and brief() served it.
SET ROLE pv19b_au;
SELECT phasevec.assert($w$n19b$w$, k, $p$SELECT true$p$) FROM unnest(ARRAY[$k$6$k$, $k$7$k$, $k$8$k$]) k;
RESET ROLE;
SELECT key, verdict FROM phasevec.verify($w$n19b$w$, 10, $e$0$e$) WHERE key IN ($k$6$k$, $k$7$k$, $k$8$k$) ORDER BY key;
SELECT phasevec._truth_halted(t.watch, sha256(convert_to(t.key, $e$UTF8$e$)),
                              phasevec._bind(t.asserted_for, t.proof, t.asserted_by_oid, t.proof_env),
                              t.asserted_by_oid, t.xmin) AS halted
  FROM phasevec.truth t WHERE key = $k$6$k$;
SELECT phasevec.refute($w$n19b$w$, $k$7$k$, $r$gone$r$);
CREATE TEMP TABLE before19b AS
SELECT key, phasevec._claim_state(t) AS state, phasevec._verdict(t) AS reads, verified_at
  FROM phasevec.truth t WHERE key IN ($k$6$k$, $k$7$k$, $k$8$k$);
SELECT phasevec.supersede($w$n19b$w$, k, $k$9$k$, $r$a newer one$r$) FROM unnest(ARRAY[$k$6$k$, $k$7$k$, $k$8$k$]) k;
SELECT phasevec.unsupersede($w$n19b$w$, k) FROM unnest(ARRAY[$k$6$k$, $k$7$k$, $k$8$k$]) k;
SELECT b.key, b.state, phasevec._claim_state(t) AS state_after, b.reads, phasevec._verdict(t) AS reads_after,
       t.verified_at IS NOT DISTINCT FROM b.verified_at AS same_verified_at
  FROM before19b b JOIN phasevec.truth t ON t.key = b.key ORDER BY b.key;
SELECT key, verdict FROM phasevec.verify($w$n19b$w$, 10, $e$0$e$) WHERE key IN ($k$6$k$, $k$7$k$, $k$8$k$) ORDER BY key;
SELECT key, verdict FROM phasevec.brief($w$n19b$w$, 100000) WHERE key IN ($k$6$k$, $k$7$k$, $k$8$k$) ORDER BY key;

-- (d) R19-F9. A TRUNCATE (by a writer granted it) empties what the watch noted: no claim of a row that is gone reads
-- 'verified', and truth_coverage() counts no row. (twenty-eighth review, RT28PA-REUSE-1) The same rows inserted
-- again are other rows: their claims are dead, and none reads 'verified' (until then they read as they did). In the
-- eighteenth
-- cut the watch trigger did not fire for a TRUNCATE: _verdict() and truth_coverage() served 'verified' for rows that
-- no longer existed, and truth_coverage() counted them after verify() too.
SELECT tgname FROM pg_trigger WHERE tgrelid = $t$n19b$t$::regclass ORDER BY 1;
SELECT count(*) FILTER (WHERE phasevec._verdict(t) = $v$verified$v$) AS verified FROM phasevec.truth t;
SELECT * FROM phasevec.truth_coverage($w$n19b$w$) ORDER BY 1;
GRANT TRUNCATE ON n19b TO pv19b_wr;
SET ROLE pv19b_wr;
TRUNCATE n19b;
RESET ROLE;
SELECT count(*) FILTER (WHERE phasevec._verdict(t) = $v$verified$v$) AS verified FROM phasevec.truth t;
SELECT * FROM phasevec.truth_coverage($w$n19b$w$) ORDER BY 1;
SELECT count(*) AS noted FROM phasevec.sources s JOIN phasevec.watches w ON w.id = s.watch WHERE w.name = $w$n19b$w$;
INSERT INTO n19b SELECT g, $t$note $t$ || g FROM generate_series(1, 9) g;
SELECT count(*) FILTER (WHERE phasevec._verdict(t) = $v$verified$v$) AS verified FROM phasevec.truth t;
-- the trigger is the watch's, for its own table only
CREATE TABLE other19b (id int PRIMARY KEY);
SELECT id AS watch_id FROM phasevec.watches WHERE name = $w$n19b$w$;
CREATE TRIGGER forge AFTER TRUNCATE ON other19b FOR EACH STATEMENT EXECUTE FUNCTION phasevec._observe('1');
TRUNCATE other19b;
SELECT count(*) AS noted FROM phasevec.sources s JOIN phasevec.watches w ON w.id = s.watch WHERE w.name = $w$n19b$w$;
DROP TABLE other19b;

-- (e) R19-PRIV-2. _key_shape() answers only a role that may watch the table (its owner), before it locks anything.
-- In the eighteenth cut any role with USAGE on the schema held a reader's lock on any table until its transaction
-- ended (an ALTER TABLE queued behind it stopped every reader of the table).
SET ROLE pv19b_nobody;
SELECT phasevec._key_shape($t$n19b$t$::regclass, $k$id$k$);
RESET ROLE;
SELECT phasevec._key_shape($t$n19b$t$::regclass, $k$id$k$) IS NULL AS watchable;

DROP TABLE n19b;
DROP EXTENSION pg_phasevec;

-- (f) R19-F9 through the update: a watch made under 0.19.0 gets its TRUNCATE trigger from the update to 0.20.0.
CREATE EXTENSION pg_phasevec VERSION $v$0.19.0$v$;
SELECT phasevec.reader_register($n$r1$n$, repeat($h$a$h$, 64), 4) > 0 AS r1;
CREATE TABLE u19b (id int PRIMARY KEY, body text);
INSERT INTO u19b SELECT g, $t$note $t$ || g FROM generate_series(1, 3) g;
SELECT phasevec.watch($w$u19b$w$, $w$u19b$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) > 0 AS watch;
ALTER EXTENSION pg_phasevec UPDATE TO $v$0.20.0$v$;
SELECT tgname FROM pg_trigger WHERE tgrelid = $t$u19b$t$::regclass ORDER BY 1;
TRUNCATE u19b;
SELECT count(*) AS noted FROM phasevec.sources;
DROP TABLE u19b;
DROP EXTENSION pg_phasevec;
DROP SCHEMA app19b, evil19b, lib19b CASCADE;
DROP OWNED BY pv19b_au, pv19b_mal, pv19b_wr, pv19b_nobody;
DROP ROLE pv19b_au, pv19b_mal, pv19b_wr, pv19b_nobody;
