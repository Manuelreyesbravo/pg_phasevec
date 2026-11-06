-- 0.20.0 (sixteenth review): what phasevec runs as its owner reads no name and no value through its caller's or a
-- proof author's settings; who may see a verdict is decided on every call; a verdict's horizon is the same in every
-- TimeZone; a read-only transaction records nothing through verify().
\set VERBOSITY terse

CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register($n$r1$n$, repeat($h$a$h$, 64), 4) > 0 AS r1;
CREATE TABLE notes16 (id int PRIMARY KEY, body text);
INSERT INTO notes16 VALUES (1, $t$one$t$), (2, $t$two$t$);
SELECT phasevec.watch($w$notes16$w$, $w$notes16$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) > 0 AS watch;
CREATE ROLE pv16_au;
CREATE ROLE pv16_reader;
CREATE ROLE pv16_verifier;
GRANT pv16_au TO pv16_verifier;
GRANT USAGE ON SCHEMA phasevec TO pv16_au, pv16_reader, pv16_verifier;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz) TO pv16_au;
GRANT EXECUTE ON FUNCTION phasevec.verify(text, int, interval, interval, int, float8),
    phasevec.verify_one(text, text, int, float8) TO pv16_verifier;
GRANT SELECT, UPDATE ON notes16 TO pv16_au, pv16_verifier;
GRANT SELECT ON notes16 TO pv16_reader;
GRANT SELECT ON phasevec.truth TO pv16_reader;
GRANT EXECUTE ON FUNCTION phasevec.brief(text, int) TO pv16_reader;

-- (a) VI-1. The author puts its own '=' for bytea before pg_catalog's, in its role's search_path: the setting every
-- new session of it (a proof's session) starts with. In the fifteenth cut the claim's take (IS DISTINCT FROM, in the
-- proof's session, as the owner) ran it as a superuser: it planted a 'verified' for the false proof of key 2.
CREATE SCHEMA pv16_s AUTHORIZATION pv16_au;
SET ROLE pv16_au;
CREATE TABLE pv16_s.log (who name, super boolean);
CREATE FUNCTION pv16_s.eq(a bytea, b bytea) RETURNS boolean LANGUAGE plpgsql AS $f$
BEGIN
    INSERT INTO pv16_s.log SELECT current_user, r.rolsuper FROM pg_catalog.pg_roles r WHERE r.rolname = current_user;
    IF (SELECT r.rolsuper FROM pg_catalog.pg_roles r WHERE r.rolname = current_user) THEN
        UPDATE phasevec.truth t SET verdict = 'verified', verified_at = pg_catalog.clock_timestamp(),
               verified_for = phasevec._bind(t.asserted_for, t.proof, t.asserted_by_oid, t.proof_env)
         WHERE t.key = '2';
    END IF;
    RETURN pg_catalog.byteaeq(a, b);
END
$f$;
CREATE OPERATOR pv16_s.= (LEFTARG = bytea, RIGHTARG = bytea, FUNCTION = pv16_s.eq);
SELECT phasevec.assert($w$notes16$w$, $k$1$k$, $p$true$p$);
SELECT phasevec.assert($w$notes16$w$, $k$2$k$, $p$false$p$);
RESET ROLE;
ALTER ROLE pv16_au SET search_path = pv16_s, pg_catalog;
SET ROLE pv16_verifier;
SELECT key, verdict FROM phasevec.verify($w$notes16$w$) ORDER BY 1;
UPDATE notes16 SET body = $t$one, edited$t$ WHERE id = 1;
-- (the claim of key 1 is due as stale, not as old: the take reads its CASE)
SELECT key, verdict FROM phasevec.verify($w$notes16$w$) ORDER BY 1;
RESET ROLE;
-- the author's operator never ran, and it is still not a superuser; key 2 is still refuted
SELECT count(*) AS author_operator_ran FROM pv16_s.log;
SELECT rolsuper FROM pg_roles WHERE rolname = $r$pv16_au$r$;
SELECT t.key, t.verdict, phasevec._verdict(t) FROM phasevec.truth t ORDER BY 1;
ALTER ROLE pv16_au RESET search_path;
UPDATE notes16 SET body = $t$one$t$ WHERE id = 1;
SELECT key, verdict FROM phasevec.verify($w$notes16$w$, 10, $e$0$e$) ORDER BY 1;

-- (b) VI-2. A verdict 27 hours old, under a max_age of '1 day', is past its horizon in every TimeZone. In the
-- fifteenth cut the horizon was computed in the reader's TimeZone: under a POSIX rule whose DST ends (24 hours back)
-- between the verdict and now, the reader's day was 48 hours long and the verdict read 'verified'.
UPDATE phasevec.watches SET max_age = interval $i$1 day$i$ WHERE name = $w$notes16$w$;
UPDATE phasevec.truth SET verified_at = clock_timestamp() - interval $i$27 hours$i$ WHERE key = $k$1$k$;
SELECT pg_catalog.set_config($s$pv16.tz$s$, format($f$<A>+12<B>-12,J1/0,J%s/%s$f$,
           extract(doy FROM e)::int - CASE WHEN extract(doy FROM e) > 59
                                              AND (extract(year FROM e)::int % 4 = 0 AND (extract(year FROM e)::int % 100 <> 0 OR extract(year FROM e)::int % 400 = 0))
                                             THEN 1 ELSE 0 END,
           to_char(e, $f$HH24:MI:SS$f$)), false) IS NOT NULL AS rule
  FROM (SELECT (clock_timestamp() AT TIME ZONE $z$UTC$z$) - interval $i$15 hours$i$ + interval $i$12 hours$i$ AS e) x;
SELECT set_config($s$TimeZone$s$, current_setting($s$pv16.tz$s$), false) IS NOT NULL AS zone_set;
-- the reader's day is longer than 27 hours there: the case the horizon must not follow
SELECT (t.verified_at + interval $i$1 day$i$) > clock_timestamp() AS zone_day_reaches_now
  FROM phasevec.truth t WHERE t.key = $k$1$k$;
SET ROLE pv16_reader;
SELECT t.key, phasevec._verdict(t) FROM phasevec.truth t ORDER BY 1;
SELECT key, verdict FROM phasevec.brief($w$notes16$w$, 1000) ORDER BY 1;
RESET ROLE;
SET TimeZone = $z$UTC$z$;
SET ROLE pv16_reader;
SELECT t.key, phasevec._verdict(t) FROM phasevec.truth t ORDER BY 1;
RESET ROLE;
RESET TimeZone;
UPDATE phasevec.watches SET max_age = interval $i$1 hour$i$ WHERE name = $w$notes16$w$;
SELECT key, verdict FROM phasevec.verify($w$notes16$w$, 10, $e$0$e$) ORDER BY 1;

-- (c) PRIV-1. A PL/pgSQL expression keeps _verdict's fn_extra for its whole transaction. A REVOKE (or row-level
-- security) in the transaction is seen by the next call: in the fifteenth cut the decision was kept, and the
-- expression went on answering for a table the caller could no longer read.
CREATE FUNCTION pv16_v(r phasevec.truth) RETURNS text LANGUAGE plpgsql AS $f$ BEGIN RETURN phasevec._verdict(r); END $f$;
BEGIN;
SET LOCAL ROLE pv16_reader;
SELECT t.key, pv16_v(t) FROM phasevec.truth t ORDER BY 1;
RESET ROLE;
REVOKE SELECT ON notes16 FROM pv16_reader;
SET LOCAL ROLE pv16_reader;
SELECT has_table_privilege($t$notes16$t$, $p$SELECT$p$) AS may_read;
SELECT t.key, pv16_v(t) FROM phasevec.truth t ORDER BY 1;
-- a forged row with a guessed text: nothing
SELECT pv16_v(json_populate_record(NULL::phasevec.truth, json_build_object($k$watch$k$, t.watch, $k$key$k$, $k$2$k$,
           $k$verdict$k$, $k$refuted$k$, $k$proof$k$, $k$x$k$, $k$halted$k$, false, $k$verified_at$k$, now(),
           $k$asserted_for$k$, sha256(convert_to($t$two$t$, $e$UTF8$e$))))) AS forged
  FROM phasevec.truth t WHERE t.key = $k$1$k$;
ROLLBACK;
BEGIN;
SET LOCAL ROLE pv16_reader;
SELECT t.key, pv16_v(t) FROM phasevec.truth t ORDER BY 1;
RESET ROLE;
ALTER TABLE notes16 ENABLE ROW LEVEL SECURITY;
CREATE POLICY only1 ON notes16 FOR SELECT USING (id = 1);
SET LOCAL ROLE pv16_reader;
SELECT array_agg(id ORDER BY id) AS reader_sees FROM notes16;
SELECT t.key, pv16_v(t) FROM phasevec.truth t ORDER BY 1;
ROLLBACK;

-- (d) MIND-2. verify() and verify_one() record verdicts (in sessions of their own): a transaction, or a session,
-- that writes nothing is refused. The cron's path (SET ROLE, then verify, in a read-write session) works.
BEGIN READ ONLY;
SET LOCAL ROLE pv16_verifier;
SELECT count(*) FROM phasevec.verify($w$notes16$w$, 10, $e$0$e$);
ROLLBACK;
SET default_transaction_read_only = on;
SET ROLE pv16_verifier;
SELECT count(*) FROM phasevec.verify($w$notes16$w$, 10, $e$0$e$);
SELECT phasevec.verify_one($w$notes16$w$, $k$1$k$, 5000);
RESET ROLE;
RESET default_transaction_read_only;
SET ROLE pv16_verifier;
SELECT count(*) FROM phasevec.verify($w$notes16$w$, 10, $e$0$e$);
RESET ROLE;

DROP FUNCTION pv16_v(phasevec.truth);
DROP TABLE notes16;
DROP EXTENSION pg_phasevec;
DROP SCHEMA pv16_s CASCADE;
DROP OWNED BY pv16_au, pv16_reader, pv16_verifier;
DROP ROLE pv16_verifier;
DROP ROLE pv16_au;
DROP ROLE pv16_reader;
