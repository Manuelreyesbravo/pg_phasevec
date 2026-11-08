-- 0.20.0 (nineteenth review: a model-based fuzzer of the claim lifecycle). A verdict of a proof is its author's: it
-- reads 'unproven' once no role has that OID and name, at once, not only after the next verify() or its horizon. And
-- verified_at never moves back: refute() in a transaction older than a verdict does not stamp an earlier time.
\set VERBOSITY terse

-- (a) F5. Keys 1 (true) and 2 (false) by pv19_au, 3 by pv19_au and then retired, 4 by pv19_keep, 5 by pv19_rn, 8 by
-- "Pv19 Odd" (a name that must be quoted). pv19_au is dropped and a new role takes its name; pv19_rn is renamed. In
-- the eighteenth cut keys 1 and 5 read 'verified' (and brief() served them) and key 2 'refuted' until the next
-- verify() or max_age.
CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register($n$r1$n$, repeat($h$a$h$, 64), 4) > 0 AS r1;
CREATE TABLE mem19 (id int PRIMARY KEY, body text);
INSERT INTO mem19 SELECT g, $t$memory $t$ || g FROM generate_series(1, 8) g;
SELECT phasevec.watch($w$mem19$w$, $w$mem19$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) > 0 AS watch;
CREATE ROLE pv19_au;
CREATE ROLE pv19_keep;
CREATE ROLE pv19_rn;
CREATE ROLE "Pv19 Odd";
GRANT USAGE ON SCHEMA phasevec TO pv19_au, pv19_keep, pv19_rn, "Pv19 Odd";
GRANT SELECT ON mem19 TO pv19_au, pv19_keep, pv19_rn, "Pv19 Odd";
GRANT UPDATE ON mem19 TO pv19_au, pv19_keep, pv19_rn, "Pv19 Odd";
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz)
   TO pv19_au, pv19_keep, pv19_rn, "Pv19 Odd";
SET ROLE pv19_au;
SELECT phasevec.assert($w$mem19$w$, k, p) FROM (VALUES ($k$1$k$, $p$SELECT true$p$), ($k$2$k$, $p$SELECT false$p$),
       ($k$3$k$, $p$SELECT true$p$)) v(k, p);
SET ROLE pv19_keep;
SELECT phasevec.assert($w$mem19$w$, $k$4$k$, $p$SELECT true$p$);
SET ROLE pv19_rn;
SELECT phasevec.assert($w$mem19$w$, $k$5$k$, $p$SELECT true$p$);
SET ROLE "Pv19 Odd";
SELECT phasevec.assert($w$mem19$w$, $k$8$k$, $p$SELECT true$p$);
RESET ROLE;
SELECT key, verdict FROM phasevec.verify($w$mem19$w$) ORDER BY key;
SELECT phasevec.refute($w$mem19$w$, $k$3$k$, $r$deleted by its owner$r$);
DROP OWNED BY pv19_au;
DROP ROLE pv19_au;
CREATE ROLE pv19_au;
ALTER ROLE pv19_rn RENAME TO pv19_rn2;
-- 1, 2 and 5 read 'unproven'; 3 is retired (refute() is nobody's proof) and reads 'refuted'; 4 and 8 'verified'
SELECT key, phasevec._verdict(t), phasevec._claim_state(t) AS state FROM phasevec.truth t ORDER BY key;
SELECT key, verdict FROM phasevec.brief($w$mem19$w$, 100000) ORDER BY key;
SELECT * FROM phasevec.truth_coverage($w$mem19$w$) ORDER BY 1;
-- the name back on its OID: it is that author again
ALTER ROLE pv19_rn2 RENAME TO pv19_rn;
SELECT key, phasevec._verdict(t) FROM phasevec.truth t WHERE key = $k$5$k$;
-- an assert() makes key 1 a claim again, of its new author: (twenty-sixth review) a steward of the
-- watch's, as its author is gone (no role that sees the row takes it any more)
SELECT phasevec.steward($w$mem19$w$, $r$pv19_au$r$);
GRANT USAGE ON SCHEMA phasevec TO pv19_au;
GRANT SELECT ON mem19 TO pv19_au;
GRANT UPDATE ON mem19 TO pv19_au;
GRANT EXECUTE ON FUNCTION phasevec.assert(text, text, text, text, jsonb, timestamptz) TO pv19_au;
SET ROLE pv19_au;
SELECT phasevec.assert($w$mem19$w$, $k$1$k$, $p$SELECT true$p$);
RESET ROLE;
SELECT phasevec.verify_one($w$mem19$w$, $k$1$k$) AS verify_one_1;

-- (b) F6. refute() in a transaction that began before a verdict was recorded: verified_at (and retired_at) is not
-- earlier than that verdict. verify_one() records through its worker, which commits on its own. In the eighteenth
-- cut refute() wrote the transaction's now(), before the verdict it replaced.
SELECT phasevec.assert($w$mem19$w$, $k$6$k$, $p$SELECT true$p$);
BEGIN;
SELECT now() AS t0 \gset
SELECT pg_sleep(0.05);
SELECT phasevec.verify_one($w$mem19$w$, $k$6$k$) AS verify_one_6;
SELECT verified_at AS va6 FROM phasevec.truth WHERE key = $k$6$k$ \gset
SELECT :'va6'::timestamptz > :'t0'::timestamptz AS judged_after_this_began;
SELECT phasevec.refute($w$mem19$w$, $k$6$k$, $r$deleted in an older transaction$r$);
SELECT verified_at >= :'va6'::timestamptz AS forward, retired_at = verified_at AS retired_then,
       phasevec._verdict(t), phasevec._claim_state(t) AS state
  FROM phasevec.truth t WHERE key = $k$6$k$;
COMMIT;
-- superseded and unsuperseded, it reads 'refuted' as of when it was retired: no earlier
SELECT phasevec.supersede($w$mem19$w$, $k$6$k$, $k$7$k$, $r$a newer one$r$);
SELECT phasevec.unsupersede($w$mem19$w$, $k$6$k$);
SELECT verified_at >= :'va6'::timestamptz AS forward, phasevec._verdict(t) FROM phasevec.truth t WHERE key = $k$6$k$;

DROP TABLE mem19;
DROP EXTENSION pg_phasevec;
DROP OWNED BY pv19_au, pv19_keep, pv19_rn, "Pv19 Odd";
DROP ROLE pv19_au, pv19_keep, pv19_rn, "Pv19 Odd";
