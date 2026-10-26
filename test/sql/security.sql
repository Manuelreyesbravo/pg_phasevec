-- 0.16.0: maintenance functions are revoked from PUBLIC, and the coarse search refuses a parameter far
-- outside a real index's range. A small watch is enough to show both.
\set VERBOSITY terse

CREATE EXTENSION pg_phasevec VERSION $v$0.13.0$v$;
ALTER EXTENSION pg_phasevec UPDATE TO $v$0.16.0$v$;
SELECT extversion FROM pg_extension WHERE extname = $e$pg_phasevec$e$;

SELECT phasevec.reader_register($n$r1$n$, repeat($h$a$h$, 64), 4) > 0 AS r1;
CREATE TABLE notes (id int PRIMARY KEY, body text);
INSERT INTO notes VALUES (1, $t$the deployed version is 0.12.0$t$), (2, $t$what runs today is the 0.13 line$t$),
                         (3, $t$cherry tart$t$), (4, $t$date palm$t$);
SELECT phasevec.watch($w$notes$w$, $w$notes$w$::regclass, $k$id$k$, $r$r.body$r$, $n$r1$n$) > 0 AS watch;
CREATE FUNCTION pg_temp.code(k text) RETURNS smallint[] LANGUAGE sql AS $f$
    SELECT CASE k WHEN $k$1$k$ THEN ARRAY[100,0,0,0] WHEN $k$2$k$ THEN ARRAY[0,100,0,0]
                  WHEN $k$3$k$ THEN ARRAY[0,0,100,0] ELSE ARRAY[0,0,0,100] END::smallint[] $f$;
SELECT count(phasevec.record($w$notes$w$, n.key, $n$r1$n$, n.text_hash, 1, pg_temp.code(n.key))) AS recorded
  FROM phasevec.next($w$notes$w$) n;

-- (a) maintenance is no longer executable by PUBLIC; the search path still is
SELECT has_function_privilege($p$public$p$, $s$phasevec.ivf_build(text,int,int,int,boolean)$s$, $e$EXECUTE$e$) AS public_ivf_build;
SELECT has_function_privilege($p$public$p$, $s$phasevec.ivf_maintain(text,double precision,int)$s$, $e$EXECUTE$e$) AS public_ivf_maintain;
SELECT has_function_privilege($p$public$p$, $s$phasevec.counts_compact(text)$s$, $e$EXECUTE$e$) AS public_counts_compact;
SELECT has_function_privilege($p$public$p$, $s$phasevec.ivf_sweep(int,bit,smallint[],int,int,int)$s$, $e$EXECUTE$e$) AS public_ivf_sweep;
SELECT has_function_privilege($p$public$p$, $s$phasevec.find(text,bigint,smallint[],int,boolean,int,bit)$s$, $e$EXECUTE$e$) AS public_find;

-- (b) a parameter outside the coarse search's range is refused (m above its 100000 ceiling)
SELECT * FROM phasevec.find_ivf($w$notes$w$, 1, ARRAY[100,0,0,0]::smallint[], 2, false, 200000, NULL, 16);

DROP TABLE notes;
DROP EXTENSION pg_phasevec;
