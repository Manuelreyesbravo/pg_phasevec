-- 0.19.0: every table and sequence of the extension is a config table, so pg_dump keeps its rows
-- (until 0.18.0 a dump of a database with watches lost the watches, the readings and the truth).
\set VERBOSITY terse

CREATE EXTENSION pg_phasevec VERSION $v$0.18.0$v$;
SELECT coalesce(array_length(extconfig, 1), 0) AS marked FROM pg_extension WHERE extname = $e$pg_phasevec$e$;
ALTER EXTENSION pg_phasevec UPDATE TO $v$0.19.0$v$;
SELECT extversion, array_length(extconfig, 1) AS marked FROM pg_extension WHERE extname = $e$pg_phasevec$e$;

-- left out: exactly the five tables the extension's own triggers rebuild during a restore
SELECT c.oid::regclass AS left_out
  FROM pg_depend d JOIN pg_class c ON c.oid = d.objid JOIN pg_extension e ON e.oid = d.refobjid
 WHERE e.extname = $e$pg_phasevec$e$ AND d.deptype = $d$e$d$ AND d.classid = $p$pg_class$p$::regclass
   AND c.relkind IN ($r$r$r$, $s$S$s$) AND c.oid <> ALL (coalesce(e.extconfig, $z${}$z$::oid[]))
 ORDER BY 1;

-- and nothing is filtered: a restore brings every row back
SELECT count(*) AS with_filter
  FROM pg_extension e, unnest(e.extcondition) AS w
 WHERE e.extname = $e$pg_phasevec$e$ AND w <> $x$$x$;

-- a fresh install lands on the same marks
DROP EXTENSION pg_phasevec;
CREATE EXTENSION pg_phasevec;
SELECT extversion, array_length(extconfig, 1) AS marked FROM pg_extension WHERE extname = $e$pg_phasevec$e$;
DROP EXTENSION pg_phasevec;
