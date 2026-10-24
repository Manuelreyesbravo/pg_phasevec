-- 0.13.0: a reader may compute on the NPU. Before 0.13.0 the seal refuses it; after, the same weights on cpu
-- and on npu are two readers, a backend nobody pins is still refused (by the function and by the
-- constraint), and a watch read by the npu reader records and serves like any other.
\set VERBOSITY terse

CREATE EXTENSION pg_phasevec VERSION $v$0.12.0$v$;
-- before 0.13.0 an npu compute is refused
SELECT phasevec.reader_register($n$qwen@npu$n$, repeat($h$a$h$, 64), 1024, NULL,
    $m${"pooling": "last", "ctx": 1024, "query_prefix": "Q: ", "tokens": "text alone, cut to fit, closed by the model own special tokens"}$m$::jsonb,
    $c${"backend": "npu", "device": "Some NPU", "system_info": "bfp16", "libs": "3333333333333333333333333333333333333333333333333333333333333333"}$c$::jsonb);

ALTER EXTENSION pg_phasevec UPDATE TO $v$0.13.0$v$;
SELECT extversion FROM pg_extension WHERE extname = $e$pg_phasevec$e$;

-- the same weights on cpu and on npu: two readers
SELECT phasevec.reader_register($n$qwen@cpu$n$, repeat($h$a$h$, 64), 1024, NULL,
    $m${"pooling": "last", "ctx": 1024, "query_prefix": "Q: ", "tokens": "text alone, cut to fit, closed by the model own special tokens"}$m$::jsonb,
    $c${"backend": "cpu", "device": "Some CPU", "system_info": "AVX512", "libs": "1111111111111111111111111111111111111111111111111111111111111111"}$c$::jsonb) > 0 AS on_cpu;
SELECT phasevec.reader_register($n$qwen@npu$n$, repeat($h$a$h$, 64), 1024, NULL,
    $m${"pooling": "last", "ctx": 1024, "query_prefix": "Q: ", "tokens": "text alone, cut to fit, closed by the model own special tokens"}$m$::jsonb,
    $c${"backend": "npu", "device": "Some NPU", "system_info": "bfp16", "libs": "3333333333333333333333333333333333333333333333333333333333333333"}$c$::jsonb) > 0 AS on_npu;
SELECT name, compute->>$k$backend$k$ AS backend FROM phasevec.readers ORDER BY id;

-- a backend nobody pins is still refused, by the function and by the constraint
SELECT phasevec.reader_register($n$qwen@tpu$n$, repeat($h$a$h$, 64), 1024, NULL,
    $m${"pooling": "last", "ctx": 1024}$m$::jsonb,
    $c${"backend": "tpu", "device": "x", "libs": "4444444444444444444444444444444444444444444444444444444444444444"}$c$::jsonb);
UPDATE phasevec.readers SET compute = jsonb_set(compute, $p${backend}$p$, $j$"tpu"$j$) WHERE name = $n$qwen@npu$n$;

-- each process proves its own compute: the npu seal does not match the cpu signature, nor the reverse
SELECT phasevec.reader_compute_matches($n$qwen@npu$n$,
    $c${"libs": "3333333333333333333333333333333333333333333333333333333333333333", "system_info": "bfp16", "device": "Some NPU", "backend": "npu"}$c$::jsonb) AS same;
SELECT phasevec.reader_compute_matches($n$qwen@npu$n$, phasevec.reader_compute($n$qwen@cpu$n$)) AS cpu_on_npu_seal;
SELECT phasevec.reader_compute_matches($n$qwen@cpu$n$, phasevec.reader_compute($n$qwen@npu$n$)) AS npu_on_cpu_seal;

-- a watch read by the npu reader records like any other; the cpu reader cannot write in its name
CREATE TABLE notes (id int PRIMARY KEY, body text);
INSERT INTO notes SELECT g, $t$note $t$ || g FROM generate_series(1, 4) g;
SELECT phasevec.watch($w$notes$w$, $w$notes$w$::regclass, $k$id$k$, $r$r.body$r$, $n$qwen@npu$n$) > 0 AS watch;
SELECT count(phasevec.record($w$notes$w$, n.key, $n$qwen@npu$n$, n.text_hash, n.key::bigint,
    array_fill(3::smallint, ARRAY[1024]), NULL, NULL, 2, 2))
  FROM phasevec.next($w$notes$w$, 4) n;
SELECT state, n FROM phasevec.coverage($w$notes$w$) WHERE n > 0;
SELECT phasevec.record($w$notes$w$, $k$1$k$, $n$qwen@cpu$n$, (SELECT text_hash FROM phasevec.sources WHERE key = $k$1$k$), 1,
    array_fill(1::smallint, ARRAY[1024]));

DROP TABLE notes;
DROP EXTENSION pg_phasevec;
