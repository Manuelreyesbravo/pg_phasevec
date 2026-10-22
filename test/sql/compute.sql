-- 0.4.0: a reader is sealed with the compute it reads on, and a reader registered before that is
-- replaced, never relabelled.
\set VERBOSITY terse

CREATE EXTENSION pg_phasevec VERSION '0.3.0';
\set m '{"reader":"vec","version":"0.1.0","base_sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","adapter_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","heads_sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","marker":"<v>","pooling":"none","read_at":"last_marker_token","mrl_dims":[1024,256,64],"query_instruction":"Query: "}'
-- a reader from before 0.4.0, with readings, on a live watch
SELECT phasevec.reader_register(:'m'::jsonb) > 0 AS legacy;
CREATE TABLE notes (id int PRIMARY KEY, body text);
INSERT INTO notes SELECT g, 'note ' || g FROM generate_series(1, 6) g;
SELECT phasevec.watch('notes', 'notes'::regclass, 'id', 'r.body', 'vec-0.1.0') > 0 AS watch;
SELECT count(phasevec.record('notes', n.key, 'vec-0.1.0', n.text_hash, n.key::bigint, array_fill(1::smallint, ARRAY[1024])))
  FROM phasevec.next('notes', 6) n;

ALTER EXTENSION pg_phasevec UPDATE TO '0.4.0';
SELECT extversion FROM pg_extension WHERE extname = 'pg_phasevec';
-- the legacy reader keeps its readings and has no compute: a reader process refuses it
SELECT name, compute IS NULL AS unpinned FROM phasevec.readers;
SELECT phasevec.reader_compute('vec-0.1.0') IS NULL AS no_compute;
SELECT phasevec.reader_compute_matches('vec-0.1.0', '{"backend":"cpu","device":"x","libs":"0000000000000000000000000000000000000000000000000000000000000000"}') AS legacy_matches;

\set cpu '{"backend":"cpu","device":"Some CPU","system_info":"CPU : AVX2 = 1","libs":"1111111111111111111111111111111111111111111111111111111111111111"}'
\set cuda '{"backend":"cuda","device":"Some GPU","system_info":"CUDA : ARCHS = 1200","libs":"2222222222222222222222222222222222222222222222222222222222222222"}'
-- a compute signature must name a backend we pin, a device and the libraries loaded
SELECT phasevec.reader_register(:'m'::jsonb, '{"backend":"hybrid","device":"x","libs":"1111111111111111111111111111111111111111111111111111111111111111"}');
SELECT phasevec.reader_register(:'m'::jsonb, '{"backend":"cpu","libs":"1111111111111111111111111111111111111111111111111111111111111111"}');
SELECT phasevec.reader_register(:'m'::jsonb, '{"backend":"cpu","device":"x","libs":"not a sha"}');
SELECT phasevec.reader_register(:'m'::jsonb, '"cpu"');
-- the manifest is still checked when a compute comes with it
SELECT phasevec.reader_register(jsonb_set(:'m'::jsonb, '{base_sha256}', 'null'), :'cpu'::jsonb);
-- control: the same weights on two backends are two readers, next to the legacy one
SELECT phasevec.reader_register(:'m'::jsonb, :'cpu'::jsonb) > 0 AS on_cpu;
SELECT phasevec.reader_register(:'m'::jsonb, :'cuda'::jsonb) > 0 AS on_cuda;
SELECT name, compute->>'backend' AS backend FROM phasevec.readers ORDER BY id;
-- the same weights on the same compute cannot be registered twice
SELECT phasevec.reader_register(jsonb_set(:'m'::jsonb, '{version}', '"0.1.1"'), :'cpu'::jsonb);
-- and the constraint holds without the function: a bad signature cannot be written in directly
UPDATE phasevec.readers SET compute = '{"backend":"hybrid"}' WHERE name = 'vec-0.1.0@cpu';

-- a process proves its compute: the same signature in another key order matches, another does not
SELECT phasevec.reader_compute_matches('vec-0.1.0@cpu',
    '{"libs":"1111111111111111111111111111111111111111111111111111111111111111","system_info":"CPU : AVX2 = 1","device":"Some CPU","backend":"cpu"}') AS same;
SELECT phasevec.reader_compute_matches('vec-0.1.0@cpu', :'cuda'::jsonb) AS cuda_on_cpu_seal;
SELECT phasevec.reader_compute_matches('vec-0.1.0@cuda', :'cpu'::jsonb) AS cpu_on_cuda_seal;
SELECT phasevec.reader_compute_matches('vec-0.1.0@cpu', jsonb_set(:'cpu'::jsonb, '{system_info}', '"CPU : AVX512 = 1"')) AS other_kernels;
SELECT phasevec.reader_compute_matches('nobody', :'cpu'::jsonb) AS no_reader;

-- the migration: switching the watch to the pinned reader makes every legacy reading foreign
SELECT phasevec.reader_switch('notes', 'vec-0.1.0@cpu');
SELECT state, n FROM phasevec.coverage('notes') WHERE n > 0;
SELECT count(*) AS to_read FROM phasevec.next('notes', 100);
-- a legacy reading is refused now that the watch belongs to the pinned reader
SELECT phasevec.record('notes', '1', 'vec-0.1.0', (SELECT text_hash FROM phasevec.sources WHERE key = '1'), 1, array_fill(1::smallint, ARRAY[1024]));
-- the pinned reader reads them again; they come back fresh, and the counts agree with a recount
SELECT count(phasevec.record('notes', n.key, 'vec-0.1.0@cpu', n.text_hash, n.key::bigint, array_fill(2::smallint, ARRAY[1024])))
  FROM phasevec.next('notes', 100) n;
SELECT state, n FROM phasevec.coverage('notes') WHERE n > 0;
SELECT count(*) AS mismatches FROM phasevec.coverage_check('notes');

DROP TABLE notes;
DROP EXTENSION pg_phasevec;
