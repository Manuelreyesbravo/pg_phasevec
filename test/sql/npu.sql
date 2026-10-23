-- 0.12.0: the bookkeeping of an NPU copy, without an NPU. find_npu refuses without a copy; npu_begin makes
-- writes listed; npu_loaded forgets what its snapshot saw; later writes are listed again; with a copy but no
-- server it fails cleanly; npu_end leaves nothing behind.
\set VERBOSITY terse

CREATE EXTENSION pg_phasevec;
SELECT extversion FROM pg_extension WHERE extname = 'pg_phasevec';
SELECT phasevec.reader_register('r256', repeat('a', 64), 256) > 0 AS r256;
CREATE TABLE docs (id int PRIMARY KEY, body text);
INSERT INTO docs SELECT g, 'doc ' || g FROM generate_series(1, 200) g;
SELECT phasevec.watch('docs', 'docs'::regclass, 'id', 'r.body', 'r256') > 0 AS watch;
CREATE FUNCTION code_of(g int) RETURNS smallint[] LANGUAGE sql IMMUTABLE AS $$
    SELECT array(SELECT (((g * 31 + j * 17 * (g % 7 + 1) + (g / 13) * j) % 255) - 127)::smallint
                   FROM generate_series(1, 256) j) $$;
CREATE FUNCTION read_as(p_from int, p_to int, p_shift int) RETURNS bigint LANGUAGE sql AS $$
    SELECT count(phasevec.record('docs', s.key, 'r256', s.text_hash, 0::bigint, code_of(s.key::int + p_shift), NULL, NULL))
      FROM phasevec.sources s WHERE s.key::int BETWEEN p_from AND p_to $$;
SELECT read_as(1, 200, 0) AS read;

-- no copy: refused, and k is bounded by the 32 each tile keeps
SELECT key FROM phasevec.find_npu('docs', code_of(5));
SELECT key FROM phasevec.find_npu('docs', code_of(5), 33);

-- begun: from now on the watch's writes are listed
SELECT phasevec.npu_begin('docs') IS NOT NULL AS begun;
SELECT read_as(1, 10, 3) AS reread;
SELECT count(*) AS dirty FROM phasevec.npu_dirty;
SELECT snap IS NULL AS loading FROM phasevec.npu_snaps;
-- loaded under a snapshot that sees those writes: they are in the copy, they leave the list
SELECT phasevec.npu_loaded('docs', pg_current_snapshot(), 200);
SELECT count(*) AS dirty_after_load FROM phasevec.npu_dirty;
SELECT n, snap IS NOT NULL AS loaded FROM phasevec.npu_snaps;
-- written after the copy: listed again, once per key
SELECT read_as(11, 12, 3) AS reread;
SELECT read_as(11, 11, 4) AS reread_again;
SELECT array_agg(key ORDER BY key) AS dirty_keys FROM phasevec.npu_dirty;

-- a copy is registered but no server answers here: a clean error, never an empty answer
DO $$
BEGIN
    PERFORM * FROM phasevec.find_npu('docs', code_of(5));
    RAISE NOTICE 'answered without a server?';
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'no server: %', CASE WHEN SQLERRM LIKE '%NPU server of watch "docs" is not reachable%' THEN 'refused' ELSE SQLERRM END;
END $$;

-- ended: nothing listed, nothing registered
SELECT phasevec.npu_end('docs');
SELECT (SELECT count(*) FROM phasevec.npu_snaps) AS snaps, (SELECT count(*) FROM phasevec.npu_dirty) AS dirty;
SELECT read_as(20, 21, 5) AS reread;
SELECT count(*) AS dirty_without_copy FROM phasevec.npu_dirty;

DROP TABLE docs;
DROP FUNCTION code_of(int), read_as(int, int, int);
DROP EXTENSION pg_phasevec;
