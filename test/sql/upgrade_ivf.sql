-- 0.10.0 over a 0.9.0 database that already has a coarse index and a delta, as :5492 has: the update keeps
-- answering exactly, keeps the delta it was given, then absorbs and maintains like a fresh 0.10.0.
\set VERBOSITY terse

CREATE EXTENSION pg_phasevec VERSION '0.9.0';
SELECT phasevec.reader_register('r256', repeat('a', 64), 256) > 0 AS r256;
CREATE TABLE docs (id int PRIMARY KEY, body text);
INSERT INTO docs SELECT g, 'doc ' || g FROM generate_series(1, 2000) g;
SELECT phasevec.watch('docs', 'docs'::regclass, 'id', 'r.body', 'r256') > 0 AS watch;
CREATE FUNCTION code_of(g int) RETURNS smallint[] LANGUAGE sql IMMUTABLE AS $$
    SELECT array(SELECT (((g * 31 + j * 17 * (g % 7 + 1) + (g / 13) * j) % 255) - 127)::smallint
                   FROM generate_series(1, 256) j) $$;
CREATE FUNCTION signs_of(c smallint[]) RETURNS bit(256) LANGUAGE sql IMMUTABLE AS $$
    SELECT string_agg(CASE WHEN x > 0 THEN '1' ELSE '0' END, '' ORDER BY o)::bit(256)
      FROM unnest(c) WITH ORDINALITY u(x, o) $$;
CREATE FUNCTION change_as(p_from int, p_to int, p_shift int) RETURNS bigint LANGUAGE plpgsql AS $$
BEGIN
    UPDATE docs SET body = 'doc ' || id || ' v' || p_shift WHERE id BETWEEN p_from AND p_to;
    RETURN (SELECT count(phasevec.record('docs', s.key, 'r256', s.text_hash, 0::bigint, code_of(s.key::int + p_shift), NULL,
                                         signs_of(code_of(s.key::int + p_shift))))
              FROM phasevec.sources s WHERE s.key::int BETWEEN p_from AND p_to);
END $$;
SELECT count(phasevec.record('docs', s.key, 'r256', s.text_hash, 0::bigint, code_of(s.key::int), NULL, signs_of(code_of(s.key::int))))
  FROM phasevec.sources s;
SELECT phasevec.ivf_build('docs') AS lists_090;
-- a delta under 0.9.0
SELECT change_as(1, 30, 1) AS changed_090;
SELECT count(*) AS delta_090 FROM phasevec.ivf_dirty;

ALTER EXTENSION pg_phasevec UPDATE TO '0.10.0';
SELECT extversion FROM pg_extension WHERE extname = 'pg_phasevec';
-- the delta of 0.9.0 is still there, with a transaction every snapshot sees
SELECT count(*) AS delta_kept, bool_and(txid IS NOT NULL) AS has_txid FROM phasevec.ivf_dirty;
SELECT (SELECT array_agg(key ORDER BY score DESC, key) FROM phasevec.find('docs', 0, code_of(11), 10, false, 2000, signs_of(code_of(11))))
     = (SELECT array_agg(key ORDER BY score DESC, key) FROM phasevec.find_ivf('docs', 0, code_of(11), 10, false, 2000, signs_of(code_of(11)), 1000))
       AS same_as_find_after_update;
-- absorbed into chunks
SELECT phasevec.ivf_absorb('docs') AS absorbed;
SELECT count(*) AS delta_after_absorb FROM phasevec.ivf_dirty;
SELECT sum(n) AS chunk_readings FROM phasevec.ivf_added;
SELECT (SELECT array_agg(key ORDER BY score DESC, key) FROM phasevec.find('docs', 0, code_of(11), 10, false, 2100, signs_of(code_of(11))))
     = (SELECT array_agg(key ORDER BY score DESC, key) FROM phasevec.find_ivf('docs', 0, code_of(11), 10, false, 2100, signs_of(code_of(11)), 1000))
       AS same_as_find_after_absorb;
-- the same, loaded privately from lists and chunks
SET phasevec.shared_ivf_cache = off;
SELECT (SELECT array_agg(key ORDER BY score DESC, key) FROM phasevec.find('docs', 0, code_of(25), 10, false, 2100, signs_of(code_of(25))))
     = (SELECT array_agg(key ORDER BY score DESC, key) FROM phasevec.find_ivf('docs', 0, code_of(25), 10, false, 2100, signs_of(code_of(25)), 1000))
       AS same_as_find_loaded;
RESET phasevec.shared_ivf_cache;
-- the error messages of find_ivf, unchanged
SELECT * FROM phasevec.find_ivf('nope', 0, code_of(1), 10, false, 200, signs_of(code_of(1)), 16);
SELECT * FROM phasevec.find_ivf('docs', 0, code_of(1), 10, false, 200, NULL, 16);
SELECT * FROM phasevec.find_ivf('docs', 0, code_of(1), 0, false, 200, signs_of(code_of(1)), 16);
-- maintained and rebuilt like a fresh 0.10.0
SELECT phasevec.ivf_maintain('docs', 0.01, 50) AS maintain;
SELECT count(*) AS chunks_after_build FROM phasevec.ivf_added;
SELECT n, absorbed FROM phasevec.ivf_cents;

DROP TABLE docs;
DROP FUNCTION code_of(int), signs_of(smallint[]), change_as(int, int, int);
DROP EXTENSION pg_phasevec;
