-- 0.17.0: a coarse index kept in memory belongs to ONE installation of the extension. DROP EXTENSION and
-- CREATE EXTENSION start the watch ids and phasevec.ivf_gen over; up to 0.16.0 the copy kept from the first
-- installation answered for the second one's watch with the same id and generation, and find_ivf swept the
-- old lists (their rows failed validation, so neighbours went missing without a word).
\set VERBOSITY terse

-- outside the extension, so they outlive it
CREATE FUNCTION code_of(g int, c int) RETURNS smallint[] LANGUAGE sql IMMUTABLE AS $$
    SELECT array(SELECT greatest(-127, least(127, (hashint8(c * 1000 + j) % 100)
                                                + (hashint8(1000000 + g::int8 * 1000 + j) % 60)))::smallint
                   FROM generate_series(1, 256) j) $$;
CREATE FUNCTION signs_of(c smallint[]) RETURNS bit(256) LANGUAGE sql IMMUTABLE AS $$
    SELECT string_agg(CASE WHEN x > 0 THEN '1' ELSE '0' END, '' ORDER BY o)::bit(256)
      FROM unnest(c) WITH ORDINALITY u(x, o) $$;
CREATE TABLE docs (id int PRIMARY KEY, body text);
INSERT INTO docs SELECT g, 'first ' || g FROM generate_series(1, 400) g;

-- the first installation: its index is built and asked once, so a copy of it is kept
CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register('r256', repeat('a', 64), 256) > 0 AS r256;
SELECT phasevec.watch('docs', 'docs'::regclass, 'id', 'r.body', 'r256') > 0 AS watch;
SELECT count(phasevec.record('docs', s.key, 'r256', s.text_hash, 0::bigint, code_of(s.key::int, s.key::int % 10),
                             NULL, signs_of(code_of(s.key::int, s.key::int % 10)))) AS recorded
  FROM phasevec.sources s;
SELECT phasevec.ivf_build('docs') AS lists;
SELECT c.watch, c.gen FROM phasevec.ivf_cents c;
SELECT count(*) AS answered FROM phasevec.find_ivf('docs', 0, code_of(7, 7), 10, false, 400, signs_of(code_of(7, 7)), 4);
DROP EXTENSION pg_phasevec CASCADE;

-- the second installation, in the same session: other texts, other codes, the same watch id and generation
UPDATE docs SET body = 'second ' || id;
CREATE EXTENSION pg_phasevec;
SELECT phasevec.reader_register('r256', repeat('a', 64), 256) > 0 AS r256;
SELECT phasevec.watch('docs', 'docs'::regclass, 'id', 'r.body', 'r256') > 0 AS watch;
SELECT count(phasevec.record('docs', s.key, 'r256', s.text_hash, 0::bigint, code_of(s.key::int, 100 + s.key::int % 10),
                             NULL, signs_of(code_of(s.key::int, 100 + s.key::int % 10)))) AS recorded
  FROM phasevec.sources s;
SELECT phasevec.ivf_build('docs') AS lists;
SELECT c.watch, c.gen FROM phasevec.ivf_cents c;
-- every list probed and m = every row: exactly find's answer, from the new lists
SELECT (SELECT array_agg(key ORDER BY score DESC, key) FROM phasevec.find('docs', 0, code_of(7, 107), 10, false, 400, signs_of(code_of(7, 107))))
     = (SELECT array_agg(key ORDER BY score DESC, key) FROM phasevec.find_ivf('docs', 0, code_of(7, 107), 10, false, 400, signs_of(code_of(7, 107)), 1000))
       AS same_as_find;
SELECT count(*) AS answered FROM phasevec.find_ivf('docs', 0, code_of(7, 107), 10, false, 400, signs_of(code_of(7, 107)), 4);
-- the delta too: a row read after the build is found
INSERT INTO docs VALUES (500, 'second 500');
SELECT count(phasevec.record('docs', s.key, 'r256', s.text_hash, 0::bigint, code_of(7, 107), NULL, signs_of(code_of(7, 107))))
  FROM phasevec.sources s WHERE s.key = '500';
SELECT key FROM phasevec.find_ivf('docs', 0, code_of(7, 107), 2, false, 400, signs_of(code_of(7, 107)), 4) ORDER BY key;

DROP EXTENSION pg_phasevec CASCADE;
DROP TABLE docs;
DROP FUNCTION code_of(int, int);
DROP FUNCTION signs_of(smallint[]);
