-- 0.9.0: phasevec.search() asks the watch's reader through the database. Without a reader it fails with
-- its cause (never an empty answer); a name that could escape the socket directory is refused.
\set VERBOSITY terse
CREATE EXTENSION pg_phasevec;
SELECT extversion FROM pg_extension WHERE extname = 'pg_phasevec';
SELECT phasevec.reader_register('r256', repeat('a', 64), 256) > 0 AS r256;
CREATE TABLE docs (id int PRIMARY KEY, body text);
INSERT INTO docs VALUES (1, 'uno');
SELECT phasevec.watch('docs', 'docs'::regclass, 'id', 'r.body', 'r256') > 0 AS watch;
SET phasevec.socket_dir = '/nonexistent/phasevec';
SELECT * FROM phasevec.search('docs', 'una pregunta');
SELECT * FROM phasevec.search('docs', '   ');
SELECT phasevec._ask('../etc', '{}');
SELECT phasevec._ask('docs', E'{}\n{}');
DROP TABLE docs;
DROP EXTENSION pg_phasevec;
