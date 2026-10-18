-- 0.6.0: how a reader reads is part of what it is.
\set VERBOSITY terse

CREATE EXTENSION pg_muninn;
-- a pooled reader as muninn-reader --register writes it
SELECT muninn.reader_register('q@cpu', repeat('b', 64), 1024, NULL,
    '{"pooling": "last", "ctx": 1024, "query_prefix": "Instruct: find\nQuery: ", "tokens": "t"}',
    jsonb_build_object('backend', 'cpu', 'device', 'd', 'libs', repeat('c', 64))) > 0 AS registered;
-- the same model asking questions another way is another reader
SELECT muninn.reader_register('q-plain@cpu', repeat('b', 64), 1024, NULL,
    '{"pooling": "last", "ctx": 1024, "query_prefix": "", "tokens": "t"}',
    jsonb_build_object('backend', 'cpu', 'device', 'd', 'libs', repeat('c', 64))) > 0 AS another_reader;
-- and cut at another context, another again
SELECT muninn.reader_register('q-512@cpu', repeat('b', 64), 1024, NULL,
    '{"pooling": "last", "ctx": 512, "query_prefix": "", "tokens": "t"}',
    jsonb_build_object('backend', 'cpu', 'device', 'd', 'libs', repeat('c', 64))) > 0 AS another_again;
-- but the same reading under another name is refused
SELECT muninn.reader_register('q-renamed@cpu', repeat('b', 64), 1024, NULL,
    '{"pooling": "last", "ctx": 1024, "query_prefix": "", "tokens": "t", "note": "a label is not a reader"}',
    jsonb_build_object('backend', 'cpu', 'device', 'd', 'libs', repeat('c', 64)));
SELECT name, reads FROM muninn.readers ORDER BY id;

DROP EXTENSION pg_muninn;
