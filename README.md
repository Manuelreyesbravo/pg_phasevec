# pg_phasevec

**Readings with provenance: what a sealed reader understood of each row, and whether it still holds.**

Vector search over a table has a quiet failure mode. The embedding was computed once, the row changed, and the index now answers from a memory of a row that no longer exists -- and nothing says so. pg_phasevec makes that visible. It stores, for each row, the code a sealed reader produced *together with the hash of the exact text it read and the identity of the reader that read it*. You search by meaning, and every answer tells you whether the reading it matched still holds for the row as it is now, or whether the row moved underneath it.

No cloud API and no network call: the reader is yours and local, and the codes live in your database next to the rows they describe.

## Why

A reading in pg_phasevec carries three things a bare embedding does not:

* **who read it** -- a reader is identified by the sha256 of its weights (adapter and heads included) and the compute it runs on. Readings taken by different readers are never compared, so swapping a model does not silently mix two coordinate systems.
* **what it read** -- the hash of the exact text. A row edited after it was read becomes **stale**: it is not searched, and it is never returned as a confident wrong answer. A reading of text that is no longer there is refused.
* **when** -- so the age of the memory is a column, not a guess.

## The model

* A **reader** is sealed. `reader_register(name, model_sha256, dims)` records what it is; a trained reader carries a manifest (base, adapter and heads shas, pooling, MRL dims) sealed by whoever serves it.
* A **watch** is what must be findable: a source table, its key column, and one named recipe for the text to read (an expression over each row). `find()` refuses to answer below the watch's `min_coverage`, so a half-filled index does not quietly answer from the rows it happens to have.
* A **reading** is what a reader understood of a row: the hash of the text, its codes, and when. Each one has a state -- pending, fresh, stale, foreign (a different reader), orphan (the row is gone), or failed (the reader said why) among them -- and coverage() shows the spread.

## Install

```sh
make PG_CONFIG=/path/to/pg_config
make install PG_CONFIG=/path/to/pg_config
```
```sql
CREATE EXTENSION pg_phasevec;
```

PostgreSQL 18 or newer. No other extension is required.

## A walk through it

```sql
CREATE EXTENSION pg_phasevec;

-- 1. Seal a reader by the sha256 of its weights and its dimensionality.
SELECT phasevec.reader_register('vec', '<model_sha256>', 1024);

CREATE TABLE docs (id int PRIMARY KEY, body text);
INSERT INTO docs VALUES (1, 'apple'), (2, 'banana'), (3, 'cherry');

-- 2. Watch the table: read the expression `r.body` of each row, keyed by `id`.
SELECT phasevec.watch('docs', 'docs'::regclass, 'id', 'r.body', 'vec');

-- 3. Fill it. next() hands out the rows that still need reading, each with the hash
--    of its exact text; the sealed reader turns each into codes (a 64-bit sketch and
--    a per-dimension code); record() stores them against that hash.
SELECT phasevec.record('docs', key, 'vec', text_hash, code64, code)
  FROM phasevec.next('docs') AS r,  -- key, body, text_hash
       LATERAL your_reader(r.body) AS codes(code64, code);

-- 4. Ask in words: the watch's reader reads the question, and phasevec answers in
--    your own snapshot, never from stale text.
SELECT key, score, state, read_at
  FROM phasevec.search('docs', 'which fruit is red?', 10);

-- ...or query with codes you computed yourself:
SELECT key, score, hamming, state
  FROM phasevec.find('docs', <q64>, ARRAY[/* per-dimension query code */]::smallint[], 10);

-- rows like a given one:
SELECT key FROM phasevec.alike('docs', '2', 5);
```

Edit a watched row and its reading turns `stale` in the same transaction; `find()` then withholds it, or returns a partial answer only when the caller asks for one with `p_partial => true`. Point the watch at a new reader with `reader_switch()` and every old reading becomes `foreign` -- coverage drops, and nothing from the old reader is mixed in.

## The surface

| | |
|---|---|
| **Readers** | `reader_register`, `reader_seal`, `reader_compute`, `reader_switch` |
| **Fill** | `watch`, `next`, `record`, `record_audit`, `record_failure` |
| **Search** | `search` (by words), `find` / `find_ivf` (by codes), `find_hybrid` (vector + lexical), `alike` (rows like a key) |
| **Index** | `ivf_build`, `ivf_maintain`, `ivf_maintain_all`, `ivf_absorb` |
| **Lexical** | `lexical`, `lexical_maintain`, `lexical_refresh` |
| **Audit** | `coverage`, `coverage_check`, `truncations`, `dupes`, `audit_sample`, `counts_compact` |

Full signatures: `\df phasevec.*`.

## What it guarantees, and what it trusts

* **Guaranteed.** A reading names the reader and the exact text it was taken from. A row changed after it was read is reported as stale, not matched as if fresh; a reading of the old text is refused. Readings from different readers are never compared. A deleted row leaves an orphan reading you can see, not a silent ghost in the index. `find()` refuses below `min_coverage`.
* **Trusted.** The reader is yours. pg_phasevec stores and searches the codes a sealed reader gives it and holds them to that reader's sha; it does not vouch for what the weights behind that sha actually do. Keep the reader sealed and local.
* The maintenance surface (`ivf_build`, `ivf_maintain`, `ivf_maintain_all`, `ivf_absorb`, `counts_compact`, and the internal sweep/delta) is `REVOKE`d from `PUBLIC`; the read and search functions run with the caller's own privileges.

## Security

0.16.0 is a security-hardening release. The SPI cursors that drive index build and maintenance skip rows with a `NULL` code instead of dereferencing it; every count, dimension and probe argument is bounded before it reaches an allocation, and an overflow in `k * dims` is caught; the proof clock cannot re-enter itself; a path built for the reader socket is refused if it would truncate; and the maintenance functions are revoked from `PUBLIC`. The checks have a regression test in `test/sql/security.sql`.

To report a vulnerability, email **manuelreyesbravo@gmail.com** with a subject starting `[pg_phasevec security]`. Please include the PostgreSQL version, `SELECT extversion FROM pg_extension WHERE extname = 'pg_phasevec'`, and the smallest sequence of statements that shows it.

## License

Apache License 2.0 -- see [LICENSE](LICENSE). Copyright 2026 Manuel Reyes Bravo.
