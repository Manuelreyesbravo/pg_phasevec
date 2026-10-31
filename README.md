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
| **Recall** | `recall_approve`, `recall_check` (is a watch still served the neighbours it was approved with?) |

Full signatures: `\df phasevec.*`.

## What it guarantees, and what it trusts

* **Guaranteed.** A reading names the reader and the exact text it was taken from. A row changed after it was read is reported as stale, not matched as if fresh; a reading of the old text is refused. Readings from different readers are never compared. A deleted row leaves an orphan reading you can see, not a silent ghost in the index. `find()` refuses below `min_coverage`.
* **Trusted.** The reader is yours. pg_phasevec stores and searches the codes a sealed reader gives it and holds them to that reader's sha; it does not vouch for what the weights behind that sha actually do. Keep the reader sealed and local.
* The maintenance surface (`ivf_build`, `ivf_maintain`, `ivf_maintain_all`, `ivf_absorb`, `counts_compact`, and the internal sweep/delta) is `REVOKE`d from `PUBLIC`; the read and search functions run with the caller's own privileges.

## Watching its own recall

A search does not fail when it degrades: `find_ivf` and `find` keep returning k plausible rows. Since 0.17.0 pg_phasevec measures what a watch is actually served and compares it with a baseline its owner approved.

```sql
-- served by the coarse index with nprobe 16 and m 200 (the defaults), 200 sampled rows, recall@10
SELECT phasevec.recall_approve('docs');
-- served by find with m 1000 (a watch without a coarse index picks find by itself)
SELECT phasevec.recall_approve('notes', p_m => 1000, p_via => 'find');

SELECT watch, verdict, baseline, current, drift, k, sample, via, nprobe, m FROM phasevec.recall_check();
```

* **What it measures.** Each sampled row asks with its own reading (and is left out of both answers). What is served is the path stored at approval: `find_ivf` with its `m` and `nprobe`, or `find` with its `m`. The truth is `find` with `m` = every live reading of the watch -- `find` prefilters by Hamming distance and rescores only `m` candidates, so with a small `m` it is not exact. recall@k is the share of the true top-k the served top-k holds, counted by score (two rows with equal codes are not a miss), rounded to four decimals.
* **Verdicts**, with pg_recall_guard's bands: `ok` if `current >= baseline - 0.02`, `degraded` if `>= baseline - 0.10`, `critical` below. A watch that cannot be measured -- no baseline, no such watch, no coarse index for `find_ivf`, its reader switched, more than half of the sample deleted, changed or superseded -- is a row with verdict `COULD NOT MEASURE: <why>`, never an exception. Both searches run with `p_partial => true`: a watch below `min_coverage` is measured on what is read.
* **The settings are the stored ones.** Lowering `nprobe` or `m` in a session changes nothing; the check degrades when the data or the index does. Measured: a watch served by `find` with `m` 50 reads 1.0 at 500 rows and 0.76 at 1000 (more rows behind the same `m`); new rows absorbed into lists trained without them read degraded; an index rebuilt with far too many lists for its `nprobe` reads critical. Rebuilding, or serving with a larger `m` and approving that, reads `ok` again.
* **Who may.** All three functions are `SECURITY DEFINER` with a pinned `search_path` and revoked from `PUBLIC`, as is `phasevec.recall_baseline`. A monitoring role gets the check and nothing else: `GRANT USAGE ON SCHEMA phasevec TO monitor; GRANT EXECUTE ON FUNCTION phasevec.recall_check(text) TO monitor;`.
* **Limits.** The truth is `find` over every live reading, so a check costs about `sample x rows` cosine scores (here ~30 us per row per question: 2000 rows, 200 questions, ~12 s); size `p_sample` to it, and keep the tables analyzed -- without statistics the same check ran ~20x slower. `find` takes at most `m` = 100000: above 100000 live readings the truth is itself prefiltered and the guard can read better than what is served. The sample is a set of keys: re-approve when most of it is gone.

0.17.0 also fixes the coarse index kept in memory across an extension reinstall: after `DROP EXTENSION` and `CREATE EXTENSION` on a server that had not restarted, the new watch matched the old installation's copy (same watch id, same generation) and `find_ivf` answered short without a word. Every kept copy now carries the installation it belongs to (`test/sql/ivf_reinstall.sql`). The copy shared by the cluster is now kept under a new name (its format changed): upgrading the library leaves the old one in shared memory until the server restarts, so restart after installing 0.17.0 to release it.

## Security

0.16.0 is a security-hardening release. The SPI cursors that drive index build and maintenance skip rows with a `NULL` code instead of dereferencing it; every count, dimension and probe argument is bounded before it reaches an allocation, and an overflow in `k * dims` is caught; the proof clock cannot re-enter itself; a path built for the reader socket is refused if it would truncate; and the maintenance functions are revoked from `PUBLIC`. The checks have a regression test in `test/sql/security.sql`.

To report a vulnerability, email **manuelreyesbravo@gmail.com** with a subject starting `[pg_phasevec security]`. Please include the PostgreSQL version, `SELECT extversion FROM pg_extension WHERE extname = 'pg_phasevec'`, and the smallest sequence of statements that shows it.

## License

Apache License 2.0 -- see [LICENSE](LICENSE). Copyright 2026 Manuel Reyes Bravo.
