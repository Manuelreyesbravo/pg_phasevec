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

The build is portable: it adds `-O3` to the server's own `CFLAGS` and nothing tied to the build machine's CPU. `make PHASEVEC_NATIVE=1` adds `-march=native` for a build that only has to run where it was compiled (until 0.19.0 that was the default, and a binary built on a newer CPU could stop with `SIGILL` on an older one).

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
| **Truth** | `assert`, `verify`, `verify_one`, `refute`, `supersede`, `unsupersede`, `disputes`, `recall`, `adopt` (what a row claims, a proof that checks it, and whether it still holds) |
| **Brief** | `brief` (what a watch still holds as true, best first, inside a character budget; text read with the caller's rights) |

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

0.17.0 also fixes the coarse index kept in memory across an extension reinstall: after `DROP EXTENSION` and `CREATE EXTENSION` on a server that had not restarted, the new watch matched the old installation's copy (same watch id, same generation) and `find_ivf` answered short without a word. Every kept copy now carries the installation it belongs to (`test/sql/ivf_reinstall.sql`). The copy shared by the cluster is now kept under a new name (its format changed): upgrading the library leaves the old one in shared memory until the server restarts, so restart after installing 0.17.0 to release it. On PostgreSQL 18 there is no shared copy (it needs `GetNamedDSA`, new in 19): each connection keeps its own, `phasevec.shared_ivf_cache` is `off` and cannot be turned on, and the answers are the same. From 0.10.0 to 0.16.0 the library did not build on PostgreSQL 18 at all; 0.17.0 does, and its suite runs on 18 and 19.

## Security

0.16.0 is a security-hardening release. The SPI cursors that drive index build and maintenance skip rows with a `NULL` code instead of dereferencing it; every count, dimension and probe argument is bounded before it reaches an allocation, and an overflow in `k * dims` is caught; the proof clock cannot re-enter itself; a path built for the reader socket is refused if it would truncate; and the maintenance functions are revoked from `PUBLIC`. The checks have a regression test in `test/sql/security.sql`.

0.20.0 fixes what two reviews of 2026-11-05 found in the truth layer and the coarse index. The second one ran attacks against a first cut of this release, which was never published; what it broke is fixed here too.

* **A verdict is about a claim, and the claim is the text its author read.** `assert()` reads the row through the watch's recipe, with the caller's rights, and records the hash of that text (`truth.asserted_for`) with its author. A verdict judges that text, the proof and the author together, and records a binding of the three (`truth.verified_for`). A writer who edits the row afterwards changes the text, not the claim: the key reads `unproven`, `verify()` does not judge the new text whatever the proof reads, and it is a claim again when its author (or `adopt()`) asserts it again. Until 0.19.0 a row edited after it was verified kept `verified`, and `brief()` served its new text as verified; the first cut verified any new text again when the proof did not read the row (`test/sql/truth_binding.sql`, `test/sql/truth_claim.sql`). An author must be able to read the rows it asserts about.
* **The row is read, not a cache.** `verify()` reads the live row, as the author, before and after the proof. `brief()` hashes the line it serves and serves it as `verified` only if it is the text the verdict judged. `phasevec.sources.text_hash`, kept by the watch trigger, is not evidence: a change the trigger never saw (`ALTER TABLE ... DISABLE TRIGGER`, `session_replication_role = replica`, `TRUNCATE` and a new `INSERT`, `ALTER COLUMN ... TYPE ... USING`, a renamed column with a new one under its name, a hand-edited dump) reads `unproven` in `brief()` and is not verified by `verify()` (`test/sql/truth_claim.sql`, `test/dump_roundtrip.sh`).
* **One state.** Under READ COMMITTED each statement of a proof can see another snapshot. The row's version (`xmin`, `ctid`) is read before and after the proof; if it moved, nothing is recorded and the key stays due. A text that changed and changed back while its proof ran was recorded `verified` for a text the proof never saw (`test/truth_race.sh`).
* **A proof runs as its author, by OID.** `assert()` records its caller's current user (`truth.asserted_by_oid`, and in `truth.asserted_by` the name it had); a `SECURITY DEFINER` wrapper vouches with its owner's rights. `verify()` runs each proof with that role's rights, in a security-restricted operation, only when the caller already holds them; `verify()` skips the others, `verify_one()` refuses them. A dropped author, or one whose name now belongs to another role, runs nothing: the claim reads `unproven` until it is asserted again. A verdict is recorded only for the author it ran as: an `assert()` of the same proof by another role while it runs leaves nothing recorded. Until 0.19.0 a proof ran with the rights of whoever called `verify()` (`test/sql/truth_author.sql`, `test/sql/truth_door.sql`, `test/truth_race.sh`).
* **One door.** `verify()` and `verify_one()` are C: they know who calls them and pass that to the internals, which carry no rights of their own (only the owner can read and write `phasevec.truth`). A verifier other than the owner is granted `verify()` or `verify_one()` and nothing else. The first cut had verifiers granted `SECURITY DEFINER` internals, and with them a verifier forged `verified` and read every proof (`test/sql/truth_door.sql`).
* **The clock bounds the verdict.** Every proof has a clock: `p_timeout_ms` must be above 0, because the cost cap is a planner estimate and not a bound. A verdict counts only if the proof ended inside its clock, so a proof that catches `query_canceled` runs on but is refuted for its time. A proof cannot run another proof. A `query_canceled` that a proof raises itself is that proof's error (it aborted every `verify()` of the watch); the caller's `statement_timeout` and a user's cancel still cancel the statement. A session-level advisory lock a proof takes is released when it ends (`test/sql/truth_deadline.sql`).
* **A proof is one expression, under the cost cap and the clock.** A proof that closed its own parenthesis made two statements: the cost step ran the second one with no clock and no cap. The wrapped proof is now parsed and must be one `SELECT`; a cost that cannot be read is refused; and the proof's clock runs from before the estimate, which can run immutable functions while planning (`test/sql/truth_cost.sql`).
* **Closed to `PUBLIC`, and to the wrong writer.** `_forget()` (callable from any user's own trigger) is the owner's only. The watch trigger notes and forgets through `_note()`, now C: it refuses a caller that does not write the watch's own table (in the first cut whoever was granted `_note()` for one table forgot, rewrote and invented the keys of every other watch). `_brief_keys()` and `brief()` are revoked from `PUBLIC`: whoever may brief is granted both, `GRANT EXECUTE ON FUNCTION phasevec.brief(text, int), phasevec._brief_keys(text) TO <role>;` (`test/sql/privileges.sql`).
* **The coarse index is checked as it loads, and every time it is used.** Every blob of `phasevec.ivf_lists` and `phasevec.ivf_added` is checked for `NULL` and for its exact length, every count for its sign, and every key offset for its place inside the keys, before anything is copied: those rows travel in `pg_dump` since 0.19.0, and a truncated or edited one made the loader read out of bounds. A copy kept in memory (by the connection or shared by the cluster) is checked against its row of `phasevec.ivf_cents` every time it is used, and `ivf_absorb` grows it only if it is the index it read: a row edited under the same version made `ivf_absorb` size its lists from the row and grow the copy with them, a write past the end of a buffer (`test/sql/ivf_blobs.sql`).

**Upgrading from 0.19.0** (`test/sql/upgrade_020.sql`). Every `verified` goes back to `unproven`, with the reason in `last_error`: it was reached with the verifier's rights, about no claim. `refuted` stays refuted, about the text the row has now. Proofs asserted before 0.20.0 have no author and do not run until they are asserted again: `SELECT phasevec.adopt('<watch>');` asserts every one of a watch again as its caller, who becomes their author (run it as the role whose rights the proofs should have; it must read the rows; `adopt` is the owner's to run or to grant). Naming an author in `phasevec.truth` by hand is not enough, a claim is also the text its author read. Calls of `verify()` and `verify_one()` keep working, except with `p_timeout_ms => 0`. Grants on `_brief_keys` are given again with `brief`. A trigger that asserts claims must fire on every column the recipe reads: an edit of a column it does not watch leaves the claim `unproven` until it is asserted again. A database that ran the unpublished first cut of 0.20.0 cannot be updated in place to this one (same version): drop and create the extension, or dump and restore the database (its proofs then wait for `adopt()`).

**Limits.**

* A proof that catches `query_canceled` keeps the verifier's session until it returns, past the caller's `statement_timeout` too (it catches that cancel the same way): the clock decides the verdict, it cannot stop such a proof; `pg_terminate_backend` does. Grant `assert()` only to roles whose code you would run in a verifier's session.
* `assert()` takes its author from whoever calls it. A trigger function that is not `SECURITY DEFINER` runs with the rights of whoever fires it, so its owner can assert in the name of anyone who writes that table, as it can do anything else with those rights: PostgreSQL's own trigger trap. phasevec cannot see who wrote the calling code.
* `_verdict(t)`, for SQL that reads `phasevec.truth` directly, compares the claim with the trigger's cache, not with the row: after a change the trigger never saw it says `verified` until the next `verify()` of the key. `brief()` and `verify()` read the row.
* A restore trusts its dump: a dump edited by hand can also rewrite `phasevec.truth`. After a restore into another cluster the roles have other OIDs, so every proof reads its author as gone until `adopt()`.
* A proof that takes one more hold on an advisory lock its verifier already held leaves it held.
* `assert()`, `verify()` and `brief()` find a row by `key_col::text = key`, without an index.

To report a vulnerability, email **manuelreyesbravo@gmail.com** with a subject starting `[pg_phasevec security]`. Please include the PostgreSQL version, `SELECT extversion FROM pg_extension WHERE extname = 'pg_phasevec'`, and the smallest sequence of statements that shows it.

## License

Apache License 2.0 -- see [LICENSE](LICENSE). Copyright 2026 Manuel Reyes Bravo.
