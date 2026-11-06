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
| **Truth** | `assert`, `verify`, `verify_one`, `refute`, `supersede`, `unsupersede`, `disputes`, `recall`, `adopt`, `truth_coverage`, `replacement` (what a row claims, a proof that checks it, and whether it still holds) |
| **Brief** | `brief` (what a watch still holds as true, best first, inside a character budget; for a role that may `SELECT` the watched table) |

Full signatures: `\df phasevec.*`.

## What it guarantees, and what it trusts

* **Guaranteed.** A reading names the reader and the exact text it was taken from. A row changed after it was read is reported as stale, not matched as if fresh; a reading of the old text is refused. Readings from different readers are never compared. A deleted row leaves an orphan reading you can see, not a silent ghost in the index. `find()` refuses below `min_coverage`.
* **Trusted.** The reader is yours. pg_phasevec stores and searches the codes a sealed reader gives it and holds them to that reader's sha; it does not vouch for what the weights behind that sha actually do. Keep the reader sealed and local.
* The maintenance surface (`ivf_build`, `ivf_maintain`, `ivf_maintain_all`, `ivf_absorb`, `counts_compact`, and the internal sweep/delta) is `REVOKE`d from `PUBLIC`. The search functions are `SECURITY DEFINER` with a pinned `search_path` (they do not run with the caller's privileges, as this page said until 0.20.0): `search`, `find`, `find_ivf` and `find_npu` are open to `PUBLIC` and give any role with `USAGE` on the schema the keys, scores and reading states of every watch (not the rows' text, not verdicts); `alike` and `find_hybrid` are revoked from `PUBLIC`. Revoke the open ones from `PUBLIC` where keys are themselves sensitive. What shows verdicts (`recall`, `disputes`, `replacement`, `truth_coverage`, `brief`) shows a watch only to a role that may `SELECT` its table (0.20.0, below).

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

0.20.0 fixes what four reviews of 2026-11-05 found in the truth layer and the coarse index. The last three ran attacks against three cuts of this release, which were never published; what they broke is fixed here too. The third one's findings came from one root -- phasevec ran code that was not its own (a watch's recipe, a proof) in more than one way, some of them with the rights or the settings of whoever happened to call it -- and there is now one way (`src/phasevec_guard.c`):

* **One guard for code that is not phasevec's, and it is a sealed room.** A recipe and a proof run in a subtransaction of their own, always rolled back, as one named role, in a security-restricted operation, read-only. Nothing that existed before the guard is in reach. The session's open cursors: the ones `pg_cursors` lists are frozen while it runs (PostgreSQL itself then refuses to run or close them), a query begun before it cannot be run inside it, and `FETCH`, `MOVE` and `CLOSE` take only cursors opened inside it. Of the commands only `SET`, `SHOW`, `EXPLAIN`, `DECLARE`, `FETCH`, `MOVE`, `CLOSE`, `CALL` and `DO` run (`NOTIFY`, `LISTEN`, `PREPARE`, `DEALLOCATE`, `DISCARD`, `LOAD` and the rest are refused). Of the system's own functions every one that only reads (stable or immutable) runs, and of the volatile ones only a reviewed few: the clock, `pg_sleep`, random numbers, `set_config`, transaction-level advisory locks (all of them end with the guard's rollback). `pg_notify`, session-level advisory locks, `setseed`, `currval` and `lastval`, the large-object descriptors, `pg_cancel_backend`, `pg_terminate_backend` and every other volatile system function are refused, and so are `pg_cursor` and `pg_prepared_statement`, which read the session's own statements. The session's timeouts (`transaction_timeout`, `statement_timeout`, `lock_timeout`, `idle_in_transaction_session_timeout`, `idle_session_timeout`) and `exit_on_error` cannot be changed, by `set_config`, `SET`, or a function's `SET` clause. In the second cut a proof set `transaction_timeout` and ended the verifier's connection with a `FATAL` before any verdict was written, so every later `verify()` of the watch died the same way; another released the verifier's own advisory locks; another chose its `random()` seed. In the third, which had no subtransaction for a recipe, a table owner's recipe read a superuser's open cursor over a table the owner could not read and sent the rows out with `NOTIFY`, delivered at the superuser's `COMMIT` (in `brief()`, and in the watch trigger of every writer); and a proof read, used up and printed in its error the verifier's open cursor (`test/sql/truth_guard.sql`, `test/sql/truth_sealed.sql`).
* **A recipe renders one text: as the table's owner, at default settings.** The watch trigger, `watch()`, `assert()`, `verify()`, `brief()`, `next()`, `lexical()` and `audit_sample()` all read a row's text through `phasevec._render()`: the recipe runs as the owner of the watched table (as PostgreSQL runs an index expression in `VACUUM` or `REINDEX`), with every setting that can change what a value reads, prints or computes at its built-in default (below) and these pinned on top: `DateStyle` ISO, `IntervalStyle` postgres, `TimeZone` UTC, `extra_float_digits` 1, `bytea_output` hex, `search_path` `pg_catalog, pg_temp`, `lc_monetary`/`lc_numeric`/`lc_time` C, `standard_conforming_strings` on, `xmloption` content, `xmlbinary` base64, `timezone_abbreviations` Default, `row_security` on. `FORCE ROW LEVEL SECURITY` does not apply to the owner there (as for a foreign-key check): in the third cut a watch over such a table rendered no row at all, or the rows a custom setting of whoever called selected. Who may read that text is the reader's own right: `SELECT` on the table, and with row-level security only the rows it sees (found as the reader, in the guard, with the reader's own settings). In the second cut `brief()` ran the recipe as its caller with full rights: a table owner swapped a column's type for one whose cast was its own code, and a superuser reading the brief made it superuser. And a row's text depended on the session that read it: a writer in another `TimeZone` edited a row so that it printed as the text its author had vouched for, and `brief()` served it `verified`.
* **A proof means what it meant to its author.** `assert()` records, in `truth.proof_env`, every setting of the author's session that can change what a value reads, prints or computes and is off its built-in default: every setting a user can set (and `RESET ALL` resets) of the groups statement behavior, locale and formatting, other client defaults and compatibility, and every custom setting (`app.tenant`, an extension's). The proof runs with every such setting at its default and the recorded ones on top, so the verifier's own decide nothing. Not recorded: resources, the planner, logging, statistics, replication and connections (they change how fast, not what), the session's timeouts, `client_encoding`, `client_min_messages`, `lc_messages`, `dynamic_library_path` and `extension_control_path`. In the second cut a verifier in another `DateStyle` read the author's `'01/11/2026'` as 11 January and recorded `verified` for a date the proof, as written, refutes; the third recorded twelve named settings, and a verifier's `default_text_search_config`, `timezone_abbreviations`, `transform_null_equals`, `row_security`, or the custom setting a row-level security policy read, decided the verdict (`test/sql/truth_sealed.sql`).
* **A proof that ends its verifier's session is that claim's failure, not the watch's.** A proof is marked in shared memory (its watch, its key, its claim) while it runs; the next `verify()` of the watch that finds the mark of a session that is gone records that claim `refuted` (`truth.halted`) and does not run it again until it is asserted again. In the third cut the mark had no key, and one ended session halted every claim of the watch whose text, proof and author read alike; and of more than eight ended sessions the ninth mark was dropped, and its claim ran again (`test/truth_race.sh`).


* **A verdict is about a claim, and the claim is the text its author read.** `assert()` reads the row through the watch's recipe (rendered as above) and records the hash of that text (`truth.asserted_for`) with its author. A verdict judges that text, the proof, the author and its settings together, and records a binding of the four (`truth.verified_for`). A writer who edits the row afterwards changes the text, not the claim: the key reads `unproven`, `verify()` does not judge the new text whatever the proof reads, and it is a claim again when its author (or `adopt()`) asserts it again. Until 0.19.0 a row edited after it was verified kept `verified`, and `brief()` served its new text as verified; the first cut verified any new text again when the proof did not read the row (`test/sql/truth_binding.sql`, `test/sql/truth_claim.sql`). An author must be able to `SELECT` the table it asserts about (and, with row-level security, see the row), at `assert()` and at every `verify()`.
* **The row is read, not a cache.** `verify()` reads the live row before and after the proof, each time with a new snapshot. `brief()` hashes the line it serves and serves it as `verified` only if it is the text the verdict judged. `phasevec.sources.text_hash`, kept by the watch trigger, is not evidence: a change the trigger never saw (`ALTER TABLE ... DISABLE TRIGGER`, `session_replication_role = replica`, `TRUNCATE` and a new `INSERT`, `ALTER COLUMN ... TYPE ... USING`, a renamed column with a new one under its name, a hand-edited dump) reads `unproven` in `brief()` and is not verified by `verify()` (`test/sql/truth_claim.sql`, `test/dump_roundtrip.sh`).
* **One state.** Under READ COMMITTED each statement of a proof can see another snapshot. The row's version (`xmin`, `ctid`) is read before and after the proof; if it moved, nothing is recorded and the key stays due. A text that changed and changed back while its proof ran was recorded `verified` for a text the proof never saw (`test/truth_race.sh`). `verify()` and `verify_one()` judge at READ COMMITTED only (each proof in a new snapshot), and `verified_at` is when the row was read for the verdict: in the third cut a verifier in a REPEATABLE READ transaction judged every proof against its first snapshot and recorded the verdicts as reached then (`test/sql/truth_sealed.sql`).
* **A proof runs as its author, by OID.** `assert()` records its caller's current user (`truth.asserted_by_oid`, and in `truth.asserted_by` the name it had); a `SECURITY DEFINER` wrapper vouches with its owner's rights. `verify()` runs each proof with that role's rights, in the guard, only when the caller already holds them; `verify()` skips the others, `verify_one()` refuses them. A dropped author, or one whose name now belongs to another role, runs nothing: the claim reads `unproven` until it is asserted again. A verdict is recorded only for the author it ran as: an `assert()` of the same proof by another role while it runs leaves nothing recorded. Until 0.19.0 a proof ran with the rights of whoever called `verify()` (`test/sql/truth_author.sql`, `test/sql/truth_door.sql`, `test/truth_race.sh`).
* **One door.** `verify()` and `verify_one()` are C: they know who calls them and pass that to the internals, which carry no rights of their own (only the owner can read and write `phasevec.truth`). A verifier other than the owner is granted `verify()` or `verify_one()` and nothing else. The first cut had verifiers granted `SECURITY DEFINER` internals, and with them a verifier forged `verified` and read every proof (`test/sql/truth_door.sql`).
* **The clock bounds the verdict.** Every proof has a clock: `p_timeout_ms` must be above 0, because the cost cap is a planner estimate and not a bound. A verdict counts only if the proof ended inside its clock, so a proof that catches `query_canceled` runs on but is refuted for its time. A proof cannot run another proof. A `query_canceled` that a proof raises itself is that proof's error (it aborted every `verify()` of the watch); the caller's `statement_timeout` and a user's cancel still cancel the statement. A session-level advisory lock a proof takes is released when it ends (`test/sql/truth_deadline.sql`).
* **A proof is one expression, under the cost cap and the clock.** A proof that closed its own parenthesis made two statements: the cost step ran the second one with no clock and no cap. The wrapped proof is now parsed and must be one `SELECT`; a cost that cannot be read is refused; and the proof's clock runs from before the estimate, which can run immutable functions while planning (`test/sql/truth_cost.sql`).
* **Closed to `PUBLIC`, and to the wrong writer.** `_forget()` (callable from any user's own trigger) is the owner's only. The watch trigger (`phasevec._observe()`) is C: it renders the row it fires for, and refuses to run on any table but its watch's. `_note()`, which took a key and a hash from whoever called it, is gone: in the first cut whoever was granted it for one table forgot, rewrote and invented the keys of every other watch, and in the second a writer limited by row-level security, or holding `UPDATE` on one unrelated column, did it to every key of its own watch. `recall()`, `disputes()`, `replacement()` and `truth_coverage()` are one C door that shows a watch only to a role that may `SELECT` its table, and with row-level security it computes over the rows that role sees, so no field carries another (in the third cut `recall()`'s `disputed_by` named keys of hidden rows, and `replacement()` followed a chain through a hidden row and showed its reason; `truth_coverage()` now counts that role's rows); until 0.20.0 any role with `USAGE` on the schema read every watch's keys, verdicts, topics, reasons and support through them. `brief()` is the same kind of door; it is revoked from `PUBLIC` and granted alone (`_brief_keys()` is its internal, the owner's) (`test/sql/privileges.sql`, `test/sql/truth_guard.sql`, `test/sql/truth_sealed.sql`). A watch's key is a column with a unique index of its own: in the third cut two rows could share a key, and a writer limited by row-level security, deleting its own row, forgot the other's key and its verdict.
* **The coarse index is checked as it loads, and every time it is used.** Every blob of `phasevec.ivf_lists` and `phasevec.ivf_added` is checked for `NULL` and for its exact length, every count for its sign, and every key offset for its place inside the keys, before anything is copied: those rows travel in `pg_dump` since 0.19.0, and a truncated or edited one made the loader read out of bounds. A copy kept in memory (by the connection or shared by the cluster) is checked against its row of `phasevec.ivf_cents` every time it is used, and `ivf_absorb` grows it only if it is the index it read: a row edited under the same version made `ivf_absorb` size its lists from the row and grow the copy with them, a write past the end of a buffer (`test/sql/ivf_blobs.sql`).

**Upgrading from 0.19.0** (`test/sql/upgrade_020.sql`). Every `verified` goes back to `unproven`, with the reason in `last_error`: it was reached with the verifier's rights, about no claim. `refuted` stays refuted, about the text the row has now. Every row of every watch is rendered again in the pinned settings; a text that reads otherwise now (a recipe that prints a date, a time, a float or a money value, or calls a function the table's owner may not run) is noted again: its reading turns stale and its verdict `unproven`. The upgrade fails if a recipe cannot run as its table's owner, read-only. Proofs asserted before 0.20.0 have no author and do not run until they are asserted again. `phasevec.adopt(watch, author)` asserts them again in the name of the role it is given: the caller must hold that role's privileges (be it, `SET ROLE` to it, or be granted it); it is the owner's to run or to grant; it returns every proof with its former author; and a superuser becomes the author only of the keys named in `p_superuser_keys` (an orphaned proof may be anyone's SQL, and a role can orphan its own on purpose). Adopt as the least-privileged role that can read what the proofs read. Naming an author in `phasevec.truth` by hand is not enough, a claim is also the text its author read. Calls of `verify()` and `verify_one()` keep working, except with `p_timeout_ms => 0`. `brief()` is granted alone; grants on `_brief_keys` are gone. A trigger of your own that asserts claims must fire on every column the recipe reads: an edit of a column it does not watch leaves the claim `unproven` until it is asserted again. A recipe that writes, or that the table's owner cannot run, now fails wherever it runs, including in the watch trigger on every write to the table. A database that ran an unpublished cut of 0.20.0 cannot be updated in place to this one (same version): drop and create the extension, or dump and restore the database (its proofs then wait for `adopt()`). **Reconnect after the update** (or restart the server): a session that loaded the library of 0.19.0 keeps it, and the new watch trigger is not in it. Its writes to a watched table are refused with a message that says so (the trigger is in a library of its own, `pg_phasevec_observe`, installed with the extension, which no older session has loaded); its calls of the new C functions (`verify()`, `brief()`, `recall()`, ...) fail with "could not find function" (`test/upgrade_reconnect.sh`). The update warns about every watch whose key column has no unique index of its own: it keeps working, but add one. A proof or a recipe that called a volatile system function outside the reviewed list (`nextval`, `currval`, `txid_current`, `pg_read_file`, ...), ran a command other than those above, or read a cursor its caller had open, now fails (a proof is refuted with the reason). A watch over a table with `FORCE ROW LEVEL SECURITY` now renders every row (as the owner, without the policies).

**Limits.**

* A proof that catches `query_canceled` keeps the verifier's session until it returns, past the caller's `statement_timeout` too (it catches that cancel the same way): the clock decides the verdict, it cannot stop such a proof; `pg_terminate_backend` does. Grant `assert()` only to roles whose code you would run in a verifier's session.
* `assert()` takes its author from whoever calls it. A trigger function that is not `SECURITY DEFINER` runs with the rights of whoever fires it, so its owner can assert in the name of anyone who writes that table, as it can do anything else with those rights: PostgreSQL's own trigger trap. phasevec cannot see who wrote the calling code.
* `_verdict(t)`, for SQL that reads `phasevec.truth` directly, compares the claim with the trigger's cache, not with the row: after a change the trigger never saw it says `verified` until the next `verify()` of the key. `brief()` and `verify()` read the row.
* A restore trusts its dump: a dump edited by hand can also rewrite `phasevec.truth`. After a restore into another cluster the roles have other OIDs, so every proof reads its author as gone until `adopt()`.
* The guard refuses functions when an expression is set up (PostgreSQL's function-execute hook). A PL/pgSQL expression the verifier's own transaction already ran, before `verify()`, is cached without that check: a proof that reaches that same cached expression is not refused. Functions that are not the system's (an extension's C function such as `dblink`) are not classified: they run with the role's rights. `random()` draws from the session's generator, so a proof moves the verifier's sequence (it cannot seed it).
* A cursor a client opened through the extended protocol (a named portal, as JDBC uses with a fetch size) is not listed by `pg_cursors`: the guard refuses to run its query, but rows it already holds in memory (a portal over `INSERT ... RETURNING` read in part) can be read by a proof, and a proof can close it.
* The settings a proof does not take from its author (resources, the planner, `max_stack_depth`, `work_mem`, the session's timeouts) are the verifier's: they can decide whether a proof runs out of memory, stack or time (refuted), not what it computes.
* Cost: every recipe or proof runs in a subtransaction of its own with its settings set. On a watch of 980 proofs `verify()` takes ~55 ms (0.19.0: ~30 ms) and `brief()` ~19 ms (0.19.0: ~24 ms). The watch trigger renders each written row in its own guard: an `UPDATE` of 1000 watched rows takes ~230 ms (0.19.0, which noted the row in PL/pgSQL without a guard: ~45 ms).
* `assert()`, `verify()`, `brief()` and the rest find a row by `key_col::text = key`, through the key column's index when its type is an integer, `oid`, `numeric` or `uuid`, by a scan otherwise.
* A recipe sees, beyond its row, what the table's owner may see (a subquery in it runs with the owner's rights), and its text goes to any role that may `SELECT` the table.
* The mark of a proof whose session ended lives in shared memory: a server crash (not a session's `FATAL`) loses it, and the claim runs again.
* A proof whose author is a superuser runs as a superuser: read-only and security-restricted, but with every right to read. Adopt orphaned proofs with a role of your choosing, not as the owner by default.
* A verifier that may act as an author runs that author's code: grant `assert()` only to roles whose code you would run in a verifier's session.

To report a vulnerability, email **manuelreyesbravo@gmail.com** with a subject starting `[pg_phasevec security]`. Please include the PostgreSQL version, `SELECT extversion FROM pg_extension WHERE extname = 'pg_phasevec'`, and the smallest sequence of statements that shows it.

## License

Apache License 2.0 -- see [LICENSE](LICENSE). Copyright 2026 Manuel Reyes Bravo.
