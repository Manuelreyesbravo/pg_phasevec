# pg_phasevec

**Readings with provenance for PostgreSQL: what a sealed reader understood of each row, and
whether it still holds.**

> **Status: 0.20.0, a 0.x preview.** pg_phasevec is research software by one author, offered for
> evaluation by people comfortable reading PostgreSQL extensions. Its interfaces and on-disk
> layout can still change between 0.x releases, and it has known open issues, listed under
> [Known limits](#known-limits). Do not put data you cannot rebuild behind it yet. Reports and
> attacks are welcome: [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md).

Vector search over a table has a quiet failure mode. The embedding was computed once, the row
changed, and the index now answers from a memory of a row that no longer exists, and nothing says
so. pg_phasevec makes that visible. It stores, next to each row of a watched table, the codes a
local embedding model (a *sealed reader*, identified by the sha256 of its weights) produced for
that row, together with the hash of the exact text it read. Searches (exact, IVF, hybrid with
full-text) answer only from readings that still match the row: a row edited after it was read is
reported `stale`, readings of different models are never mixed, and a search refuses to answer
below a declared coverage.

An optional *truth* layer lets roles attach SQL proofs ("claims") to rows. A background worker
re-checks each proof as its author, and `brief()` serves only what still holds.

C and SQL; no other extension, no network call. The reader is yours and runs locally.

## Contents

* [Status: what this preview is](#status-what-this-preview-is)
* [The model](#the-model)
* [Install](#install)
* [A walk through it](#a-walk-through-it)
* [The surface](#the-surface)
* [Claims and proofs](#claims-and-proofs)
* [Watching its own recall](#watching-its-own-recall)
* [Upgrading](#upgrading)
* [Backup, restore and copies](#backup-restore-and-copies)
* [Known limits](#known-limits)
* [Project](#project)

## Status: what this preview is

**For whom.** Teams running retrieval (RAG) or agent memory inside PostgreSQL who need to know
whether an answer still reflects the data, and reviewers who want to attack that claim.

**What it promises**, in plain words:

* A reading names the reader that took it and the exact text it was taken from. A row changed
  after it was read is reported `stale` and is not searched; a reading of text that is no longer
  there is refused. Readings from different readers are never compared. A deleted row leaves an
  `orphan` reading you can see. `find()` refuses to answer below the watch's `min_coverage`.
* A claim's proof runs as its author, read-only, in a background worker of its own, under a cost
  cap and a clock. A verdict is about the text the author read and the row the claim was made on;
  when either changes, the claim reads `unproven` until it is judged again.
* What shows claims (`brief`, `recall`, `disputes`, `replacement`, `truth_coverage`) shows a watch
  only to a role that may `SELECT` its table, and under row-level security only the rows that
  role sees.

**The threat model.** The database's superusers, the extension's owner and the owners of watched
tables are trusted. The reader is trusted: pg_phasevec holds codes to the sha of the weights that
produced them, but it does not vouch for what those weights do. Ordinary roles are not trusted:
an author, a tenant under row-level security, or a role with `USAGE` on the schema should not be
able to change another role's claims, see rows its policies hide through phasevec, or make a
verdict say what its proof does not. A copy of the cluster's files is trusted like the cluster:
see [Backup, restore and copies](#backup-restore-and-copies).

**What it is not.** Not a vector index for very large corpora (the coarse IVF index is simple and
in memory), not a model server, not a certified or audited product. The multi-tenant rules for
who may change a claim are the newest and least settled part; if your authors do not trust each
other, read [Known limits](#known-limits) first.

**Tested on** PostgreSQL 18 and 19 (CI and the suites in `test/`). Newer versions are untested.

## The model

* A **reader** is sealed. `reader_register(name, model_sha256, dims)` records what it is; a
  trained reader carries a manifest (base, adapter and heads shas, pooling, Matryoshka dims)
  sealed by whoever serves it.
* A **watch** is what must be findable: a source table, its key column, and one *recipe* for the
  text to read (an SQL expression over the row `r`). `find()` refuses to answer below the watch's
  `min_coverage`, so a half-filled index does not quietly answer from the rows it happens to have.
* A **reading** is what a reader understood of a row: the hash of the text, its codes, and when.
  Each one has a state (`pending`, `fresh`, `stale`, `foreign` for another reader, `orphan` when
  the row is gone, `failed` when the reader said why, among others), and `coverage()` shows the
  spread.

## Install

```sh
make PG_CONFIG=/path/to/pg_config
make install PG_CONFIG=/path/to/pg_config
```
```sql
CREATE EXTENSION pg_phasevec;
```

* PostgreSQL 18 or 19 with its server headers, a C compiler and `make`. No other extension, no
  `shared_preload_libraries`.
* A **UTF8** database: `CREATE EXTENSION` refuses any other encoding.
* `verify()` and `verify_one()` judge each proof in a background worker: they need free slots of
  `max_worker_processes` (8 by default, shared with parallel query and logical replication):
  `verify_one()` one, `verify()` two at a time.
* The build is portable: it adds `-O3` to the server's own `CFLAGS` and nothing tied to the build
  machine's CPU. `make PHASEVEC_NATIVE=1` adds `-march=native` for a binary that only has to run
  where it was built.
* `reader/` holds a reference reader process (C++ over llama.cpp, `reader/build.sh`). It is not
  needed to build, install or test the extension; `search()` and `recall()` need a reader like it
  listening on `<phasevec.socket_dir>/<watch>.sock`.

**Supported tables.** A watch reads a plain table (not partitioned, not a partition, no
inheritance) by a key column with a unique btree index of its own, enforced at once: a
`PRIMARY KEY` or `UNIQUE` constraint on that column alone, not `DEFERRABLE`, with no predicate
and no expression. `watch()` refuses anything else and says why; DDL that later breaks it is
caught on the next read, which refuses until the table is back in shape.

## A walk through it

On a throwaway database. No model is needed: a toy SQL function stands in for the reader.

```sql
CREATE EXTENSION pg_phasevec;

-- 1. A reader, sealed by the sha256 of its weights (a fake one here) and its dimensions.
SELECT phasevec.reader_register('toy', repeat('a', 64), 4);

-- 2. Watch a table: read the expression r.body of each row, keyed by id.
CREATE TABLE docs (id int PRIMARY KEY, body text);
INSERT INTO docs VALUES (1, 'apple'), (2, 'banana'), (3, 'cherry');
SELECT phasevec.watch('docs', 'docs'::regclass, 'id', 'r.body', 'toy');

-- 3. Fill it. next() hands out the rows that need reading, each with the hash of its exact
--    text; the reader turns each into codes (a 64-bit sketch and a per-dimension code);
--    record() stores them against that hash. Here the "reader" is hand-made codes.
CREATE FUNCTION toy_reader(body text, OUT code64 bigint, OUT code smallint[])
LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE body WHEN 'apple' THEN 1 WHEN 'banana' THEN 2 ELSE 4 END::bigint,
         CASE body WHEN 'apple'  THEN ARRAY[100,0,0,0]
                   WHEN 'banana' THEN ARRAY[0,100,0,0]
                   ELSE ARRAY[0,0,100,0] END::smallint[] $$;
SELECT count(phasevec.record('docs', n.key, 'toy', n.text_hash, c.code64, c.code))
  FROM phasevec.next('docs') n, toy_reader(n.body) c;
SELECT state, n, share FROM phasevec.coverage('docs') WHERE n > 0;      -- fresh 3

-- 4. Search with codes (a question read by the same reader).
SELECT key, round(score::numeric, 4) AS score, state
  FROM phasevec.find('docs', 1, ARRAY[90,10,0,0]::smallint[], 3);      -- key 1 first

-- 5. Change a row: its reading is stale at once, and the search says so.
UPDATE docs SET body = 'apricot' WHERE id = 1;
SELECT key, state FROM phasevec.reading_states ORDER BY key;            -- 1 stale
SELECT key FROM phasevec.find('docs', 1, ARRAY[90,10,0,0]::smallint[], 3);
-- ERROR:  phasevec: watch docs covers 66.7% of its rows and declared 95.0%: stale 33.3%
SELECT key, state
  FROM phasevec.find('docs', 1, ARRAY[90,10,0,0]::smallint[], 3, p_partial => true);
```

With a real reader running, `phasevec.search('docs', 'which fruit is red?', 10)` asks in words:
the watch's reader reads the question and phasevec answers from fresh readings only.
`reader_switch()` points a watch at a new reader; every old reading becomes `foreign` and nothing
of the old reader is mixed in.

A claim, judged as its author (continue as a superuser in the same database; `verify()` must run
in a transaction that has written nothing):

```sql
CREATE TABLE tasks (id int PRIMARY KEY, done boolean);
INSERT INTO tasks VALUES (5, true);
INSERT INTO docs VALUES (4, 'task 5 is done');
CREATE ROLE author LOGIN;
GRANT USAGE ON SCHEMA phasevec TO author;
GRANT SELECT, UPDATE ON docs TO author;   -- the first claim on a row goes to a role that may
GRANT SELECT ON tasks TO author;          -- UPDATE it (or the table's owner, or a steward)
GRANT EXECUTE ON FUNCTION phasevec.assert, phasevec.verify, phasevec.brief TO author;

SET ROLE author;
SELECT phasevec.assert('docs', '4', 'EXISTS (SELECT 1 FROM public.tasks WHERE id = 5 AND done)');
SELECT key, verdict FROM phasevec.verify('docs', p_every => interval '0');   -- 4 | verified
SELECT key, verdict, line FROM phasevec.brief('docs') ORDER BY key;
RESET ROLE;
UPDATE tasks SET done = false WHERE id = 5;
SET ROLE author;
SELECT key, verdict FROM phasevec.verify('docs', p_every => interval '0');   -- 4 | refuted
SELECT key FROM phasevec.brief('docs') ORDER BY key;                       -- no 4
RESET ROLE;
```

## The surface

| | |
|---|---|
| **Readers** | `reader_register`, `reader_seal`, `reader_compute`, `reader_switch` |
| **Fill** | `watch`, `next`, `record`, `record_audit`, `record_failure`, `watch_truncate` |
| **Search** | `search` (by words), `find` / `find_ivf` (by codes), `find_hybrid` (vector + lexical), `alike` (rows like a key) |
| **Index** | `ivf_build`, `ivf_maintain`, `ivf_maintain_all`, `ivf_absorb` |
| **Lexical** | `lexical`, `lexical_maintain`, `lexical_refresh` |
| **Audit** | `coverage`, `coverage_check`, `truncations`, `dupes`, `audit_sample`, `counts_compact` |
| **Recall** | `recall_approve`, `recall_check` |
| **Truth** | `assert`, `verify`, `verify_one`, `refute`, `supersede`, `unsupersede`, `disputes`, `recall`, `truth_coverage`, `replacement` |
| **Authorship** | `steward`, `adopt`, `rebind`, `migrate` |
| **Brief** | `brief` (what a watch still holds as true, best first, inside a character budget) |

Full signatures: `\df phasevec.*`. Privileges: the maintenance and truth functions are revoked
from `PUBLIC` and granted by the extension's owner. `search`, `find`, `find_ivf` and `find_npu`
are `SECURITY DEFINER` and open to any role with `USAGE` on the schema: they give keys, scores
and reading states of every watch (not the rows' text, not verdicts). Revoke them from `PUBLIC`
where keys are themselves sensitive.

## Claims and proofs

`assert(watch, key, proof)` records a claim about a row: an SQL boolean expression, run later as
the asserting role. `verify()` runs due proofs in background workers, each in a read-only,
security-restricted session of the author with the settings the author's session had, under a
cost cap and a clock (`p_timeout_ms`). A verdict serves while it is fresh (the watch's `max_age`)
and while the row's text is the one the author read; otherwise the claim reads `unproven`.
`refute()` retires a claim, `supersede(old, new)` replaces one, `brief()` serves what still holds.

**Who may change a claim.** A key has one claim, about one row.

| The claim is... | Who may change it |
|---|---|
| absent, or *dead* (its row is gone and another is under the key) | the table's owner; a steward of the watch; a role that may `UPDATE` that row (row-level security included). Reading the row is never enough, and the row must exist. |
| alive, its author still that role | the author (same OID and name, in this cluster or installation, not cut by `rebind()`); the table's owner; a steward |
| alive, its author gone (dropped, renamed, from another cluster, cut by `rebind()`, or asserted before 0.20.0) | the table's owner or a steward, who settles it or gives it to an author with `adopt()` |
| made by a role only as a steward | that role only while it is still a steward |

A *steward* is a role the table's owner names with `phasevec.steward('watch', 'role')` and takes
back with `phasevec.steward('watch', 'role', false)`. It counts while that owner owns the table,
and reaches only the rows row-level security lets it see. A `SECURITY DEFINER` function owned by
the table's owner acts as the owner for whoever calls it.

## Watching its own recall

A search does not fail when it degrades: `find_ivf` and `find` keep returning k plausible rows.
`recall_approve()` records what a watch is served now as a baseline; `recall_check()` compares
what it is served later.

```sql
SELECT phasevec.recall_approve('docs');                               -- find_ivf, nprobe 16, m 200
SELECT phasevec.recall_approve('notes', p_m => 1000, p_via => 'find');
SELECT watch, verdict, baseline, current, drift FROM phasevec.recall_check();
```

* Each sampled row asks with its own reading, which must carry a 256-bit code (`record(...,
  p_code256)`); a watch filled with per-dimension codes only cannot be approved. The truth is
  `find` over every live reading; recall@k is the share of the true top-k the served top-k holds.
* Verdicts: `ok` within 0.02 of the baseline, `degraded` within 0.10, `critical` below; a watch
  that cannot be measured is a row `COULD NOT MEASURE: <why>`, never an exception.
* The settings are the stored ones; lowering `nprobe` or `m` in a session changes nothing.
* All three functions are `SECURITY DEFINER` and revoked from `PUBLIC`: `GRANT EXECUTE ON FUNCTION
  phasevec.recall_check(text) TO monitor;` gives a monitoring role the check and nothing else.
* The check costs about `sample x rows` cosine scores: size `p_sample` to it, and keep the tables
  analyzed.

## Upgrading

`ALTER EXTENSION pg_phasevec UPDATE` after installing the new library and scripts. Upgrades to
0.20.0 from 0.17.0 (PGXN), 0.18.0 and 0.19.0 have been run and checked.

* **Reconnect after the update** (or restart): a session that loaded the old library keeps it.
  Its writes to a watched table are refused with a message that says so.
* **Run the update alone**, in a transaction of its own, at `READ COMMITTED`, with a
  `lock_timeout` that says how long it may wait (it holds nothing of phasevec's while it waits for
  others, and stops with nothing changed, naming the sessions in its way, when the time is up),
  not together with DDL on a watched table. It refuses a database that is not UTF8, a watch
  outside the supported tables, and objects outside the extension that depend on functions it
  drops, naming each.
* **Every claim waits for its table's owner.** Proofs asserted before 0.20.0 have no author and
  do not run; `verified` verdicts go back to `unproven`. The table's owner (or a steward) runs
  `SELECT * FROM phasevec.adopt('watch', 'role')` to assert them again in the name of `role`
  (adopt as the least-privileged role that can read what the proofs read).
* For each watch whose table was being written during the update, a `WARNING` gives the
  statement to run afterwards: `SELECT phasevec.watch_truncate('<watch>');`.
* Every row is rendered again with pinned settings; a recipe whose text depended on the session
  (a date, a float, a money value) reads `stale` once.

The details, and why each step is there, are in [doc/review-history.md](doc/review-history.md).

## Backup, restore and copies

* **pg_dump / pg_restore** carry phasevec's data (since 0.19.0): readers, watches, readings,
  claims, the coarse index. Plain, custom and directory formats, `-1`, and parallel `-j N`
  restores bring back the same rows, verdicts and counts (`test/review30.sh`). After a restore
  every key is marked for the coarse index's next `ivf_maintain`.
* **A dump of 0.19.0** restored where 0.20.0 is installed: run `SELECT * FROM phasevec.migrate();`
  as the extension's owner before the database takes writes. Until then the doors refuse.
* **Into another cluster**, authors and stewards are roles of the old cluster: every claim is an
  orphan until the table's owner adopts it, and stewards must be named again.
* **A copy of the cluster's files** (`pg_basebackup`, a promoted standby, `pg_createsubscriber`,
  `pg_upgrade --copy` or `--clone`) carries the cluster's identity and its OID counter, so a role
  made there under an author's OID and name *is* that author. Run `SELECT * FROM
  phasevec.rebind();` in every database with pg_phasevec after making a copy you do not fully
  trust: every claim whose author is not the table's owner becomes an orphan, and the stewards
  are removed. `rebind()` is revoked from `PUBLIC`: the extension's owner runs it or grants it to
  a table's owner.

## Known limits

Open findings of the last red-team pass (round 30) against this code, not fixed in 0.20.0:

* **A writer's right can be checked before a wait and used after it.** A role that may `UPDATE`
  a row may claim it when its claim is dead; that right is computed before the claim's lock is
  taken and reused after it, so with a concurrent delete and re-insert of the row by another
  tenant, a claim can be taken over on that tenant's new row (RV30-1).
* **`rebind()` leaves refutations and replacements in force.** A claim retired by `refute()` or
  replaced by `supersede()` by an author that `rebind()` cuts keeps its verdict, and `adopt()`
  does not list it; the table's owner must find and settle such claims by hand
  (RT29PA-REBIND-RETIRED).
* **`rebind()` does not hold on a live `pg_createsubscriber` subscription**: the publisher's next
  `verify()` writes the binding back. Drop the subscription before `rebind()`, or rebind after
  every replicated change (RT29PL-1). `rebind()` works per database: run it in each one. It cuts
  authorship, not table privileges: audit the copy's roles and grants too.
* **A lexical configuration is checked by its owner's name**, not OID: a `CREATEROLE` role that
  re-creates a departed owner's name, where it may create the configuration again, has its
  configuration used; renaming the owner role stops lexical reading silently (RT29PL-3).
* **The update with `lock_timeout = 0`** and any enabled `ddl_command_*` event trigger retries
  until `statement_timeout`; give it a `lock_timeout` (RT29PU-2).
* **`supersede()` of another role's live claim by the table's owner keeps that claim's author**,
  who may undo it with `unsupersede()`.
* A key has one claim; a role that only `INSERT`s does not get the first claim on its row. An
  application that rewrites a row by `DELETE` and `INSERT` makes a new row and loses its claims:
  `UPDATE` it, or `INSERT ... ON CONFLICT DO UPDATE`.
* A recipe renders a text or nothing: an error from the server or another session while it
  renders (a lock timeout, a cancel) ends the write that rendered it, even if the recipe catches
  it.
* `verify()` and `verify_one()` refuse a read-only transaction, session or standby.
* On PostgreSQL 18 there is no coarse-index copy shared across backends (`GetNamedDSA` is new in
  19): each connection keeps its own, with the same answers.
* The integrity of phasevec's own tables among themselves is kept by its functions and triggers,
  not by foreign keys (a parallel restore loads them in any order). Write them only through
  phasevec's functions.

The full list of limits as each review left them, including the ones of the update procedure, is
in [doc/review-history.md](doc/review-history.md). To look for more, [fuzz/](fuzz/README.md)
runs random sequences of claim operations against a model and replays past findings.

## Project

* [CHANGELOG.md](CHANGELOG.md): what changed in each release.
* [doc/review-history.md](doc/review-history.md): what each review found, and which test plays it.
* [SECURITY.md](SECURITY.md): how to report a vulnerability (privately).
* [CONTRIBUTING.md](CONTRIBUTING.md): reports and attack cases welcome; code contributions not
  accepted for now.
* Tests: `test/installcheck.sh` (the regression suite, against a throwaway cluster) and the
  multi-session `test/*.sh` suites.
* [fuzz/](fuzz/README.md): a model-based fuzzer of the claim lifecycle, with its spec, threat
  model and the replays of what it found.

## License

Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). Copyright 2026 Manuel Reyes
Bravo. "pg_phasevec" is the project's name; see [TRADEMARK.md](TRADEMARK.md).
