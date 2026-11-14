# Changelog

All dates are of the commit that set the version. 0.19.0 and 0.20.0 were never tagged; what they
changed ships in 0.20.0. The review-by-review account, with the test that plays each finding, is
in [doc/review-history.md](doc/review-history.md).

## Unreleased

* `fuzz/`: the model-based fuzzer of the claim lifecycle, with its spec, threat model and the
  replays of the findings it was used on; run against 0.20.0 (fdd19cb). No code change.

## 0.20.0 -- unreleased (preview)

A rewrite of the truth layer and of the update procedure, after twenty-eight internal reviews and
red-team passes, and a package review. Upgrade with `ALTER EXTENSION pg_phasevec UPDATE` from
0.17.0, 0.18.0 or 0.19.0; read "Upgrading" in the README first: every claim waits for `adopt()`
by its table's owner, and sessions must reconnect.

**Claims and proofs**

* A claim is its author's. `assert()` records its caller by OID and name, in this cluster; a proof
  runs as that role, and once no role has that OID and name the verdict reads `unproven`.
* A proof runs in a background worker of its own, read-only, in a security-restricted operation,
  with the settings the author's session had, under a cost cap and a clock. A recipe or a proof
  that is not phasevec's own code runs through one guard (`src/phasevec_guard.c`): a rolled-back
  subtransaction, one named role, no temporary objects, no cursors of the caller.
* A verdict is bound to the text its author read (`truth.asserted_for`) and to the row the claim
  was made on (`truth.asserted_row`, from `sources.born`). When the row is gone and another is
  under the key, the claim is *dead*: no one's, `unproven`, claimable again.
* `refute()` retires a claim (no proof, not judged again). Freshness is judged in UTC at the moment
  of reading. `verify()` refuses a read-only transaction.
* Who may change a claim: its author, the table's owner, a steward (`steward()`), or, for a key
  with no live claim, a role that may `UPDATE` its row. `adopt()` gives orphaned proofs an author;
  `rebind()` cuts every author but the table's owner after a copy of the cluster; `migrate()`
  brings a restored 0.19.0 dump to 0.20.0.
* `recall()`, `disputes()`, `replacement()`, `truth_coverage()`, `brief()` and `_verdict()` show a
  watch only to a role that may `SELECT` its table, and only the rows row-level security lets it
  see.

**Readings and search**

* Recipes render as the table's owner, at default settings, read-only; a write to a watched table
  never runs the writer's settings into a reading. Only UTF8 databases, and watches over plain
  tables keyed by a unique btree index of their own.
* The search functions are `SECURITY DEFINER` with a pinned `search_path`; the coarse index's
  blobs are checked as they load and every time they are used.
* The default build is portable; `make PHASEVEC_NATIVE=1` adds `-march=native` (the default until
  0.19.0).

**The update from 0.19.0** takes everything it changes before it changes anything, waits only
while it holds nothing of phasevec's, bounds every later wait, runs only at READ COMMITTED, names
the sessions and objects in its way, and gives each busy watch its `TRUNCATE` trigger afterwards
(`watch_truncate()`).

**Package review** (round 30; `test/review30.sh`, each case failing on 23af2e9):

* A restore loads phasevec's tables in any order: `pg_restore -j N` lost every claim to the
  extension's own foreign keys, which pg_dump orders but does not record as dependencies. The
  foreign keys between phasevec's tables are replaced by triggers, and the counts are recounted
  once per bulk load.
* A dead claim is no claim on any read path: it read `replaced` or `expired` and hid the next
  tenant's row from `brief()` and the searches, and `recall()` showed its topic and support.
* The update gives back the caller's `lock_timeout` and `deadlock_timeout` only after its last
  `DROP FUNCTION`.
* `phasevec._find_ivf_hide` is revoked from `PUBLIC`.
* The README is rewritten for a first reader; the review history moved to `doc/`; SECURITY,
  CONTRIBUTING, AUTHORS, NOTICE, TRADEMARK and this file are new; comments and hints no longer
  name the author's private deployment.

## 0.19.0 -- 2026-11-05 (never tagged)

* The extension's data goes into `pg_dump`. Its tables were plain members of the extension, so a
  dump restored the watches' triggers on the watched tables but not the watches, readings, sources
  or claims. The tables users and maintenance write are now configuration tables
  (`pg_extension_config_dump`), with their sequences; the counts the triggers derive are rebuilt
  on restore. `test/dump_roundtrip.sh`.

## 0.18.0 -- 2026-11-02

* `brief(watch, budget)`: what a watch still holds as true, as lines of text, best first (verified,
  then most useful, then most recently confirmed), inside a character budget. Replaced, expired
  and refuted keys never come out.

## 0.17.0 -- 2026-10-31

* `recall_approve()` and `recall_check()`: a watch measures the recall it is actually served and
  compares it with a baseline its owner approved (`ok`, `degraded`, `critical`), with the bands
  of pg_recall_guard.
* The coarse index kept in memory carries the installation it belongs to: after `DROP EXTENSION`
  and `CREATE EXTENSION` without a restart, `find_ivf` no longer answered from the old copy.
  Restart after installing, to release the old shared copy.
* Builds and runs on PostgreSQL 18 (no coarse-index copy shared across backends there).

## 0.16.0 -- 2026-10-26

* Security hardening: index build and maintenance skip `NULL` codes; every count, dimension and
  probe argument is bounded before an allocation; the proof clock cannot re-enter itself; reader
  socket paths that would truncate are refused; maintenance functions are revoked from `PUBLIC`
  (`test/sql/security.sql`).
