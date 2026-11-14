# pg_phasevec claim lifecycle: a specification for model-based fuzzing

Written against a development state of 0.20.0, commit a400376; **line citations are to
a400376**, not to the release. Where the code changed since (the fixes of section 6, and the
rules for who may change a claim, section 3b), the text says so, and `fuzz.py` follows the code
of v0.20.0 (fdd19cb). Paths are relative to the pg_phasevec repository:

* `U` = `sql/pg_phasevec--0.19.0--0.20.0.sql`
* `S14` = `sql/pg_phasevec--0.13.0--0.14.0.sql`
* `T` = `src/phasevec_truth.c`
* `R` = `README.md`

Markers: **[DISAGREE]** the code and the README say different things; **[Fn]** the fuzzer
reproduced it (section 6 and `findings/`); **[NOTE]** a design choice that needs a decision,
not a contradiction.

## 1. What a claim is

One row of `phasevec.truth` per (watch, key) (`S14:17-33`), plus the 0.20.0 columns
(`U:232-236`). The lifecycle depends on:

* `verdict`: the stored state, one of `unproven`, `verified`, `refuted`, `replaced` (`S14:27`).
* `proof`: SQL that must return true. NULL after `refute()` (`U:370`) or for a proofless claim.
* `asserted_by_oid`, `asserted_by`: the author. NULL for claims asserted before 0.20.0.
* `asserted_for`: sha256 of the row text as rendered at `assert()`. NULL when there was no proof
  or no row the author could see (`T:3688-3699`).
* `proof_env`: the author's session settings, replayed in the proof's session.
* `verified_for`: `_bind(asserted_for, proof, author, env)` of the judged claim (`U:285-286`).
* `verified_at`: when the row was read for the verdict.
* `halted`: the proof ended its own session (`U:486-511`).
* `replaced_by`, `reason`: `verdict = replaced` iff `replaced_by IS NOT NULL` (`S14:32`).
* `expires_at`: hard expiry.
* `watches.max_age`: the horizon of a proof's verdict, 1 hour by default (`U:258`).

## 2. States

Only the four stored states of `S14:27` exist as values. Everything else is derived when read,
by `_verdict_of()` (`U:294-324`); the first rule that matches wins:

1. stored `replaced` -> `replaced` (`U:296`);
2. `expires_at <= clock_timestamp()` -> `expired` (`U:302`);
3. verified or refuted, `proof IS NOT NULL`, not halted, `verified_at + max_age` not in the
   future (UTC) -> `unproven`, "past the horizon" (`U:306-313`);
   3b. (6068555) verified or refuted, `proof IS NOT NULL`, `asserted_by_oid` not NULL, and no role
   has that OID and name -> `unproven`, "author gone";
4. `verified` whose `verified_for` is not the claim's binding -> `unproven` (`U:314-318`);
5. verified or refuted whose `asserted_for` is not `sources.text_hash` -> `unproven`, "stale"
   (`U:319-322`);
6. otherwise the stored verdict (`U:323`).

Derived names used below (none is a column value):

* **unproven**: stored `unproven`, never judged since the last `assert()`.
* **verified**, **refuted**: judged by a proof, inside the horizon, for the current text.
* **stale**: verified or refuted whose row text changed or whose row is gone. Served `unproven`,
  and served as before again if the text comes back (`R:186`).
* **retired**: `refuted` with `proof IS NULL`, written by `refute()` (`U:351-374`). No horizon:
  served `refuted` while the row text is the one in `asserted_for`.
* **halted**: `refuted` with `halted = true`; not run again until asserted (`U:486-511`).
* **replaced**: stored `replaced`; `replacement()` follows the chain (`U:816-827`).
* **expired**: `expires_at` has passed; served `expired` whatever the stored verdict.
* **orphan**: a proof whose author is unknown (`asserted_by_oid` NULL, asserted before 0.20.0)
  or gone (no role with that OID and that name). `verify()` does not run it (`U:415`,
  `T:3620-3629`).
* **no claim**: a watched row with no truth row. `brief()` and `truth_coverage()` serve it as
  `unproven` (`U:749`, `U:831`).
* `recall()` also serves `disputed` (two live claims of one topic with different texts).

## 3. Operations

* **`assert(w, k, proof, topic, support, expires_at)`**. Granted roles only (`S14:227`). Upsert:
  author := the caller; `asserted_for` := the text hash if there is a proof and the author sees
  the row, else NULL; verdict := `unproven` unless `replaced`; clears `verified_at`,
  `verified_for`, `halted`, `looked_*`, `interrupted_*` (`U:328-346`, `T:3673-3720`). It
  overwrites a claim of another author.
* **`refute(w, k, reason)`**. SECURITY DEFINER, granted roles, no author check (`U:358-374`).
  Upsert: verdict := `refuted`, proof := NULL, `verified_at := now()`. `asserted_for` is kept
  when the claim existed, and is the current `sources` hash for a new one. Does nothing to a
  `replaced` claim (`U:373`), without saying so.
* **`supersede(w, old, new, reason)`**. Granted roles (`S14:228`). Upsert `old`: verdict :=
  `replaced`, `replaced_by := new`. Refuses `new = old` and a `new` with no row (`S14:73-91`).
* **`unsupersede(w, k)`**. Granted roles (`S14:229`). If `replaced`: verdict := `unproven`,
  `replaced_by`, `reason`, `verified_at` := NULL; proof, author, `asserted_for` kept
  (`S14:93-101`). Since 578af0f a retired claim comes back `refuted`; since 3910404 (F8) a
  halted one too, with its `verified_at` (nothing judges either again); a judged one
  `unproven` and due.
* **`adopt(w, author, keys, superuser_keys)`**. Granted roles; the caller must hold `author`
  (`T:3815`). Re-asserts as `author` every orphan claim with `proof IS NOT NULL` that is not
  `replaced` (`T:3834`). Since 3910404 (F7) it locks the orphans (`FOR NO KEY
  UPDATE`) and reads each again once held: a claim a concurrent `refute()` or `assert()` made no
  orphan is not adopted (returned with `adopted = false`).
* **`verify(w, n, every, budget, timeout_ms, max_cost)`**. C door (`R:190`). Takes due claims
  (`U:402-430`) whose author the caller holds and judges each in a session of its author. A
  stale claim keeps its verdict and records `looked_*`; a gone author records `unproven`. A
  verdict is recorded only if the binding still matches and `verified_at` does not move back
  (`U:447-472`).
* **`verify_one(w, k, ...)`**. As `verify()` for one key; raises when it cannot judge, when the
  author is unknown, or when the caller does not hold the author (`T:3578-3662`). Since
  3910404 (F10) also when the claim was asserted again while it waited for the row (the
  take checks the claim's bind under the lock); before, it answered `unproven` for a claim it never
  ran.
* **`watch(...)`**. The table owner. Creates the watch and its trigger. There is no `unwatch()`:
  a watch ends with `DROP TABLE` (its `sql_drop` trigger deletes the watch and, by cascade, its
  claims; `R:172`, `R:212`).
* **Row INSERT, UPDATE, DELETE of the watched table**. The C trigger renders the row as the table
  owner and writes `sources.text_hash` (`U:593-620`). It never writes `truth` (`U:286-292`).
* **`TRUNCATE` of the watched table** (op `truncate`, the owner). Since 3910404 (F9) a
  statement trigger (`phasevec_watch_<id>_truncate`, also added by the update to old watches)
  deletes the watch's `sources` rows: no claim of a gone row is served `verified` or `refuted`, and
  `truth_coverage()` counts no gone row. Before, it served them until the next `verify()`.
* **`ALTER EXTENSION pg_phasevec UPDATE` 0.19.0 -> 0.20.0**. `verified` -> `unproven` with a
  reason; `refuted` stays refuted, bound to the current text; no claim gets an author
  (`U:575-581`).
* **Dump and restore**. `truth` and `sources` are config tables
  (`sql/pg_phasevec--0.18.0--0.19.0.sql:28-29`); `attempts` is unlogged and not dumped.
* **`DROP ROLE author`**. Nothing in `truth` changes: the claim becomes an orphan.
* **`UPDATE phasevec.watches SET max_age`**. The owner; moves every horizon at once.
* **Assert under one session's settings, verify under another's** (op `env_assert`; also
  `env_assert2`). The README rule (R, "A proof means what it meant to its author", and
  Limits): a
  claim records what is in effect where `assert()` is called, as its author has it there. A `SET`
  clause of the author's own `SECURITY DEFINER` function, and a `SET` (or `SET LOCAL`) in its
  body, are the author's; a caller's own settings count only when the caller has the author's
  privileges (here: the author itself), otherwise the proof has the author's own value. A
  setting a `SET` merges into the value it replaces (`DateStyle`: `SET DateStyle = ISO` keeps the
  order, `DMY` or `MDY`) is recorded only when every value under it is the author's; else not at
  all (the proof has the author's default, `ISO, MDY` in the fuzz cluster). The verifier's own
  settings decide nothing. The op: `via` = `direct` (the author's session sets `search_path` and
  `DateStyle`, then asserts), `wrapper` (`fz_env.assert_via`, owned by `fz_author`, `SET search_path
  = fz_s1, pg_catalog SET DateStyle = ISO`) or `wrapper_local` (`fz_env.assert_local`, `SET
  search_path = fz_s2, pg_catalog`, `SET LOCAL DateStyle = 'Postgres'` in its body), called by
  `fz_author`, `fz_reader` or `fz_author_b` after their own `SET`s; then `verify()` by the owner or
  an author after other `SET`s. Proofs: `sp` = `SELECT flag()` (`fz_s1.flag()` true,
  `fz_s2.flag()` false, not found: an error, refuted) and `ds` = `SELECT '03/04/2026'::date =
  date '2026-03-04'` (true under `MDY`). The model (`Claim.env_set`) computes the settings the
  proof runs under and the INV-VERIFIED-HOLDS re-run uses them. `adopt()` records the adopter's
  (a plain session: the defaults).

### 3b. Who may change a claim (v0.20.0, as modelled)

Added to 0.20.0 after a400376 (238e47d, ab6316d, 5deabb2, b84816e); `Model.may_change`,
`Model.how`, `Model.may_adopt`:

* A claim that exists is changed (`assert`, `refute`, `supersede`, `unsupersede`) by the table's
  owner, by a role with the privileges of its author while the author is still that role (same
  OID and name, bound in this cluster, and the claim still about the row it was made on), or by a
  *steward* of the watch (`phasevec.steward(watch, role, on)`) that row-level security does not
  keep from the row. A claim whose author is gone or unknown: the owner or a steward only.
* Nobody claims by coming first: a key with no claim gets one only if its row exists, from the
  owner, such a steward, or a role that may `UPDATE` the row (`Model.writes`: `UPDATE` on the
  table and the row passing the role's policy). Reading the row is not enough.
* `adopt()` changes claims: the owner's or a steward's call only; under row-level security it
  skips orphans on rows the caller does not see.
* A claim is about its row. `phasevec.sources.born` names the row a key had when the claim was
  made (`Claim.row`, the nil UUID when there was none); a key whose row was deleted and written
  again (op `reinsert`, `TRUNCATE` and inserts) has another row, and a claim about the old one is
  *dead*: served `unproven`, no one's, claimable as a key with no claim (`Model.dead`). A claim
  made with a steward's right alone gives its author no right of its own (`Claim.by_steward`).
* `rebind()` (op `rebind`, the owner, for the watch or for all) cuts what a copy of the cluster
  would have inherited: every claim's author is no longer bound here (`Claim.here`).
* An operation the model refuses must fail and leave `phasevec.truth` unchanged (INV-AUTHOR).

## 4. Allowed transitions

Ops: `A` assert, `F` refute, `S` supersede, `U` unsupersede, `V` verify or verify_one judging
the claim, `D` adopt, `W` a row write that changes the text, `X` the clock passing a bound.
"-" means no change. Cells name the state served afterwards.

| from | A | F | S | U | V | D | W | X |
|---|---|---|---|---|---|---|---|---|
| none | unproven | retired | replaced | - | - | - | - | - |
| unproven | unproven | retired | replaced | - | ver/ref/unp | orphan: unp | - | expired |
| verified | unproven | retired | replaced | - | ver/ref | orphan: unp | stale | unp, expired |
| refuted | unproven | retired | replaced | - | ver/ref | orphan: unp | stale | unp, expired |
| retired | unproven | retired | replaced | - | - | - [F1] | unp [NOTE] | expired |
| halted | unproven | retired | replaced | - | - | orphan: unp | stale | expired |
| replaced | replaced | - [F4] | replaced | kept [F3, F8] | - | - | - | - |
| stale | unproven | retired | replaced | - | stale | orphan: unp | stale or back | - |

`ver` verified, `ref` refuted, `unp` unproven. `X` from verified or refuted is "past the
horizon" (`unp`) or `expired`; a retired or halted claim has no horizon. `kept`: the state it had
behind its replacement, with that state's verdict (retired or halted: `ref`; judged: `unp`, due).

## 5. Invariants

Each one is checked by `fuzz.py` after every step, under the id in brackets.

1. **[INV-RETIRED] A retired claim comes back only through `assert()`.** From `R:173`
   ("`refute()` now retires the claim ... it reads `refuted`, with no horizon, while its text
   is the refuted one; an `assert()` makes it a claim again") and `U:351-357`. While the row is
   there and its text is the refuted one, the claim is served `refuted` (or `replaced`,
   `expired`), never `verified` or `unproven`, and `brief()` never serves it.
   * **[NOTE]** The code revives a retired claim as `unproven` when its row text changes
     (`U:352` "when that text changes, it is not refuted any more"; `U:319-322`; `R:186`). The
     fuzzer follows the code there. A stricter reading ("revived only by assert") would not:
     editing a retired claim's row brings it back into `brief()`.
   * **[DISAGREE] [F1]** Upgrade, then `adopt()` or the horizon, brings back claims retired in
     0.19.0.
   * **[DISAGREE] [F2]** A claim with no `asserted_for` is not retired by `refute()`.
   * **[DISAGREE] [F3]** `supersede()` then `unsupersede()` revives a retired claim.
   * **[F4]** `refute()` of a replaced claim does nothing and says nothing.
   * **[NOTE] (spec ambiguity, 2026-11-06 run)** 0.19.0 kept no text for a claim, so the
     update ties a claim it retires to the row's text *at the update* (`U:668-673` at 8902c9b,
     "about the row's text as it is now"). A claim refuted under 0.19.0 whose row was deleted
     before the update is retired about no text (`asserted_for` NULL): a row inserted later
     with the very text that was refuted reads `unproven` (stale), while the same steps on
     0.20.0 alone read `refuted`. The fuzzer follows the code (seed 58820081,
     `findings/model-INV-RETIRED.upgrade-no-row-seed58820081.json`); whether a retired claim
     with no recorded text should stay retired for any text is a decision for the README.
2. **[INV-VERIFIED-HOLDS] A served `verified` means the proof held for exactly the current
   text, env and author, within `max_age`.** From `U:294-324`, `R:183-184`, `R:189`. Checked
   without the model: the author is still that role (OID and name); `asserted_for` is the hash
   `_render()` gives now; `verified_for` is `_bind(...)` of the stored claim; `verified_at +
   max_age` is in the future; the claim is not expired; and the proof, run now as its author,
   returns true (the fuzzer's proofs read only their own row).
   * **[DISAGREE] [F5]** (fixed in 6068555) `R:189` says a dropped author's claim "reads
     `unproven` until it is asserted again". `_verdict_of()` has no author check, so it keeps
     serving `verified`.
3. **[INV-ISOLATION] No reader sees a verdict for a row it cannot see.** From `R:93`,
   `U:864-874`, `T:4351-4356` and `T:4474`. A role without `SELECT` on the table gets nothing
   from `brief()`, `truth_coverage()` and `replacement()`, and NULL from `_verdict()`. With
   row-level security on, a reader gets no brief line, verdict, count or chain step of a row
   its policy hides.
4. **[INV-MONOTONIC] A claim's `verified_at` never moves back between two asserts.** From
   `R:126` ("Verdicts move forward in time") and `U:471`.
   * **[DISAGREE] [F6]** (fixed in 6068555) `refute()` writes `verified_at = now()` (`U:369`)
     without the guard of `U:471`.
5. **[INV-REPLACED] `replaced` is served as `replaced`.** Stored `replaced` iff `_verdict()`
   says `replaced` (`U:296`), and `replacement()` serves the stored chain (`U:816-827`).
6. **[INV-PRIV] An operation the role was not granted fails and changes nothing in `truth`.**
   From `R:190` and the grants (`S14:227-232`, `U:855-880`). Exercised: the reader and the
   outsider calling assert, refute, supersede, verify and adopt; a second author running
   another author's proof (`T:3630`); writing `phasevec.truth` directly.
   * **[NOTE] (2026-11-06 run)** `verify_one()` by another author on a *replaced* claim answers
     NULL and changes nothing, as on a claim with no proof: `_truth_of()` has no row for it
     (`U:515-524`) and `verify_one()` returns before it asks for the author's rights
     (`T:3803-3811` at 8902c9b). Not a breach (it says only that the key has no claim to run,
     which `_verdict()` already serves as `replaced`); the fuzzer no longer counts it (seed
     47130021, `findings/model-INV-PRIV.verify-one-replaced-seed47130021.json`).
7. **[INV-DUMP] A dump and a restore into the same cluster serve the same verdicts.**
8. **[INV-MODEL] What `_verdict()`, `brief()`, `truth_coverage()` and `replacement()` serve is
   what the reference model computes from the operations.** A race or a wrong derived state
   in the implementation shows up here.
9. **Upgrade.** After 0.19.0 -> 0.20.0, no `verified` is carried over (`U:575-578`); a proof
   with no author does not run (`U:415`, `T:3628`); a claim retired by `refute()` in 0.19.0
   stays retired (INV-RETIRED; `R:173` names this as a bug fixed before 0.20.0).

10. **[INV-AUTHOR] A change the rules of section 3b refuse fails and changes nothing.** An
    `assert`, `refute`, `supersede`, `unsupersede` or `adopt` the model refuses must raise and
    leave `phasevec.truth` as it was. Race steps run as the claim's author or are skipped.
11. **[INV-BORN] A key's row is another exactly when a step wrote one.** `sources.born` changes
    on an insert of a key with no row, a `reinsert`, a `TRUNCATE` and inserts; a `dump_restore`
    keeps it. `INV-MODEL/meta` compares each claim's row, `by_steward` and `here` with the
    database.
12. **[INV-RESTORE19] A 0.19.0 database restored where 0.20.0 is installed serves nothing as
    `verified` before `phasevec.migrate()`**, and the doors refuse until then (op
    `restore_upgrade`, half of the upgrade sequences).

**[NOTE] Liveness and `brief()`.** A claim refuted by its own proof is served `unproven` once
its horizon passes (`U:306-313`), and `brief()` serves `unproven` lines (`U:758`). If
`verify()` stops running, false claims come back into the brief as unproven. That follows
`R:128` (no verdict serves past its horizon), but a deployment may want refuted-by-proof claims
to stay out of `brief()`.

## 6. Findings

Each file in `findings/` is a sequence; `fuzz.py --replay <file>` runs it once from a fresh
database. On v0.20.0 (fdd19cb) every file replays `ok`. `f<N>-*.json` are the named findings
below; `INV-...-seed<N>.json` are what a random run shrank one of them to; `model-*.json` were
harness false positives (the model, not the extension, was wrong), fixed in `fuzz.py`.

F1-F7 were found by this fuzzer. F9 and F11-F14 were found in review of the extension and then
made into an operation of the fuzzer and a replay. F8 and F10, found in the same review as F9,
have no replay of their own (the model follows F8).

* **F1** (INV-RETIRED/adopted). 0.19.0 `refute()`, upgrade, then `adopt()` or the horizon: the
  retired claim was asserted again and the next `verify()` served it `verified`. Fixed in 578af0f.
* **F2** (INV-RETIRED/no-text). `refute()` of a claim with no proof (no `asserted_for`) did not
  retire it: served `unproven`, and in `brief()`. Fixed in 578af0f.
* **F3** (INV-RETIRED/revived). `supersede()` then `unsupersede()` brought a retired claim back
  `unproven`. Fixed in 578af0f.
* **F4** (INV-RETIRED/ignored-while-replaced). `refute()` of a replaced claim did nothing and said
  nothing; after `unsupersede()` and `verify()` the claim was `verified`. Fixed in 578af0f.
* **F5** (INV-VERIFIED-HOLDS/author-gone). After `DROP ROLE` of the author (and a new role of that
  name) `_verdict()` and `brief()` kept serving `verified` until `max_age`. Fixed in 6068555.
* **F6** (INV-MONOTONIC/refute). `refute()` in a transaction that began before a `verify()`
  recorded a newer verdict moved `verified_at` back. Fixed in 6068555.
* **F7** (INV-MODEL/retired-has-proof, INV-MODEL/proof). `adopt()` read the orphans with the
  snapshot of its start and upserted them: a `refute()` or `assert()` that held the row and
  committed while `adopt()` waited was overwritten with the orphan's old proof. Fixed in 3910404
  (`adopt()` locks each orphan and reads it again once held).
* **F8**. `unsupersede()` of a halted claim did not give its `refuted` back. Fixed in
  3910404; no replay.
* **F9** (INV-MODEL). A `TRUNCATE` of the watched table was not seen: claims of gone rows kept
  serving `verified` or `refuted` until the next `verify()`. Fixed in 3910404 (a statement
  trigger).
* **F10**. `verify_one()` answered `unproven` for a claim asserted again while it
  waited for the row, a claim it never ran. Fixed in 3910404; no replay.
* **F11** (INV-MODEL). A caller's `DateStyle` order (`DMY`) was recorded as the author's through
  the author's wrapper with `SET DateStyle = ISO`. Fixed in f8bdd83.
* **F12** (with `FZ_RECIPE_TS=1`). With a recipe whose text depends on a setting (a
  `timestamptz` column), the update bound a claim it retired to the text 0.19.0 had noted, then
  noted the rows again in other settings: every claim retired under 0.19.0 read `unproven` and
  was back in `brief()`. Fixed in de2a8b2.
* **F13**. A claim outlived its row: deleting a row and writing another under the
  same key left the old claim, and its author's rights, on the new row. Fixed in b84816e (a claim
  is about its row, `sources.born`; `rebind()`).
* **F14** (INV-MODEL). A dead claim (its row gone and another written under the key) was still
  served `replaced` or `expired`, which kept the new row out of `brief()`. Fixed in e240fde.

Files: F1 `f1-upgrade-retired-adopted.json`, `f1-upgrade-retired-horizon.json`,
`INV-RETIRED.adopted-seed20261149.json`; F2 `f2-refute-no-text.json`,
`INV-RETIRED.no-text-seed20261111.json`; F3 `f3-unsupersede-revives.json`,
`INV-RETIRED.revived-seed20261129.json`; F4 `f4-refute-ignored-replaced.json`,
`INV-RETIRED.ignored-while-replaced-seed20261158.json`; F5 `f5-author-gone-verified.json`,
`INV-VERIFIED-HOLDS.author-gone-seed20261122.json`, `INV-MODEL.author-gone-seed24680015.json`;
F6 `f6-refute-verified-at-back.json`; F7 `f7-adopt-*.json` (both orphan paths: an upgraded
claim with no author and a dropped author; since ab6316d `adopt()` is the owner's or a steward's,
so these files name `fz_author` a steward first); F9 `f9-truncate-*.json`; F11
`f11-datestyle-wrapper.json`; F12 `f12-upgrade-retired-ts-recipe.json` (replay it with
`FZ_RECIPE_TS=1`); F13 `f13-key-reuse-rebind.json`; F14 `f14-dead-claim-verdict.json`.

Some old sequences were written before the rules of section 3b. Where a step's role may no longer
change the claim, the step is a no-op; `--replay` prints which steps were (for example
`model-INV-VERIFIED-HOLDS.tenant-rls-seed31337059.json`, step 1).

Harness false positives (`model-*.json`), each fixed in `fuzz.py`:

* `model-INV-PRIV.verify-one-replaced-seed47130021.json`: `verify_one()` by another author on a
  replaced claim answers NULL and changes nothing, as on a claim with no proof; not a breach
  (section 5.6).
* `model-INV-RETIRED.upgrade-no-row-seed58820081.json`: a claim refuted under 0.19.0 whose row
  was gone at the update is retired about no text (section 5.1, last note).
* `model-INV-VERIFIED-HOLDS.resync-rls-seed80412196.json`: after a concurrent `verify()` and an
  RLS toggle the checker re-ran a proof judged before the toggle (a verdict binds text, settings
  and author, not the table's policies).
* `model-INV-VERIFIED-HOLDS.tenant-rls-seed31337059.json`: under RLS a `tenant` write moves a row
  out of a role's policy without changing its text; the model now treats it as an RLS toggle for
  that key.
* `model-INV-MODEL.cycle019-seed2950108.json`: a supersede cycle 0.19.0 allowed is undone by the
  update; the model lacked that step.
* `model-INV-MODEL.orphan-conc-assert-seed3008282.json`,
  `model-INV-MODEL.conc-assert-gone-author-seed28100098.json`: two concurrent asserts both
  refused (an orphan after `rebind()`, or an author dropped and created again under its name);
  the old claim stays as it was, which the model mistook for the new role's assert.

## 7. Not covered yet

* `halted` claims (a proof that ends its own session): the model follows them
  (`Model.unsupersede`, `served`), but no op makes one; `test/sql/truth_review19b.sql` covers the
  supersede round trip. `topic` and `disputed`, `recall()`.
* A watch on a partitioned table, collations. Of the `proof_env` replay, `env_assert` covers
  `search_path` and `DateStyle` (direct, through a wrapper's `SET` clause, `SET LOCAL` in its
  body, callers with and without the author's privileges; `env_assert2` adds `SET LOCAL`,
  `set_config(..., true)`, a caller's own function's `SET` clause and `ALTER ROLE ... SET`); not
  covered: placeholders, a setting that cannot be set again (a revoked `SET` privilege, a dropped
  text search configuration: `test/sql/truth_review20.sql`).
* `DROP TABLE` of a watched table during `verify()`; a restore into another cluster (new OIDs).
* Long READ COMMITTED reader transactions across a horizon (`R:137`).
* A superuser as the author (`adopt()` with `p_superuser_keys`).
