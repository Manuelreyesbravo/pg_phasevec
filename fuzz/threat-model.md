# pg_phasevec claims: the threat model the fuzzer checks

Companion to `spec.md` (same citation keys: `U`, `S14`, `T`, `R`; line numbers are to a400376,
see there). It states, for the claim layer of pg_phasevec 0.20.0, who is trusted, what each role
may and may not achieve, and which of those promises `fuzz.py` checks. The README's "Status: what
this preview is" and "Known limits" sections are the authority; this file follows them.

## Actors

* **Superuser and extension owner.** Trusted. Owns `phasevec.truth`, `sources`, `attempts`;
  every internal runs as it (`R:190`). Can edit `phasevec.truth` by hand: out of scope as an
  attacker, in scope as a careless caller (it is made an author only through
  `adopt(..., p_superuser_keys)`, `T:3794-3812`).
* **Table owner.** Trusted for its table. May change any claim on it, name and remove stewards
  (`phasevec.steward()`), adopt orphans, run `rebind()` when granted it.
* **Steward.** A role the table owner names for a watch. May change and adopt claims on the rows
  row-level security lets it see, while it is a steward and that owner owns the table.
* **Author.** A role granted `assert()` (and usually `verify()`). Its proofs run with its rights,
  in a session of its own, with the settings it had where it asserted (`R:178`, `R:189`).
* **Table writer.** A role that may `INSERT`, `UPDATE` or `DELETE` the watched table. It changes
  the text a claim is about, not the claim (`U:286-292`); a role that may `UPDATE` a row may make
  the first claim on it.
* **Reader with access.** May `SELECT` the watched table (under row-level security, some of its
  rows) and is granted `brief()`; may be granted `SELECT` on `phasevec.truth` to call
  `_verdict()`.
* **Reader without access.** `USAGE` on the schema, no `SELECT` on the table.
* **Verifier.** A role granted `verify()` or `verify_one()`; it runs the proofs of the authors it
  holds, as those authors.

Not trusted: authors, writers, readers and verifiers against each other, including tenants
separated only by row-level security.

## What must hold

**Author.**
* May assert, re-assert and (if granted) verify its own claims; its proof sees only what its role
  sees, and only settings it could set itself (`R:168`, `R:178`).
* May not change, retire, supersede or unsupersede a claim that is not its own (unless it is a
  steward reaching the row), nor make the first claim on a row it may not `UPDATE` (INV-AUTHOR).
* May not have a verdict recorded for a text it did not read, for another author, or for other
  settings (`asserted_for`, `verified_for`; INV-VERIFIED-HOLDS).
* May not run another author's proof: `verify()` skips it, `verify_one()` refuses (INV-PRIV).

**Table writer.**
* May make any claim stale by editing its row; the verdict then serves `unproven`, and comes back
  if the text comes back (`R:186`). A retired claim edited this way reads `unproven` (spec.md,
  INV-RETIRED note).
* May not touch `truth`, nor block a verifier on it.
* A row deleted and written again under its key is another row: the old claim is dead and no
  one's (INV-BORN, INV-MODEL).

**Reader.** Sees verdicts, brief lines, counts and chain steps only of rows it may `SELECT`, with
row-level security applied per row; changes nothing (INV-ISOLATION, INV-PRIV). A reader without
access gets nothing from `brief()`, the doors or `_verdict()`. It still gets keys, scores and
reading states from the search functions open to `PUBLIC` (`R:93`): revoke them where keys are
sensitive.

**Verifier.** May not choose the author a proof runs as, forge a verdict (only C internals write
it), or judge with its own rights (`R:189-190`). `verified_at` never moves back (INV-MONOTONIC).

**Lifecycle.** A retired claim stays retired on every path: `supersede()`/`unsupersede()`,
`adopt()`, the update from 0.19.0 and a restore of a 0.19.0 dump (INV-RETIRED, INV-RESTORE19). A
claim whose author is gone (dropped, recreated under the same name, cut by `rebind()`) does not
serve `verified` (INV-VERIFIED-HOLDS/author-gone). A dump and restore into the same cluster serves
the same verdicts (INV-DUMP).

## What the fuzzer does not check

* Hostile recipes and proofs as code (resource use, functions with side effects, event triggers):
  covered by the extension's own tests in `test/`, not here.
* A restore into another cluster (new OIDs), copies of the cluster's files and
  `pg_createsubscriber`; `rebind()` is exercised only in the cluster it runs in.
* More than two tenants and two authors; `recall()`, `disputes()`, topics.
* The limits listed under "Known limits" in the README are known; a sequence that shows one
  is still welcome as a regression test.

`spec.md` section 7 lists the rest.
