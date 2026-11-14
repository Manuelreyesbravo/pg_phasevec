# fuzz: a model-based fuzzer for the claim lifecycle

`fuzz.py` runs random sequences of operations on pg_phasevec's claims against a throwaway
PostgreSQL cluster, and after every step compares what the extension serves with a small
reference model written in Python and with invariants that need no model. A failing sequence is
shrunk and saved as JSON, and can be replayed.

* [`spec.md`](spec.md): the claim's states, the operations and their transitions, who may change
  a claim, the invariants, and what was found (section 6).
* [`threat-model.md`](threat-model.md): who is trusted, what each role may and may not achieve,
  what the fuzzer does not check.
* [`fuzz.py`](fuzz.py): the harness. Python 3, standard library only (run with 3.11 and 3.15); it
  talks to the server through `psql`.
* [`findings/`](findings/): the sequences of past findings, every one fixed; see below.

It was run against v0.20.0 (fdd19cb): every file in `findings/` replays `ok`, and a 10-minute
random run found nothing.

## What it models

One database per sequence: a table `public.notes` (keys 1 to 5, two tenants), a watch on it, a
row-level security policy that splits the tenants between two roles, and the roles `fz_owner`
(bootstrap superuser, owner of the extension and the table), `fz_author` and `fz_author_b`
(authors), `fz_reader` (reader of tenant `a`), `fz_outsider` (`USAGE` on the schema only) and
`fz_writer` (writes the table).

The operations, chosen at random with weights (`gen_op()`):

* claims: `assert` (with a proof that is true, false, none, or reads the row), `refute`,
  `supersede`, `unsupersede`, `adopt`, `verify` and `verify_one` by different roles, `steward` on
  and off, `rebind`;
* the table: inserts, updates, deletes, tenant changes, `reinsert` (delete and write a key again),
  `TRUNCATE`, row-level security on and off, `UPDATE` granted and revoked;
* roles and time: `DROP ROLE` of an author and a new role of that name, the watch's `max_age`
  made tiny or long, claims that expire;
* settings: asserting directly or through an author's `SECURITY DEFINER` wrapper, under other
  `search_path` and `DateStyle` values, with `SET LOCAL`, `set_config(..., true)` and
  `ALTER ROLE ... SET` (`env_assert`, `env_assert2`);
* races: two sessions at once, one holding a row or a claim in an open transaction while the other
  verifies, asserts, adopts, truncates or refutes (the `conc_*` operations);
* versions: a quarter of the sequences start at 0.19.0 and move to 0.20.0, half of them by
  `ALTER EXTENSION ... UPDATE` and half by `pg_dump` / `pg_restore` into 0.20.0 and
  `phasevec.migrate()`; `dump_restore` within 0.20.0.

After every step it reads, as the owner, as `fz_reader` and as `fz_outsider`, what `_verdict()`,
`brief()`, `truth_coverage()` and `replacement()` serve, and checks:

| Invariant | In short |
|---|---|
| INV-MODEL | what is served is what the model computes from the operations |
| INV-RETIRED | a claim retired by `refute()` comes back only through `assert()` |
| INV-VERIFIED-HOLDS | a served `verified` holds now: same author, text, settings, horizon |
| INV-ISOLATION | no role sees a verdict, line, count or chain step of a row it cannot see |
| INV-MONOTONIC | `verified_at` never moves back between two asserts |
| INV-REPLACED | stored `replaced` is served `replaced`, and the chain is the stored one |
| INV-PRIV | a call the role was not granted fails and changes nothing |
| INV-AUTHOR | a change the claim rules refuse fails and changes nothing |
| INV-BORN | a key's row is another exactly when a step wrote one |
| INV-DUMP | a dump and restore serve the same verdicts |
| INV-RESTORE19 | a restored 0.19.0 dump serves no `verified` before `migrate()` |

`spec.md` section 5 states each one with its source in the code and the README.

## Build an install to point it at

The fuzzer needs a PostgreSQL 18 or 19 install (`bin/initdb`, `pg_ctl`, `psql`, `pg_dump`,
`pg_restore`) with pg_phasevec installed in it, the upgrade scripts included (`make install`
installs them). Use an install of its own: the fuzzer creates and drops roles and databases, but
only in a cluster it creates.

```sh
# a copy of an existing install, so nothing is installed into the real one
cp -r --preserve=mode,timestamps /usr/local/pgsql /dev/shm/pvfuzz/pg
make -C /path/to/pg_phasevec PG_CONFIG=/dev/shm/pvfuzz/pg/bin/pg_config
make -C /path/to/pg_phasevec PG_CONFIG=/dev/shm/pvfuzz/pg/bin/pg_config install
```

## Run

```sh
cd fuzz
nice -n 19 python3 fuzz.py --pg /dev/shm/pvfuzz/pg --minutes 10 --seed "$(date +%s)" \
    --out /dev/shm/pvfuzz/findings > fuzz.log 2>&1
tail fuzz.log
```

Each run makes its own cluster in a fresh directory under `/dev/shm/pvfz-*` (`FZ_BASE_DIR` to put
it elsewhere): `initdb`, `fsync=off`, `listen_addresses = ''`, so it listens only on a unix socket
in that directory and opens no TCP port. The cluster is stopped and removed on exit. A run keeps
about one core busy, plus a background worker per proof while `verify()` runs, and uses about
150 MB.

The last lines say what happened:

```
N sequences, M steps, S s, seeds A..B
FINDING INV-.../cause: seed X (K sequences) <out>/INV-...-seedX.json
```

Exit code 0: nothing found; 1: at least one finding. Each new finding is printed when it is met,
with its shrunk sequence. Race steps sleep for fractions of a second; on a loaded machine a race
can resolve the other way, which the model follows, but run it on a quiet one.

Options:

* `--pg DIR`: the install (default: the parent of `pg_config --bindir`).
* `--port N`: the number in the socket's name (default 65535). No TCP port is opened, so it cannot
  collide with a running server.
* `--seed N`: sequence `i` uses seed `N + i`; the seed printed with a finding regenerates it.
* `--steps N`: operations per sequence (default 40). `--minutes M`: stop starting sequences after
  M minutes (default 3).
* `--upgrade-p P`: share of sequences that start at 0.19.0 (default 0.25).
* `--skip LIST`: invariants not to check, by id (`INV-RETIRED`) or id/cause
  (`INV-MODEL/author-gone`).
* `--shrink-minutes M`: time to shrink each finding (default 2). `--max-findings N`: stop after N
  distinct findings (default 20). `--out DIR`: where findings go (default `findings/`).
* `FZ_RECIPE_TS=1`: the watch's recipe also prints a `timestamptz` column, whose text depends on
  the session's `TimeZone`. `FZ_CONC_BOOST=F`: multiply the weight of the race operations.

If a run is killed with `kill -9`, stop and remove its cluster by hand:

```sh
for d in /dev/shm/pvfz-*; do /dev/shm/pvfuzz/pg/bin/pg_ctl -D "$d/data" -m immediate stop
  rm -rf "$d"; done
```

## Replay a finding

```sh
python3 fuzz.py --pg /dev/shm/pvfuzz/pg --replay findings/f7-adopt-overwrites-refute-upgrade.json
FZ_RECIPE_TS=1 python3 fuzz.py --pg /dev/shm/pvfuzz/pg --replay \
    findings/f12-upgrade-retired-ts-recipe.json
```

It prints `replay: ok`, or the step and the invariant it broke, and exits 0 or 1. When a step was
a no-op because the claim rules no longer let its role act (some sequences predate those rules),
it says which.

## What it found

All fixed in 0.20.0 before its release; `spec.md` section 6 has the details and the files.

| Id | What | Fixed in |
|---|---|---|
| F1 | a claim retired under 0.19.0 came back after the update and `adopt()` | 578af0f |
| F2 | `refute()` of a claim with no proof did not retire it | 578af0f |
| F3 | `supersede()` then `unsupersede()` revived a retired claim | 578af0f |
| F4 | `refute()` of a replaced claim was silently ignored | 578af0f |
| F5 | a dropped (and recreated) author's verdict kept serving `verified` | 6068555 |
| F6 | `refute()` in an older transaction moved `verified_at` back | 6068555 |
| F7 | `adopt()` overwrote a `refute()` or `assert()` that committed while it waited | 3910404 |
| F9 | a `TRUNCATE` of the watched table was not seen | 3910404 |
| F11 | a caller's `DateStyle` order was recorded as the author's through a wrapper | f8bdd83 |
| F12 | with a setting-dependent recipe, the update revived claims retired under 0.19.0 | de2a8b2 |
| F13 | a row deleted and written again under its key kept the old row's claim | b84816e |
| F14 | a claim about a gone row was still served `replaced` or `expired` | e240fde |

F1-F7 were found by the fuzzer. F9 and F11-F14 were found in review and then made into fuzzer
operations and replays. `model-*.json` are harness false positives, kept as regression tests of
the model.

## Reporting

* A sequence that breaks an invariant on the current release: open a GitHub issue with the JSON
  file, the seed, the PostgreSQL and pg_phasevec versions, and the tail of the log.
* If it lets a role change a claim it may not change, see a row its privileges hide, or make a
  verdict say what its proof does not, do not open an issue: report it privately as
  [SECURITY.md](../SECURITY.md) says.
* What the README lists under "Known limits" is known.
* A failure that comes from the model rather than the extension is welcome too: say why you think
  so, and it becomes a `model-*.json` regression.

## Extending

Add an operation in `gen_op()` and `Runner.step()`, its effect in `Model`, and, if the model
cannot predict it (a race), call `self.resync(keys)` afterwards so that only the model-free
invariants judge it. `spec.md` section 7 lists what is not covered yet.
