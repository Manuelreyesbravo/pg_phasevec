# Security

pg_phasevec runs SQL it did not write (a watch's recipe, a claim's proof) and decides who may
change a claim, so a way around either is the most valuable report this project can receive.

## Reporting a vulnerability

**Do not open a public issue.** Report it privately, by either:

* GitHub's private vulnerability reporting: the **Security** tab of this repository, then
  **Report a vulnerability**; or
* email to **manuelreyesbravo@gmail.com**, subject starting with `[pg_phasevec security]`.

Please include the PostgreSQL version, the pg_phasevec version (`SELECT extversion FROM
pg_extension WHERE extname = 'pg_phasevec'`), and the smallest sequence of statements that shows
it. A script in the style of `test/review30.sh` (roles, a watch, the attack, and a check of what
changed) is ideal, because it becomes the regression test.

You will get an acknowledgement within 72 hours. A confirmed issue is fixed before it is
disclosed, gets a regression case in `test/`, and is credited to you in the CHANGELOG unless you
prefer otherwise.

## What counts

Anything that lets a role that is not trusted (see "Status: what this preview is" in the README):

* change, retire or replace a claim it may not change, or take one it may not take;
* make a verdict say what its proof does not, or a proof run with rights or settings that are not
  its author's;
* read through phasevec a row, a claim, a topic or a support that its privileges or row-level
  security hide from it;
* get a reading of text that is no longer the row's served as `fresh`, or two readers' codes
  compared;
* make the update, a restore or `migrate()` lose or alter data.

What the README lists under "Known limits" is known; a clearer way to explain it is welcome too.

## Supported versions

The latest release. Fixes are not backported while the project is pre-1.0.
