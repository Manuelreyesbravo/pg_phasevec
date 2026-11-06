-- pg_phasevec 0.19.0 -> 0.20.0: a verdict is about one claim (the text its author read, the proof, the author),
-- judged in one state under one clock, and the only door to it is a function that knows who calls it.
\echo Use "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" to load this file. \quit

-- (fourteenth review) The extension's tables are taken first, in the order its writers take them: a write to a watched
-- table reads its watch (phasevec.watches), notes the row's text (sources, and lexstats and lexdocs for a lexical
-- watch), and an assert() in the same transaction writes phasevec.truth. Below, truth is altered before watches: in
-- the thirteenth cut a writer that held watches on its way to truth and this script, holding truth on its way to
-- watches, deadlocked, and one of them was aborted. Run the update alone, not in a transaction with DDL on watched
-- tables (that DDL waits for their writers while this holds the extension's tables they wait for).
LOCK TABLE phasevec.watches, phasevec.sources, phasevec.lexstats, phasevec.lexdocs, phasevec.truth
    IN ACCESS EXCLUSIVE MODE;

-- Found by the public-readiness review of 2026-11-05, then by an adversarial review of the first cut of 0.20.0
-- (never released) that ran the attacks:
--
-- 1. A 'verified' truth survived any later edit of its row, and brief() served the new text as verified. The first
--    cut bound each verdict to phasevec.sources.text_hash, a cache only the watch trigger keeps: a table owner who
--    disabled the trigger, set session_replication_role = replica, truncated and inserted again, or rewrote the
--    column with DDL (ALTER COLUMN TYPE ... USING, RENAME plus ADD COLUMN DEFAULT) changed the text with the
--    verdict kept. And a proof that did not read the row verified whatever text a writer put there next.
--    Now the claim records what its author vouched for: assert() reads the row through the watch's recipe, with the
--    author's rights, and keeps its hash (asserted_for). verify() reads the live row, as the author, before and
--    after the proof: the text must be the asserted one, and the row must not move while the proof runs (under READ
--    COMMITTED each statement of a proof can see another snapshot: a text that changed and changed back passed).
--    brief() hashes the line it serves and serves it as 'verified' only if that is the text the verdict judged.
--    The cache is never evidence: a stale one only makes _verdict() say 'unproven'.
-- 2. verify() ran each proof with the rights of whoever called it (a confused deputy). A proof runs as its author
--    (src/phasevec_truth.c). The author is the role's OID, used only while that role still has the name it had (a
--    dropped author, or its name taken by another role, runs nothing). The verdict is bound to the author too: an
--    assert by another role while the proof runs leaves nothing recorded.
-- 3. verify() and verify_one() are C: they know their caller, check it, and write through internals that carry no
--    rights of their own (_truth_due, _truth_of, _truth_set run as whoever calls them, and only the owner can read
--    and write phasevec.truth). In the first cut a verifier needed EXECUTE on SECURITY DEFINER internals, and with
--    it forged 'verified' through _truth_set and listed every proof through _truth_due.
-- 4. The proof clock bounds the verdict: a proof that catches query_canceled runs on but is refuted for its time; a
--    proof cannot run another proof (a nested one reset the outer timer); a query_canceled a proof raises itself is
--    that proof's error (it aborted every verify() of the watch); a session advisory lock a proof takes is released.
--    A proof always has a clock (p_timeout_ms > 0): the cost cap is a planner estimate, not a bound.
-- 5. A proof that closed its own parenthesis made two statements and the second ran in the cost step, with no clock
--    and no cap. Fixed in the library, for every version of the SQL.
-- 6. _forget() was executable by PUBLIC behind a pg_trigger_depth() test that any user's own trigger passes, and in
--    the first cut _note() with a NULL hash did the same for whoever was granted _note(). _note() is C now and
--    refuses a caller that does not write the watch's own table; _forget() is the owner's.
-- 7. _brief_keys() is SECURITY DEFINER and was executable by PUBLIC: any role with USAGE on the schema read the
--    keys, verdicts, usefulness and recipes of every watch. It is the owner's; brief() is granted by the owner.
--
-- Then a second adversarial review ran attacks against that second cut (also never released), and they come from
-- one root: phasevec ran code that was not its own (the recipe, the proof) in more than one way, and in some of them
-- with the rights or the settings of whoever happened to call it. Now there is one guard (src/phasevec_guard.c):
--
-- 8. brief() ran the recipe as its caller with full rights, outside the read-only, security-restricted guard of
--    assert() and verify(): a table owner swapped a column's type for one whose cast was its own code, and a
--    superuser reading the brief made it superuser. A recipe now renders as the table's OWNER (as PostgreSQL runs an
--    index expression in VACUUM or REINDEX), in the guard, everywhere: the watch trigger, assert, verify, brief,
--    next, lexical, audit_sample, watch. Who may read the text is the reader's own right (SELECT on the table; with
--    row-level security, the rows it sees, found as the reader).
-- 9. The text and the proof depended on the session's settings: a writer in another TimeZone (or DateStyle) made an
--    edited row print as the text its author had vouched for, and it was served 'verified'; a verifier in another
--    DateStyle read the author's '01/11/2026' as 11 January and recorded 'verified' for a row the proof, as written,
--    refutes. A recipe renders in pinned settings (DateStyle ISO, TimeZone UTC, extra_float_digits 1, bytea_output
--    hex, search_path pg_catalog, pg_temp, lc_* C, ...), so every reader reads one text; a claim records its
--    author's settings (truth.proof_env) and its proof runs with them, so it means what it meant to its author.
-- 10. A proof could change the verifier's session for good: set transaction_timeout and end the verifier's
--    connection with a FATAL before any verdict was written (every later verify() of the watch died the same way);
--    release the verifier's own session advisory locks; reseed its random(). In the guard the timeouts cannot be
--    changed, and the functions that change the session past a rollback cannot be called. A proof whose verifier's
--    session ends anyway is refuted by the next verify() of the watch, and not run again until asserted again.
-- 11. adopt() made its caller (usually the superuser owner) the author of any orphaned proof, unseen; a role could
--    orphan its own proof on purpose to have it adopted. adopt() now names the author, needs its privileges, works
--    granted and after SET ROLE, returns every proof with its former author, and makes a superuser the author of a
--    key only when that key is named.
-- 12. recall(), disputes(), replacement() and truth_coverage() showed every watch's keys, verdicts, topics, reasons
--    and support to any role with USAGE on the schema. They are one C door now: a watch is shown only to a role that
--    may SELECT its table (and with row-level security, only the keys of the rows it sees).
-- 13. _note() checked that its caller wrote the watched table at all: a writer limited by row-level security, or
--    with UPDATE on one unrelated column, forged, invented or forgot every key of the watch. The watch trigger is C
--    now and renders the row it fires for; _note() is gone.
--
-- Then a third adversarial review ran attacks against the third cut (ee1ec24, never released). The guard is now a
-- sealed room (src/phasevec_guard.c), and the doors compute over what their caller sees:
--
-- 14. A recipe had no subtransaction of its own: it read its caller's open cursor (a superuser's, over a table its
--    owner could not read) and NOTIFYed the rows out at the caller's COMMIT; a proof read, used up and printed its
--    verifier's open cursor. Each guard is a subtransaction, always rolled back; the session's cursors are frozen
--    while it runs; only a reviewed few commands and volatile system functions run in it.
-- 15. A claim recorded twelve named settings; every other one (text search configuration, timezone abbreviations,
--    transform_null_equals, row_security, a custom setting a policy reads) came from the verifier and decided the
--    verdict. A claim records every setting that changes meaning and is off its default; a proof and a recipe start
--    from the defaults.
-- 16. recall()'s disputed_by named keys of rows the caller does not see; replacement() followed a chain through such
--    a row and showed its reason. Each _door_* takes the caller's visible keys (p_visible) and computes over them.
-- 17. A verifier in REPEATABLE READ judged against its first snapshot and recorded the verdict as reached now. verify()
--    judges at READ COMMITTED, and verified_at is when the row was read (_truth_set's p_at).
-- 18. One ended verifier halted every claim that read alike, and past eight ended sessions a mark was dropped. The mark
--    names the claim's key (_truth_halted's p_key_hash); every mark is taken.
-- 19. After this update every write to a watched table from a session that loaded the library of 0.19.0 failed with
--    "could not find function". The trigger is in a library of its own that says to reconnect.
-- 20. A watch over a FORCE ROW LEVEL SECURITY table rendered nothing as its owner; a key column that is not unique let
--    a writer forget another's key. The owner renders without FORCE; watch() needs a unique key.
--
-- Then a fifth adversarial review ran attacks against the fifth cut (ce02558, never released):
--
-- 21. The watch trigger kept its plan per session after ALTER TABLE: a session that wrote before a RENAME, DROP and
--    ADD, or ALTER COLUMN TYPE hashed the old column (a changed row stayed fresh) or failed every write until it
--    reconnected. The plan is kept with the table's row type and parsed again when it changes (src/phasevec_truth.c).
-- 22. A temporary view, type, domain, operator or collation of the verifier's session decided a proof (only tables
--    and functions were refused). Everything a query run in the guard uses is checked (src/phasevec_guard.c).
-- 23. A write that changed a row's text waited on every open transaction that had judged that key (a trigger on
--    phasevec.sources wrote the verdict). Staleness is computed when read again, in _verdict(); no writer waits on a
--    verifier.
-- 24. Two verify() of one watch deadlocked on verdict rows under writes, and the aborted call lost every verdict it
--    had reached. verify() takes each claim's row before judging it, or leaves it to whoever holds it.
--
-- Then a sixth adversarial review ran attacks against the sixth cut (78e1e89, never released):
--
-- 25. The verifier's temporary objects decided proofs through names looked up while they run (to_regclass, a cast of
--    text to regclass, pg_input_is_valid, set_config of default_text_search_config) and through the RETURNING type
--    of JSON_VALUE and JSON_QUERY; on PostgreSQL 18 also through a regconfig or regdictionary constant. verify() and
--    verify_one() run only in a session with no temporary object; the walk sees those types and constants
--    (src/phasevec_guard.c).
-- 26. A halt mark was cleared before its record was written, in the caller's transaction: a rollback, or a
--    verify_one() refused to a role that may not act as the author, erased it, and that role held the claim's row.
--    It is cleared when the record commits, by a verifier that may act as the author (_truth_halted's p_verifier).
-- 27. On a partition whose columns stand in another order the watch trigger rendered a whole-row recipe in the
--    partition's order. It reads a partition's row as one of the watch's table.
-- 28. verify() wrote 'unproven' over the verdict of a claim whose row said something else when it looked, and the
--    verdict stayed when the text came back. It leaves the verdict and records that it looked (truth.looked_at,
--    looked_for).
--
-- Then a seventh adversarial review ran attacks against the seventh cut (2ecf398, never released):
--
-- 29. A custom placeholder (app.tenant) stays in a session once anything named it, and a rollback does not take it
--    away: current_setting('app.tenant', true) then reads '' where it read NULL, and the guard could not tell one
--    that exists from one that does not. A proof that only called set_config, judged first in a verify(), decided a
--    later author's verdict through the row-level security policy it ran under; a pooled verifier connection that
--    once ran SET LOCAL app.tenant recorded verdicts the persistent state refutes. A claim records every placeholder
--    its author's session had (truth.proof_env, "app.tenant=" for one with no value), and is judged only in a
--    session whose placeholders are those (src/phasevec_guard.c, guard_env_misfit). A claim recorded before names
--    only the placeholders that had a value then: it reads as if its author's session had no other.
--
-- Then an eighth review moved each proof into a session of its own (a background worker connected as its author,
-- src/phasevec_truth.c), and a ninth ran attacks against that cut (2f42e62, never released):
--
-- 30. A worker terminated by another process (a role with pg_signal_backend, the verifier from another session) was
--    taken for a proof that ended its own session: a true claim was recorded refuted and halted for good, and left
--    brief(). The worker notes who sent it SIGTERM: a session another process ends leaves its claim due, its verdict
--    as it was (_truth_interrupted, truth.interrupted_at); only one the proof ended itself is halted.
-- 31. A claim over 64 kB blocked its verifier inside a send, with no deadline: behind a proof that catches
--    query_canceled, or a worker waiting for a lock, neither the proof's clock nor p_budget ended the call. Sends do
--    not wait now: the verifier keeps every deadline while it sends, a large claim in pieces.
-- 32. A proof that waited for its verifier through a third session (an ALTER TABLE queued behind the verifier's read)
--    waited out its clock and was recorded refuted, and the ALTER and every reader of the table waited n times the
--    clock. The verifier walks the waits and stops with an error; a proof still waiting for another session's lock
--    when its clock ends is 'unproven', not refuted.
-- 33. A verifier with an uncommitted write that refuted a claim committed, together with that write, a 'verified' its
--    proof reached on the state before it. A transaction that has written may not verify, and the worker takes,
--    judges and records each claim in a transaction of its own, committing each verdict as it is reached.
--
-- Then a tenth adversarial review ran attacks against the ninth cut (c1461cf, never released):
--
-- 34. verify_one() judged before it took the claim's row, then waited for the row a verify() was judging; when that
--    one had recorded 'refuted' (the claim had turned false), verify_one() wrote its older 'verified' over it, and
--    brief() served it. Every worker takes the claim's row before it judges, and _truth_set does not replace a
--    verdict (or an interruption) read later than the judgment it records.
-- 35. An ordinary author set its own role's transaction_timeout to 1 ms: its proofs' sessions ended before they judged,
--    and its claims kept their old 'verified' forever. The worker pins the session timeouts before it connects.
-- 36. A claim that cannot be judged for its author's sake (a new session of the author fails as it starts) kept serving
--    its verdict, and with p_n such claims held the head of the queue and kept other authors' claims from being
--    judged. It is recorded, and its turn goes behind the claims that wait (see 37 and 38: the tenth cut's marks,
--    unjudged_at, unjudged_until, unjudged_why and tried_at, are gone).
--
-- Then an eleventh adversarial review ran attacks against the tenth cut (07b019f, never released). Each one stopped
-- judgment from moving while the old verdict was still served. Three rules replace the patches:
--
-- 37. Safety does not depend on liveness. A verdict ('verified', 'refuted') serves only while it is fresh: judged within
--    its watch's max_age (phasevec.watches.max_age, 1 hour by default). Past it, it reads 'unproven' (_verdict),
--    whatever kept it from being judged again: an assert() left open on its row (by any role that may assert), an
--    author holding its own claims, a lock, the server, no worker free, a verifier that does not run. In the tenth
--    cut an uncommitted assert() held a claim's row with no time limit, and brief() served the old 'verified' after
--    the committed state refuted it.
-- 38. The due queue is a fair rotation. Every attempt to judge a claim spends its turn, judged or not (taken by another
--    transaction, an error that is not the proof's, a session that ends), in phasevec.attempts: written only by the
--    proofs' own sessions, each attempt in a transaction of its own committed at once, so no other session can hold
--    it. _truth_due takes the claims whose turn is oldest first (a claim never tried, from when it was asserted): a
--    claim due is tried within ceil(N / p_n) calls of verify() that run their p_n. In the tenth cut a stale claim
--    (its row edited, not asserted again) always sorted first: once p_n rows were edited, no other claim was judged
--    again; and an author holding its own claims' rows in an open transaction had them skipped, unrecorded, at the
--    head of the queue.
-- 39. Only the proof's own logic decides its verdict. An error in the proof is its answer (refuted) when it comes from
--    what the proof computes (data, constraints, SQL, rights, RAISE, program limits); not when it comes from the
--    server or from other sessions (connections, rollbacks, insufficient resources, lock not available, operator
--    intervention, system and internal errors): then nothing is judged and the verdict stays until its horizon (the
--    table is in src/phasevec_truth.c, not_a_verdict). In the tenth cut a role with no grants filled the shared lock
--    table with advisory locks, a proof failed 'out of shared memory', and a true claim was recorded refuted. A lock
--    wait, a deadlock and a lock_timeout (ninth review) are the same: nothing judged (they recorded 'unproven').
--
-- Then a twelfth adversarial review ran attacks against the eleventh cut (4f966eb, never released), and found each
-- of those rules broken by something that was not the claim's:
--
-- 40. Only the proof's own work can refute it by time. A lock another session held, let go just before the clock
--    ended, left the proof to finish after it, and a true claim was recorded refuted. Now a proof that waited for a
--    lock and ended after its clock is not judged (src/phasevec_truth.c, lock_waited_since).
-- 41. A turn is spent by a session its author cannot end. The proof's session, the author's own, spent it: an author
--    that terminated its own sessions before they did kept its claims at the head of the queue. Now verify()'s
--    keeper, a session of the extension's owner, spends the turns before the claims go to their author's session.
-- 42. Freshness is judged at the moment of reading: _verdict() and every read path compare max_age and expires_at
--    with clock_timestamp(), not now() (the start of the reader's transaction).
--
-- Found by the sixteenth review (four lenses; each finding run against this cut):
--
-- 43. A statement phasevec ran as its owner resolved its names through the search_path of whoever was connected. A
--    proof's session is a session of its author: an author's ALTER ROLE ... SET search_path put its own '=' for
--    bytea before pg_catalog's, the IS DISTINCT FROM of the claim's take ran it as the owner (a superuser), and the
--    author made itself superuser and wrote a 'verified' for a false proof. Now become() (src/phasevec_truth.c)
--    pins search_path = pg_catalog, pg_temp and every setting that changes what a value reads or prints (the same
--    pins a recipe has, transform_null_equals off) for each statement it runs, kept plans included; and every
--    operator in phasevec's own C statements names its schema. Below, _term() and _reads() name theirs, and the C
--    functions that run SQL as their caller (the IVF ones) carry a search_path of their own.
-- 44. _verdict(t) kept who may see a watch for as long as PL/pgSQL kept its expression (a transaction): after a
--    REVOKE or ENABLE ROW LEVEL SECURITY it went on answering, and a forged row told whether a guess was a hidden
--    row's text. Now it checks on every call; and it keeps only which table a watch reads, in fixed slots (each miss
--    kept a copy of the watch in the query's memory: 1 GB for one query over 20 watches).
-- 45. The freshness horizon was computed in the reader's TimeZone: a '1 day' max_age lasted that zone's day (48 hours
--    under a POSIX rule). It is computed in UTC (_verdict_of, _truth_due, the claim's take), whoever reads.
-- 46. verify() in a READ ONLY transaction ran every proof and committed their verdicts, in sessions of its own. A
--    transaction (or session, or standby) that writes nothing records nothing through verify() either.
-- 47. A proof session kept judging, and stamping 'verified', in the name of an author dropped during the call. A
--    verdict is recorded in its author's name only while the author is a role (locked against DROP ROLE until it
--    commits).

ALTER TABLE phasevec.truth ADD COLUMN asserted_by name, ADD COLUMN asserted_by_oid oid,
                           ADD COLUMN asserted_for bytea, ADD COLUMN verified_for bytea,
                           ADD COLUMN proof_env text[], ADD COLUMN halted boolean NOT NULL DEFAULT false,
                           ADD COLUMN looked_at timestamptz, ADD COLUMN looked_for bytea,
                           ADD COLUMN interrupted_at timestamptz, ADD COLUMN interrupted_why text;
COMMENT ON COLUMN phasevec.truth.asserted_by IS
    $q$The name of the role that asserted the proof, when it did (0.20.0). With asserted_by_oid: the proof runs as that role only while the OID still has this name.$q$;
COMMENT ON COLUMN phasevec.truth.asserted_by_oid IS
    $q$The role that asserted the proof (0.20.0): the proof runs with its rights. NULL for a proof asserted before 0.20.0, which does not run until asserted again (phasevec.adopt).$q$;
COMMENT ON COLUMN phasevec.truth.asserted_for IS
    $q$What the author vouched for (0.20.0): sha256 of the row's text as the recipe renders it (as the table's owner, in pinned settings) when it asserted. NULL when there was no row it could see.$q$;
COMMENT ON COLUMN phasevec.truth.verified_for IS
    $q$What the verdict judged (0.20.0): phasevec._bind of the claim (asserted_for, proof, author, proof_env). A 'verified' that does not match the claim, or whose text is not the row's, reads 'unproven'.$q$;
COMMENT ON COLUMN phasevec.truth.looked_at IS
    $q$When verify() last found the row gone or saying something else than what was asserted (0.20.0): the verdict is left bound to the text it judged, and the claim is not due again for that text until p_every has passed.$q$;
COMMENT ON COLUMN phasevec.truth.looked_for IS
    $q$The row's text hash (phasevec.sources) when verify() found it stale (looked_at); NULL when the row was gone (0.20.0).$q$;
COMMENT ON COLUMN phasevec.truth.proof_env IS
    $q$What the author's session had changed when it asserted, over the configuration every new session of the author starts from ("name=value": DateStyle, TimeZone, search_path, application_name, ...; "app.tenant=" for a custom placeholder it made, with no value): the proof runs in a new session of its author, with these on top (0.20.0).$q$;
COMMENT ON COLUMN phasevec.truth.interrupted_at IS
    $q$When the session that ran this proof was last ended by another process while it ran (0.20.0, ninth review): nothing was judged, and the verdict stays as it was until its horizon (watches.max_age). Cleared by a verdict or an assert.$q$;
COMMENT ON COLUMN phasevec.truth.interrupted_why IS
    $q$Who ended the session that ran this proof (interrupted_at): the process that terminated it.$q$;
-- 37. A verdict serves while it is fresh: judged (verified_at) within its watch's max_age. Choose it longer than the
-- time verify() takes to come round every claim of the watch: ceil(claims / p_n) calls, each p_every or the cron's
-- interval apart (whichever is longer), and the same again for a call that judges a claim just after p_every.
ALTER TABLE phasevec.watches ADD COLUMN max_age interval NOT NULL DEFAULT interval $q$1 hour$q$
    CONSTRAINT watches_max_age_check CHECK (max_age > interval $q$0$q$);
COMMENT ON COLUMN phasevec.watches.max_age IS
    $q$How long a verdict of this watch serves after it was judged (0.20.0, eleventh review): past verified_at + max_age a 'verified' or 'refuted' reads 'unproven', whatever kept it from being judged again. Longer than verify() takes to come round every claim (ceil(claims / p_n) calls, p_every or the cron's interval apart, twice). The owner sets it: UPDATE phasevec.watches SET max_age = ... WHERE name = ...$q$;

-- 38. Whose turn it is. Written only by phasevec's own sessions (src/phasevec_truth.c, record_attempt): since the
-- twelfth review (41) verify()'s keeper, a session of the owner, before a claim goes to its author's session; each
-- attempt in a transaction of its own committed at once: no other session writes or holds these rows. Unlogged:
-- after a crash the rotation starts again from when each claim was asserted, and nothing about a verdict is lost.
CREATE UNLOGGED TABLE phasevec.attempts (
    watch         int  NOT NULL REFERENCES phasevec.watches(id) ON DELETE CASCADE,
    key           text NOT NULL,
    attempted_at  timestamptz NOT NULL,
    why           text,
    PRIMARY KEY (watch, key)
);
COMMENT ON TABLE phasevec.attempts IS
    $q$When a proof's session last got each claim, judged or not, and why it was not judged when it was not (0.20.0, eleventh review): verify() takes the claims whose turn is oldest. The owner's only.$q$;
REVOKE ALL ON phasevec.attempts FROM PUBLIC;

COMMENT ON COLUMN phasevec.truth.halted IS
    $q$The session that ran this proof ended while it ran (0.20.0): it is refuted and not run by verify() again until asserted again.$q$;

-- A verdict judges (text, proof, author, the author's settings). Every part is framed, so no two claims read alike.
CREATE FUNCTION phasevec._bind(p_text_hash bytea, p_proof text, p_author oid, p_env text[])
RETURNS bytea LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $f$
    SELECT sha256(CASE WHEN p_text_hash IS NULL THEN $q$\x00$q$::bytea ELSE $q$\x01$q$::bytea || p_text_hash END
                  || int8send(coalesce(p_author, 0)::bigint)
                  || int4send(octet_length(convert_to(coalesce(p_proof, $q$$q$), $q$UTF8$q$)))
                  || convert_to(coalesce(p_proof, $q$$q$), $q$UTF8$q$)
                  || convert_to(coalesce(array_to_string(p_env, chr(10), $q$$q$), $q$$q$), $q$UTF8$q$))
$f$;

-- The truth a key has NOW. 'verified' only for the claim it judged, and only while the row's text, as the watch
-- trigger last saw it, is the asserted one; 'refuted' only while it is the refuted one. (brief() also checks the text
-- it serves; verify() checks the live row.) Computed when read: a writer never touches a verdict. In the fifth cut a
-- trigger on phasevec.sources set the verdict of a row whose text changed to 'unproven' as it was written, and so the
-- write waited for every open transaction that had judged that key (a verify() for its whole budget, or longer inside
-- a larger transaction): under load a writer went from 0.2 ms to 13-36 ms, and failed on lock_timeout.
CREATE FUNCTION phasevec._verdict_of(t phasevec.truth) RETURNS text
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    SELECT CASE WHEN t.verdict = $q$replaced$q$ THEN $q$replaced$q$
                -- (twelfth review) Freshness is judged at the moment of reading: clock_timestamp(), not now(). now()
                -- is when the reader's transaction began: in a long READ COMMITTED transaction brief() and
                -- truth_coverage() served 'verified' past max_age (and past expires_at) for as long as it stayed
                -- open, after it could itself see the claim was false. Not statement_timestamp() either: one long
                -- statement (a DO block, a function looping over brief()) is a reader of its own.
                WHEN t.expires_at IS NOT NULL AND t.expires_at <= clock_timestamp() THEN $q$expired$q$
                -- (eleventh review, 37) a verdict of a proof serves while it is fresh: judged within the watch's
                -- max_age. Not a halted claim's (its proof ended its session: not run again) nor a refute() with
                -- no proof (nothing judges it again).
                WHEN t.verdict IN ($q$verified$q$, $q$refuted$q$) AND t.proof IS NOT NULL AND NOT t.halted
                 -- (sixteenth review, 45) in UTC: in the reader's TimeZone a '1 day' max_age was the length of
                 -- that zone's day (48 hours under a POSIX rule a reader may set; 23 or 25 across a DST change).
                 AND coalesce(timezone($q$UTC$q$, t.verified_at)
                              + (SELECT w.max_age FROM phasevec.watches w WHERE w.id = t.watch)
                              > timezone($q$UTC$q$, clock_timestamp()), false)
                     IS NOT TRUE
                THEN $q$unproven$q$
                WHEN t.verdict = $q$verified$q$
                 AND (t.verified_for IS NULL
                      OR t.verified_for IS DISTINCT FROM phasevec._bind(t.asserted_for, t.proof, t.asserted_by_oid,
                                                                        t.proof_env))
                THEN $q$unproven$q$
                WHEN t.verdict IN ($q$verified$q$, $q$refuted$q$)
                 AND t.asserted_for IS DISTINCT FROM (SELECT s.text_hash FROM phasevec.sources s
                                                      WHERE s.watch = t.watch AND s.key = t.key)
                THEN $q$unproven$q$
                ELSE t.verdict END
$f$;

-- assert(): the same signature and grants; now C (src/phasevec_truth.c): it sees who calls it, renders the row as
-- the table's owner in pinned settings, records the caller's settings, and writes through _assert_set, as the owner.
CREATE FUNCTION phasevec._assert_set(p_watch text, p_key text, p_proof text, p_topic text, p_support jsonb,
                                     p_expires_at timestamptz, p_author oid, p_text_hash bytea, p_env text[])
RETURNS void LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $f$
DECLARE w phasevec.watches := phasevec._watch(p_watch);
BEGIN
    INSERT INTO phasevec.truth AS t (watch, key, proof, topic, support, expires_at,
                                     asserted_by, asserted_by_oid, asserted_for, proof_env)
    VALUES (w.id, p_key, p_proof, p_topic, p_support, p_expires_at,
            pg_get_userbyid(p_author), p_author, p_text_hash, p_env)
    ON CONFLICT (watch, key) DO UPDATE
       SET proof = EXCLUDED.proof, topic = EXCLUDED.topic, support = EXCLUDED.support,
           expires_at = EXCLUDED.expires_at, asserted_by = EXCLUDED.asserted_by,
           asserted_by_oid = EXCLUDED.asserted_by_oid, asserted_for = EXCLUDED.asserted_for,
           proof_env = EXCLUDED.proof_env, halted = false,
           verdict = CASE WHEN t.verdict = $q$replaced$q$ THEN t.verdict ELSE $q$unproven$q$ END,
           verified_at = NULL, verified_for = NULL, last_error = NULL, changed_at = now(),
           looked_at = NULL, looked_for = NULL, interrupted_at = NULL, interrupted_why = NULL;
END;
$f$;
CREATE OR REPLACE FUNCTION phasevec.assert(p_watch text, p_key text, p_proof text DEFAULT NULL, p_topic text DEFAULT NULL,
                                           p_support jsonb DEFAULT NULL, p_expires_at timestamptz DEFAULT NULL)
RETURNS void AS $q$MODULE_PATHNAME$q$, $q$phasevec_assert$q$ LANGUAGE C VOLATILE;

-- refute(): as in 0.14.1, and the refutation is about the text it refuted (the asserted one, or the row's text as
-- the trigger last saw it when nothing was asserted): when that text changes, it is not refuted any more.
CREATE OR REPLACE FUNCTION phasevec.refute(p_watch text, p_key text, p_reason text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
DECLARE w phasevec.watches := phasevec._watch(p_watch);
BEGIN
    IF coalesce(btrim(p_reason), $q$$q$) = $q$$q$ THEN
        RAISE EXCEPTION $q$phasevec: a refutation says why$q$;
    END IF;
    INSERT INTO phasevec.truth AS t (watch, key, verdict, verified_at, last_error, asserted_for)
    VALUES (w.id, p_key, $q$refuted$q$, now(), p_reason,
            (SELECT s.text_hash FROM phasevec.sources s WHERE s.watch = w.id AND s.key = p_key))
    ON CONFLICT (watch, key) DO UPDATE
       SET verdict = $q$refuted$q$, verified_at = now(), last_error = p_reason, changed_at = now(),
           verified_for = phasevec._bind(t.asserted_for, t.proof, t.asserted_by_oid, t.proof_env)
     WHERE t.verdict <> $q$replaced$q$;
END;
$f$;

-- The internals of verify() and verify_one() (src/phasevec_truth.c). They are not SECURITY DEFINER: they read and
-- write phasevec.truth, which only the owner can, so they work only when the C functions call them as the owner.
-- The C side passes the caller's OID, which a caller cannot choose.
--
-- The due proofs p_verifier may run, oldest first; a proof whose author is gone (no role with that OID and name)
-- is due for anyone: what verify() records for it is 'unproven'. A halted claim is not due. A verdict whose row's
-- text changed since (it reads 'unproven' already, _verdict) is due first, so verify() says why: the writer that
-- changed the text did not touch the verdict (_truth_stale; verify() checks it again when it takes the claim).
CREATE FUNCTION phasevec._truth_stale(t phasevec.truth) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    SELECT t.verdict IN ($q$verified$q$, $q$refuted$q$)
       AND t.asserted_for IS DISTINCT FROM (SELECT s.text_hash FROM phasevec.sources s
                                            WHERE s.watch = t.watch AND s.key = t.key)
$f$;
--
-- (eleventh review, 38) Oldest turn first: when a proof's session last got the claim (phasevec.attempts), or for a
-- claim it never got, when it was asserted (changed_at). An attempt spends the turn whatever became of it, so a
-- claim that cannot be judged now (its row held, a stale text, an error that is not the proof's) goes behind every
-- claim that waits: of N claims due, each is tried within ceil(N / p_n) calls that run their p_n. In the tenth cut a
-- stale claim sorted first (tried_at NULLS FIRST, and the stale path set tried_at NULL): once p_n rows had been
-- edited, no other claim was judged again. The order is one queue, not a round per author: with a round per author
-- an author of few claims is tried more often, and one of many waits longer than ceil(N / p_n) calls; and with one
-- queue no author holds its head (every turn it spends goes to the back). verify() then sends the claims of one
-- author together, as before.
DROP FUNCTION phasevec._truth_due(int, int, interval);
CREATE FUNCTION phasevec._truth_due(p_watch int, p_n int, p_every interval, p_verifier oid)
RETURNS TABLE (key text, proof text, author oid, author_known boolean, asserted_for bytea, env text[], bind bytea)
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    SELECT t.key, t.proof, t.asserted_by_oid, r.oid IS NOT NULL, t.asserted_for, t.proof_env,
           phasevec._bind(t.asserted_for, t.proof, t.asserted_by_oid, t.proof_env)
      FROM phasevec.truth t
      LEFT JOIN phasevec.attempts a ON a.watch = t.watch AND a.key = t.key
      LEFT JOIN pg_catalog.pg_roles r ON r.oid = t.asserted_by_oid AND r.rolname = t.asserted_by
     CROSS JOIN LATERAL (SELECT (SELECT s.text_hash FROM phasevec.sources s
                                  WHERE s.watch = t.watch AND s.key = t.key) AS text_hash) s
     CROSS JOIN LATERAL (SELECT t.verdict IN ($q$verified$q$, $q$refuted$q$)
                                AND t.asserted_for IS DISTINCT FROM s.text_hash AS stale) x
     WHERE t.watch = p_watch AND t.proof IS NOT NULL AND t.verdict <> $q$replaced$q$
       AND t.asserted_by_oid IS NOT NULL AND NOT t.halted
       -- a stale claim is due once for each text it reads (verify() records that it looked: looked_at,
       -- looked_for), and again for the same text after p_every; any other, when its verdict is older than p_every
       AND CASE WHEN x.stale
                THEN t.looked_at IS NULL OR timezone($q$UTC$q$, t.looked_at) < timezone($q$UTC$q$, now()) - p_every
                     OR t.looked_for IS DISTINCT FROM s.text_hash
                ELSE t.verified_at IS NULL OR timezone($q$UTC$q$, t.verified_at) < timezone($q$UTC$q$, now()) - p_every END
       AND (r.oid IS NULL OR pg_catalog.pg_has_role(p_verifier, r.oid, $q$USAGE$q$))
     ORDER BY coalesce(a.attempted_at, t.changed_at), t.key
     LIMIT p_n
$f$;

-- One key's claim (verify_one, which runs a halted claim too: it was asked for); no row when it has no proof or was
-- replaced.
CREATE FUNCTION phasevec._truth_of(p_watch int, p_key text)
RETURNS TABLE (key text, proof text, author oid, author_known boolean, asserted_for bytea, env text[], bind bytea)
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    SELECT t.key, t.proof, t.asserted_by_oid, r.oid IS NOT NULL, t.asserted_for, t.proof_env,
           phasevec._bind(t.asserted_for, t.proof, t.asserted_by_oid, t.proof_env)
      FROM phasevec.truth t
      LEFT JOIN pg_catalog.pg_roles r ON r.oid = t.asserted_by_oid AND r.rolname = t.asserted_by
     WHERE t.watch = p_watch AND t.key = p_key AND t.proof IS NOT NULL AND t.verdict <> $q$replaced$q$
$f$;

-- Record what a proof's run found, only for the claim it judged (p_bind: the same text, proof, author and settings).
-- Anything else changed meanwhile: nothing is recorded. p_outcome NULL records nothing (the row moved while the
-- proof ran). p_at: when the row was read for it, the state it judged (verified_at). Returns the verdict as it
-- reads now. (tenth review) A verdict read after p_at is not replaced: verdicts only move
-- forward in time. A worker takes the claim's row before it judges, so of two judgments of one claim the later one
-- commits later; a record of what a verifier found about an earlier run (a proof that took too long) can still come
-- after a newer verdict, and is dropped.
DROP FUNCTION phasevec._truth_set(int, text, boolean, text);
CREATE FUNCTION phasevec._truth_set(p_watch int, p_key text, p_outcome text, p_error text, p_bind bytea,
                                    p_at timestamptz)
RETURNS text LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $f$
DECLARE v text;
BEGIN
    IF p_outcome = $q$stale$q$ THEN
        -- the row is gone or says something else, and the watch trigger saw it too (the verdict reads 'unproven'
        -- already): the verdict is left bound to the text it judged; only that verify() looked is recorded. When
        -- the trigger did not see it (_truth_stale is false), the row and the claim disagree: 'unproven'.
        UPDATE phasevec.truth t
           SET looked_at = now(),
               looked_for = (SELECT s.text_hash FROM phasevec.sources s WHERE s.watch = t.watch AND s.key = t.key)
         WHERE t.watch = p_watch AND t.key = p_key AND t.verdict IN ($q$verified$q$, $q$refuted$q$)
           AND phasevec._bind(t.asserted_for, t.proof, t.asserted_by_oid, t.proof_env) = p_bind
           AND phasevec._truth_stale(t);
        p_outcome := CASE WHEN FOUND THEN NULL ELSE $q$unproven$q$ END;
    END IF;
    IF p_outcome IS NOT NULL THEN
        UPDATE phasevec.truth t
           SET verdict = p_outcome, verified_at = coalesce(p_at, now()), last_error = p_error, halted = false,
               verified_for = CASE WHEN p_outcome IN ($q$verified$q$, $q$refuted$q$) THEN p_bind END,
               looked_at = NULL, looked_for = NULL, interrupted_at = NULL, interrupted_why = NULL
         WHERE t.watch = p_watch AND t.key = p_key AND t.verdict <> $q$replaced$q$
           AND phasevec._bind(t.asserted_for, t.proof, t.asserted_by_oid, t.proof_env) = p_bind
           AND (t.verified_at IS NULL OR t.verified_at <= coalesce(p_at, now()));
    END IF;
    SELECT phasevec._verdict_of(t) INTO v FROM phasevec.truth t WHERE t.watch = p_watch AND t.key = p_key;
    RETURN v;
END;
$f$;

-- A claim whose proof ended the session that ran it (since the eighth review a session of the proof's own, a
-- background worker: src/phasevec_truth.c; the verifier that sent it records this): refuted, and not due again until
-- asserted again. It names the claim's key (p_key_hash, sha256 of it) and the claim (p_bind): in the third cut only
-- the claim, and one session that ended halted every key whose text, proof and author read alike. Recorded only by a
-- verifier that may act as the claim's author (anyone, for a claim whose author is gone): another one neither writes
-- nor locks the row (in the sixth review a role with no rights over the author held it, and the author's assert()
-- waited). A claim asserted again since the proof began (p_started) is not the one that ran: it runs. Returns 1 when
-- recorded, 0 when no such claim is left, -1 when this verifier may not record it.
CREATE FUNCTION phasevec._truth_halted(p_watch int, p_key_hash bytea, p_bind bytea, p_verifier oid,
                                       p_started timestamptz)
RETURNS int LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $f$
DECLARE k text; a oid; known boolean;
BEGIN
    SELECT t.key, t.asserted_by_oid, r.oid IS NOT NULL INTO k, a, known
      FROM phasevec.truth t
      LEFT JOIN pg_catalog.pg_roles r ON r.oid = t.asserted_by_oid AND r.rolname = t.asserted_by
     WHERE t.watch = p_watch AND t.verdict <> $q$replaced$q$
       AND sha256(convert_to(t.key, $q$UTF8$q$)) = p_key_hash
       AND phasevec._bind(t.asserted_for, t.proof, t.asserted_by_oid, t.proof_env) = p_bind
       AND (t.changed_at IS NULL OR t.changed_at <= p_started)
       -- (tenth review) a verdict read after this proof began stands
       AND (t.verified_at IS NULL OR t.verified_at <= p_started);
    IF NOT FOUND THEN
        RETURN 0;
    END IF;
    IF known AND NOT pg_catalog.pg_has_role(p_verifier, a, $q$USAGE$q$) THEN
        RETURN -1;
    END IF;
    UPDATE phasevec.truth t
       SET verdict = $q$refuted$q$, verified_at = now(), verified_for = p_bind, halted = true, changed_at = now(),
           interrupted_at = NULL, interrupted_why = NULL,
           last_error = $q$the session that ran this proof ended while it ran: not run again until it is asserted again$q$
     WHERE t.watch = p_watch AND t.key = k AND t.verdict <> $q$replaced$q$
       AND phasevec._bind(t.asserted_for, t.proof, t.asserted_by_oid, t.proof_env) = p_bind;
    RETURN CASE WHEN FOUND THEN 1 ELSE 0 END;
END;
$f$;

-- (eleventh review, 38) A claim is about to be tried: its turn is spent, whatever becomes of it. Called only by
-- phasevec's own sessions, in a transaction of their own that commits at once (src/phasevec_truth.c, record_attempt):
-- since the twelfth review (41) by verify()'s keeper, a session its author cannot end, before the author's gets it.
CREATE FUNCTION phasevec._truth_attempt(p_watch int, p_key text)
RETURNS void LANGUAGE sql SET search_path = pg_catalog, pg_temp AS $f$
    INSERT INTO phasevec.attempts AS a (watch, key, attempted_at) VALUES (p_watch, p_key, clock_timestamp())
    ON CONFLICT (watch, key) DO UPDATE SET attempted_at = EXCLUDED.attempted_at, why = NULL
$f$;

-- (ninth, tenth and eleventh reviews) A claim tried and not judged: its proof's session was ended by another process
-- while it ran (a role with pg_signal_backend, the author, a shutdown: interrupted_at, interrupted_why), or the proof
-- failed for a reason that is not its own (39), or a session of its author could not judge it (it ends as it starts,
-- a setting it has). Nothing about the verdict is recorded: it stays as it was, and serves only until its horizon
-- (37). Why is kept with the claim's turn (phasevec.attempts). Until the ninth review an ended session was recorded
-- refuted and halted; in the tenth cut a claim its author's sessions could not judge was marked unjudged, kept its
-- verdict for one p_every more, and with the stale path held the head of the queue. Returns the verdict as it reads
-- now.
CREATE FUNCTION phasevec._truth_tried(p_watch int, p_key text, p_why text, p_interrupted boolean)
RETURNS text LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $f$
DECLARE v text;
BEGIN
    INSERT INTO phasevec.attempts AS a (watch, key, attempted_at, why) VALUES (p_watch, p_key, clock_timestamp(), p_why)
    ON CONFLICT (watch, key) DO UPDATE SET attempted_at = greatest(a.attempted_at, EXCLUDED.attempted_at), why = p_why;
    IF p_interrupted THEN
        UPDATE phasevec.truth t SET interrupted_at = now(), interrupted_why = p_why
         WHERE t.watch = p_watch AND t.key = p_key AND t.verdict <> $q$replaced$q$;
    END IF;
    SELECT phasevec._verdict_of(t) INTO v FROM phasevec.truth t WHERE t.watch = p_watch AND t.key = p_key;
    RETURN v;
END;
$f$;

-- verify() and verify_one(): the same signatures and grants; now C. See src/phasevec_truth.c.
CREATE OR REPLACE FUNCTION phasevec.verify(p_watch text, p_n int DEFAULT 100,
                                           p_every interval DEFAULT interval $q$10 minutes$q$,
                                           p_budget interval DEFAULT interval $q$5 seconds$q$,
                                           p_timeout_ms int DEFAULT 2000, p_max_cost float8 DEFAULT 1e6)
RETURNS TABLE (key text, verdict text, error text)
AS $q$MODULE_PATHNAME$q$, $q$phasevec_verify$q$ LANGUAGE C VOLATILE;
CREATE OR REPLACE FUNCTION phasevec.verify_one(p_watch text, p_key text, p_timeout_ms int DEFAULT 2000,
                                               p_max_cost float8 DEFAULT 1e6)
RETURNS text AS $q$MODULE_PATHNAME$q$, $q$phasevec_verify_one$q$ LANGUAGE C VOLATILE;

DROP FUNCTION phasevec._prove_c(text, int, float8);

-- Proofs asserted before 0.20.0 have no author, and after a restore into another cluster (or a DROP ROLE) an author
-- OID may name no role, or another one. adopt() asserts such proofs again in the name of the author it is given
-- (C, src/phasevec_truth.c): the caller must hold that role's privileges, every proof comes back with its former
-- author, and a superuser becomes the author only of the keys named in p_superuser_keys. Replaced keys are left.
CREATE FUNCTION phasevec.adopt(p_watch text, p_author regrole, p_keys text[] DEFAULT NULL,
                               p_superuser_keys text[] DEFAULT NULL)
RETURNS TABLE (key text, proof text, former_author text, adopted boolean, note text)
AS $q$MODULE_PATHNAME$q$, $q$phasevec_adopt$q$ LANGUAGE C VOLATILE;
COMMENT ON FUNCTION phasevec.adopt(text, regrole, text[], text[]) IS
    $q$Asserts again, in the name of p_author (the caller must hold its privileges), the proofs of a watch whose author is unknown (asserted before 0.20.0) or gone; returns each one. A superuser becomes the author only of keys named in p_superuser_keys. Owner only, or granted.$q$;

-- Verdicts reached before 0.20.0 were reached with the verifier's rights and about no claim: a 'verified' is not
-- carried over (back to unproven, with the reason in last_error). A 'refuted' stays refuted, about the row's text
-- as it is now. Their proofs have no author and do not run until asserted again (phasevec.adopt).
UPDATE phasevec.truth
   SET verdict = $q$unproven$q$, verified_at = NULL, changed_at = now(),
       last_error = $q$verified before 0.20.0, with the verifier's rights: not carried over$q$
 WHERE verdict = $q$verified$q$;
UPDATE phasevec.truth t SET asserted_for = s.text_hash
  FROM phasevec.sources s
 WHERE s.watch = t.watch AND s.key = t.key AND t.verdict = $q$refuted$q$;

-- ------------------------------------------------------------------------------------------ rendering a row --
-- 8, 9, 13. One way to read a watched row's text: phasevec._render() (C), the recipe as the table's owner in the
-- guard and the pinned settings, for a caller that may SELECT the table (and its rows, with row-level security).
CREATE FUNCTION phasevec._render(p_watch text, p_keys text[])
RETURNS TABLE (key text, body text, text_hash bytea)
AS $q$MODULE_PATHNAME$q$, $q$phasevec_render$q$ LANGUAGE C STABLE;
COMMENT ON FUNCTION phasevec._render(text, text[]) IS
    $q$The rows of a watch (p_keys NULL: all) as its recipe renders them: as the table's owner, read-only and security-restricted, in pinned settings. For a caller that may SELECT the table (0.20.0).$q$;

-- The watch trigger's write, as the owner: notes a key's text (lexemes too), or with a NULL hash forgets the key.
CREATE FUNCTION phasevec._note_set(p_watch int, p_key text, p_hash bytea, p_body text)
RETURNS void LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    cfg regconfig;
    lx  tsvector;
BEGIN
    SELECT w.lexical INTO cfg FROM phasevec.watches w WHERE w.id = p_watch;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'phasevec: no watch %', p_watch;
    END IF;
    IF p_hash IS NULL THEN
        DELETE FROM phasevec.sources WHERE watch = p_watch AND key = p_key;
        RETURN;
    END IF;
    IF cfg IS NOT NULL THEN
        lx := phasevec._lexemes(cfg, p_body);
    END IF;
    INSERT INTO phasevec.sources AS s (watch, key, text_hash, lexemes, lexeme_n)
    VALUES (p_watch, p_key, p_hash, lx, length(lx))
    ON CONFLICT (watch, key) DO UPDATE
       SET text_hash = EXCLUDED.text_hash,
           lexemes = EXCLUDED.lexemes,
           lexeme_n = EXCLUDED.lexeme_n,
           changed_at = CASE WHEN s.text_hash IS DISTINCT FROM EXCLUDED.text_hash
                             THEN clock_timestamp() ELSE s.changed_at END;
    PERFORM pg_notify('phasevec', p_watch::text);
END;
$$;

-- The watch trigger: C. Same name, so every trigger already installed (phasevec_watch_<id>) keeps working. It is
-- declared in a library of its own (src/pg_phasevec_observe.c), which runs phasevec_observe from the session's
-- pg_phasevec library: a session that loaded the library of 0.19.0 or before, and wrote to a watched table after
-- this update, got "could not find function"; now it is told to reconnect (the write is refused, not let through).
CREATE OR REPLACE FUNCTION phasevec._observe() RETURNS trigger
AS $q$pg_phasevec_observe$q$, $q$phasevec_observe_entry$q$ LANGUAGE C;
DROP FUNCTION phasevec._note(int, text, bytea, text);

CREATE OR REPLACE FUNCTION phasevec.next(p_watch text, p_limit integer DEFAULT 64)
RETURNS TABLE(key text, body text, text_hash bytea)
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    SELECT x.key, x.body, x.text_hash
      FROM phasevec._render(p_watch, ARRAY(SELECT t.key FROM phasevec._todo(p_watch, p_limit) t)) x
$f$;

CREATE OR REPLACE FUNCTION phasevec.audit_sample(p_watch text, p_n integer)
RETURNS TABLE(key text, body text, text_hash bytea, code smallint[], code256 bit)
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $f$
DECLARE
    w phasevec.watches := phasevec._watch(p_watch);
BEGIN
    RETURN QUERY
    WITH cand AS (
        SELECT rd.key, rd.text_hash, rd.code, rd.code256
          FROM phasevec.readings rd
          JOIN phasevec.kstate k ON k.watch = rd.watch AND k.key = rd.key AND k.main IN ('fresh', 'doubtful')
         WHERE rd.watch = w.id AND rd.reader = w.reader AND rd.failed IS NULL)
    SELECT c.key, x.body, c.text_hash, c.code, c.code256
      FROM cand c
      JOIN phasevec._render(p_watch, ARRAY(SELECT cand.key FROM cand)) x ON x.key = c.key
     ORDER BY md5(c.key || clock_timestamp()::text) LIMIT p_n;
END;
$f$;

CREATE OR REPLACE FUNCTION phasevec.lexical(p_watch text, p_config regconfig)
RETURNS bigint LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $f$
DECLARE
    w    phasevec.watches := phasevec._watch(p_watch);
    x    record;
    n    bigint := 0;
BEGIN
    IF NOT pg_has_role(current_user, (SELECT c.relowner FROM pg_class c WHERE c.oid = w.source), 'USAGE') THEN
        RAISE EXCEPTION 'phasevec: only the owner of % may change how watch % is read', w.source, p_watch;
    END IF;
    UPDATE phasevec.watches SET lexical = p_config WHERE id = w.id;
    IF p_config IS NULL THEN
        UPDATE phasevec.sources SET lexemes = NULL, lexeme_n = NULL WHERE watch = w.id AND lexemes IS NOT NULL;
        DELETE FROM phasevec.lexstats WHERE watch = w.id;
        DELETE FROM phasevec.lexdocs WHERE watch = w.id;
        RETURN 0;
    END IF;
    FOR x IN SELECT r.key, r.body, r.text_hash FROM phasevec._render(p_watch, NULL) r LOOP
        UPDATE phasevec.sources s
           SET lexemes = l.lx, lexeme_n = length(l.lx)
          FROM (SELECT phasevec._lexemes(p_config, x.body) AS lx) l
         WHERE s.watch = w.id AND s.key = x.key AND s.text_hash = x.text_hash;
        IF FOUND THEN
            n := n + 1;
        END IF;
    END LOOP;
    PERFORM phasevec.lexical_refresh(p_watch);
    RETURN n;
END;
$f$;

CREATE OR REPLACE FUNCTION phasevec.watch(p_name text, p_source regclass, p_key name, p_recipe text, p_reader text,
                                          p_min_coverage numeric DEFAULT 0.95, p_doubt_below real DEFAULT NULL::real)
RETURNS integer LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $f$
DECLARE
    tbl_owner oid;
    rid       int;
    wid       int;
BEGIN
    SELECT c.relowner INTO tbl_owner FROM pg_class c WHERE c.oid = p_source AND c.relkind IN ('r', 'p');
    IF NOT FOUND THEN
        RAISE EXCEPTION 'phasevec: % is not a table', p_source;
    END IF;
    IF NOT pg_has_role(current_user, tbl_owner, 'USAGE') THEN
        RAISE EXCEPTION 'phasevec: a watch is a trigger on %, so only its owner may create one', p_source;
    END IF;
    -- A recipe never reads a temporary table (0.20.0): one is its session's, and a watch outlives the session.
    IF EXISTS (SELECT 1 FROM pg_class c WHERE c.oid = p_source AND c.relpersistence = 't') THEN
        RAISE EXCEPTION 'phasevec: % is a temporary table: a watch outlives its session', p_source;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = p_source AND a.attname = p_key
                   AND a.attnum > 0 AND NOT a.attisdropped) THEN
        RAISE EXCEPTION 'phasevec: % has no column %', p_source, p_key;
    END IF;
    -- A key names one row (0.20.0): with two rows under one key, a writer who could see and delete only its own
    -- forgot the other's, with its verdict.
    IF NOT EXISTS (SELECT 1 FROM pg_index i JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attname = p_key
                    WHERE i.indrelid = p_source AND i.indisunique AND i.indnkeyatts = 1
                      AND i.indkey[0] = a.attnum AND i.indpred IS NULL AND i.indexprs IS NULL) THEN
        RAISE EXCEPTION 'phasevec: % is not a key of %: a watch needs a column with a unique index of its own', p_key, p_source
            USING HINT = 'A PRIMARY KEY or a UNIQUE constraint on that column alone.';
    END IF;
    SELECT id INTO rid FROM phasevec.readers WHERE name = p_reader;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'phasevec: no reader named %', p_reader
            USING HINT = 'Register it with phasevec.reader_register(); nothing is read without a sealed reader.';
    END IF;

    INSERT INTO phasevec.watches (name, source, key_col, recipe, reader, min_coverage, doubt_below)
    VALUES (p_name, p_source, p_key, p_recipe, rid, p_min_coverage, p_doubt_below)
    RETURNING id INTO wid;
    -- The recipe must be an expression over the row, aliased r; it is read as every reader reads it (0.20.0).
    PERFORM 1 FROM phasevec._render(p_name, ARRAY[]::text[]);

    EXECUTE format('CREATE TRIGGER %I AFTER INSERT OR UPDATE OR DELETE ON %s '
                   'FOR EACH ROW EXECUTE FUNCTION phasevec._observe(%L, %L, %L)',
                   'phasevec_watch_' || wid, p_source, wid, p_key, p_recipe);

    -- Every row already there is noted, so it is pending until read -- not invisible.
    INSERT INTO phasevec.sources (watch, key, text_hash)
    SELECT wid, x.key, x.text_hash FROM phasevec._render(p_name, NULL) x;
    RETURN wid;
END;
$f$;

-- ---------------------------------------------------------------------------------- the doors to verdicts --
-- 7, 8. brief(): C. It shows a watch only to a role that may SELECT its table; each line is the row's text as the
-- recipe renders it (as the table's owner, in the guard); a key reads 'verified' only if that line is the text its
-- verdict judged. _brief_keys() is its internal, the owner's.
DROP FUNCTION phasevec._brief_keys(text);
CREATE FUNCTION phasevec._brief_keys(p_watch text)
RETURNS TABLE (key text, verdict text, net_use bigint, seen timestamptz, judged bytea)
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    SELECT s.key, coalesce(phasevec._verdict_of(t), $q$unproven$q$),
           coalesce(u.helped, 0) - coalesce(u.not_helped, 0),
           coalesce(t.verified_at, t.changed_at),
           CASE WHEN phasevec._verdict_of(t) = $q$verified$q$ THEN t.asserted_for END
      FROM phasevec.watches w
      JOIN phasevec.sources s ON s.watch = w.id
      LEFT JOIN phasevec.truth t ON t.watch = w.id AND t.key = s.key
      LEFT JOIN phasevec.usefulness u ON u.watch = w.id AND u.key = s.key
     WHERE w.name = p_watch
       AND coalesce(phasevec._verdict_of(t), $q$unproven$q$) IN ($q$verified$q$, $q$unproven$q$)
     ORDER BY (coalesce(phasevec._verdict_of(t), $q$unproven$q$) = $q$verified$q$) DESC,
              coalesce(u.helped, 0) - coalesce(u.not_helped, 0) DESC,
              coalesce(t.verified_at, t.changed_at) DESC NULLS LAST, s.key
$f$;
CREATE OR REPLACE FUNCTION phasevec.brief(p_watch text, p_budget int DEFAULT 8000)
RETURNS TABLE (key text, verdict text, net_use bigint, line text)
AS $q$MODULE_PATHNAME$q$, $q$phasevec_brief$q$ LANGUAGE C STABLE;

-- 12. recall(), disputes(), replacement(), truth_coverage(): the same signatures and grants, now one C door that
-- shows a watch only to a role that may SELECT its table, and runs the body (phasevec._door_<name>) as the owner.
-- p_visible (the last argument of each _door_*): the keys of the rows the caller sees when row-level security filters
-- them, NULL when it does not. The body computes over those keys only, so no field (disputed_by, a reason, a count)
-- carries a row the caller does not see.
CREATE FUNCTION phasevec._door_recall(p_watch text, p_question text, p_k int, p_partial boolean, p_visible text[])
RETURNS TABLE (key text, score double precision, adjusted double precision, verdict text, support jsonb,
               verified_at timestamptz, topic text, disputed_by text[], usefulness integer, state text)
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    WITH w AS (SELECT (phasevec._watch(p_watch)).id AS id),
    hits AS (SELECT * FROM phasevec.search(p_watch, p_question, least(p_k * 3, 1000), p_partial) x
              WHERE p_visible IS NULL OR x.key = ANY (p_visible)),
    th AS (SELECT h.key, t.topic AS tp, t.support AS sp, t.verified_at AS va,
                  coalesce(phasevec._verdict_of(t), $q$unproven$q$) AS v
             FROM hits h CROSS JOIN w LEFT JOIN phasevec.truth t ON t.watch = w.id AND t.key = h.key),
    vivas AS (SELECT t.topic, t.key, s.text_hash FROM phasevec.truth t CROSS JOIN w
                JOIN phasevec.sources s ON s.watch = t.watch AND s.key = t.key
               WHERE t.watch = w.id AND t.topic IN (SELECT th.tp FROM th WHERE th.tp IS NOT NULL)
                 AND (p_visible IS NULL OR t.key = ANY (p_visible))
                 AND phasevec._verdict_of(t) IN ($q$verified$q$, $q$unproven$q$)),
    disp AS (SELECT a.key, array_agg(b.key ORDER BY b.key) AS keys
               FROM vivas a JOIN vivas b ON b.topic = a.topic AND b.key <> a.key AND b.text_hash <> a.text_hash
              GROUP BY a.key)
    SELECT h.key, h.score,
           h.score * (1 + 0.1 * tanh(coalesce(us.helped - us.not_helped, 0) / 5.0)),
           CASE WHEN dp.keys IS NOT NULL THEN $q$disputed$q$ ELSE th.v END,
           th.sp, th.va, th.tp, dp.keys, coalesce(us.helped - us.not_helped, 0)::int, h.state
      FROM hits h
      JOIN th ON th.key = h.key
      CROSS JOIN w
      LEFT JOIN phasevec.usefulness us ON us.watch = w.id AND us.key = h.key
      LEFT JOIN disp dp ON dp.key = h.key
     ORDER BY 3 DESC NULLS LAST, (th.v = $q$verified$q$) DESC, h.key
     LIMIT p_k
$f$;
CREATE FUNCTION phasevec._door_disputes(p_watch text, p_visible text[])
RETURNS TABLE (topic text, key_a text, key_b text)
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    WITH vivas AS (
        SELECT t.topic, t.key, s.text_hash FROM phasevec.truth t
          JOIN phasevec.sources s ON s.watch = t.watch AND s.key = t.key
         WHERE t.watch = (phasevec._watch(p_watch)).id AND t.topic IS NOT NULL
           AND (p_visible IS NULL OR t.key = ANY (p_visible))
           AND phasevec._verdict_of(t) IN ($q$verified$q$, $q$unproven$q$))
    SELECT a.topic, a.key, b.key FROM vivas a JOIN vivas b ON b.topic = a.topic AND b.key > a.key
     WHERE a.text_hash <> b.text_hash
     ORDER BY 1, 2, 3
$f$;
-- A chain is followed only through rows the caller sees: it ends before the first one it does not.
CREATE FUNCTION phasevec._door_replacement(p_watch text, p_key text, p_visible text[])
RETURNS TABLE (step integer, key text, reason text)
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    WITH RECURSIVE c(step, key, reason, seen) AS (
        SELECT 0, p_key, NULL::text, ARRAY[p_key]
      UNION ALL
        SELECT c.step + 1, t.replaced_by, t.reason, c.seen || t.replaced_by
          FROM c JOIN phasevec.truth t ON t.watch = (phasevec._watch(p_watch)).id AND t.key = c.key
         WHERE t.verdict = $q$replaced$q$ AND c.step < 50 AND NOT t.replaced_by = ANY (c.seen)
           AND (p_visible IS NULL OR t.replaced_by = ANY (p_visible)))
    SELECT step, key, reason FROM c ORDER BY step
$f$;
CREATE FUNCTION phasevec._door_truth_coverage(p_watch text, p_visible text[])
RETURNS TABLE (verdict text, n bigint)
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    SELECT coalesce(phasevec._verdict_of(t), $q$unproven$q$) AS verdict, count(*)
      FROM phasevec.sources s
      LEFT JOIN phasevec.truth t ON t.watch = s.watch AND t.key = s.key
     WHERE s.watch = (phasevec._watch(p_watch)).id AND (p_visible IS NULL OR s.key = ANY (p_visible))
     GROUP BY 1 ORDER BY 1
$f$;
CREATE OR REPLACE FUNCTION phasevec.recall(p_watch text, p_question text, p_k int DEFAULT 10, p_partial boolean DEFAULT false)
RETURNS TABLE (key text, score double precision, adjusted double precision, verdict text, support jsonb,
               verified_at timestamptz, topic text, disputed_by text[], usefulness integer, state text)
AS $q$MODULE_PATHNAME$q$, $q$phasevec_door$q$ LANGUAGE C STABLE;
CREATE OR REPLACE FUNCTION phasevec.disputes(p_watch text)
RETURNS TABLE (topic text, key_a text, key_b text)
AS $q$MODULE_PATHNAME$q$, $q$phasevec_door$q$ LANGUAGE C STABLE;
CREATE OR REPLACE FUNCTION phasevec.replacement(p_watch text, p_key text)
RETURNS TABLE (step integer, key text, reason text)
AS $q$MODULE_PATHNAME$q$, $q$phasevec_door$q$ LANGUAGE C STABLE;
CREATE OR REPLACE FUNCTION phasevec.truth_coverage(p_watch text)
RETURNS TABLE (verdict text, n bigint)
AS $q$MODULE_PATHNAME$q$, $q$phasevec_door$q$ LANGUAGE C STABLE;

-- ---------------------------------------------------------------- privileges --
-- New internals: the owner only (and they carry no rights of their own). A verifier other than the owner is
-- granted verify() or verify_one(), nothing else; it runs only the proofs whose author it may act as. _render()
-- stays open: it checks its caller itself.
REVOKE ALL ON FUNCTION phasevec._bind(bytea, text, oid, text[]), phasevec._truth_stale(phasevec.truth),
    phasevec._assert_set(text, text, text, text, jsonb, timestamptz, oid, bytea, text[]),
    phasevec._truth_due(int, int, interval, oid), phasevec._truth_of(int, text),
    phasevec._truth_set(int, text, text, text, bytea, timestamptz), phasevec._truth_halted(int, bytea, bytea, oid, timestamptz),
    phasevec._truth_attempt(int, text), phasevec._truth_tried(int, text, text, boolean),
    phasevec._note_set(int, text, bytea, text), phasevec.adopt(text, regrole, text[], text[]),
    phasevec._door_recall(text, text, int, boolean, text[]), phasevec._door_disputes(text, text[]),
    phasevec._door_replacement(text, text, text[]), phasevec._door_truth_coverage(text, text[])
  FROM PUBLIC;
-- (fifteenth review) _verdict(t) is a door, like recall() and the rest: it shows a claim's verdict to a role that may
-- SELECT its watch's table (and, under row-level security, see its row), and NULL to anyone else, and computes it as
-- the owner (_verdict_of, the owner's). As SQL that ran as its caller it read phasevec.watches, phasevec.sources and
-- _bind (closed to PUBLIC above): a reader granted phasevec.truth and the watched table got "permission denied for
-- function _bind" as soon as verify() wrote a fresh verdict. Every reader of phasevec.truth may call it, as before.
CREATE OR REPLACE FUNCTION phasevec._verdict(t phasevec.truth) RETURNS text
AS $q$MODULE_PATHNAME$q$, $q$phasevec_verdict$q$ LANGUAGE C STABLE;
REVOKE ALL ON FUNCTION phasevec._verdict_of(phasevec.truth) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION phasevec._verdict(phasevec.truth) TO PUBLIC;
COMMENT ON FUNCTION phasevec._verdict(phasevec.truth) IS
    $q$The truth a claim has now (verified, refuted, unproven, expired, replaced), for SQL that reads phasevec.truth directly; NULL for a claim whose watched table (or row, under row-level security) the caller may not read (0.20.0).$q$;
COMMENT ON FUNCTION phasevec._verdict_of(phasevec.truth) IS
    $q$What _verdict() computes, as the owner, after it has checked who reads (0.20.0). The owner's only.$q$;
-- 6 and 7: closed to PUBLIC. brief() calls _brief_keys() as the owner: whoever may brief is granted brief() only.
REVOKE ALL ON FUNCTION phasevec._forget(int, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION phasevec._brief_keys(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION phasevec.brief(text, int) FROM PUBLIC;
COMMENT ON FUNCTION phasevec._brief_keys(text) IS
    $q$Keys, verdicts, usefulness and judged text hash of a watch, for brief() (which runs it as the owner). The owner's only (0.20.0).$q$;

-- 9. Every row's text in the pinned settings: what the watch trigger noted before 0.20.0 was rendered in its
-- writer's settings. A text that now reads otherwise is noted again (its reading turns stale, its verdict unproven).
DO $d$
DECLARE
    w record;
    x record;
BEGIN
    FOR w IN SELECT id, name FROM phasevec.watches ORDER BY id LOOP
        FOR x IN SELECT r.key, r.body, r.text_hash FROM phasevec._render(w.name, NULL) r
                   JOIN phasevec.sources s ON s.watch = w.id AND s.key = r.key
                  WHERE s.text_hash IS DISTINCT FROM r.text_hash LOOP
            PERFORM phasevec._note_set(w.id, x.key, x.text_hash, x.body);
        END LOOP;
    END LOOP;
END
$d$;

-- A key names one row: watch() refuses a key column without a unique index of its own (0.20.0). A watch made before
-- keeps working, but with two rows under one key they share one verdict, and a writer who deletes its own row (one
-- row-level security lets it see) forgets the other's. Each such watch is named here.
DO $d$
DECLARE
    w record;
BEGIN
    FOR w IN SELECT x.name, x.source, x.key_col FROM phasevec.watches x
              WHERE NOT EXISTS (SELECT 1 FROM pg_index i
                                  JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attname = x.key_col
                                 WHERE i.indrelid = x.source AND i.indisunique AND i.indnkeyatts = 1
                                   AND i.indkey[0] = a.attnum AND i.indpred IS NULL AND i.indexprs IS NULL)
              ORDER BY x.id LOOP
        RAISE WARNING 'phasevec: watch % reads % by %, which is not unique there', w.name, w.source, w.key_col
            USING HINT = 'Add a UNIQUE constraint on that column alone: two rows under one key share one verdict.';
    END LOOP;
END
$d$;

-- (twelfth review) Freshness is judged at the moment of reading, in every read path: what hides an expired claim
-- from find(), find_hybrid(), find_npu(), find_ivf(), the replacement chain and the recall measure compared
-- expires_at with now(), the start of the reader's transaction (_verdict() above, and the library's own filter in
-- src/phasevec_ivf.c, read clock_timestamp() too). Each of these functions is defined again here with only that
-- comparison changed; nothing else in them is touched.
DO $d$
DECLARE
    f record;
    n int := 0;
BEGIN
    FOR f IN SELECT p.oid, pg_get_functiondef(p.oid) AS def FROM pg_proc p
              WHERE p.pronamespace = $q$phasevec$q$::regnamespace AND p.prosrc LIKE $q$%expires_at <= now()%$q$
                AND p.proname NOT IN ($q$_verdict$q$, $q$_verdict_of$q$)
              ORDER BY p.oid LOOP
        EXECUTE replace(f.def, $q$expires_at <= now()$q$, $q$expires_at <= clock_timestamp()$q$);
        n := n + 1;
    END LOOP;
    IF n <> 7 THEN
        RAISE EXCEPTION $q$phasevec: % read paths compare expires_at with now(), 7 were expected$q$, n;
    END IF;
END
$d$;

-- (sixteenth review, 43) No name phasevec uses is looked up through its caller's search_path. These two are inlined
-- into their callers (no SET clause of their own): every operator names its schema, and the backslashes are in E''
-- strings, which standard_conforming_strings does not change.
CREATE OR REPLACE FUNCTION phasevec._reads(p_manifest jsonb)
RETURNS jsonb
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
    SELECT pg_catalog.jsonb_strip_nulls(pg_catalog.jsonb_build_object(
        'pooling', p_manifest OPERATOR(pg_catalog.->) 'pooling', 'ctx', p_manifest OPERATOR(pg_catalog.->) 'ctx',
        'query_prefix', p_manifest OPERATOR(pg_catalog.->) 'query_prefix',
        'tokens', p_manifest OPERATOR(pg_catalog.->) 'tokens', 'marker', p_manifest OPERATOR(pg_catalog.->) 'marker',
        'query_instruction', p_manifest OPERATOR(pg_catalog.->) 'query_instruction'));
$$;
CREATE OR REPLACE FUNCTION phasevec._term(p_lexeme text)
RETURNS tsquery
LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
AS $$
    SELECT (E'\'' OPERATOR(pg_catalog.||) pg_catalog.replace(pg_catalog.replace(p_lexeme, E'\\', E'\\\\'), E'\'', E'\'\'')
            OPERATOR(pg_catalog.||) E'\'')::pg_catalog.tsquery;
$$;
-- The C functions that run SQL with their caller's identity (src/phasevec_ivf.c) resolve it in pg_catalog first,
-- as every SQL function of the extension does; the truth functions run theirs as the owner, in become().
ALTER FUNCTION phasevec._ivf_build(integer, integer, integer, integer, integer, integer, boolean)
    SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION phasevec._ivf_build(integer, integer, integer, integer, integer, integer, boolean, boolean)
    SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION phasevec.ivf_sweep(integer, bit, smallint[], integer, integer, integer)
    SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION phasevec.ivf_delta(integer, integer, bit, smallint[], integer)
    SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION phasevec._ivf_absorb(integer, integer, text)
    SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION phasevec._ivf_find(integer, integer, bit, smallint[], integer, integer, integer, integer, real)
    SET search_path = pg_catalog, pg_temp;
