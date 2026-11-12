-- pg_phasevec 0.19.0 -> 0.20.0: a verdict is about one claim (the text its author read, the proof, the author),
-- judged in one state under one clock, and the only door to it is a function that knows who calls it.
\echo Use "ALTER EXTENSION pg_phasevec UPDATE TO '0.20.0'" to load this file. \quit

-- (eighteenth review) 0.20.0 lives in a UTF8 database only: CREATE EXTENSION and this update refuse any other. A
-- claim's identity and a key's hash are the bytes of their text; in a UTF8 database every one of them is the same
-- UTF-8 on every side (the proof's session, _truth_halted, a reader that hashes what it read). In the seventeenth cut
-- they were converted to UTF-8 first, and in SQL_ASCII, WIN1252 or LATIN1 a byte with no UTF-8 equivalent raised:
-- one author's assert() stopped verify() for its whole watch, and a halt was never recorded. The hashing takes the
-- bytes as they are (it cannot fail), in any database, as a second line.
DO $enc$
BEGIN
    IF pg_catalog.getdatabaseencoding() OPERATOR(pg_catalog.<>) 'UTF8' THEN
        RAISE EXCEPTION 'phasevec 0.20.0 needs a UTF8 database; % is %', pg_catalog.current_database(),
                        pg_catalog.getdatabaseencoding()
            USING ERRCODE = 'feature_not_supported',
                  HINT = 'Create the database WITH ENCODING ''UTF8'' (pg_dump and restore into it), then install or update '
                         'pg_phasevec there. README, Supported configurations.';
    END IF;
END
$enc$;

-- (fourteenth review) The extension's tables are taken first, in the order its writers take them: a write to a watched
-- table reads its watch (phasevec.watches), notes the row's text (sources, and lexstats and lexdocs for a lexical
-- watch), and an assert() in the same transaction writes phasevec.truth. Below, truth is altered before watches: in
-- the thirteenth cut a writer that held watches on its way to truth and this script, holding truth on its way to
-- watches, deadlocked, and one of them was aborted. Run the update alone, not in a transaction with DDL on watched
-- tables (that DDL waits for their writers while this holds the extension's tables they wait for).
-- (twentieth review, RT20M-3, RT20-CRASH-1/2) Only the extension's tables are taken here: no watched table is held
-- while this waits; the TRUNCATE triggers below are made only on a table no one is writing (taken with NOWAIT, once),
-- and phasevec.watch_truncate() makes the rest.
-- (twenty-fourth review, RT24P-RR) The update runs only at READ COMMITTED. Under REPEATABLE READ or SERIALIZABLE
-- the transaction's snapshot was taken when ALTER EXTENSION began, before the update waited for anything: a refute()
-- committed while it waited was not seen, the claim was not retired, and adopt() and verify() later served it
-- 'verified'. At READ COMMITTED every statement after the locks below reads what committed before they were held.
DO $iso$
BEGIN
    IF pg_catalog.current_setting('transaction_isolation') IN ('repeatable read', 'serializable') THEN
        RAISE EXCEPTION 'phasevec: the update to 0.20.0 runs only at READ COMMITTED, and this transaction is %',
                        pg_catalog.upper(pg_catalog.current_setting('transaction_isolation'))
            USING ERRCODE = 'feature_not_supported',
                  DETAIL = 'Its snapshot was taken before the update waited for phasevec''s tables: what '
                           'committed meanwhile (a refute()) would be missed. Nothing was changed.',
                  HINT = 'Run ALTER EXTENSION pg_phasevec UPDATE in a transaction of its own, after '
                         'SET default_transaction_isolation = ''read committed''.';
    END IF;
    -- (twenty-sixth review, RT26PU-2) Whether the caller's transaction holds a lock another
    -- session may wait for, taken before this script: read here, before the script takes anything
    -- (_update_lock, below, bounds its first wait when it does).
    -- (twenty-seventh review, RT28-LT0-1, RT27PU-1) Not "has a transaction id": ALTER EXTENSION
    -- writes the extension's catalog row before it runs the script, so there always was one, and
    -- with lock_timeout = 0 the first wait was bounded anyway (overlapping holders of 1.5 s starved
    -- the update). What it took for that write it has let go of: a lone ALTER EXTENSION holds
    -- here only its own virtual and real transaction ids (and the lock of this query's pg_locks).
    -- What the caller took before, in the same transaction (a table read or written, an advisory
    -- or an object lock, the catalog a CREATE ROLE wrote; an earlier step of an update through
    -- 0.19.0, which takes phasevec's tables), is listed: then the first wait is bounded.
    EXECUTE pg_catalog.format($q$CREATE FUNCTION phasevec._update_caller_holds() RETURNS boolean
                                 LANGUAGE sql IMMUTABLE AS %L$q$,
                              CASE WHEN EXISTS (
                                  SELECT 1 FROM pg_catalog.pg_locks l
                                   WHERE l.pid OPERATOR(pg_catalog.=) pg_catalog.pg_backend_pid()
                                     AND l.granted
                                     AND l.locktype OPERATOR(pg_catalog.<>) ALL
                                         (ARRAY['virtualxid', 'transactionid'])
                                     AND l.relation IS DISTINCT FROM
                                         'pg_catalog.pg_locks'::pg_catalog.regclass)
                                   THEN 'SELECT true' ELSE 'SELECT false' END);
END
$iso$;
-- (twenty-fourth review: the principle under the twentieth, twenty-third and twenty-fourth reviews' lock findings)
-- Everything the update changes is locked before it changes anything, by one function (_update_lock), and every
-- wait in it is one PostgreSQL can resolve without aborting anyone else:
--  * What it locks: phasevec's five tables (ACCESS EXCLUSIVE, in its writers' order: watches first), the catalog row
--    of each of phasevec's functions (FOR UPDATE: a GRANT, ALTER or CREATE OR REPLACE writes it) and each function's
--    own lock in the mode DROP FUNCTION takes (ALTER ... OWNER TO the owner it has: nothing changes, and the lock
--    conflicts with every lock another session can hold on a function: a COMMENT's, and the one PostgreSQL
--    takes on it to record a dependency, a view or a BEGIN ATOMIC body that names it: 19beta2 and 18.6 do).
--    The twenty-third review's cut wrote the comment again (the lock a COMMENT takes), and a transaction that had
--    made a view over _brief_keys and then wrote a watched table met the update at its DROP FUNCTION (RT24P-DEP3).
--  * A try waits first for one of them, holding nothing of phasevec's (phasevec.watches; after a failed
--    try, the one that ended it), as long as the caller's lock_timeout lets it (0: as long as it takes).
--    Then it takes the rest, each waited for, queued, at most 100 ms times the try's number and never more
--    than half the deadlock_timeout this session reads (500 ms by default), with this session's own deadlock
--    check after 1 ms. A transaction in the update's way that then waits for the update closes a cycle: if
--    it began waiting first, the update's own check finds the cycle and the update gives up; if it began
--    later, the update's wait ends before that transaction's deadlock check runs. Either way the update's
--    subtransaction lets go of what the try took, and that transaction goes on.
--    (twenty-sixth review, RT26PU-1) Both assume the holder the update queues behind is not
--    waiting already: a holder that waits for a third session, which then waits for the update,
--    closes a cycle whose check is the holder's own, armed before the update queued, and it fell
--    inside the update's bound (a client aborted in 9 of 18 timings). So each one is first tried
--    without waiting (no queue, no edge), and when a holder of it is waiting for some lock
--    itself, the try ends there, and the next try waits for it first, holding nothing.
--    (twenty-sixth review, RT26PU-2) The first wait holds nothing of the try's, and nothing of
--    the caller's either, unless the caller's transaction holds a lock it took before the update
--    (a migration tool's one transaction, or an update from an older version through 0.19.0):
--    then the first wait is bounded like the others, and a deadlock in it ends the update; until
--    this review it was not, and the session that then waited for the caller's write was the one
--    the deadlock detector aborted, while the comment said the update would be.
--    (twenty-seventh review, RT28-LT0-1) "Holds a lock", read from pg_locks: the transaction id the
--    twenty-sixth review's cut read was always there (ALTER EXTENSION writes its catalog row
--    first), so every first wait was bounded, and with lock_timeout = 0 the update starved.
--    Until this review the update held phasevec.watches and took the rest only NOWAIT, 50 tries at most:
--    under steady writers (who take watches) and steady readers of phasevec.truth (who do not), the two
--    were never free at once, and the update stopped in about a second whatever the caller's lock_timeout
--    (RT24P-LIVE). A queued wait gets each one as soon as its holders end, since a new reader queues behind
--    the update; a bound that grows with each try outlasts holders that keep it longer than 100 ms.
--  * Tries go on until the caller's lock_timeout is spent (0: until the update has everything, or is canceled);
--    then the update stops, named, with nothing changed.
--  * An object outside the extension that depends on a function this script drops (a view, a default, a BEGIN
--    ATOMIC function: referring to one needs only USAGE on the schema) stops the update before it locks anything,
--    and again once it holds everything, every such object named (RT24P-DEP). Until this review DROP FUNCTION
--    found them one per run, after every watch was rendered.
-- What it takes later it holds already, or takes in phasevec._update_step without waiting; the rest of the script
-- runs under the same bound as a try (lock_timeout: half the deadlock_timeout, at most 100 ms, at most the
-- caller's; deadlock_timeout 1 ms), so a wait nothing above foresaw (a catalog a VACUUM FULL holds) ends the update,
-- with PostgreSQL's own error and nothing changed, before any other session's deadlock check. The caller's
-- lock_timeout and deadlock_timeout come back at the end of this script.
-- (twenty-sixth review, RT26PU-5) A function's own lock is taken as DROP FUNCTION takes it, by the
-- library (_update_lock_routine): until this review by ALTER ... OWNER TO its own owner, a DDL
-- command every event trigger saw, and one a ddl_command_start policy refused.
CREATE FUNCTION phasevec._update_lock_routine(oid) RETURNS void
AS $q$MODULE_PATHNAME$q$, $q$phasevec_update_lock_routine$q$ LANGUAGE C STRICT VOLATILE;
CREATE FUNCTION phasevec._update_lock_routine_now(oid) RETURNS boolean
AS $q$MODULE_PATHNAME$q$, $q$phasevec_update_lock_routine_now$q$ LANGUAGE C STRICT VOLATILE;
CREATE FUNCTION phasevec._update_lock_table_now(oid) RETURNS boolean
AS $q$MODULE_PATHNAME$q$, $q$phasevec_update_lock_table_now$q$ LANGUAGE C STRICT VOLATILE;
-- p_wait false: taken only if no one is in the way, and never queued (false when it is not).
CREATE FUNCTION phasevec._update_take(p_kind text, p_what oid, p_wait boolean) RETURNS boolean
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $f$
BEGIN
    IF p_kind = 'table' THEN
        IF NOT p_wait THEN
            RETURN phasevec._update_lock_table_now(p_what);
        END IF;
        EXECUTE format('LOCK TABLE %s IN ACCESS EXCLUSIVE MODE', p_what::regclass);
    ELSIF p_kind = 'row' THEN
        IF NOT p_wait THEN
            PERFORM 1 FROM pg_proc p WHERE p.oid = p_what FOR UPDATE SKIP LOCKED;
            RETURN FOUND;
        END IF;
        PERFORM 1 FROM pg_proc p WHERE p.oid = p_what FOR UPDATE;
    ELSE
        IF NOT p_wait THEN
            RETURN phasevec._update_lock_routine_now(p_what);
        END IF;
        PERFORM phasevec._update_lock_routine(p_what);
    END IF;
    RETURN true;
END;
$f$;
-- Who holds what a try takes, as pg_locks shows it (the 'row' of a function: the transaction that
-- wrote its catalog row, by its own id).
CREATE FUNCTION phasevec._update_holders(p_kind text, p_what oid)
RETURNS TABLE (pid int, vxid text) LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    SELECT l.pid, l.virtualtransaction
      FROM pg_locks l
     WHERE l.granted AND l.pid IS DISTINCT FROM pg_backend_pid()
       AND CASE p_kind
           WHEN 'table' THEN
                l.locktype = 'relation' AND l.relation = p_what
                AND l.database = (SELECT d.oid FROM pg_database d
                                   WHERE d.datname = current_database())
           WHEN 'row' THEN
                l.locktype = 'transactionid'
                AND l.transactionid = (SELECT p.xmax FROM pg_proc p WHERE p.oid = p_what)
           ELSE l.locktype = 'object' AND l.classid = 'pg_proc'::regclass AND l.objid = p_what END
$f$;
-- A function of phasevec's as the update names it, whatever the search_path.
CREATE FUNCTION phasevec._update_routine(p_oid oid) RETURNS text
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    SELECT format($q$%I.%I(%s)$q$, n.nspname, p.proname, pg_get_function_identity_arguments(p.oid))
      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE p.oid = p_oid
$f$;
-- Every object outside the extension that depends on a function this script drops, named; NULL when none.
-- (twenty-fifth review, RT25PU-2) And every column outside the extension that stores the row type
-- of a table this script alters (phasevec.truth, phasevec.watches: ALTER TABLE ... ADD COLUMN
-- refuses while one does), directly or through an array, a domain, or a composite type or view
-- whose own row type is stored, or a range (and its multirange) over one: PostgreSQL's own walk
-- (find_composite_type_dependencies; ranges since the twenty-sixth review, RT26PU-3). A type is
-- USAGE to PUBLIC: any role with USAGE on the schema could make such a table, and the update failed
-- on it after the locks, one table per run.
CREATE FUNCTION phasevec._update_dependents() RETURNS text
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    WITH RECURSIVE
    e(f, t) AS (SELECT y.typelem, y.oid FROM pg_type y
                 WHERE y.typelem <> 0 AND y.typsubscript = 'array_subscript_handler'::regproc
                UNION ALL
                SELECT y.typbasetype, y.oid FROM pg_type y WHERE y.typtype = 'd'
                UNION ALL
                -- (twenty-sixth review, RT26PU-3) a range over it, and the range's multirange
                SELECT r.rngsubtype, r.rngtypid FROM pg_range r
                UNION ALL
                SELECT r.rngtypid, r.rngmultitypid FROM pg_range r
                UNION ALL
                SELECT a.atttypid, c.reltype
                  FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
                 WHERE a.attnum > 0 AND NOT a.attisdropped AND c.relkind IN ('v', 'c', 'f')
                   AND c.reltype <> 0),
    ty(oid) AS (SELECT c.reltype FROM pg_class c
                 WHERE c.oid IN ('phasevec.truth'::regclass, 'phasevec.watches'::regclass)
                UNION
                SELECT e.t FROM ty JOIN e ON e.f = ty.oid),
    rows_of AS (SELECT format('column %I of %s stores type %s', a.attname, a.attrelid::regclass,
                              format_type(a.atttypid, a.atttypmod)) AS what, a.attrelid, a.attnum
                  FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
                 WHERE a.attnum > 0 AND NOT a.attisdropped AND a.atttypid IN (SELECT ty.oid FROM ty)
                   AND c.relkind NOT IN ('v', 'c', 'f'))
    SELECT nullif(concat_ws('; ',
                            (SELECT string_agg(r.what, '; ' ORDER BY r.attrelid, r.attnum)
                               FROM rows_of r), (
    SELECT string_agg(format('%s depends on function %s',
                             CASE WHEN d.classid = 'pg_rewrite'::regclass
                                  THEN (SELECT pg_describe_object('pg_class'::regclass, r.ev_class, 0)
                                          FROM pg_rewrite r WHERE r.oid = d.objid)
                                  ELSE pg_describe_object(d.classid, d.objid, d.objsubid) END,
                             d.refobjid::regprocedure), '; ' ORDER BY d.refobjid, d.classid, d.objid)
      FROM pg_depend d
     WHERE d.refclassid = 'pg_proc'::regclass AND d.deptype = 'n'
       AND d.refobjid IN (SELECT to_regprocedure(f)
                            FROM unnest(ARRAY['phasevec._truth_due(int, int, interval)',
                                              'phasevec._truth_set(int, text, boolean, text)',
                                              'phasevec._prove_c(text, int, float8)',
                                              'phasevec._note(int, text, bytea, text)',
                                              'phasevec._brief_keys(text)']) f)
       AND NOT EXISTS (SELECT 1 FROM pg_depend e
                        WHERE e.refclassid = 'pg_extension'::regclass AND e.deptype = 'e'
                          AND e.refobjid = (SELECT x.oid FROM pg_extension x WHERE x.extname = 'pg_phasevec')
                          AND ((e.classid = d.classid AND e.objid = d.objid)
                               OR (d.classid = 'pg_rewrite'::regclass AND e.classid = 'pg_class'::regclass
                                   AND e.objid = (SELECT r.ev_class FROM pg_rewrite r WHERE r.oid = d.objid))))
    )), '')
$f$;
-- (twenty-fifth review, RT25PU-3, RT26-PREP-1) Who holds a lock, as pg_locks shows it: a session by
-- its pid, or a prepared transaction by its name (its locks have no pid, and it is in
-- pg_prepared_xacts, not pg_stat_activity: until this review the update said "none any more" of
-- one).
CREATE FUNCTION phasevec._update_who(p_pid int, p_vxid text) RETURNS text
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    SELECT CASE WHEN p_pid IS NOT NULL THEN p_pid::text
                ELSE coalesce((SELECT format('prepared transaction %L', x.gid)
                                 FROM pg_prepared_xacts x
                                 JOIN pg_locks l ON l.locktype = 'transactionid'
                                                AND l.transactionid = x.transaction
                                WHERE l.virtualtransaction = p_vxid AND l.pid IS NULL LIMIT 1),
                              'a prepared transaction') END
$f$;
-- The caller's lock_timeout and deadlock_timeout, set again at the end of this script.
DO $lt$
BEGIN
    EXECUTE pg_catalog.format($q$CREATE FUNCTION phasevec._update_lock_timeout() RETURNS text LANGUAGE sql IMMUTABLE
                                 AS %L$q$, pg_catalog.format($q$SELECT %L::text$q$,
                                                            pg_catalog.current_setting($q$lock_timeout$q$)));
    EXECUTE pg_catalog.format($q$CREATE FUNCTION phasevec._update_deadlock_timeout() RETURNS text LANGUAGE sql
                                 IMMUTABLE AS %L$q$, pg_catalog.format($q$SELECT %L::text$q$,
                                                            pg_catalog.current_setting($q$deadlock_timeout$q$)));
END
$lt$;
CREATE FUNCTION phasevec._update_lock() RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $f$
DECLARE
    caller_ms  int := (SELECT s.setting::int FROM pg_settings s WHERE s.name = 'lock_timeout');
    half_ms    int := (SELECT greatest(1, least(s.setting::int, s.reset_val::int) / 2)
                         FROM pg_settings s WHERE s.name = 'deadlock_timeout');
    hold_ms    int;
    tries      int := 0;
    started    timestamptz;
    left_ms    int;
    first_kind text := 'table';
    first_what oid := 'phasevec.watches'::regclass;
    kind       text;
    what       oid;
    first      boolean;
    held       boolean := false;
    t          record;
    deps       text;
    holders    text;
    -- (twenty-eighth review, RT28PU-1) or an event trigger that may fire for the script's own DDL
    -- before this runs (CREATE FUNCTION above): what it wrote, the caller's transaction holds
    -- during the first wait, and _update_caller_holds() was read before it fired. A session in
    -- the update's queue that then wrote, or waited for, what the trigger holds was the one the
    -- deadlock detector aborted ("deadlock detected ... ddl_marker"). Any enabled one that fires
    -- for a CREATE FUNCTION counts (phasevec's own is on sql_drop): what it takes cannot be told
    -- from what the script takes for its own DDL.
    wrote      boolean := phasevec._update_caller_holds()
                          OR EXISTS (SELECT 1 FROM pg_event_trigger e
                                      WHERE e.evtenabled <> 'D'
                                        AND e.evtevent IN ('ddl_command_start', 'ddl_command_end'));
BEGIN
    hold_ms := least(100, half_ms);
    IF caller_ms > 0 THEN
        hold_ms := least(hold_ms, caller_ms);
    END IF;
    FOR pass IN 1..2 LOOP
        deps := phasevec._update_dependents();
        IF deps IS NOT NULL THEN
            RAISE EXCEPTION 'phasevec: the update to 0.20.0 drops functions, or alters tables, '
                            'that objects outside the extension depend on: nothing was changed'
                USING ERRCODE = 'dependent_objects_still_exist',
                      DETAIL = deps || '.',
                      HINT = 'The functions are internals of phasevec 0.19.0, gone in 0.20.0; a '
                             'column that stores the row type of phasevec.truth or '
                             'phasevec.watches keeps the update from adding theirs. Drop those '
                             'objects (or change them not to refer to them), then run the update '
                             'again.';
        END IF;
        EXIT WHEN held;
        PERFORM set_config('deadlock_timeout', '1ms', true);
        -- (twenty-fifth review, RT26-LT-1, RT25PU-4) The caller's lock_timeout counts from the
        -- first try, and the first try is always made, with 1 ms at least: with lock_timeout = 1ms
        -- the time spent before it (the check above) used up the budget, and the update stopped,
        -- saying it had waited, on a database where nothing held anything.
        started := clock_timestamp();
        WHILE NOT held LOOP
            left_ms := CASE WHEN caller_ms > 0
                            THEN caller_ms - (extract(epoch FROM clock_timestamp() - started) * 1000)::int END;
            EXIT WHEN left_ms <= 0 AND tries > 0;
            tries := tries + 1;
            BEGIN
                kind := first_kind;
                what := first_what;
                first := true;
                -- (twenty-sixth review, RT27-LT0-1) With lock_timeout = 0 (left_ms NULL) the first
                -- wait has no bound: greatest(1, NULL) is 1, and the twenty-fifth review's cut made
                -- 1 ms tries for ever, out of the queue, which overlapping holders starved.
                -- (twenty-seventh review, RT28-LT0-1) Unless the caller holds a lock of its own
                -- (wrote: _update_caller_holds): until this review that was always so, and this
                -- wait was bounded by half the deadlock_timeout whatever lock_timeout said.
                PERFORM set_config('lock_timeout',
                                   CASE WHEN wrote
                                        THEN greatest(1, least(half_ms, hold_ms * least(tries, 100),
                                                               left_ms))::text
                                        WHEN left_ms IS NULL THEN '0'
                                        ELSE greatest(1, left_ms)::text END || 'ms', true);
                PERFORM phasevec._update_take(kind, what, true);
                first := false;
                FOR t IN SELECT 'table' AS kind, x.r::oid AS what, x.n AS ord
                           FROM unnest(ARRAY['phasevec.watches'::regclass, 'phasevec.sources'::regclass,
                                             'phasevec.lexstats'::regclass, 'phasevec.lexdocs'::regclass,
                                             'phasevec.truth'::regclass]) WITH ORDINALITY x(r, n)
                         UNION ALL
                         SELECT k.kind, p.oid, 5 + k.n FROM pg_proc p
                           CROSS JOIN (VALUES ('row', 1), ('routine', 2)) k(kind, n)
                          WHERE p.pronamespace = 'phasevec'::regnamespace
                         ORDER BY ord, what LOOP
                    kind := t.kind;
                    what := t.what;
                    left_ms := CASE WHEN caller_ms > 0
                                    THEN caller_ms - (extract(epoch FROM clock_timestamp() - started) * 1000)::int
                               END;
                    CONTINUE WHEN phasevec._update_take(kind, what, false);
                    -- (RT26PU-1) a holder that waits itself: not queued behind, this try ends here
                    IF EXISTS (SELECT 1 FROM phasevec._update_holders(kind, what) h
                                WHERE h.pid IS NOT NULL AND pg_blocking_pids(h.pid) <> '{}') THEN
                        RAISE EXCEPTION USING ERRCODE = 'lock_not_available';
                    END IF;
                    PERFORM set_config('lock_timeout',
                                       greatest(1, least(half_ms, hold_ms * least(tries, 100), left_ms)) || 'ms',
                                       true);
                    PERFORM phasevec._update_take(kind, what, true);
                END LOOP;
                held := true;
            EXCEPTION WHEN lock_not_available OR deadlock_detected THEN
                -- A deadlock while this try held nothing is not its own (a lock of the caller's transaction
                -- closed it): another try would close it again. (Only the first wait of a caller
                -- that holds a lock is bounded, and checked; the others hold nothing of the
                -- caller's.)
                IF first AND SQLSTATE = '40P01' THEN
                    RAISE;
                END IF;
                -- the next try waits for this one first, holding nothing of phasevec's
                first_kind := kind;
                first_what := what;
            END;
        END LOOP;
        IF NOT held THEN
            SELECT string_agg(DISTINCT phasevec._update_who(h.pid, h.vxid), ', ')
              INTO holders
              FROM phasevec._update_holders(first_kind, first_what) h;
            -- (twenty-sixth review, RT26PU-4) A catalog row changed in a subtransaction (a
            -- SAVEPOINT, an EXCEPTION block) carries that subtransaction's id, whose lock is gone
            -- once it is released: its holder is one of the transactions that began before it and
            -- run still. Until this review: "none any more".
            IF holders IS NULL AND first_kind = 'row' THEN
                SELECT 'a subtransaction of one of: '
                       || string_agg(x.who, ', ' ORDER BY x.who)
                  INTO holders
                  FROM (SELECT a.pid::text AS who FROM pg_stat_activity a, pg_proc p
                         WHERE p.oid = first_what AND a.pid <> pg_backend_pid()
                           AND a.backend_xid IS NOT NULL AND p.xmax::text::bigint <> 0
                           AND a.backend_xid::text::bigint <= p.xmax::text::bigint
                        UNION ALL
                        SELECT format('prepared transaction %L', x.gid)
                          FROM pg_prepared_xacts x, pg_proc p
                         WHERE p.oid = first_what AND p.xmax::text::bigint <> 0
                           AND x.transaction::text::bigint <= p.xmax::text::bigint) x;
            END IF;
            RAISE EXCEPTION 'phasevec: the update to 0.20.0 could not take % within lock_timeout (%): '
                            'nothing was changed',
                            CASE first_kind WHEN 'table' THEN 'phasevec''s tables'
                                 ELSE format('phasevec''s function %s', phasevec._update_routine(first_what)) END,
                            phasevec._update_lock_timeout()
                USING ERRCODE = 'lock_not_available',
                      DETAIL = format('It waited last for %s. Sessions holding it: %s.',
                                      CASE first_kind
                                      WHEN 'table' THEN format('phasevec.%I', (SELECT c.relname FROM pg_class c
                                                                               WHERE c.oid = first_what))
                                      WHEN 'row' THEN format('the catalog row of %s',
                                                             phasevec._update_routine(first_what))
                                      ELSE phasevec._update_routine(first_what) END,
                                      coalesce(holders, 'none any more')),
                      HINT = CASE WHEN wrote
                                  THEN 'This session held a lock before the update (an earlier '
                                       'statement of its transaction, a session-level advisory '
                                       'lock, what an event trigger wrote), or an event trigger '
                                       'is enabled: every wait was bounded, so that the update, '
                                       'not a session waiting for that lock, gives way. Run it '
                                       'again, from a session that holds none, with no event '
                                       'trigger enabled (ALTER EVENT TRIGGER ... DISABLE), or '
                                       'when those sessions are done.'
                                  ELSE 'Run the update again (with a longer lock_timeout, or 0 '
                                       'when only one of phasevec''s tables is busy, it waits for '
                                       'them), or end those sessions first (pg_stat_activity), '
                                       'and commit or roll back those prepared transactions '
                                       '(pg_prepared_xacts).' END;
        END IF;
    END LOOP;
    PERFORM set_config('lock_timeout', hold_ms || 'ms', true);
END;
$f$;
SELECT phasevec._update_lock();

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
-- 48. (eighteenth review) A claim retired by refute() came back: under 0.19.0 refute() kept its proof, and after this
--    update adopt() asserted it again and verify() served it 'verified'; refute() of a replaced claim did nothing, and
--    unsupersede() brought it back; a retired claim superseded and unsuperseded read 'unproven' for good; refute() of
--    a claim with no text recorded read 'unproven'. Retired is a state of its own (truth.retired_at, _claim_state).
-- 49. A key named two rows: a DEFERRABLE unique index, and an inheritance child the parent's index does not cover,
--    let a writer limited by row-level security read another's row through _render(). A watch reads a plain table
--    outside any inheritance tree, by a unique btree index enforced at once; every read checks it again, with ONLY.
-- 50. One author's byte stopped a watch: the hashes converted to UTF-8, which raises in SQL_ASCII and WIN1252. 0.20.0
--    lives in a UTF8 database only, and every hash takes a text's bytes.
-- 51. A proof's session waited for a claim's row holding the watched table: an owner's refute() and then DDL in one
--    transaction deadlocked with it (src/phasevec_truth.c).
-- 52. (nineteenth review) A dropped author's verdict served: after DROP ROLE (and a new role with its name) a claim
--    went on reading 'verified' until its horizon or the next verify(). A verdict of a proof reads 'unproven' as soon
--    as no role has its author's OID and name (_verdict_of).
-- 53. (nineteenth review) refute() in a transaction older than a verdict stamped verified_at with its own now(),
--    before that verdict. Every writer of verified_at now keeps it from moving back (refute(), unsupersede(),
--    _truth_halted; _truth_set and assert() already did, or clear it).
-- 54. (nineteenth review, R19-F7) adopt() asserted again a claim refute() retired, or another author asserted, while it
--    ran: it read the orphans with no lock. Every read-then-write of a claim now reads it again under the claim's row
--    lock and writes only the claim it read: adopt() (each orphan taken and read again), the take of a claim for its
--    proof (its bind: R19-F10, verify_one() answered 'unproven' for a claim asserted again while it waited, never
--    run), _truth_halted (a claim asserted again since the proof began), _truth_tried (an interruption is the tried
--    claim's), as _truth_set already did. assert(), refute() and supersede() write blind (the last one stands);
--    unsupersede() is one statement on the locked row.
-- 55. (nineteenth review, R19-F8) A halted claim superseded and unsuperseded read 'unproven' for good, and brief()
--    served it: unsupersede() gives a halted claim back its 'refuted' (unsupersede()).
-- 56. (nineteenth review, R19-F9) After TRUNCATE, _verdict() and truth_coverage() served 'verified' for rows that
--    were gone: the watch trigger now fires on TRUNCATE too and forgets the rows (_note_clear). A trigger, not a
--    look at the row on every read: the cache is the trigger's, every other read path reads the live row already,
--    and a read of the table in _verdict() would cost every reader a query, with its rights.
-- 57. (nineteenth review, R19-PRIV-1) A caller of an author's SECURITY DEFINER wrapper hardened with SET search_path
--    chose the search_path of the author's proof: the claim recorded the session's settings, read past every SET
--    clause, and the caller's operator ran as the author (a superuser's: the caller made itself one). A claim now
--    records what is in effect where assert() (or adopt()) is called, as the author has it there: a SET clause of
--    the author's own function is the author's, and nothing a role without the author's privileges set is recorded
--    (src/phasevec_guard.c, guard_env_now).
-- 58. (nineteenth review, R19-PRIV-2) _key_shape() locked any table for any role with USAGE on the schema: it answers
--    only a role that may watch the table, before it locks it. (RT19-CRASH-1) A DROP TABLE while a verifier read the
--    table's shape was an internal error: the indexes are read from pg_index, and a table gone is the shape refusal.
-- 59. (twentieth review, RT20M-1) A claim asserted again by a transaction that began before its proof did, and that
--    committed after the proof's session ended itself, was halted (_truth_halted took the assert's changed_at, its
--    transaction's start, for older than the proof). A record made apart from the run it is about (a halt, a proof
--    that overran, an interruption) is now the claim's only while its row is the version that run took (xmin), not
--    by any time (_truth_halted, _truth_set, _truth_tried).
-- 60. (twentieth review, RT20M-2) A wrapper's SET DateStyle = ISO over its caller's 'SQL, DMY' recorded 'ISO, DMY' as
--    the author's: a composite setting is recorded only when every value it was built on is the author's.
-- 61. (twentieth review, RT20P-ENV-1) A recorded setting that could not be set again (a role's REVOKE, an object
--    dropped) was dropped with a WARNING and the proof judged without it: now the claim reads 'unproven', with why.
-- 62. (twentieth review, RT20M-3, RT20-CRASH-1/2, RT20P-UPD-1) The update took the watched tables with NOWAIT until all
--    were free: it starved under steady writes, ignored lock_timeout, deadlocked a transaction that read phasevec and
--    then wrote, and failed on a table owner's trigger of the TRUNCATE trigger's name. It takes only phasevec's tables
--    (queued, bounded by lock_timeout, named when it gives up); a busy table's TRUNCATE trigger is made apart
--    (phasevec.watch_truncate()). (RT20M-4) adopt() takes the watched table before the claims' rows, as DROP TABLE
--    does; (RT20M-5) a replaced claim is not taken for its proof.

ALTER TABLE phasevec.truth ADD COLUMN asserted_by name, ADD COLUMN asserted_by_oid oid,
                           ADD COLUMN asserted_for bytea, ADD COLUMN verified_for bytea,
                           ADD COLUMN proof_env text[], ADD COLUMN halted boolean NOT NULL DEFAULT false,
                           ADD COLUMN looked_at timestamptz, ADD COLUMN looked_for bytea,
                           ADD COLUMN interrupted_at timestamptz, ADD COLUMN interrupted_why text,
                           ADD COLUMN retired_at timestamptz,
                           ADD CONSTRAINT truth_retired_check
                               CHECK (retired_at IS NULL OR (proof IS NULL AND verdict IN ($q$refuted$q$, $q$replaced$q$)));
ALTER TABLE phasevec.truth
    ADD COLUMN data_version text NOT NULL DEFAULT $q$0.19.0$q$
    CONSTRAINT truth_data_version_check CHECK (data_version IN ($q$0.19.0$q$, $q$0.20.0$q$));
COMMENT ON COLUMN phasevec.truth.data_version IS
    'The version of pg_phasevec that wrote this claim as it is (0.20.0, twenty-fifth review): '
    'every write of 0.20.0 says ''0.20.0''; the default, ''0.19.0'', is what a row written before '
    'the column was made reads, by the update or by a pg_dump of 0.19.0 restored here. Such a '
    'claim is not changed or judged until phasevec.migrate() (or the update) brings it to 0.20.0.';
-- (twenty-seventh review, RT27PA-3, RT27PL-1) This installation, and the one where a claim's author
-- was that role: the rule below (before phasevec.stewards) says why.
DO $here$
BEGIN
    EXECUTE pg_catalog.format($q$CREATE FUNCTION phasevec._here() RETURNS uuid
                                 LANGUAGE sql IMMUTABLE PARALLEL SAFE AS %L$q$,
                              pg_catalog.format('SELECT %L::uuid', pg_catalog.gen_random_uuid()));
END
$here$;
COMMENT ON FUNCTION phasevec._here() IS
    'This installation of pg_phasevec (0.20.0, twenty-seventh review): made with the extension, '
    'kept by pg_upgrade and by every copy of the cluster''s files (a physical replica, '
    'pg_basebackup, pg_createsubscriber); a pg_dump restored, or a logical replica made from a '
    'schema dump, has another. An author or a steward recorded in another installation and '
    'another cluster (phasevec._from_here()) is no one here; after a copy that is not trusted as '
    'the original, phasevec.rebind() (twenty-eighth review).';
-- The cluster: its system identifier, which every database of it and a physical replica share,
-- and which pg_upgrade (a new cluster) and a restore elsewhere do not. A role is the cluster's: an
-- author or a steward recorded in this cluster (a restore into another of its databases, a logical
-- replica in it), or in this installation (pg_upgrade), is still that role while its OID has its
-- name; recorded in neither, it is no one.
CREATE FUNCTION phasevec._cluster() RETURNS bigint
AS $q$MODULE_PATHNAME$q$, $q$phasevec_cluster$q$ LANGUAGE C STABLE PARALLEL SAFE;
CREATE FUNCTION phasevec._from_here(p_in uuid, p_cluster bigint) RETURNS boolean
LANGUAGE sql STABLE PARALLEL SAFE AS $f$
    SELECT p_in IS NOT DISTINCT FROM phasevec._here()
        OR p_cluster IS NOT DISTINCT FROM phasevec._cluster()
$f$;
ALTER TABLE phasevec.truth ADD COLUMN asserted_in uuid, ADD COLUMN asserted_cluster bigint;
COMMENT ON COLUMN phasevec.truth.asserted_in IS
    'The installation (phasevec._here()) where asserted_by_oid was this role (0.20.0, '
    'twenty-seventh review). With asserted_cluster: in another cluster and another installation '
    'the claim''s author is no one (an orphan), whatever role has that OID and name there.';
COMMENT ON COLUMN phasevec.truth.asserted_cluster IS
    'The cluster (phasevec._cluster(), its system identifier) where asserted_by_oid was this '
    'role (0.20.0, twenty-seventh review); see asserted_in.';
-- (twenty-eighth review, RT28PA-REUSE-1) A claim is about the row it was made on, not only about
-- its key. phasevec.sources.born is new each time the watch notes a key it did not have (an
-- INSERT, an UPDATE that gives a row the key, a row written again after a DELETE or a TRUNCATE),
-- and an assert(), a refute() or an adopt() records the one of the row it is about (asserted_row).
-- Once that row is gone the claim is dead (_claim_dead): its author no longer changes it, its
-- proof is not run, it reads 'unproven', and its key is claimed again as a key with no claim is
-- (by the table's owner, a steward, or a role that may UPDATE the row there now). Until this
-- review a tenant claimed its own row, deleted it, and kept the claim on another tenant's later
-- row under that key: it refuted that row out of the other tenant's brief(), and the tenant that
-- wrote the row was refused. Read when a claim is changed or judged: a writer of the watched table
-- writes phasevec.sources, as before, and never phasevec.truth.
ALTER TABLE phasevec.sources ADD COLUMN born uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid();
COMMENT ON COLUMN phasevec.sources.born IS
    'New each time the watch notes a key it did not have (0.20.0, twenty-eighth review): the row '
    'under this key is not the one a claim with another phasevec.truth.asserted_row was about.';
-- (twenty-eighth review, RT28PA-REVOKE-1) by_steward: the claim was made what it is through a
-- steward's right alone (_claim_how). Its author is named, and its proof runs as it, but it changes
-- the claim only while it is a steward of the watch; revoked, it is like any role that is not one.
ALTER TABLE phasevec.truth ADD COLUMN asserted_row uuid,
                           ADD COLUMN by_steward boolean NOT NULL DEFAULT false;
COMMENT ON COLUMN phasevec.truth.asserted_row IS
    'phasevec.sources.born of the row the claim''s author made it about (0.20.0, twenty-eighth '
    'review): once the row under the key is another, the claim is dead (phasevec._claim_dead). '
    'NULL for a claim with no author made before it (asserted before 0.20.0).';
COMMENT ON COLUMN phasevec.truth.by_steward IS
    'The claim''s author made it what it is only as a steward of the watch (0.20.0, twenty-eighth '
    'review): it changes the claim only while it is still one.';
-- A claim made where its key had no row (by its author, or the owner) records the nil UUID, which
-- no row is born with: the first row the key then has is another.
-- (package review, RT29PA-DEAD-LEAK/-VERDICT) The one test of whether a claim is alive, for every
-- reader: _verdict_of() before any other verdict, the doors (recall(), disputes(), replacement(),
-- brief()) and every search's filter of replaced, refuted and expired keys. Until then
-- _verdict_of() tested it only for 'verified' and 'refuted', after 'replaced' and 'expired', and
-- the doors and the searches not at all: a dead claim's topic and support reached recall() for
-- the next tenant's row under its key, and its 'replaced' or expiry hid that row from brief() and
-- search. No SET clause and every operator named by its schema, so that it is inlined into its
-- callers (each of them pins its own search_path).
CREATE FUNCTION phasevec._claim_dead(t phasevec.truth) RETURNS boolean
LANGUAGE sql STABLE AS $f$
    SELECT t.asserted_row IS NOT NULL
       AND EXISTS (SELECT 1 FROM phasevec.sources s
                    WHERE s.watch OPERATOR(pg_catalog.=) t.watch
                      AND s.key OPERATOR(pg_catalog.=) t.key
                      AND s.born OPERATOR(pg_catalog.<>) t.asserted_row)
$f$;
COMMENT ON FUNCTION phasevec._claim_dead(phasevec.truth) IS
    'Another row is under the claim''s key than the one its author made it about: that row is '
    'gone, and the claim is no one''s (0.20.0, twenty-eighth review). While the key has no row '
    'the claim is as it was (verify() says the row is gone).';
COMMENT ON COLUMN phasevec.truth.retired_at IS
    $q$When refute() retired this claim (0.20.0, eighteenth review): it has no proof, nothing judges it again, and only an assert() makes it a claim again. NULL for a claim that is not retired. phasevec._claim_state() names every state.$q$;
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
    $q$What was in effect where the claim was asserted (a SET clause of the author's function included; nothing a role without the author's privileges set), over the configuration every new session of the author starts from ("name=value": DateStyle, TimeZone, search_path, application_name, ...; "app.tenant=" for a custom placeholder it made, with no value): the proof runs in a new session of its author, with these on top (0.20.0).$q$;
COMMENT ON COLUMN phasevec.truth.interrupted_at IS
    $q$When the session that ran this proof was last ended by another process while it ran (0.20.0, ninth review): nothing was judged, and the verdict stays as it was until its horizon (watches.max_age). Cleared by a verdict or an assert.$q$;
COMMENT ON COLUMN phasevec.truth.interrupted_why IS
    $q$Who ended the session that ran this proof (interrupted_at): the process that terminated it.$q$;
-- 37. A verdict serves while it is fresh: judged (verified_at) within its watch's max_age. Choose it longer than the
-- time verify() takes to come round every claim of the watch: ceil(claims / p_n) calls, each p_every or the cron's
-- interval apart (whichever is longer), and the same again for a call that judges a claim just after p_every.
ALTER TABLE phasevec.watches ADD COLUMN max_age interval NOT NULL DEFAULT interval $q$1 hour$q$
    CONSTRAINT watches_max_age_check CHECK (max_age > interval $q$0$q$),
    ADD COLUMN data_version text NOT NULL DEFAULT $q$0.19.0$q$
    CONSTRAINT watches_data_version_check CHECK (data_version IN ($q$0.19.0$q$, $q$0.20.0$q$));
COMMENT ON COLUMN phasevec.watches.data_version IS
    'The version of pg_phasevec that this watch''s rows are as (0.20.0, twenty-fifth review): '
    'watch() makes ''0.20.0''; the default, ''0.19.0'', is a watch made before the column, brought'
    ' to 0.20.0 by the update, or restored from a pg_dump of 0.19.0 (phasevec.migrate() brings '
    'it). Until then no claim of the watch is changed or judged.';
-- (twenty-sixth review, RT26PL-1) What arrives by replication is not this server's 0.20.0's: the
-- label was a default applied on INSERT, and a 0.19.0 write that reached a migrated row as an
-- UPDATE (logical replication from a 0.19.0 publisher, which has no such column) kept '0.20.0' with
-- 0.19.0's state under it (a refute() that kept the proof), migrate() skipped it, and adopt() plus
-- verify() served the refuted claim 'verified'. A row a subscription's apply writes now reads
-- '0.19.0' whatever the publisher sent, and migrate() brings it, after cut-over. The trigger is a
-- replica one (it fires only with session_replication_role = replica, as the apply runs), and it
-- changes only what a logical replication worker writes: a session of phasevec's own that set the
-- role writes as 0.20.0.
-- (twenty-seventh review, RT27PL-3) Only what a 0.19.0 publisher wrote: the twenty-sixth review's
-- cut labelled '0.19.0' every row an apply wrote, a 0.20.0 publisher's too (a read replica, or a
-- move to another major version by logical replication), and migrate() then dropped its verdicts
-- with a false "verified before 0.20.0". Every write of 0.20.0 now leaves a new mark in the row
-- (written: the trigger, on this server, before the row is stored), and the row sent carries it.
-- An apply whose row has none (an INSERT of a publisher with no such column), or the mark the row
-- had (an UPDATE of a publisher with no such column: the subscriber keeps what it had), comes from
-- 0.19.0, and reads '0.19.0'; one with a new mark keeps the publisher's data_version. The trigger
-- fires always (ENABLE ALWAYS): marking a write, in any session; labelling, only in an apply.
ALTER TABLE phasevec.truth ADD COLUMN written uuid;
ALTER TABLE phasevec.watches ADD COLUMN written uuid;
COMMENT ON COLUMN phasevec.truth.written IS
    'A new value at every write of pg_phasevec 0.20.0 (twenty-seventh review): what a logical '
    'replication apply writes with none, or with the one the row had, comes from 0.19.0.';
COMMENT ON COLUMN phasevec.watches.written IS
    'A new value at every write of pg_phasevec 0.20.0 (twenty-seventh review): what a logical '
    'replication apply writes with none, or with the one the row had, comes from 0.19.0.';
CREATE FUNCTION phasevec._data_from_elsewhere() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $f$
BEGIN
    IF current_setting($q$session_replication_role$q$) = $q$replica$q$
       AND (SELECT a.backend_type FROM pg_stat_get_activity(pg_backend_pid()) a)
           LIKE $q$logical replication%$q$ THEN
        IF NEW.written IS NULL
           OR (TG_OP = $q$UPDATE$q$ AND NEW.written IS NOT DISTINCT FROM OLD.written) THEN
            NEW.data_version := $q$0.19.0$q$;
        END IF;
    ELSE
        NEW.written := gen_random_uuid();
    END IF;
    RETURN NEW;
END;
$f$;
REVOKE ALL ON FUNCTION phasevec._data_from_elsewhere() FROM PUBLIC;
CREATE TRIGGER phasevec_data_from_elsewhere BEFORE INSERT OR UPDATE ON phasevec.truth
    FOR EACH ROW EXECUTE FUNCTION phasevec._data_from_elsewhere();
ALTER TABLE phasevec.truth ENABLE ALWAYS TRIGGER phasevec_data_from_elsewhere;
CREATE TRIGGER phasevec_data_from_elsewhere BEFORE INSERT OR UPDATE ON phasevec.watches
    FOR EACH ROW EXECUTE FUNCTION phasevec._data_from_elsewhere();
ALTER TABLE phasevec.watches ENABLE ALWAYS TRIGGER phasevec_data_from_elsewhere;
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

-- A verdict judges (text, proof, author, the author's settings): phasevec._bind, the claim's identity (src/phasevec_truth.c,
-- phasevec_bind): every part framed, so no two claims read alike. (seventeenth review) Until then the settings were
-- joined with a newline, and {x.a=1, x.b=2} bound as {"x.a=1<newline>x.b=2"}: a verdict judged for one claim was
-- recorded, and served 'verified', for the other.
CREATE FUNCTION phasevec._bind(p_text_hash bytea, p_proof text, p_author oid, p_env text[])
RETURNS bytea AS $q$MODULE_PATHNAME$q$, $q$phasevec_bind$q$ LANGUAGE C IMMUTABLE PARALLEL SAFE;

-- (eighteenth review) The state a claim is in, named; every transition below goes through these names, and nothing
-- else moves a claim between them:
--   'judged'   it has a proof, run by verify() when it is due and by verify_one() when asked
--   'halted'   its proof ended the session that ran it: verify() does not run it again, verify_one() does when asked
--   'bare'     no proof and not retired (an assert() with no proof, a key only superseded): nothing judges it
--   'retired'  refute() retired it: no proof (truth_retired_check), and only an assert() makes it a claim again
-- supersede() hides a claim in any state behind its replacement (verdict 'replaced', not a state) and unsupersede()
-- shows it again in the state it kept: a retired or a halted one reads 'refuted' again (nothing judges it again), a
-- judged one 'unproven' and due at once, a bare one 'unproven'.
--   assert()                   any -> 'judged' ('bare' with no proof); the only way out of 'retired'
--   refute()                   any -> 'retired', a replaced claim too (it stays behind its replacement, retired)
--   a proof that ends its session  'judged' -> 'halted'
--   verify(), verify_one(), adopt(), recording a verdict, a halt, an interruption
--                              'judged' (verify_one() and adopt() 'halted' too); never a retired claim
--   the update to 0.20.0       a claim refute() made under 0.19.0 -> 'retired' (below)
-- In the seventeenth cut "retired" was only "proof IS NULL", kept by refute() alone: a claim refuted under 0.19.0
-- kept its proof through the update and adopt() brought it back 'verified'; refute() of a replaced claim did nothing
-- and unsupersede() brought it back 'verified'; a retired claim superseded and unsuperseded read 'unproven' for good.
-- Of the three columns that decide it (inlined where it is used, so a scan reads them as columns), and of a row.
CREATE FUNCTION phasevec._claim_state(p_retired_at timestamptz, p_proof text, p_halted boolean) RETURNS text
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $f$
    SELECT CASE WHEN p_retired_at IS NOT NULL THEN 'retired'
                WHEN p_proof IS NULL THEN 'bare'
                WHEN p_halted THEN 'halted'
                ELSE 'judged' END
$f$;
CREATE FUNCTION phasevec._claim_state(t phasevec.truth) RETURNS text
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $f$
    SELECT phasevec._claim_state(t.retired_at, t.proof, t.halted)
$f$;

-- The truth a key has NOW. 'verified' only for the claim it judged, and only while the row's text, as the watch
-- trigger last saw it, is the asserted one; 'refuted' only while it is the refuted one. (brief() also checks the text
-- it serves; verify() checks the live row.) Computed when read: a writer never touches a verdict. In the fifth cut a
-- trigger on phasevec.sources set the verdict of a row whose text changed to 'unproven' as it was written, and so the
-- write waited for every open transaction that had judged that key (a verify() for its whole budget, or longer inside
-- a larger transaction): under load a writer went from 0.2 ms to 13-36 ms, and failed on lock_timeout.
CREATE FUNCTION phasevec._verdict_of(t phasevec.truth) RETURNS text
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    SELECT CASE -- (package review, RT29PA-DEAD-VERDICT) a claim about a row that is gone says
                -- nothing about the row under its key now, whatever it read: 'replaced' and
                -- 'expired' included, a retired one too (phasevec._claim_dead, inlined)
                WHEN phasevec._claim_dead(t) THEN $q$unproven$q$
                WHEN t.verdict = $q$replaced$q$ THEN $q$replaced$q$
                -- (twelfth review) Freshness is judged at the moment of reading: clock_timestamp(), not now(). now()
                -- is when the reader's transaction began: in a long READ COMMITTED transaction brief() and
                -- truth_coverage() served 'verified' past max_age (and past expires_at) for as long as it stayed
                -- open, after it could itself see the claim was false. Not statement_timestamp() either: one long
                -- statement (a DO block, a function looping over brief()) is a reader of its own.
                WHEN t.expires_at IS NOT NULL AND t.expires_at <= clock_timestamp() THEN $q$expired$q$
                -- (eleventh review, 37) a verdict of a proof serves while it is fresh: judged within the watch's
                -- max_age. Not a halted claim's (its proof ended its session: not run again) nor a retired one's
                -- (refute(): no proof, truth_retired_check; nothing judges it again). A retired claim reads 'refuted'
                -- below while its row's text is the one refute() refuted (eighteenth review: asserted_for is that text).
                WHEN t.verdict IN ($q$verified$q$, $q$refuted$q$) AND t.proof IS NOT NULL AND NOT t.halted
                 -- (sixteenth review, 45) in UTC: in the reader's TimeZone a '1 day' max_age was the length of
                 -- that zone's day (48 hours under a POSIX rule a reader may set; 23 or 25 across a DST change).
                 AND coalesce(timezone($q$UTC$q$, t.verified_at)
                              + (SELECT w.max_age FROM phasevec.watches w WHERE w.id = t.watch)
                              > timezone($q$UTC$q$, clock_timestamp()), false)
                     IS NOT TRUE
                THEN $q$unproven$q$
                -- (nineteenth review, 52) a verdict of a proof is its author's: once no role has that OID and name
                -- (DROP ROLE, a new role under the name, a rename), it reads 'unproven' until an assert() or adopt(),
                -- as verify() would record it (_truth_due's test: that OID has that name, i.e. the role of that name
                -- has that OID, one catalog cache lookup; a join with pg_roles cost 3.5 us a claim, brief() +50%).
                -- Checked here, when read: DROP ROLE fires no event trigger (a role is the cluster's, not a
                -- database's), and a role dropped from another database of the cluster is gone from this one too. A
                -- retired claim (no proof) is nobody's verdict.
                -- (twenty-eighth review, RT28PA-REUSE-1: a dead claim, first above)
                WHEN t.verdict IN ($q$verified$q$, $q$refuted$q$) AND t.proof IS NOT NULL
                 AND t.asserted_by_oid IS NOT NULL
                 AND (pg_catalog.to_regrole(pg_catalog.quote_ident(t.asserted_by))
                          IS DISTINCT FROM t.asserted_by_oid
                      -- (twenty-seventh review, RT27PL-1) an author of another cluster
                      OR NOT phasevec._from_here(t.asserted_in, t.asserted_cluster))
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

-- (twenty-fifth review, RT25PC-AUTH-1) A claim is its author's. Until this review any role granted
-- assert(), refute(), supersede() or unsupersede() changed any claim: a tenant under row-level
-- security replaced, retired and hid another tenant's verified claims on rows it could not see, and
-- a role with no SELECT on the table did it through assert() with no proof, refute(), supersede()
-- and unsupersede(). Now each of them takes its caller (its current user, as assert() always did: a
-- SECURITY DEFINER wrapper acts with its owner's rights), refuses a caller that may not read the
-- watched table (src/phasevec_truth.c, must_read), learns whether the caller sees each row it names
-- (with row-level security), and changes a claim only when _claim_mine says so, on the claim's row
-- as the write takes it (ON CONFLICT ... WHERE, or the row taken FOR UPDATE): no claim can change
-- hands between the check and the write. A claim is changed by
--   * a role with the privileges of the watched table's owner (who can change every row the claim
--     is about), or
--   * a role with the privileges of the claim's author, while the author is still that role (its
--     OID has its name);
--   * a key with no claim, or with a claim of no author still there (asserted before 0.20.0, or its
--     author dropped or renamed), by a role that sees its row.
-- Who last made a claim what it is is its author: assert(), and refute() too (the role that retired
-- it) and a supersede() of a key with no claim (the placeholder). A refusal reads alike for a row
-- the caller does not see, a row that does not exist and another author's claim.
-- (twenty-sixth review: the owner's rule, in place of the twenty-fifth's "first come") A claim is
-- changed (assert() over it, refute(), supersede(), unsupersede(), adopt()) only by
--   * a role with the privileges of its author, while the author is still that role;
--   * a role with the privileges of the watched table's owner;
--   * a role with the privileges of a steward of its watch (phasevec.stewards): the explicit
--     grant, by the table's owner, of the right to change every claim of that watch.
-- No one else takes a claim, also when its author is gone or unknown (asserted before 0.20.0, its
-- author dropped, or a restore into another cluster): until the twenty-sixth review any role that
-- saw the row took such a claim, and its first come held it (RT26PA-4, RT27-DECISION). A key with
-- no claim at all gets one from a role that sees its row, and the row must exist, with or without
-- row-level security (RT26PA-2: until this review a reader of a table with none reserved keys no
-- row had yet, and the author who then wrote the row was refused).
-- (twenty-seventh review: the owner's rule (b), clarified) No one gets a claim by coming first. A
-- key with no claim gets one only from a role with an explicit privilege over its row, which must
-- exist (phasevec.sources has it): the table's owner's privileges, a steward's (for a row the
-- steward is not kept from by row-level security), or UPDATE on the watched table together with
-- the row passing the caller's row-level security for an UPDATE (its SELECT and UPDATE USING
-- policies: the row is taken FOR KEY SHARE as the caller, in the guard, and let go at once).
-- Reading a row is never enough: until this review a role with SELECT alone, or a tenant reading
-- a shared row, claimed every row no claim was on yet, and the role that wrote the row was then
-- refused (RT27PA-1, RT28-DECISION-FIRSTCLAIM); the owner and the stewards claimed keys no row had
-- (RT28-RESERVE-PRIV). A claim that exists is changed by its author, the owner, or a steward of
-- the watch who is not kept from its row by row-level security: a steward is shown nothing about a
-- row it does not see, and it no longer changes one (RT28-STEWARD-ORACLE: its supersede() of a
-- hidden key told, through the cycle check, which hidden keys replaced which).
-- Who an author or a steward is, is bound to the cluster where it was recorded (_cluster(): its
-- system identifier, shared by every database of it and by a physical replica), or to this
-- installation (_here(): a value made with the extension, which pg_upgrade keeps and pg_dump does
-- not): a restore or a logical replica in another cluster makes every claim an orphan and every
-- steward no one, whatever role a CREATEROLE role makes there under the stored OID and name
-- (RT27PA-3, RT27PL-1: until this review such a role took them). (twenty-eighth review) Not a copy
-- of the cluster's files, which keeps both: phasevec.rebind(), below. The owner adopts the orphans
-- (phasevec.adopt()) and names the stewards again. A restore into another database of the same
-- cluster keeps them (the same roles), and so does pg_upgrade (the same installation).
-- A steward is the table owner's: it counts while the role that named it (as the table's owner)
-- still owns the table. ALTER TABLE ... OWNER TO ends every steward the former owner named, until
-- the new one names it (RT27PA-4). A steward revoked (phasevec.steward(..., false), a membership
-- revoked) changes nothing from then on; what it changed while it was one stays as it left it, in
-- its name where it was the last to make the claim what it is (an assert(), a refute(), a
-- supersede() of a key with no claim), and is changed by its author, the owner and the stewards,
-- as any claim (RT27PA-2).
CREATE TABLE phasevec.stewards (
    watch     int  NOT NULL REFERENCES phasevec.watches (id) ON DELETE CASCADE,
    role      oid  NOT NULL,
    role_name name NOT NULL,
    named_by  oid  NOT NULL,
    named_in  uuid NOT NULL,
    named_cluster bigint NOT NULL,
    PRIMARY KEY (watch, role)
);
COMMENT ON TABLE phasevec.stewards IS
    'The stewards of each watch (0.20.0, twenty-sixth review): a role with the privileges of one '
    'changes every claim of the watch on a row row-level security does not keep it from, as the '
    'table''s owner does. Named and no longer named by the table''s owner with phasevec.steward(). '
    'A steward is the role of that OID while it has that name, named in this cluster or this '
    'installation (named_cluster, named_in: phasevec._from_here()) by the role that still owns '
    'the table (named_by): dropped, renamed, restored or replicated into another cluster, or the '
    'table given to another owner, it is no one until named again.';
REVOKE ALL ON phasevec.stewards FROM PUBLIC;
SELECT pg_catalog.pg_extension_config_dump('phasevec.stewards', '');
-- An author of a claim, or a steward, is still that role here.
CREATE FUNCTION phasevec._role_here(p_role oid, p_name name, p_in uuid, p_cluster bigint)
RETURNS boolean LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    SELECT p_role IS NOT NULL AND phasevec._from_here(p_in, p_cluster)
       AND to_regrole(quote_ident(p_name)) IS NOT DISTINCT FROM p_role
$f$;
CREATE FUNCTION phasevec._steward_of(p_watch int, p_caller oid, p_table_owner oid)
RETURNS boolean LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    SELECT EXISTS (SELECT 1 FROM phasevec.stewards s
                    WHERE s.watch = p_watch AND s.named_by = p_table_owner
                      AND phasevec._role_here(s.role, s.role_name, s.named_in, s.named_cluster)
                      AND coalesce(pg_has_role(p_caller, s.role, $q$USAGE$q$), false))
$f$;
-- The owner's privileges or a steward's: who may adopt() (per row: only rows the caller sees).
CREATE FUNCTION phasevec._claim_privileged(p_watch int, p_caller oid, p_table_owner oid)
RETURNS boolean LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    SELECT coalesce(pg_has_role(p_caller, p_table_owner, $q$USAGE$q$), false)
        OR phasevec._steward_of(p_watch, p_caller, p_table_owner)
$f$;
-- t: the claim's row as the write takes it, or NULL::phasevec.truth for a key with no claim.
-- p_sees: row-level security does not keep the caller from the key's row (true without it).
-- p_writes: the caller has UPDATE on the table and the row passes its row-level security for an
-- UPDATE (src/phasevec_truth.c, caller_writes; asked only for a key with no claim).
-- (twenty-eighth review) Which right lets the caller change the claim, or NULL: 'owner',
-- 'author', 'writer' (a first claim by a role that may UPDATE the row) or 'steward', in that order.
-- A dead claim (_claim_dead, RT28PA-REUSE-1) is claimed as a key with no claim is. A claim made
-- through a steward's right alone (by_steward, RT28PA-REVOKE-1) gives its author no right of its
-- own: it changes it as a steward, while it is one. Until this review a steward with no other
-- right over a row (SELECT only) claimed it first, and kept changing it after the owner revoked it,
-- while the role that wrote the row was refused.
CREATE FUNCTION phasevec._claim_how(t phasevec.truth, p_watch int, p_key text, p_caller oid,
                                    p_sees boolean, p_writes boolean, p_table_owner oid)
RETURNS text LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    SELECT CASE
        WHEN coalesce(pg_has_role(p_caller, p_table_owner, $q$USAGE$q$), false)
        THEN CASE WHEN t.key IS NOT NULL
                       OR EXISTS (SELECT 1 FROM phasevec.sources s
                                   WHERE s.watch = p_watch AND s.key = p_key)
                  THEN $q$owner$q$ END
        WHEN t.key IS NULL OR phasevec._claim_dead(t)
        THEN CASE WHEN NOT EXISTS (SELECT 1 FROM phasevec.sources s
                                    WHERE s.watch = p_watch AND s.key = p_key)
                  THEN NULL
                  WHEN coalesce(p_writes, false) THEN $q$writer$q$
                  WHEN coalesce(p_sees, false)
                       AND phasevec._steward_of(p_watch, p_caller, p_table_owner)
                  THEN $q$steward$q$ END
        WHEN NOT t.by_steward
             AND phasevec._role_here(t.asserted_by_oid, t.asserted_by, t.asserted_in,
                                     t.asserted_cluster)
             AND coalesce(pg_has_role(p_caller, t.asserted_by_oid, $q$USAGE$q$), false)
        THEN $q$author$q$
        WHEN coalesce(p_sees, false) AND phasevec._steward_of(p_watch, p_caller, p_table_owner)
        THEN $q$steward$q$
        END
$f$;
CREATE FUNCTION phasevec._claim_mine(t phasevec.truth, p_watch int, p_key text, p_caller oid,
                                     p_sees boolean, p_writes boolean, p_table_owner oid)
RETURNS boolean LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    SELECT phasevec._claim_how(t, p_watch, p_key, p_caller, p_sees, p_writes, p_table_owner)
           IS NOT NULL
$f$;
CREATE FUNCTION phasevec._claim_refused(p_watch text, p_key text, p_caller oid) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $f$
BEGIN
    RAISE EXCEPTION 'phasevec: role "%" may not change the claim on key % of watch %',
                    pg_get_userbyid(p_caller), p_key, p_watch
        USING ERRCODE = 'insufficient_privilege',
              DETAIL = 'A claim is changed by a role with the privileges of its author (while '
                       'the author is still that role), of the watched table''s owner, or of a '
                       'steward of the watch (phasevec.steward()). A key with no claim gets one '
                       'only from one of these, or from a role that may UPDATE its row; its row '
                       'must exist.';
END;
$f$;
-- The claim on a key, taken FOR UPDATE, when the caller may change it; refused alike otherwise
-- (no claim it may make, another's claim, a row it does not see or that does not exist). Then,
-- and only then, whether it is 0.19.0's (RT28-MIGRATED-ORACLE: until this review that came
-- first, and told a tenant which key it did not see held a claim of 0.19.0).
CREATE FUNCTION phasevec._claim_take(p_watch phasevec.watches, p_name text, p_key text,
                                     p_caller oid, p_sees boolean, p_writes boolean,
                                     p_table_owner oid) RETURNS phasevec.truth
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $f$
DECLARE c phasevec.truth;
BEGIN
    PERFORM phasevec._migrated(p_watch.id, NULL);
    -- (twenty-eighth review, RT28PA-LOCK-ORACLE) Checked first on the claim as it committed, with
    -- no lock: until this review the lock came first, and a caller probing a key it does not see
    -- waited for whoever was changing that key's claim (or got "canceling statement due to lock
    -- timeout"), and so learnt that the hidden key had a claim, changed now. A caller with no
    -- right over the claim as it is waits for no one; one that has it takes the row and is checked
    -- again on what it took.
    SELECT * INTO c FROM phasevec.truth t WHERE t.watch = p_watch.id AND t.key = p_key;
    IF NOT phasevec._claim_mine(c, p_watch.id, p_key, p_caller, p_sees, p_writes,
                                p_table_owner) THEN
        PERFORM phasevec._claim_refused(p_name, p_key, p_caller);
    END IF;
    SELECT * INTO c FROM phasevec.truth t WHERE t.watch = p_watch.id AND t.key = p_key FOR UPDATE;
    IF NOT phasevec._claim_mine(c, p_watch.id, p_key, p_caller, p_sees, p_writes,
                                p_table_owner) THEN
        PERFORM phasevec._claim_refused(p_name, p_key, p_caller);
    END IF;
    PERFORM phasevec._migrated(p_watch.id, p_key);
    RETURN c;
END;
$f$;
-- (twenty-sixth review) The table's owner names, or no longer names, a steward of a watch (C,
-- src/phasevec_truth.c, which knows its caller; the write is _steward_set's, as the owner).
CREATE FUNCTION phasevec._steward_set(p_watch text, p_role oid, p_grant boolean, p_caller oid)
RETURNS boolean LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $f$
DECLARE w phasevec.watches := phasevec._watch(p_watch);
        own oid := (SELECT c.relowner FROM pg_class c WHERE c.oid = w.source);
BEGIN
    IF NOT coalesce(pg_has_role(p_caller, own, $q$USAGE$q$), false) THEN
        RAISE EXCEPTION 'phasevec: only the owner of %, the table of watch %, names its stewards',
                        w.source, p_watch
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF p_grant AND NOT EXISTS (SELECT 1 FROM pg_roles r WHERE r.oid = p_role) THEN
        RAISE EXCEPTION 'phasevec: a steward is a role'
            USING ERRCODE = 'undefined_object';
    END IF;
    IF p_grant THEN
        INSERT INTO phasevec.stewards AS s (watch, role, role_name, named_by, named_in,
                                            named_cluster)
        VALUES (w.id, p_role, pg_get_userbyid(p_role), own, phasevec._here(), phasevec._cluster())
        ON CONFLICT (watch, role) DO UPDATE
           SET role_name = EXCLUDED.role_name, named_by = EXCLUDED.named_by,
               named_in = EXCLUDED.named_in, named_cluster = EXCLUDED.named_cluster
         WHERE (s.role_name, s.named_by, s.named_in, s.named_cluster)
               IS DISTINCT FROM (EXCLUDED.role_name, EXCLUDED.named_by, EXCLUDED.named_in,
                                 EXCLUDED.named_cluster);
    ELSE
        DELETE FROM phasevec.stewards s WHERE s.watch = w.id AND s.role = p_role;
    END IF;
    RETURN FOUND;
END;
$f$;
CREATE FUNCTION phasevec.steward(p_watch text, p_role regrole, p_grant boolean DEFAULT true)
RETURNS boolean AS $q$MODULE_PATHNAME$q$, $q$phasevec_steward$q$ LANGUAGE C VOLATILE;
COMMENT ON FUNCTION phasevec.steward(text, regrole, boolean) IS
    'Names p_role a steward of the watch (p_grant false: no longer): a role with its privileges '
    'changes every claim of the watch on a row it is not kept from by row-level security, as the '
    'table''s owner does (0.20.0, twenty-sixth review). For the table''s owner; a steward counts '
    'while that role owns the table. True when it changed something.';

-- (twenty-eighth review, RV29-1, RV29-2, RT28PA-CLONE-1, RT28PL-1) A copy of a cluster cannot be
-- told from the cluster it was copied from by any value the copy carries: a pg_basebackup, a
-- standby promoted, pg_createsubscriber, pg_upgrade --copy or --clone keep its system identifier
-- or this installation's _here(), or both, and the copy's OID counter. A role with CREATEROLE in
-- the copy can make a role under an author's OID and name, and that role is then the author.
-- This review stops trying to bind an author to more than the twenty-seventh did (its cluster or
-- its installation): after making a copy it does not trust as it trusts the original, the table's
-- owner (or a superuser, for every watch) cuts what the copy inherited. Every claim of the watch
-- whose author is not the table's owner becomes an orphan (asserted_in and asserted_cluster
-- NULL: the author is no one here, its verdicts read 'unproven', and the owner adopt()s what it
-- keeps), and the watch has no steward until the owner names them again.
CREATE FUNCTION phasevec._rebind_set(p_watch text, p_caller oid)
RETURNS TABLE (watch text, claims bigint, stewards bigint)
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $f$
DECLARE w phasevec.watches;
        own oid;
BEGIN
    IF p_watch IS NOT NULL THEN
        w := phasevec._watch(p_watch);
        own := (SELECT c.relowner FROM pg_class c WHERE c.oid = w.source);
        IF NOT coalesce(pg_has_role(p_caller, own, $q$USAGE$q$), false) THEN
            RAISE EXCEPTION 'phasevec: only the owner of %, the table of watch %, rebinds its '
                            'claims', w.source, p_watch
                USING ERRCODE = 'insufficient_privilege';
        END IF;
    END IF;
    FOR w IN SELECT x.* FROM phasevec.watches x
              WHERE p_watch IS NULL OR x.name = p_watch ORDER BY x.id LOOP
        own := (SELECT c.relowner FROM pg_class c WHERE c.oid = w.source);
        CONTINUE WHEN NOT coalesce(pg_has_role(p_caller, own, $q$USAGE$q$), false);
        watch := w.name;
        UPDATE phasevec.truth t SET asserted_in = NULL, asserted_cluster = NULL
         WHERE t.watch = w.id AND t.asserted_by_oid IS DISTINCT FROM own
           AND (t.asserted_in IS NOT NULL OR t.asserted_cluster IS NOT NULL);
        GET DIAGNOSTICS claims = ROW_COUNT;
        DELETE FROM phasevec.stewards s WHERE s.watch = w.id;
        GET DIAGNOSTICS stewards = ROW_COUNT;
        RETURN NEXT;
    END LOOP;
END;
$f$;
CREATE FUNCTION phasevec.rebind(p_watch text DEFAULT NULL)
RETURNS TABLE (watch text, claims bigint, stewards bigint)
AS $q$MODULE_PATHNAME$q$, $q$phasevec_rebind$q$ LANGUAGE C VOLATILE;
COMMENT ON FUNCTION phasevec.rebind(text) IS
    'After a copy of the cluster (pg_basebackup, a standby promoted, pg_createsubscriber, '
    'pg_upgrade --copy or --clone) that is not trusted as the original is: every claim of the '
    'watch (NULL: of every watch whose table the caller owns; a superuser''s, every watch) whose '
    'author is not the table''s owner becomes an orphan, and the watch has no steward until the '
    'owner names them again (0.20.0, twenty-eighth review). The owner adopt()s what it keeps. '
    'Returns, per watch, how many claims and stewards it cut.';

-- (twenty-fifth review, RT25PU-1) What pg_phasevec 0.19.0 wrote is not changed or judged by 0.20.0
-- until it is brought to 0.20.0: every row of phasevec.watches and phasevec.truth carries the
-- version that wrote it (data_version). The update brings them all (below); a pg_dump of a 0.19.0
-- database restored where 0.20.0 is installed brings its rows in as 0.19.0 wrote them (pg_dump
-- names no version: CREATE EXTENSION makes 0.20.0, on empty tables, and the dump's rows come after
-- it, with the column's default), and phasevec.migrate() brings those. Until it runs, every door
-- that changes or judges a claim of such a watch refuses, named, with what to do (and a claim of
-- 0.19.0 reads as 0.20.0 reads one it never judged: never 'verified'). Until this review the
-- restore left them as they were: a claim refute()d under 0.19.0 kept its proof, adopt() asserted
-- it again and verify() served it 'verified'; its watch had no TRUNCATE trigger.
CREATE FUNCTION phasevec._migrated(p_watch int, p_key text) RETURNS boolean
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $f$
BEGIN
    IF EXISTS (SELECT 1 FROM phasevec.watches w
                WHERE w.id = p_watch AND w.data_version <> $q$0.20.0$q$)
       OR (p_key IS NOT NULL
           AND EXISTS (SELECT 1 FROM phasevec.truth t
                        WHERE t.watch = p_watch AND t.key = p_key
                          AND t.data_version <> $q$0.20.0$q$)) THEN
        RAISE EXCEPTION 'phasevec: watch % holds what pg_phasevec 0.19.0 wrote, not brought to '
                        '0.20.0: its claims are not changed or judged until they are',
                        (SELECT w.name FROM phasevec.watches w WHERE w.id = p_watch)
            USING ERRCODE = 'object_not_in_prerequisite_state',
                  DETAIL = 'A pg_dump of a 0.19.0 database restored where 0.20.0 is installed '
                           'brings its rows in as 0.19.0 wrote them: what the update does to them '
                           '(a refuted claim retired, a verified one not carried over, the '
                           'TRUNCATE trigger) has not been done.',
                  HINT = 'The extension''s owner runs SELECT * FROM phasevec.migrate(); once, '
                         'after the restore.';
    END IF;
    RETURN true;
END;
$f$;

-- assert(): the same signature and grants; now C (src/phasevec_truth.c): it sees who calls it, renders the row as
-- the table's owner in pinned settings, records the caller's settings, and writes through _assert_set, as the owner.
-- p_caller: the caller whose right to change the claim is checked (_claim_mine; p_sees: it sees the
-- row). (twenty-sixth review, RT26PA-1, RT27-ADOPT-1) adopt() too passes its caller: until this
-- review it passed NULL, which skipped the check, and a role granted adopt() took the orphans of
-- rows row-level security hid from it, and was handed their proofs.
-- (twenty-seventh review) p_writes: the caller may write the row (src/phasevec_truth.c,
-- caller_writes), for a key with no claim (_claim_mine).
CREATE FUNCTION phasevec._assert_set(p_watch text, p_key text, p_proof text, p_topic text,
                                     p_support jsonb, p_expires_at timestamptz, p_author oid,
                                     p_text_hash bytea, p_env text[], p_caller oid, p_sees boolean,
                                     p_writes boolean)
RETURNS void LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $f$
DECLARE w phasevec.watches := phasevec._watch(p_watch);
        own oid := (SELECT c.relowner FROM pg_class c WHERE c.oid = w.source);
        cl phasevec.truth;
BEGIN
    cl := phasevec._claim_take(w, p_watch, p_key, p_caller, p_sees, p_writes, own);
    INSERT INTO phasevec.truth AS t (watch, key, proof, topic, support, expires_at,
                                     asserted_by, asserted_by_oid, asserted_in, asserted_cluster,
                                     asserted_for, proof_env, data_version, asserted_row,
                                     by_steward)
    VALUES (w.id, p_key, p_proof, p_topic, p_support, p_expires_at,
            pg_get_userbyid(p_author), p_author, phasevec._here(), phasevec._cluster(),
            p_text_hash, p_env, $q$0.20.0$q$,
            coalesce((SELECT s.born FROM phasevec.sources s WHERE s.watch = w.id AND s.key = p_key),
                     $q$00000000-0000-0000-0000-000000000000$q$::uuid),
            coalesce(phasevec._claim_how(cl, w.id, p_key, p_caller, p_sees, p_writes, own)
                     = $q$steward$q$, false))
    ON CONFLICT (watch, key) DO UPDATE
       SET proof = EXCLUDED.proof, topic = EXCLUDED.topic, support = EXCLUDED.support,
           expires_at = EXCLUDED.expires_at, asserted_by = EXCLUDED.asserted_by,
           asserted_by_oid = EXCLUDED.asserted_by_oid, asserted_in = EXCLUDED.asserted_in,
           asserted_cluster = EXCLUDED.asserted_cluster, asserted_for = EXCLUDED.asserted_for,
           asserted_row = EXCLUDED.asserted_row,
           by_steward = coalesce(phasevec._claim_how(t, w.id, p_key, p_caller, p_sees, p_writes,
                                                     own) = $q$steward$q$, false),
           proof_env = EXCLUDED.proof_env, halted = false, retired_at = NULL,
           verdict = CASE WHEN t.verdict = $q$replaced$q$ THEN t.verdict ELSE $q$unproven$q$ END,
           verified_at = NULL, verified_for = NULL, last_error = NULL, changed_at = now(),
           looked_at = NULL, looked_for = NULL, interrupted_at = NULL, interrupted_why = NULL,
           data_version = $q$0.20.0$q$
     WHERE phasevec._claim_mine(t, w.id, p_key, p_caller, p_sees, p_writes, own);
    IF NOT FOUND THEN
        PERFORM phasevec._claim_refused(p_watch, p_key, p_caller);
    END IF;
END;
$f$;
CREATE OR REPLACE FUNCTION phasevec.assert(p_watch text, p_key text, p_proof text DEFAULT NULL, p_topic text DEFAULT NULL,
                                           p_support jsonb DEFAULT NULL, p_expires_at timestamptz DEFAULT NULL)
RETURNS void AS $q$MODULE_PATHNAME$q$, $q$phasevec_assert$q$ LANGUAGE C VOLATILE;

-- refute(): as in 0.14.1, and the refutation is about the text it refuted: the row's text as the watch trigger last
-- saw it when refute() ran; when that text changes, it is not refuted any more.
-- (seventeenth review) A refutation retires the claim: its proof goes with it, so no verify(), verify_one() or
-- adopt() judges it again, and it reads 'refuted', with no horizon, while its text is the refuted one; an assert()
-- makes it a claim again. Until then the proof stayed: the next verify() past p_every judged it again and served it
-- 'verified', and adopt() asserted every refuted claim again (an application retires a deleted note with refute()).
-- (eighteenth review) Retired is a state of its own (retired_at, _claim_state), on every path:
--   * a replaced claim is retired too, behind its replacement: until then refute() of a replaced key did nothing, no
--     error, and unsupersede() brought it back 'verified';
--   * the text it is about is recorded on every refute(): only a claim refute() inserted had it, and a claim
--     asserted before 0.20.0 (no text) or with no proof read 'unproven' after refute(), not 'refuted' (an application
--     went on serving every note deleted after the update).
-- (nineteenth review, 53) verified_at and retired_at never move back: a transaction that began before a verdict was
-- recorded (its now() is earlier) stamps that verdict's time, not its own.
-- (twenty-fifth review, RT25PC-AUTH-1) C (src/phasevec_truth.c), through _refute_set as the owner:
-- the caller's own claim, or one it may change (_claim_mine); the role that retired it is its
-- author.
CREATE FUNCTION phasevec._refute_set(p_watch text, p_key text, p_reason text, p_caller oid,
                                     p_sees boolean, p_writes boolean)
RETURNS void LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $f$
DECLARE w phasevec.watches := phasevec._watch(p_watch);
        own oid := (SELECT c.relowner FROM pg_class c WHERE c.oid = w.source);
        h bytea;
        b uuid;
        cl phasevec.truth;
BEGIN
    IF coalesce(btrim(p_reason), $q$$q$) = $q$$q$ THEN
        RAISE EXCEPTION $q$phasevec: a refutation says why$q$;
    END IF;
    cl := phasevec._claim_take(w, p_watch, p_key, p_caller, p_sees, p_writes, own);
    SELECT s.text_hash, s.born INTO h, b FROM phasevec.sources s
     WHERE s.watch = w.id AND s.key = p_key;
    b := coalesce(b, $q$00000000-0000-0000-0000-000000000000$q$::uuid);
    INSERT INTO phasevec.truth AS t (watch, key, verdict, verified_at, last_error, asserted_for,
                                     retired_at, asserted_by, asserted_by_oid, asserted_in,
                                     asserted_cluster, data_version, asserted_row, by_steward)
    VALUES (w.id, p_key, $q$refuted$q$, now(), p_reason, h, now(), pg_get_userbyid(p_caller),
            p_caller, phasevec._here(), phasevec._cluster(), $q$0.20.0$q$, b,
            coalesce(phasevec._claim_how(cl, w.id, p_key, p_caller, p_sees, p_writes, own)
                     = $q$steward$q$, false))
    ON CONFLICT (watch, key) DO UPDATE
       SET verdict = CASE WHEN t.verdict = $q$replaced$q$ THEN t.verdict ELSE $q$refuted$q$ END,
           verified_at = greatest(now(), t.verified_at), last_error = p_reason, changed_at = now(),
           retired_at = greatest(now(), t.verified_at),
           proof = NULL, halted = false, asserted_for = h, verified_for = NULL,
           looked_at = NULL, looked_for = NULL, interrupted_at = NULL, interrupted_why = NULL,
           asserted_by = EXCLUDED.asserted_by, asserted_by_oid = EXCLUDED.asserted_by_oid,
           asserted_in = EXCLUDED.asserted_in, asserted_cluster = EXCLUDED.asserted_cluster,
           asserted_row = EXCLUDED.asserted_row,
           by_steward = coalesce(phasevec._claim_how(t, w.id, p_key, p_caller, p_sees, p_writes,
                                                     own) = $q$steward$q$, false),
           data_version = $q$0.20.0$q$
     WHERE phasevec._claim_mine(t, w.id, p_key, p_caller, p_sees, p_writes, own);
    IF NOT FOUND THEN
        PERFORM phasevec._claim_refused(p_watch, p_key, p_caller);
    END IF;
END;
$f$;
CREATE OR REPLACE FUNCTION phasevec.refute(p_watch text, p_key text, p_reason text) RETURNS void
AS $q$MODULE_PATHNAME$q$, $q$phasevec_refute$q$ LANGUAGE C VOLATILE;

-- supersede(): (twenty-fifth review, RT25PC-AUTH-1) C, through _supersede_set as the owner: the old
-- key's claim is one the caller may change (_claim_mine; with none, a placeholder whose author is
-- the caller), and the new key a row the caller sees (a role that sees no such row reads that it
-- does not exist, as for a row that does not). (RT25PC-INFO-2) A replacement closes no cycle: a new
-- key whose replacement chain leads back to the old one is refused. Until this review 2 -> 3 then 3
-- -> 2 was taken, both read 'replaced' and both left brief(). The supersedes of a watch take its
-- row of phasevec.watches (FOR NO KEY UPDATE, which no write of a claim waits for) and read the
-- chain after it, at READ COMMITTED (refused at REPEATABLE READ or SERIALIZABLE, whose snapshot
-- would not show a supersede committed while this one waited): of two at once that would close a
-- cycle, the second sees the first.
CREATE FUNCTION phasevec._supersede_set(p_watch text, p_old text, p_new text, p_reason text,
                                        p_caller oid, p_sees_old boolean, p_sees_new boolean,
                                        p_writes_old boolean)
RETURNS void LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $f$
DECLARE w phasevec.watches := phasevec._watch(p_watch);
        own oid := (SELECT c.relowner FROM pg_class c WHERE c.oid = w.source);
        cl phasevec.truth;
BEGIN
    IF p_old = p_new THEN
        RAISE EXCEPTION $q$phasevec: a row cannot replace itself$q$;
    END IF;
    IF coalesce(btrim(p_reason), $q$$q$) = $q$$q$ THEN
        RAISE EXCEPTION $q$phasevec: a replacement says why$q$;
    END IF;
    IF current_setting($q$transaction_isolation$q$) <> $q$read committed$q$ THEN
        RAISE EXCEPTION 'phasevec: supersede() runs only at READ COMMITTED'
            USING ERRCODE = 'feature_not_supported',
                  DETAIL = 'It reads the replacement chain as it is once it holds the watch: a '
                           'snapshot taken before would not show a supersede() committed '
                           'meanwhile, and two could close a cycle.',
                  HINT = 'Call it outside the transaction, or in one at READ COMMITTED.';
    END IF;
    PERFORM phasevec._migrated(w.id, NULL);
    -- (the owner's privileges, not a steward's: under row-level security a steward is not told
    -- which rows it does not see exist)
    IF NOT (p_sees_new OR coalesce(pg_has_role(p_caller, own, $q$USAGE$q$), false))
       OR NOT EXISTS (SELECT 1 FROM phasevec.sources s WHERE s.watch = w.id AND s.key = p_new) THEN
        RAISE EXCEPTION $q$phasevec: row % of watch % does not exist: it cannot replace anything$q$,
                        p_new, p_watch;
    END IF;
    PERFORM 1 FROM phasevec.watches x WHERE x.id = w.id FOR NO KEY UPDATE;
    -- (twenty-sixth review, RT26PA-3) The old key's claim is the caller's to change before the
    -- chain is read: until this review the cycle check came first, and its error told a tenant
    -- that a key row-level security hid from it had a claim, in the chain of a row it saw.
    -- (twenty-seventh review, RT28-STEWARD-ORACLE) A steward is not kept from the old key's row
    -- (p_sees_old), as the new key's: the chain it reads goes through rows it may not see, but
    -- from a row it sees to another it sees.
    cl := phasevec._claim_take(w, p_watch, p_old, p_caller, p_sees_old, p_writes_old, own);
    IF EXISTS (WITH RECURSIVE c(k) AS (
                   SELECT p_new
                   UNION
                   SELECT t.replaced_by
                     FROM c JOIN phasevec.truth t ON t.watch = w.id AND t.key = c.k
                    WHERE t.verdict = $q$replaced$q$ AND t.replaced_by IS NOT NULL)
               SELECT 1 FROM c WHERE c.k = p_old) THEN
        RAISE EXCEPTION 'phasevec: row % of watch % is replaced, in the end, by row %: % cannot '
                        'replace %', p_new, p_watch, p_old, p_new, p_old
            USING ERRCODE = 'invalid_parameter_value',
                  DETAIL = 'A replacement that closes a cycle would hide every claim on it.';
    END IF;
    INSERT INTO phasevec.truth AS t (watch, key, replaced_by, reason, verdict, asserted_by,
                                     asserted_by_oid, asserted_in, asserted_cluster, data_version,
                                     asserted_row, by_steward)
    VALUES (w.id, p_old, p_new, p_reason, $q$replaced$q$, pg_get_userbyid(p_caller), p_caller,
            phasevec._here(), phasevec._cluster(), $q$0.20.0$q$,
            coalesce((SELECT s.born FROM phasevec.sources s WHERE s.watch = w.id AND s.key = p_old),
                     $q$00000000-0000-0000-0000-000000000000$q$::uuid),
            coalesce(phasevec._claim_how(cl, w.id, p_old, p_caller, p_sees_old, p_writes_old, own)
                     = $q$steward$q$, false))
    ON CONFLICT (watch, key) DO UPDATE
       SET replaced_by = p_new, reason = p_reason, verdict = $q$replaced$q$, changed_at = now()
     WHERE phasevec._claim_mine(t, w.id, p_old, p_caller, p_sees_old, p_writes_old, own);
    IF NOT FOUND THEN
        PERFORM phasevec._claim_refused(p_watch, p_old, p_caller);
    END IF;
END;
$f$;
CREATE OR REPLACE FUNCTION phasevec.supersede(p_watch text, p_old text, p_new text, p_reason text)
RETURNS void AS $q$MODULE_PATHNAME$q$, $q$phasevec_supersede$q$ LANGUAGE C VOLATILE;

-- unsupersede(): (eighteenth review) a claim comes back in the state it kept behind its replacement (supersede()
-- changes none of retired_at, proof, halted, verified_at, verified_for): with the verdict that state has. A state no
-- verify() judges again comes back with the verdict it had: a retired one reads 'refuted' again, as of when it was
-- retired, and (nineteenth review, R19-F8) a halted one reads 'refuted' again, as of its halt, bound to the claim it
-- halted. A judged one comes back 'unproven' and due at once (verify() judges it again), and a bare one 'unproven'.
-- Until the eighteenth review every claim came back 'unproven': a retired one (no proof, so never judged again) was
-- served 'unproven' for good; until the nineteenth a halted one was (verify() does not run it again), and brief()
-- served a claim its proof had refuted.
-- (twenty-fifth review, RT25PC-AUTH-1) C, through _unsupersede_set as the owner, on the claim's row
-- taken FOR UPDATE: only a claim the caller may change (_claim_mine); a key with none is refused
-- alike when the caller does not see its row, and left as it is when it does.
CREATE FUNCTION phasevec._unsupersede_set(p_watch text, p_key text, p_caller oid, p_sees boolean,
                                          p_writes boolean)
RETURNS void LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $f$
DECLARE w phasevec.watches := phasevec._watch(p_watch);
        own oid := (SELECT c.relowner FROM pg_class c WHERE c.oid = w.source);
BEGIN
    PERFORM phasevec._claim_take(w, p_watch, p_key, p_caller, p_sees, p_writes, own);
    UPDATE phasevec.truth t
       SET replaced_by = NULL, reason = NULL,
           verdict = CASE phasevec._claim_state(t.retired_at, t.proof, t.halted)
                          WHEN $q$retired$q$ THEN $q$refuted$q$
                          WHEN $q$halted$q$ THEN $q$refuted$q$
                          ELSE $q$unproven$q$ END,
           verified_at = CASE phasevec._claim_state(t.retired_at, t.proof, t.halted)
                              WHEN $q$retired$q$ THEN greatest(t.retired_at, t.verified_at)
                              WHEN $q$halted$q$ THEN t.verified_at END,
           changed_at = now()
     WHERE t.watch = w.id AND t.key = p_key AND t.verdict = $q$replaced$q$;
END;
$f$;
CREATE OR REPLACE FUNCTION phasevec.unsupersede(p_watch text, p_key text) RETURNS void
AS $q$MODULE_PATHNAME$q$, $q$phasevec_unsupersede$q$ LANGUAGE C VOLATILE;

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
                                     AND phasevec._from_here(t.asserted_in, t.asserted_cluster)
                                     AND NOT phasevec._claim_dead(t)
     CROSS JOIN LATERAL (SELECT (SELECT s.text_hash FROM phasevec.sources s
                                  WHERE s.watch = t.watch AND s.key = t.key) AS text_hash) s
     CROSS JOIN LATERAL (SELECT t.verdict IN ($q$verified$q$, $q$refuted$q$)
                                AND t.asserted_for IS DISTINCT FROM s.text_hash AS stale) x
     WHERE t.watch = p_watch AND phasevec._claim_state(t.retired_at, t.proof, t.halted) = $q$judged$q$ AND t.verdict <> $q$replaced$q$
       AND t.asserted_by_oid IS NOT NULL
       -- (twenty-fifth review, RT25PU-1) not a watch, nor a claim, that 0.19.0 wrote and nothing
       -- brought to 0.20.0
       AND phasevec._migrated(p_watch, NULL) AND t.data_version = $q$0.20.0$q$
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

-- One key's claim (verify_one, which runs a halted claim too: it was asked for); no row when it has no proof, is
-- retired or was replaced.
CREATE FUNCTION phasevec._truth_of(p_watch int, p_key text)
RETURNS TABLE (key text, proof text, author oid, author_known boolean, asserted_for bytea, env text[], bind bytea)
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    SELECT t.key, t.proof, t.asserted_by_oid, r.oid IS NOT NULL, t.asserted_for, t.proof_env,
           phasevec._bind(t.asserted_for, t.proof, t.asserted_by_oid, t.proof_env)
      FROM phasevec.truth t
      LEFT JOIN pg_catalog.pg_roles r ON r.oid = t.asserted_by_oid AND r.rolname = t.asserted_by
                                     AND phasevec._from_here(t.asserted_in, t.asserted_cluster)
                                     AND NOT phasevec._claim_dead(t)
     WHERE t.watch = p_watch AND t.key = p_key AND phasevec._claim_state(t.retired_at, t.proof, t.halted) IN ($q$judged$q$, $q$halted$q$)
       AND t.verdict <> $q$replaced$q$ AND phasevec._migrated(p_watch, p_key)
$f$;

-- Record what a proof's run found, only for the claim it judged (p_bind: the same text, proof, author and settings).
-- Anything else changed meanwhile: nothing is recorded. p_outcome NULL records nothing (the row moved while the
-- proof ran). p_at: when the row was read for it, the state it judged (verified_at). Returns the verdict as it
-- reads now. (tenth review) A verdict read after p_at is not replaced: verdicts only move
-- forward in time. A worker takes the claim's row before it judges, so of two judgments of one claim the later one
-- commits later; a record of what a verifier found about an earlier run (a proof that took too long) can still come
-- after a newer verdict, and is dropped.
-- (twentieth review, RT20M-1) p_taken: for a record made in another transaction than the one that took the claim for
-- its proof (what the verifier found about a run whose session it ended, src/phasevec_truth.c), the version of the
-- claim's row that run took (its xmin): the record is the claim's only while no one has written the row since. The
-- bind cannot tell it (the same proof asserted again binds alike), and neither can a time: a writer's now() is the
-- start of its transaction, which may be older than the run it outlasted.
DROP FUNCTION phasevec._truth_set(int, text, boolean, text);
CREATE FUNCTION phasevec._truth_set(p_watch int, p_key text, p_outcome text, p_error text, p_bind bytea,
                                    p_at timestamptz, p_taken xid DEFAULT NULL)
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
           AND phasevec._claim_state(t.retired_at, t.proof, t.halted) <> $q$retired$q$
           AND phasevec._bind(t.asserted_for, t.proof, t.asserted_by_oid, t.proof_env) = p_bind
           AND (p_taken IS NULL OR t.xmin = p_taken)
           AND phasevec._truth_stale(t);
        p_outcome := CASE WHEN FOUND THEN NULL ELSE $q$unproven$q$ END;
    END IF;
    IF p_outcome IS NOT NULL THEN
        UPDATE phasevec.truth t
           SET verdict = p_outcome, verified_at = coalesce(p_at, now()), last_error = p_error, halted = false,
               verified_for = CASE WHEN p_outcome IN ($q$verified$q$, $q$refuted$q$) THEN p_bind END,
               looked_at = NULL, looked_for = NULL, interrupted_at = NULL, interrupted_why = NULL
         WHERE t.watch = p_watch AND t.key = p_key AND t.verdict <> $q$replaced$q$
           AND phasevec._claim_state(t.retired_at, t.proof, t.halted) <> $q$retired$q$
           AND phasevec._bind(t.asserted_for, t.proof, t.asserted_by_oid, t.proof_env) = p_bind
           AND (p_taken IS NULL OR t.xmin = p_taken)
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
-- waited). A claim written since its proof's session took it is not the one that ran: it runs. Returns 1 when
-- recorded, 0 when no such claim is left, -1 when this verifier may not record it.
-- (twentieth review, RT20M-1) "Written since" is the version of the claim's row the proof's session took (p_taken, its
-- xmin), not a time: every write of the row makes a new version, the proof's own session writes none, and the version
-- does not depend on any clock. In the nineteenth review's cut it was changed_at <= p_started, and changed_at is the
-- writer's now(), the start of its transaction: an assert() whose transaction began before the proof, and that waited
-- for the proof's row and committed after the session ended, was taken for the claim that ran and halted, and the
-- assert that is the documented way out of a halt was undone (verify() never ran it again).
CREATE FUNCTION phasevec._truth_halted(p_watch int, p_key_hash bytea, p_bind bytea, p_verifier oid, p_taken xid)
RETURNS int LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $f$
DECLARE k text; a oid; known boolean;
BEGIN
    IF p_taken IS NULL THEN
        RETURN 0;
    END IF;
    SELECT t.key, t.asserted_by_oid, r.oid IS NOT NULL INTO k, a, known
      FROM phasevec.truth t
      LEFT JOIN pg_catalog.pg_roles r ON r.oid = t.asserted_by_oid AND r.rolname = t.asserted_by
                                     AND phasevec._from_here(t.asserted_in, t.asserted_cluster)
                                     AND NOT phasevec._claim_dead(t)
     WHERE t.watch = p_watch AND t.verdict <> $q$replaced$q$ AND phasevec._claim_state(t.retired_at, t.proof, t.halted) <> $q$retired$q$
       -- the key's own bytes, as the proof's session hashes them (src/phasevec_truth.c, key_hash)
       AND sha256(convert_to(t.key, getdatabaseencoding()::name)) = p_key_hash
       AND phasevec._bind(t.asserted_for, t.proof, t.asserted_by_oid, t.proof_env) = p_bind
       -- the row as the proof's session took it: nothing written since (a verdict, an assert of the same claim)
       AND t.xmin = p_taken;
    IF NOT FOUND THEN
        RETURN 0;
    END IF;
    IF known AND NOT pg_catalog.pg_has_role(p_verifier, a, $q$USAGE$q$) THEN
        RETURN -1;
    END IF;
    UPDATE phasevec.truth t
       SET verdict = $q$refuted$q$, verified_at = greatest(now(), t.verified_at), verified_for = p_bind, halted = true,
           changed_at = now(),
           interrupted_at = NULL, interrupted_why = NULL,
           last_error = $q$the session that ran this proof ended while it ran: not run again until it is asserted again$q$
     WHERE t.watch = p_watch AND t.key = k AND t.verdict <> $q$replaced$q$ AND phasevec._claim_state(t.retired_at, t.proof, t.halted) <> $q$retired$q$
       AND phasevec._bind(t.asserted_for, t.proof, t.asserted_by_oid, t.proof_env) = p_bind
       -- again under the row's lock (a write that committed since the check above made a new version)
       AND t.xmin = p_taken;
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
-- (nineteenth review, R19-F7) An interruption is the claim's that was tried (p_bind), read again under the row's lock:
-- until then it was stamped on whatever claim the key had when it was recorded, one asserted since included.
-- (twentieth review, RT20M-1) and, when the run is known (p_taken, as for _truth_halted), only while no one has
-- written the row since that run took it.
CREATE FUNCTION phasevec._truth_tried(p_watch int, p_key text, p_why text, p_interrupted boolean, p_bind bytea,
                                      p_taken xid DEFAULT NULL)
RETURNS text LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $f$
DECLARE v text;
BEGIN
    INSERT INTO phasevec.attempts AS a (watch, key, attempted_at, why) VALUES (p_watch, p_key, clock_timestamp(), p_why)
    ON CONFLICT (watch, key) DO UPDATE SET attempted_at = greatest(a.attempted_at, EXCLUDED.attempted_at), why = p_why;
    IF p_interrupted THEN
        UPDATE phasevec.truth t SET interrupted_at = now(), interrupted_why = p_why
         WHERE t.watch = p_watch AND t.key = p_key AND t.verdict <> $q$replaced$q$
           AND phasevec._claim_state(t.retired_at, t.proof, t.halted) <> $q$retired$q$
           AND phasevec._bind(t.asserted_for, t.proof, t.asserted_by_oid, t.proof_env) = p_bind
           AND (p_taken IS NULL OR t.xmin = p_taken);
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
-- as it is now (bound after step 9). Their proofs have no author and do not run until asserted again (phasevec.adopt).
-- The refuted ones are bound to the row's text, and those refute() refuted retired, after step 9 below: bound to the
-- text as this update renders it. (twenty-fifth review, RT25PU-1) All three in
-- phasevec._migrate_claims(), after step 9: the same function brings the claims of a 0.19.0 dump
-- restored here (phasevec.migrate()).

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
    SELECT phasevec._config_of(w.lexical) INTO cfg FROM phasevec.watches w WHERE w.id = p_watch;
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

-- (nineteenth review, R19-F9) The watch's TRUNCATE trigger's write, as the owner: the table is empty, and so is what
-- the watch noted of it. Until then the watch trigger was AFTER INSERT OR UPDATE OR DELETE only: after a TRUNCATE
-- phasevec.sources kept every row's text, _verdict() and truth_coverage() served 'verified' for rows that were gone
-- (until the next verify(), or max_age), and truth_coverage() counted them after that too.
CREATE FUNCTION phasevec._note_clear(p_watch int)
RETURNS void LANGUAGE sql SET search_path = pg_catalog, pg_temp AS $$
    DELETE FROM phasevec.sources WHERE watch = p_watch
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

-- (twenty-seventh review, RT27PL-2) The text search configuration of a lexical watch is kept by its
-- name, schema-qualified, and found when it is used. Since 0.6.0 it was a regconfig column, and
-- pg_upgrade refuses every database with a reg* column other than regclass, regrole and regtype in
-- a table ("Checking for reg* data types in user tables"): no database with pg_phasevec, 0.19.0's
-- too, could be upgraded with it. Found by name, a configuration renamed or dropped since is no
-- configuration: rows are noted without their lexical reading (find_hybrid() says the reading is
-- partial) until phasevec.lexical() names one again; a write to the table is not refused for it
-- (a dropped one refused every write until then). One dropped before the update keeps its OID's
-- text, which names none.
CREATE FUNCTION phasevec._config_name(p_config regconfig) RETURNS text
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    SELECT coalesce((SELECT format($q$%I.%I$q$, n.nspname, c.cfgname)
                       FROM pg_ts_config c JOIN pg_namespace n ON n.oid = c.cfgnamespace
                      WHERE c.oid = p_config),
                    p_config::oid::text)
$f$;
-- (twenty-eighth review, RV29-4) and by its owner's name as the table's owner named it
-- (lexical_owner): found by name, a configuration renamed or dropped since could be replaced by
-- one a role with CREATE on that schema made under the old name, and the watch read every new row
-- with it (and with what that role later mapped into it). A configuration under the name whose
-- owner is not the one named is no configuration (_config_of): rows are noted without their
-- lexical reading until phasevec.lexical() names one again. pg_catalog's are taken as they are
-- (only a superuser makes one there, and its owner's name is the cluster's first superuser's).
ALTER TABLE phasevec.watches ADD COLUMN lexical_owner name;
COMMENT ON COLUMN phasevec.watches.lexical_owner IS
    'The name of the owner of the lexical configuration when the table''s owner named it with '
    'phasevec.lexical() (0.20.0, twenty-eighth review): a configuration found under that name with '
    'another owner is not read with. NULL for a configuration in pg_catalog.';
UPDATE phasevec.watches w
   SET lexical_owner = (SELECT pg_catalog.pg_get_userbyid(c.cfgowner) FROM pg_catalog.pg_ts_config c
                         WHERE c.oid OPERATOR(pg_catalog.=) w.lexical::pg_catalog.oid
                           AND c.cfgnamespace OPERATOR(pg_catalog.<>)
                               'pg_catalog'::pg_catalog.regnamespace)
 WHERE w.lexical IS NOT NULL;
ALTER TABLE phasevec.watches
    ALTER COLUMN lexical TYPE text USING phasevec._config_name(lexical);
COMMENT ON COLUMN phasevec.watches.lexical IS
    'The text search configuration the watch is read lexically with (phasevec.lexical()), by its '
    'schema-qualified name, found when it is used; NULL: not read lexically. (0.20.0: text, so '
    'pg_upgrade takes the database; until then regconfig.)';
CREATE FUNCTION phasevec._config_find(p_config text) RETURNS regconfig
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    SELECT CASE WHEN p_config IS NULL OR p_config ~ $q$^[0-9]+$$q$ THEN NULL
                ELSE (SELECT c.oid::regconfig
                        FROM pg_ts_config c JOIN pg_namespace n ON n.oid = c.cfgnamespace,
                             LATERAL (SELECT parse_ident(p_config) AS x) i
                       WHERE c.cfgname = i.x[cardinality(i.x)]
                         AND n.nspname = CASE WHEN cardinality(i.x) > 1 THEN i.x[1]
                                              ELSE $q$pg_catalog$q$ END) END
$f$;
-- (twenty-eighth review, RV29-4) The configuration under the name, while its owner is the one
-- every watch that names it recorded (lexical_owner); one in pg_catalog as it is.
CREATE FUNCTION phasevec._config_of(p_config text) RETURNS regconfig
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    SELECT f.c
      FROM (SELECT phasevec._config_find(p_config) AS c) f
      JOIN pg_ts_config c ON c.oid = f.c
     WHERE c.cfgnamespace = $q$pg_catalog$q$::regnamespace
        OR NOT EXISTS (SELECT 1 FROM phasevec.watches w
                        WHERE w.lexical = p_config
                          AND w.lexical_owner IS DISTINCT FROM pg_get_userbyid(c.cfgowner))
$f$;
CREATE FUNCTION phasevec._lexemes(p_config text, p_body text) RETURNS tsvector
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    SELECT phasevec._lexemes(phasevec._config_of(p_config), p_body)
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
    UPDATE phasevec.watches
       SET lexical = phasevec._config_name(p_config),
           lexical_owner = (SELECT pg_get_userbyid(c.cfgowner) FROM pg_ts_config c
                             WHERE c.oid = p_config
                               AND c.cfgnamespace <> $q$pg_catalog$q$::regnamespace)
     WHERE id = w.id;
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

-- (eighteenth review) Why a table and a key column are not what a watch reads, or NULL when they are (C: the same
-- check every read makes, src/phasevec_truth.c, source_shape_problem).
CREATE FUNCTION phasevec._key_shape(p_source regclass, p_key name) RETURNS text
AS $q$MODULE_PATHNAME$q$, $q$phasevec_key_shape$q$ LANGUAGE C STABLE STRICT;
COMMENT ON FUNCTION phasevec._key_shape(regclass, name) IS
    $q$Why p_source cannot be watched by p_key (a partitioned table, a partition, an inheritance parent or child, a key without a unique btree index of its own enforced at once), or NULL when it can (0.20.0, eighteenth review).$q$;

-- (twentieth review, RT20M-3, RT20P-UPD-1) A watch's TRUNCATE trigger (R19-F9), made where it is missing: by watch(),
-- by this update for every older watch whose table no one is writing, and by phasevec.watch_truncate() for the rest.
-- CREATE TRIGGER holds the table in SHARE ROW EXCLUSIVE mode, which waits for its writers: p_wait false takes it only if
-- it is free now ('busy' otherwise), so the update never waits for a writer while it holds phasevec's tables (a writer
-- holds its table and then waits for them). A trigger of that name already there is the watch's when it is phasevec's
-- own ('there'); another one ('taken': a table owner may make any trigger on its table) is left alone and named. In the
-- nineteenth review's cut the update failed on it with a bare "already exists".
CREATE FUNCTION phasevec._truncate_trigger(p_watch int, p_wait boolean)
RETURNS text LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $f$
DECLARE
    src regclass;
    nm  name := $q$phasevec_watch_$q$ || p_watch || $q$_truncate$q$;
    tg  record;
BEGIN
    SELECT w.source INTO src FROM phasevec.watches w WHERE w.id = p_watch;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'phasevec: no watch %', p_watch;
    END IF;
    IF p_wait THEN
        EXECUTE format($q$LOCK TABLE %s IN SHARE ROW EXCLUSIVE MODE$q$, src);
    ELSE
        BEGIN
            EXECUTE format($q$LOCK TABLE %s IN SHARE ROW EXCLUSIVE MODE NOWAIT$q$, src);
        EXCEPTION WHEN lock_not_available THEN
            RETURN $q$busy$q$;
        END;
    END IF;
    SELECT t.tgfoid, t.tgtype, t.tgargs INTO tg FROM pg_trigger t WHERE t.tgrelid = src AND t.tgname = nm;
    IF FOUND THEN
        -- AFTER TRUNCATE FOR EACH STATEMENT (tgtype 32), phasevec._observe(<this watch>)
        RETURN CASE WHEN tg.tgfoid = $q$phasevec._observe()$q$::regprocedure AND tg.tgtype = 32
                         AND tg.tgargs = convert_to(p_watch::text, $q$UTF8$q$) || $q$\x00$q$::bytea
                    THEN $q$there$q$ ELSE $q$taken$q$ END;
    END IF;
    EXECUTE format($q$CREATE TRIGGER %I AFTER TRUNCATE ON %s FOR EACH STATEMENT EXECUTE FUNCTION phasevec._observe(%L)$q$,
                   nm, src, p_watch);
    RETURN $q$made$q$;
END;
$f$;

-- (twentieth review) The TRUNCATE trigger of a watch made before 0.20.0, for a table this update found busy (it says
-- which): true when made, false when it was there. It waits for the table's writers like any CREATE TRIGGER (and as
-- long as lock_timeout lets it), holding nothing else of phasevec's; one call per watch, each in its own transaction.
-- The caller must own the table, as for watch(), and it runs with the caller's rights (it makes a trigger on the
-- caller's table): the extension's owner runs it, or grants it with what it reads (twenty-first review: a role
-- granted only watch_truncate() got "permission denied for table watches"): EXECUTE on it and on
-- phasevec._truncate_trigger(int, boolean), and SELECT (id, name, source) on phasevec.watches, which shows that role
-- every watch's name and table (not its recipe).
CREATE FUNCTION phasevec.watch_truncate(p_watch text) RETURNS boolean
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $f$
DECLARE
    wid int;
    src regclass;
    r   text;
BEGIN
    SELECT x.id, x.source INTO wid, src FROM phasevec.watches x WHERE x.name = p_watch;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'phasevec: no watch named %', p_watch;
    END IF;
    IF NOT pg_has_role(current_user, (SELECT c.relowner FROM pg_class c WHERE c.oid = src), $q$USAGE$q$) THEN
        RAISE EXCEPTION 'phasevec: a watch''s TRUNCATE trigger is a trigger on %, so only its owner may make it', src;
    END IF;
    r := phasevec._truncate_trigger(wid, true);
    IF r = $q$taken$q$ THEN
        RAISE EXCEPTION 'phasevec: % already has a trigger named %, which is not the watch''s', src,
                        $q$phasevec_watch_$q$ || wid || $q$_truncate$q$
            USING ERRCODE = 'duplicate_object',
                  HINT = format('Drop or rename that trigger, then call phasevec.watch_truncate(%L) again.', p_watch);
    END IF;
    RETURN r = $q$made$q$;
END;
$f$;
REVOKE ALL ON FUNCTION phasevec._truncate_trigger(int, boolean), phasevec.watch_truncate(text) FROM PUBLIC;
COMMENT ON FUNCTION phasevec.watch_truncate(text) IS
    $q$Makes the TRUNCATE trigger of a watch made before 0.20.0 whose table the update found busy: true when made, false when it was there. Waits for the table's writers (lock_timeout bounds it). The caller must own the table. The owner's; a role granted it also needs EXECUTE on phasevec._truncate_trigger(int, boolean) and SELECT (id, name, source) on phasevec.watches (0.20.0).$q$;

CREATE OR REPLACE FUNCTION phasevec.watch(p_name text, p_source regclass, p_key name, p_recipe text, p_reader text,
                                          p_min_coverage numeric DEFAULT 0.95, p_doubt_below real DEFAULT NULL::real)
RETURNS integer LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $f$
DECLARE
    tbl_owner oid;
    rid       int;
    wid       int;
    why       text;
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
    -- forgot the other's, with its verdict. (eighteenth review) Provably, in everything phasevec reads: a plain
    -- table, in no inheritance tree, by a column with a unique btree index of its own enforced at once (not
    -- DEFERRABLE). Every read checks it again (src/phasevec_truth.c, source_shape_problem).
    why := phasevec._key_shape(p_source, p_key);
    IF why IS NOT NULL THEN
        RAISE EXCEPTION 'phasevec: % cannot be watched by %: %', p_source, p_key, why
            USING HINT = 'A plain table, keyed by a PRIMARY KEY or a UNIQUE constraint (not DEFERRABLE) on that column '
                         'alone (README, Supported configurations).';
    END IF;
    SELECT id INTO rid FROM phasevec.readers WHERE name = p_reader;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'phasevec: no reader named %', p_reader
            USING HINT = 'Register it with phasevec.reader_register(); nothing is read without a sealed reader.';
    END IF;

    INSERT INTO phasevec.watches (name, source, key_col, recipe, reader, min_coverage, doubt_below,
                                  data_version)
    VALUES (p_name, p_source, p_key, p_recipe, rid, p_min_coverage, p_doubt_below, $q$0.20.0$q$)
    RETURNING id INTO wid;
    -- The recipe must be an expression over the row, aliased r; it is read as every reader reads it (0.20.0).
    PERFORM 1 FROM phasevec._render(p_name, ARRAY[]::text[]);

    EXECUTE format('CREATE TRIGGER %I AFTER INSERT OR UPDATE OR DELETE ON %s '
                   'FOR EACH ROW EXECUTE FUNCTION phasevec._observe(%L, %L, %L)',
                   'phasevec_watch_' || wid, p_source, wid, p_key, p_recipe);
    -- (nineteenth review, R19-F9) and a TRUNCATE: the watch forgets every row the table had
    IF phasevec._truncate_trigger(wid, true) = 'taken' THEN
        RAISE EXCEPTION 'phasevec: % already has a trigger named %', p_source, 'phasevec_watch_' || wid || '_truncate'
            USING ERRCODE = 'duplicate_object', HINT = 'Drop or rename that trigger, then watch the table again.';
    END IF;

    -- Every row already there is noted, so it is pending until read -- not invisible.
    INSERT INTO phasevec.sources (watch, key, text_hash)
    SELECT wid, x.key, x.text_hash FROM phasevec._render(p_name, NULL) x;
    RETURN wid;
END;
$f$;

-- (twenty-first review, RT21P-UPD-1, RT21P-UPD-2) What this update reads of a watch, while it holds phasevec's
-- tables, it reads without waiting for a lock. A writer of a watched table holds that table and then waits for
-- phasevec's tables (its watch trigger reads its watch), so any lock the update waited for there could close a cycle
-- through such a writer, and the deadlock detector aborted the writer. What a watch's step reads is not a list the
-- update can know beforehand: the watched table, its indexes and TOAST table, and whatever the recipe reads, in a
-- subquery or inside a function of its own. In the twentieth review's second cut only the watched table was taken
-- with NOWAIT; a REINDEX of its key's index, or an ALTER TABLE of a table its recipe read, followed by a write to the
-- watched table, still had the writer aborted (and the update went on). So each step runs under lock_timeout = 1 ms
-- (this function's SET clause: the caller's comes back when it returns): a lock another session holds ends the try,
-- whose subtransaction lets go of what it took. It is tried again four times over 0.3 s, pausing with no lock
-- awaited (a short lock, such as an autovacuum's on a catalog, passes), and then the update stops, named, with
-- nothing changed. The steps: 'shape' (_key_shape, its answer), 'trigger' (the TRUNCATE trigger with its own NOWAIT,
-- _truncate_trigger's answer), 'render' (every row noted again where its text reads otherwise now). The rest of the
-- update writes only phasevec's own tables, which it holds, and the system catalogs (twenty-third review: the entries
-- of phasevec's functions it holds too, from the top of this script). Dropped at the end of this script.
-- (twenty-second review, RT22P-UPD-1) A recipe that reads through a function of its own with an EXCEPTION clause
-- caught the lock failure and rendered its fallback text: the step noted it for every row, and the claims retired
-- below were bound to it. phasevec's guard now ends a render in which such an error was raised, caught or not
-- (src/phasevec_guard.c, guard_leave), with the error's code: here it is retried like any other lock failure.
CREATE FUNCTION phasevec._update_step(p_watch int, p_step text) RETURNS text
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp SET lock_timeout = '1ms' AS $f$
DECLARE
    w       record;
    x       record;
    holders text;
    nsp     text;
    rel     text;
    msg     text;
BEGIN
    SELECT y.name, y.source, y.key_col INTO w FROM phasevec.watches y WHERE y.id = p_watch;
    FOR attempt IN 1..5 LOOP
        BEGIN
            IF p_step = $q$shape$q$ THEN
                RETURN phasevec._key_shape(w.source, w.key_col);
            ELSIF p_step = $q$trigger$q$ THEN
                RETURN phasevec._truncate_trigger(p_watch, false);
            END IF;
            FOR x IN SELECT r.key, r.body, r.text_hash FROM phasevec._render(w.name, NULL) r
                       JOIN phasevec.sources s ON s.watch = p_watch AND s.key = r.key
                      WHERE s.text_hash IS DISTINCT FROM r.text_hash LOOP
                PERFORM phasevec._note_set(p_watch, x.key, x.text_hash, x.body);
            END LOOP;
            RETURN NULL;
        EXCEPTION WHEN lock_not_available THEN
            IF attempt < 5 THEN
                PERFORM pg_sleep(0.02 * 2 ^ (attempt - 1));
            ELSE
                -- (twenty-second review) Only what this step reads: the relation whose lock it waited for (the
                -- error's table: phasevec's guard names it, caught by the recipe or not), the watched table, its
                -- indexes and its TOAST table. Until this review every AccessExclusiveLock in the database was listed.
                -- When the error names no table (PostgreSQL 18 gives no context for a lock wait, from which the guard
                -- reads it), any relation the recipe could read: not another session's temporary one (a recipe uses
                -- none), not one that is not committed yet, not phasevec's own.
                GET STACKED DIAGNOSTICS nsp = SCHEMA_NAME, rel = TABLE_NAME;
                rel := nullif(rel, $q$$q$);
                SELECT string_agg(DISTINCT format('%s (%s %s)',
                                                  phasevec._update_who(l.pid, l.virtualtransaction),
                                                  CASE WHEN l.granted THEN 'holds' ELSE 'waits for' END,
                                                  l.relation::regclass), ', ')
                  INTO holders
                  FROM pg_locks l
                 WHERE l.locktype = $q$relation$q$ AND l.mode = $q$AccessExclusiveLock$q$
                   AND l.pid IS DISTINCT FROM pg_backend_pid()
                   AND l.database = (SELECT d.oid FROM pg_database d WHERE d.datname = current_database())
                   AND (l.relation IN (SELECT w.source::oid
                                      UNION ALL SELECT i.indexrelid FROM pg_index i WHERE i.indrelid = w.source
                                      UNION ALL SELECT c.reltoastrelid FROM pg_class c WHERE c.oid = w.source
                                      UNION ALL SELECT c.oid FROM pg_class c
                                                  JOIN pg_namespace n ON n.oid = c.relnamespace
                                                 WHERE n.nspname = nsp AND c.relname = rel)
                        OR (rel IS NULL AND EXISTS (SELECT 1 FROM pg_class c
                                                     WHERE c.oid = l.relation AND c.relpersistence <> $q$t$q$
                                                       AND c.relnamespace <> $q$phasevec$q$::regnamespace)));
                RAISE EXCEPTION 'phasevec: the update to 0.20.0 found what watch % reads (table %, its indexes, what its '
                                'recipe reads) locked by another session: nothing was changed', w.name, w.source
                    USING ERRCODE = 'lock_not_available',
                          DETAIL = format('Sessions holding or waiting to alter a relation: %s. While it holds '
                                          'phasevec''s tables the update waits for no lock on what a watch reads.',
                                          coalesce(holders, 'none any more')),
                          HINT = 'Run the update again once that transaction has ended '
                                 '(pg_stat_activity; a prepared one: pg_prepared_xacts).';
            END IF;
        WHEN OTHERS THEN
            -- (twenty-third review, RT23P-UPD-3) An error of the render that is not the server's (a lock, a deadlock,
            -- a cancel, a resource: raised again) is the recipe's, or its rows': returned, and the update names every
            -- watch with one, together (as the shape step's). A recipe's own RAISE of one of the server's codes comes
            -- out of its guard as its own (P0001: src/phasevec_guard.c, guard_catch); until this review a RAISE of
            -- 55P03 was retried as a lock and blamed on "another session", and the first such error ended the update
            -- with no word of the watch.
            IF p_step <> $q$render$q$
               OR left(SQLSTATE, 2) IN ($q$08$q$, $q$40$q$, $q$53$q$, $q$57$q$, $q$58$q$, $q$F0$q$, $q$HV$q$,
                                        $q$XX$q$) THEN
                RAISE;
            END IF;
            GET STACKED DIAGNOSTICS msg = MESSAGE_TEXT;
            RETURN format($q$%s (SQLSTATE %s)$q$, msg, SQLSTATE);
        END;
    END LOOP;
END;
$f$;

-- A key names one row (0.20.0), provably in everything phasevec reads (eighteenth review): a watch made before
-- that a read would now refuse (a partitioned table or a partition, an inheritance parent or child, a key without
-- a unique btree index of its own enforced at once) stops the update, named, with what to do. Until the seventeenth
-- cut such a watch was only warned about, and kept serving; every read now refuses it.
-- (twentieth review, second pass; twenty-first review) _key_shape() reads the table and its indexes under a reader's
-- lock, and this update holds phasevec's tables: a watched table that another session is altering (ALTER TABLE,
-- TRUNCATE, REINDEX, in a transaction that then writes it and waits for phasevec's tables) stops the update, named,
-- and nothing changed (phasevec._update_step, above). In the first cut of the twentieth review the update waited for
-- that table, and the deadlock detector aborted the other session's transaction.
DO $d$
DECLARE
    w record;
    why text;
    bad text := $q$$q$;
BEGIN
    FOR w IN SELECT x.id, x.name, x.source, x.key_col FROM phasevec.watches x ORDER BY x.id LOOP
        why := phasevec._update_step(w.id, $q$shape$q$);
        IF why IS NOT NULL THEN
            bad := bad || format(E'\n  watch %s reads %s by %s: %s', w.name, w.source, w.key_col, why);
        END IF;
    END LOOP;
    IF bad <> $q$$q$ THEN
        RAISE EXCEPTION 'phasevec 0.20.0 does not read these watches:%', bad
            USING ERRCODE = 'feature_not_supported',
                  HINT = 'Give each table a PRIMARY KEY or a UNIQUE constraint (not DEFERRABLE) on its key column alone, '
                         'and take it out of any inheritance tree, or drop the watch (phasevec.watches), then update. '
                         'README, Supported configurations.';
    END IF;
END
$d$;

-- (nineteenth review, R19-F9) Every watch made before this update gets its TRUNCATE trigger too. (twentieth review)
-- Only where its table is free now (NOWAIT, once): a table a writer holds is not waited for (the writer may be waiting
-- for phasevec's tables, which this holds), and neither is a trigger of the watch's name that is not phasevec's. Each
-- such watch is named, with what to do: until phasevec.watch_truncate() makes its trigger, a TRUNCATE of its table
-- leaves what the watch noted, as under 0.19.0.
DO $tr$
DECLARE
    w record;
    busy text := $q$$q$;
    taken text := $q$$q$;
BEGIN
    FOR w IN SELECT x.id, x.name, x.source FROM phasevec.watches x ORDER BY x.id LOOP
        CASE phasevec._update_step(w.id, $q$trigger$q$)
            WHEN $q$busy$q$ THEN
                busy := busy OPERATOR(pg_catalog.||) pg_catalog.format(E'\n  SELECT phasevec.watch_truncate(%L);', w.name);
            WHEN $q$taken$q$ THEN
                taken := taken OPERATOR(pg_catalog.||) pg_catalog.format(E'\n  watch %s: %s has a trigger named %I',
                    w.name, w.source, $q$phasevec_watch_$q$ OPERATOR(pg_catalog.||) w.id
                                      OPERATOR(pg_catalog.||) $q$_truncate$q$);
            ELSE NULL;
        END CASE;
    END LOOP;
    IF busy OPERATOR(pg_catalog.<>) $q$$q$ THEN
        RAISE WARNING 'phasevec: these watched tables were being written during the update; each watch needs its '
                      'TRUNCATE trigger made, one statement each (a TRUNCATE of the table forgets nothing until then):%',
                      busy;
    END IF;
    IF taken OPERATOR(pg_catalog.<>) $q$$q$ THEN
        RAISE WARNING 'phasevec: these watched tables have a trigger with the name of the watch''s TRUNCATE trigger, '
                      'which is not phasevec''s:%', taken
            USING HINT = 'Drop or rename each one, then call phasevec.watch_truncate(<watch>).';
    END IF;
END
$tr$;

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
      -- (package review, RT29PA-DEAD-VERDICT) a dead claim is no claim of this row
      LEFT JOIN phasevec.truth t ON t.watch = w.id AND t.key = s.key AND NOT phasevec._claim_dead(t)
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
             -- (package review, RT29PA-DEAD-LEAK) a dead claim's topic, support and stamp are
             -- about a row that is gone, maybe another tenant's: no claim of this row
             FROM hits h CROSS JOIN w LEFT JOIN phasevec.truth t ON t.watch = w.id AND t.key = h.key
                                                                AND NOT phasevec._claim_dead(t)),
    vivas AS (SELECT t.topic, t.key, s.text_hash FROM phasevec.truth t CROSS JOIN w
                JOIN phasevec.sources s ON s.watch = t.watch AND s.key = t.key
               WHERE t.watch = w.id AND t.topic IN (SELECT th.tp FROM th WHERE th.tp IS NOT NULL)
                 AND (p_visible IS NULL OR t.key = ANY (p_visible))
                 AND NOT phasevec._claim_dead(t)
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
           AND NOT phasevec._claim_dead(t)
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
           AND NOT phasevec._claim_dead(t)
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
    phasevec._claim_state(phasevec.truth), phasevec._claim_state(timestamptz, text, boolean),
    phasevec._assert_set(text, text, text, text, jsonb, timestamptz, oid, bytea, text[], oid,
                         boolean, boolean),
    phasevec._claim_mine(phasevec.truth, int, text, oid, boolean, boolean, oid),
    phasevec._claim_take(phasevec.watches, text, text, oid, boolean, boolean, oid),
    phasevec._claim_privileged(int, oid, oid), phasevec._steward_of(int, oid, oid),
    phasevec._role_here(oid, name, uuid, bigint),
    phasevec._steward_set(text, oid, boolean, oid),
    phasevec.steward(text, regrole, boolean),
    phasevec._claim_refused(text, text, oid),
    phasevec._migrated(int, text),
    phasevec._refute_set(text, text, text, oid, boolean, boolean),
    phasevec._supersede_set(text, text, text, text, oid, boolean, boolean, boolean),
    phasevec._unsupersede_set(text, text, oid, boolean, boolean),
    phasevec._config_name(regconfig), phasevec._config_of(text), phasevec._lexemes(text, text),
    phasevec._config_find(text), phasevec._claim_how(phasevec.truth, int, text, oid, boolean,
                                                     boolean, oid),
    phasevec._claim_dead(phasevec.truth), phasevec._rebind_set(text, oid), phasevec.rebind(text),
    phasevec._truth_due(int, int, interval, oid), phasevec._truth_of(int, text),
    phasevec._truth_set(int, text, text, text, bytea, timestamptz, xid), phasevec._truth_halted(int, bytea, bytea, oid, xid),
    phasevec._truth_attempt(int, text), phasevec._truth_tried(int, text, text, boolean, bytea, xid),
    phasevec._note_set(int, text, bytea, text), phasevec._note_clear(int),
    phasevec.adopt(text, regrole, text[], text[]),
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
-- (twenty-first review) Read without waiting for a lock, as every step of a watch (phasevec._update_step).
-- (twenty-third review, RT23P-UPD-3) A watch whose rows its recipe does not render (an error of the recipe's own, or
-- of its rows': a write of such a row fails the same way under 0.19.0) stops the update, every such watch named with
-- its error: the claims retired below are bound to the text as this step notes it, and a watch left as 0.19.0 noted
-- it would bring them back, 'unproven', at the first write that renders its row in the pinned settings (RT21M-1).
DO $d$
DECLARE
    w   record;
    why text;
    bad text := $q$$q$;
BEGIN
    FOR w IN SELECT x.id, x.name, x.source FROM phasevec.watches x ORDER BY x.id LOOP
        why := phasevec._update_step(w.id, $q$render$q$);
        IF why IS NOT NULL THEN
            bad := bad OPERATOR(pg_catalog.||) pg_catalog.format(E'\n  watch %s (table %s): %s', w.name, w.source, why);
        END IF;
    END LOOP;
    IF bad OPERATOR(pg_catalog.<>) $q$$q$ THEN
        RAISE EXCEPTION 'phasevec: the update to 0.20.0 could not render the rows of these watches: nothing was '
                        'changed%', bad
            USING ERRCODE = 'object_not_in_prerequisite_state',
                  HINT = 'Each one''s recipe failed on its rows, as it renders them for the update (as the table''s '
                         'owner, in the pinned settings). Have the recipe, or the rows, fixed, or drop the watch '
                         '(phasevec.watches), then update.';
    END IF;
END
$d$;

-- (twenty-fifth review, RT25PU-1) What this update does to the claims 0.19.0 wrote, one watch at a
-- time, in one function: the update calls it for every watch (below), and phasevec.migrate() for
-- the watches a pg_dump of 0.19.0 brought in. It changes only rows that say 0.19.0 wrote them, and
-- says 0.20.0 of each when done; it runs after the watch's rows are noted as 0.20.0 renders them
-- (step 9 here; migrate() renders them first too). Returns how many claims it brought.
--  * Verdicts reached before 0.20.0 were reached with the verifier's rights and about no claim: a
--    'verified' is not carried over (back to unproven, with the reason in last_error). A 'refuted'
--    stays refuted, about the row's text as it is now. Their proofs have no author and do not run
--    until asserted again (phasevec.adopt).
--  * A 'refuted' from before 0.20.0 is about the row's text as it is now: as step 9 noted it, in
--    the pinned settings, the same text every reader renders. (twenty-first review, RT21M-1) Until
--    then these claims were bound, and retired, before step 9, to the text 0.19.0 had noted in its
--    writer's settings: with a recipe that prints a date, a time or a float on a server whose
--    TimeZone or DateStyle is not the pinned one, step 9 noted every row again, every retired claim
--    then read 'unproven', and brief() and truth_coverage() served what refute() had retired.
--  * (eighteenth review) A claim refute() refuted under 0.19.0 is retired, as refute() retires one
--    now: under 0.19.0 refute() left its proof, and after this update adopt() asserted it again and
--    the next verify() served it 'verified' (an application: every note deleted before the update came
--    back current). 0.19.0 recorded 'refuted' in two places, and their columns tell them apart:
--    refute() always gave a reason (last_error) and stamped verified_at and changed_at with one
--    now(); verify() recorded a proof's false with no reason, and its error (or NULL) at a
--    verified_at later than the assert that set changed_at. So a refuted claim with a reason judged
--    in the instant it last changed is retired, and so is one with no proof (refute() of a key
--    never asserted). The only claims this retires that refute() did not are those a proof refuted
--    by an error in the transaction that asserted it: the safe side (an assert() judges them
--    again). A replaced claim whose last verdict had a reason (0.19.0 kept last_error through
--    supersede(), and supersede() changed changed_at) cannot tell refute() from a proof's error: it
--    is retired too, and reads 'refuted' if it is ever unsuperseded. What the columns cannot show
--    is a claim refute() refuted and the next verify() then judged 'verified' under 0.19.0: that is
--    a verified claim now (back to 'unproven' above); the application that refuted it refutes it
--    again (in its own upgrade procedure).
--  * (twenty-sixth review, RT27-CYCLE-019) 0.19.0 took a supersede() that closed a cycle (9 -> 10,
--    then 10 -> 9), and every key on it read 'replaced' and left brief() for good; 0.20.0 refuses
--    one (supersede()), and until this review one 0.19.0 wrote survived the update and migrate().
--    Of each cycle the newest link (changed_at, then the greatest key), the one 0.20.0 would have
--    refused, is undone as unsupersede() undoes it (after the claims are retired: a retired one
--    comes back 'refuted'), with a WARNING that names it.
CREATE FUNCTION phasevec._migrate_claims(p_watch int) RETURNS bigint
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $f$
DECLARE n bigint;
        cyc record;
BEGIN
    UPDATE phasevec.truth t
       SET verdict = $q$unproven$q$, verified_at = NULL, changed_at = now(),
           last_error = $q$verified before 0.20.0, with the verifier's rights: not carried over$q$
     WHERE t.watch = p_watch AND t.data_version = $q$0.19.0$q$ AND t.verdict = $q$verified$q$;
    UPDATE phasevec.truth t SET asserted_for = s.text_hash
      FROM phasevec.sources s
     WHERE t.watch = p_watch AND t.data_version = $q$0.19.0$q$
       AND s.watch = t.watch AND s.key = t.key
       AND (t.verdict = $q$refuted$q$ OR (t.verdict = $q$replaced$q$ AND t.last_error IS NOT NULL));
    UPDATE phasevec.truth t
       SET proof = NULL, halted = false, retired_at = coalesce(t.verified_at, t.changed_at)
     WHERE t.watch = p_watch AND t.data_version = $q$0.19.0$q$
       AND ((t.verdict = $q$refuted$q$
             AND (t.proof IS NULL OR (t.last_error IS NOT NULL AND t.verified_at = t.changed_at)))
            OR (t.verdict = $q$replaced$q$ AND t.last_error IS NOT NULL));
    LOOP
        WITH RECURSIVE c(start, k) AS (
            SELECT t.key, t.replaced_by FROM phasevec.truth t
             WHERE t.watch = p_watch AND t.verdict = $q$replaced$q$ AND t.replaced_by IS NOT NULL
            UNION
            SELECT c.start, t.replaced_by
              FROM c JOIN phasevec.truth t ON t.watch = p_watch AND t.key = c.k
             WHERE t.verdict = $q$replaced$q$ AND t.replaced_by IS NOT NULL)
        SELECT t.key, t.replaced_by INTO cyc
          FROM phasevec.truth t
         WHERE t.watch = p_watch AND t.data_version = $q$0.19.0$q$
           AND t.key IN (SELECT c.start FROM c WHERE c.k = c.start)
         ORDER BY t.changed_at DESC, t.key DESC LIMIT 1;
        EXIT WHEN NOT FOUND;
        RAISE WARNING 'phasevec: in watch %, row % replaced by row % closed a cycle of '
                      'replacements under 0.19.0: undone, as unsupersede() would',
                      (SELECT w.name FROM phasevec.watches w WHERE w.id = p_watch), cyc.key,
                      cyc.replaced_by
            USING DETAIL = 'Every key on the cycle read ''replaced'' and none was served.';
        UPDATE phasevec.truth t
           SET replaced_by = NULL, reason = NULL,
               verdict = CASE phasevec._claim_state(t.retired_at, t.proof, t.halted)
                              WHEN $q$retired$q$ THEN $q$refuted$q$
                              WHEN $q$halted$q$ THEN $q$refuted$q$
                              ELSE $q$unproven$q$ END,
               verified_at = CASE phasevec._claim_state(t.retired_at, t.proof, t.halted)
                                  WHEN $q$retired$q$ THEN greatest(t.retired_at, t.verified_at)
                                  WHEN $q$halted$q$ THEN t.verified_at END,
               changed_at = now()
         WHERE t.watch = p_watch AND t.key = cyc.key;
    END LOOP;
    UPDATE phasevec.truth t SET data_version = $q$0.20.0$q$
     WHERE t.watch = p_watch AND t.data_version = $q$0.19.0$q$;
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END;
$f$;
REVOKE ALL ON FUNCTION phasevec._migrate_claims(int) FROM PUBLIC;
DO $d$
DECLARE
    w record;
BEGIN
    FOR w IN SELECT x.id FROM phasevec.watches x ORDER BY x.id LOOP
        PERFORM phasevec._migrate_claims(w.id);
    END LOOP;
END
$d$;
UPDATE phasevec.watches SET data_version = $q$0.20.0$q$;

-- (twenty-fifth review, RT25PU-1) After a pg_dump of a 0.19.0 database is restored where 0.20.0 is
-- installed, the extension's owner runs this once: every watch whose rows (or some of its claims)
-- 0.19.0 wrote is brought to 0.20.0, as the update brings it, and named with the claims it brought
-- and what became of its TRUNCATE trigger ('made', 'there', or 'taken': a trigger of the table's
-- owner has its name; phasevec.watch_truncate() says what to do). Every watch's table and key are
-- checked first (a watch 0.20.0 does not read stops it, every one named, nothing changed). Then, a
-- watch at a time: its table taken in SHARE ROW EXCLUSIVE mode (its writers wait, and it waits for
-- them, as long as lock_timeout lets it), its TRUNCATE trigger, every row noted again where 0.20.0
-- renders it otherwise (the rendering of step 9: as the table's owner, in the pinned settings),
-- then _migrate_claims(). Run it before the database takes writes again, at READ COMMITTED; with
-- nothing to bring it returns no row. Until it runs, what changes or judges a claim of such a watch
-- refuses (phasevec._migrated).
-- (twenty-sixth review, RT26PL-INFO-1) And a watch of 0.20.0 whose row trigger or TRUNCATE trigger
-- is gone (DROP EXTENSION ... CASCADE, CREATE EXTENSION, then a data-only restore of phasevec's
-- tables: every watch came back with no trigger on its table, and migrate() found nothing): its
-- triggers are made again, and its rows noted again, which a change the triggers never saw needs.
-- row_trigger: 'made' or 'there'.
CREATE FUNCTION phasevec.migrate()
RETURNS TABLE (watch text, claims bigint, truncate_trigger text, row_trigger text)
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $f$
DECLARE
    w   record;
    x   record;
    why text;
    bad text := $q$$q$;
BEGIN
    IF current_setting($q$transaction_isolation$q$) <> $q$read committed$q$ THEN
        RAISE EXCEPTION 'phasevec: migrate() runs only at READ COMMITTED'
            USING ERRCODE = 'feature_not_supported',
                  HINT = 'Call it outside the transaction, or in one at READ COMMITTED.';
    END IF;
    FOR w IN SELECT y.id, y.name, y.source, y.key_col FROM phasevec.watches y
              WHERE y.data_version <> $q$0.20.0$q$
                 OR EXISTS (SELECT 1 FROM phasevec.truth t
                             WHERE t.watch = y.id AND t.data_version <> $q$0.20.0$q$)
                 OR NOT EXISTS (SELECT 1 FROM pg_trigger g WHERE g.tgrelid = y.source
                                   AND g.tgname = $q$phasevec_watch_$q$ || y.id)
                 OR NOT EXISTS (SELECT 1 FROM pg_trigger g WHERE g.tgrelid = y.source
                                   AND g.tgname = $q$phasevec_watch_$q$ || y.id || $q$_truncate$q$)
              ORDER BY y.id LOOP
        why := phasevec._key_shape(w.source, w.key_col);
        IF why IS NOT NULL THEN
            bad := bad || format(E'\n  watch %s reads %s by %s: %s', w.name, w.source, w.key_col,
                                 why);
        END IF;
    END LOOP;
    IF bad <> $q$$q$ THEN
        RAISE EXCEPTION 'phasevec 0.20.0 does not read these watches: nothing was migrated%', bad
            USING ERRCODE = 'feature_not_supported',
                  HINT = 'Give each table a PRIMARY KEY or a UNIQUE constraint (not DEFERRABLE) on '
                         'its key column alone, and take it out of any inheritance tree, or drop '
                         'the watch (phasevec.watches), then call phasevec.migrate() again. '
                         'README, Supported configurations.';
    END IF;
    FOR w IN SELECT y.id, y.name, y.source, y.key_col, y.recipe FROM phasevec.watches y
              WHERE y.data_version <> $q$0.20.0$q$
                 OR EXISTS (SELECT 1 FROM phasevec.truth t
                             WHERE t.watch = y.id AND t.data_version <> $q$0.20.0$q$)
                 OR NOT EXISTS (SELECT 1 FROM pg_trigger g WHERE g.tgrelid = y.source
                                   AND g.tgname = $q$phasevec_watch_$q$ || y.id)
                 OR NOT EXISTS (SELECT 1 FROM pg_trigger g WHERE g.tgrelid = y.source
                                   AND g.tgname = $q$phasevec_watch_$q$ || y.id || $q$_truncate$q$)
              ORDER BY y.id LOOP
        EXECUTE format($q$LOCK TABLE %s IN SHARE ROW EXCLUSIVE MODE$q$, w.source);
        watch := w.name;
        truncate_trigger := phasevec._truncate_trigger(w.id, true);
        IF EXISTS (SELECT 1 FROM pg_trigger g WHERE g.tgrelid = w.source
                      AND g.tgname = $q$phasevec_watch_$q$ || w.id) THEN
            row_trigger := $q$there$q$;
        ELSE
            EXECUTE format('CREATE TRIGGER %I AFTER INSERT OR UPDATE OR DELETE ON %s '
                           'FOR EACH ROW EXECUTE FUNCTION phasevec._observe(%L, %L, %L)',
                           'phasevec_watch_' || w.id, w.source, w.id, w.key_col, w.recipe);
            row_trigger := $q$made$q$;
        END IF;
        FOR x IN SELECT r.key, r.body, r.text_hash FROM phasevec._render(w.name, NULL) r
                   JOIN phasevec.sources s ON s.watch = w.id AND s.key = r.key
                  WHERE s.text_hash IS DISTINCT FROM r.text_hash LOOP
            PERFORM phasevec._note_set(w.id, x.key, x.text_hash, x.body);
        END LOOP;
        claims := phasevec._migrate_claims(w.id);
        -- (twenty-eighth review, RV29-4) a 0.19.0 dump names a configuration and no owner: the
        -- one under that name now, as the update takes it
        UPDATE phasevec.watches y
           SET data_version = $q$0.20.0$q$,
               lexical_owner = coalesce(y.lexical_owner,
                                        (SELECT pg_get_userbyid(c.cfgowner) FROM pg_ts_config c
                                          WHERE c.oid = phasevec._config_find(y.lexical)
                                            AND c.cfgnamespace <> $q$pg_catalog$q$::regnamespace))
         WHERE y.id = w.id;
        RETURN NEXT;
    END LOOP;
END;
$f$;
REVOKE ALL ON FUNCTION phasevec.migrate() FROM PUBLIC;
COMMENT ON FUNCTION phasevec.migrate() IS
    'Brings to 0.20.0 what a pg_dump of a 0.19.0 database restored here brought in, as the update '
    'would have (0.20.0, twenty-fifth review): a refute()d claim retired, a ''verified'' one not '
    'carried over, the rows rendered again, each watch''s TRUNCATE trigger. One row per watch it '
    'brought. Run once after the restore, before the database takes writes. The owner''s. '
    '(twenty-sixth review) Also a watch whose row or TRUNCATE trigger is gone: they are made '
    'again, and rows that arrived by replication (they read as 0.19.0 wrote them) after '
    'cut-over.';

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

-- (package review, RT29PA-DEAD-VERDICT) Every search hides a key whose claim is replaced, refuted or
-- expired; a dead claim (phasevec._claim_dead: its row is gone, another is under its key) hid the
-- next row under that key, maybe another tenant's, from find(), find_ivf(), find_hybrid(),
-- find_npu(), alike(), search() and the recall measure, and _replacements() served a dead claim's
-- replacement in its place. Each such filter now skips a dead claim, as _verdict_of() does; nothing
-- else in these functions is touched. (src/phasevec_ivf.c, VALIDATE_TRUTH, does the same.)
DO $d$
DECLARE
    f   record;
    def text;
    n   int := 0;
    m   int;
BEGIN
    FOR f IN SELECT p.oid, pg_get_functiondef(p.oid) AS def FROM pg_proc p
              WHERE p.pronamespace = $q$phasevec$q$::regnamespace
                AND p.prosrc ~ $q$NOT EXISTS \(SELECT 1 FROM phasevec\.truth$q$
              ORDER BY p.oid LOOP
        m := (SELECT count(*) FROM regexp_matches(f.def,
                  $q$NOT EXISTS \(SELECT 1 FROM phasevec\.truth (\w+)\s+WHERE $q$, $q$g$q$));
        def := regexp_replace(f.def, $q$NOT EXISTS \(SELECT 1 FROM phasevec\.truth (\w+)\s+WHERE $q$,
                              $q$NOT EXISTS (SELECT 1 FROM phasevec.truth \1 WHERE NOT phasevec._claim_dead(\1) AND $q$,
                              $q$g$q$);
        IF def LIKE $q$%JOIN phasevec.truth tr ON tr.watch = w.id AND tr.verdict = 'replaced'%$q$ THEN
            def := replace(def, $q$JOIN phasevec.truth tr ON tr.watch = w.id AND tr.verdict = 'replaced'$q$,
                           $q$JOIN phasevec.truth tr ON tr.watch = w.id AND tr.verdict = 'replaced' AND NOT phasevec._claim_dead(tr)$q$);
            m := m + 1;
        END IF;
        EXECUTE def;
        n := n + m;
    END LOOP;
    IF n <> 11 THEN
        RAISE EXCEPTION $q$phasevec: % search filters of claims were made to skip a dead claim, 11 were expected$q$, n;
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

-- (package review, RT29PL-2) No foreign key between phasevec's own tables. pg_dump orders the data of
-- an extension's configuration tables by their foreign keys, but records that order only as the
-- order of the archive, not as a dependency of one table's data on another's: pg_restore -j N
-- loaded phasevec.truth, phasevec.sources and phasevec.readings in parallel with phasevec.watches,
-- their COPY failed on the extension's own foreign keys, and the restored database had its watches
-- and no claims (each key then read as a key with no claim, and its first writer claimed it). The
-- restore is now independent of the order in which pg_restore loads the tables. What the foreign
-- keys did is done here instead, at the only times it matters: a watch that is deleted (DROP TABLE
-- of its table, phasevec's sql_drop trigger) takes everything of it along (_watch_gone), and a
-- watch's or a reader's id is not changed or deleted while anything refers to it (_ids_kept). Every
-- row of these tables is written by phasevec's own functions, each of which finds its watch and
-- reader first, under the locks it takes on the watched table.
CREATE FUNCTION phasevec._watch_gone() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
BEGIN
    -- rows with triggers that count (readings, sources) first, then what those triggers count.
    -- Row by row, with no transition table: phasevec's guard walks every query it plans, and a
    -- transition table is not an object it can name.
    DELETE FROM phasevec.readings x WHERE x.watch = OLD.id;
    DELETE FROM phasevec.sources x WHERE x.watch = OLD.id;
    DELETE FROM phasevec.truth x WHERE x.watch = OLD.id;
    DELETE FROM phasevec.stewards x WHERE x.watch = OLD.id;
    DELETE FROM phasevec.usefulness x WHERE x.watch = OLD.id;
    DELETE FROM phasevec.recall_baseline x WHERE x.watch = OLD.id;
    DELETE FROM phasevec.audits x WHERE x.watch = OLD.id;
    DELETE FROM phasevec.lexstats x WHERE x.watch = OLD.id;
    DELETE FROM phasevec.lexdocs x WHERE x.watch = OLD.id;
    DELETE FROM phasevec.ivf_cents x WHERE x.watch = OLD.id;
    DELETE FROM phasevec.ivf_lists x WHERE x.watch = OLD.id;
    DELETE FROM phasevec.ivf_added x WHERE x.watch = OLD.id;
    DELETE FROM phasevec.npu_snaps x WHERE x.watch = OLD.id;
    DELETE FROM phasevec.attempts x WHERE x.watch = OLD.id;
    DELETE FROM phasevec.kstate x WHERE x.watch = OLD.id;
    DELETE FROM phasevec.counts x WHERE x.watch = OLD.id;
    DELETE FROM phasevec.count_deltas x WHERE x.watch = OLD.id;
    RETURN NULL;
END;
$f$;
CREATE FUNCTION phasevec._ids_kept() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.id IS DISTINCT FROM OLD.id THEN
            RAISE EXCEPTION 'phasevec: the id of a row of %.% is not changed', TG_TABLE_SCHEMA, TG_TABLE_NAME
                USING ERRCODE = 'foreign_key_violation';
        END IF;
        RETURN NEW;
    END IF;
    -- DELETE of a reader (a deleted watch takes its rows along: _watch_gone)
    IF EXISTS (SELECT 1 FROM phasevec.watches x WHERE x.reader = OLD.id)
       OR EXISTS (SELECT 1 FROM phasevec.readings x WHERE x.reader = OLD.id)
       OR EXISTS (SELECT 1 FROM phasevec.audits x WHERE x.reader = OLD.id) THEN
        RAISE EXCEPTION 'phasevec: reader % is named by a watch, a reading or an audit: it is not deleted', OLD.id
            USING ERRCODE = 'foreign_key_violation';
    END IF;
    RETURN OLD;
END;
$f$;
REVOKE ALL ON FUNCTION phasevec._watch_gone() FROM PUBLIC;
REVOKE ALL ON FUNCTION phasevec._ids_kept() FROM PUBLIC;
DO $d$
DECLARE
    c record;
    n int := 0;
BEGIN
    FOR c IN SELECT k.conrelid::regclass::text AS t, k.conname FROM pg_constraint k
              WHERE k.contype = 'f' AND k.connamespace = 'phasevec'::regnamespace
                AND k.confrelid IN ('phasevec.watches'::regclass, 'phasevec.readers'::regclass)
              ORDER BY k.conrelid, k.conname LOOP
        EXECUTE pg_catalog.format('ALTER TABLE %s DROP CONSTRAINT %I', c.t, c.conname);
        n := n + 1;
    END LOOP;
    IF n <> 20 THEN
        RAISE EXCEPTION 'phasevec: % foreign keys between phasevec''s tables were dropped, 20 were expected', n;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_constraint k WHERE k.contype = 'f' AND k.connamespace = 'phasevec'::regnamespace) THEN
        RAISE EXCEPTION 'phasevec: a foreign key between phasevec''s tables is left';
    END IF;
END
$d$;
CREATE TRIGGER phasevec_watch_gone AFTER DELETE ON phasevec.watches
    FOR EACH ROW EXECUTE FUNCTION phasevec._watch_gone();
CREATE TRIGGER phasevec_ids_kept BEFORE UPDATE OF id ON phasevec.watches
    FOR EACH ROW EXECUTE FUNCTION phasevec._ids_kept();
CREATE TRIGGER phasevec_ids_kept BEFORE UPDATE OF id OR DELETE ON phasevec.readers
    FOR EACH ROW EXECUTE FUNCTION phasevec._ids_kept();

-- (package review, RT29PL-2) What the triggers count (phasevec.kstate, phasevec.counts) is counted
-- once per COPY, after its rows, and not row by row. pg_restore loads phasevec.watches,
-- phasevec.sources and phasevec.readings with COPY, with -j N each in a transaction of its own: a
-- row counted while the rows of the other two tables were not committed yet was counted against
-- what that transaction saw (a reading with no row read 'orphan', a row with no reading 'pending'),
-- and the counts of a parallel restore drifted from a recount (coverage_check()). Now a COPY FROM
-- into one of the three counts nothing row by row; at its end it takes phasevec.kstate (so the
-- recounts of two such loads follow each other) and recounts every watch from what is committed
-- then, as _recount() does when a watch is made. The last load to end sees all the others'. A
-- COPY into these tables is the owner's (or a superuser's) only; phasevec writes them with INSERT.
CREATE FUNCTION phasevec._copying(p_rel oid) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $f$
    SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_stat_progress_copy c
                    WHERE c.pid OPERATOR(pg_catalog.=) pg_catalog.pg_backend_pid()
                      AND c.relid OPERATOR(pg_catalog.=) p_rel
                      AND c.command OPERATOR(pg_catalog.=) 'COPY FROM')
$f$;
CREATE OR REPLACE FUNCTION phasevec._counted() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
BEGIN
    IF TG_OP = 'INSERT' AND phasevec._copying(TG_RELID) THEN
        RETURN NULL;  -- counted at the end of the COPY (_copied)
    END IF;
    IF TG_OP IN ('UPDATE', 'DELETE') THEN
        PERFORM phasevec._refresh(OLD.watch, OLD.key);
    END IF;
    IF TG_OP = 'INSERT' OR (TG_OP = 'UPDATE' AND (NEW.watch, NEW.key) IS DISTINCT FROM (OLD.watch, OLD.key)) THEN
        PERFORM phasevec._refresh(NEW.watch, NEW.key);
    END IF;
    RETURN NULL;
END;
$f$;
CREATE OR REPLACE FUNCTION phasevec._watch_changed() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
BEGIN
    IF TG_OP = 'INSERT' AND phasevec._copying(TG_RELID) THEN
        RETURN NULL;  -- counted at the end of the COPY (_copied)
    END IF;
    PERFORM phasevec._recount(NEW.id);
    RETURN NULL;
END;
$f$;
CREATE FUNCTION phasevec._copied() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $f$
BEGIN
    IF NOT phasevec._copying(TG_RELID) THEN
        RETURN NULL;
    END IF;
    LOCK TABLE phasevec.kstate IN EXCLUSIVE MODE;
    -- a statement of its own, after the lock: its snapshot sees every load committed before it
    PERFORM phasevec._recount(w.id) FROM phasevec.watches w ORDER BY w.id;
    RETURN NULL;
END;
$f$;
REVOKE ALL ON FUNCTION phasevec._copying(oid) FROM PUBLIC;
REVOKE ALL ON FUNCTION phasevec._copied() FROM PUBLIC;
CREATE TRIGGER phasevec_copied AFTER INSERT ON phasevec.watches
    FOR EACH STATEMENT EXECUTE FUNCTION phasevec._copied();
CREATE TRIGGER phasevec_copied AFTER INSERT ON phasevec.sources
    FOR EACH STATEMENT EXECUTE FUNCTION phasevec._copied();
CREATE TRIGGER phasevec_copied AFTER INSERT ON phasevec.readings
    FOR EACH STATEMENT EXECUTE FUNCTION phasevec._copied();

-- (package review) phasevec._find_ivf_hide (0.14's find_ivf, renamed in 0.15.0) is SECURITY DEFINER
-- and was executable by PUBLIC: an administrator who revoked find_ivf() from PUBLIC, as this
-- page says to where keys are sensitive, left the same answer one name away. find_ivf() (the
-- owner's) calls it.
REVOKE ALL ON FUNCTION phasevec._find_ivf_hide(text, bigint, smallint[], int, boolean, int, bit, int)
    FROM PUBLIC;

-- (package review, RT29PU-1) The update's own helpers go, and only then do the caller's
-- lock_timeout and deadlock_timeout come back (the update's own from _update_lock, above): until
-- then they came back before these DROP FUNCTIONs, and a wait of an event trigger they fire (while
-- every phasevec table is still held) ran under the caller's settings, not the update's bound, so
-- a client could be the one the deadlock detector aborted.
DO $d$
DECLARE
    lt text := phasevec._update_lock_timeout();
    dt text := phasevec._update_deadlock_timeout();
BEGIN
    DROP FUNCTION phasevec._update_step(int, text);
    DROP FUNCTION phasevec._update_lock();
    DROP FUNCTION phasevec._update_take(text, oid, boolean);
    DROP FUNCTION phasevec._update_holders(text, oid);
    DROP FUNCTION phasevec._update_lock_routine(oid);
    DROP FUNCTION phasevec._update_lock_routine_now(oid);
    DROP FUNCTION phasevec._update_lock_table_now(oid);
    DROP FUNCTION phasevec._update_caller_holds();
    DROP FUNCTION phasevec._update_lock_timeout();
    DROP FUNCTION phasevec._update_deadlock_timeout();
    DROP FUNCTION phasevec._update_dependents();
    DROP FUNCTION phasevec._update_routine(oid);
    DROP FUNCTION phasevec._update_who(int, text);
    PERFORM pg_catalog.set_config('lock_timeout', lt, true);
    PERFORM pg_catalog.set_config('deadlock_timeout', dt, true);
END
$d$;
