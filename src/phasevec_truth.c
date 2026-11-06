/*
 * pg_phasevec 0.14.2: a proof with its own clock.
 *
 * statement_timeout is armed when a top-level statement starts, so a PL/pgSQL verify() could not cut one slow proof
 * among many. Here the proof runs inside an internal subtransaction (always rolled back), read-only, with a timer of
 * its own (a USER_TIMEOUT). Before running, the planner estimates the proof (EXPLAIN): one above max_cost is refuted
 * without running.
 *
 * 0.20.0: a verdict is about one claim, judged in one state, by one author, under one clock, and everything phasevec
 * runs that is not its own goes through one guard (phasevec_guard.c).
 *
 * - A watch's recipe is the table owner's SQL. It renders a row's text in one way only: as the table's owner, in the
 *   guard, with the pinned settings (DateStyle ISO, TimeZone UTC, ...). The watch trigger, assert(), verify(),
 *   brief(), next() and the rest all read the same text for the same row, whoever calls them from whatever session.
 *   Who may read that text is the reader's own right: SELECT on the table, and with row-level security, the rows the
 *   reader sees (found as the reader, in the guard too).
 * - A claim is (the row's text when its author asserted it, the proof, the author, the author's settings). The
 *   proof runs as its author, in the guard, with the settings its author had: a date literal means what it meant to
 *   the author, not to whoever verifies.
 * - (eighth review) A proof does not run in its verifier's session: it runs in a session of its own, a background
 *   worker connected as its author (see "the proof's own session" below). The verifier's uncommitted writes and DDL,
 *   its session_user, application_name, settings, placeholders, temporary objects and cursors are not there.
 * - verify() and verify_one() are C, so they know who calls them, and they are the only door to a verdict: the
 *   internals they use carry no rights of their own and only the owner may run them.
 * - One stable state: inside the proof's subtransaction the row is read before and after the proof (text hash and
 *   row version). The text must be the one asserted, and the version must not move while the proof runs.
 * - The clock bounds the verdict. A proof cannot run another proof. A query_canceled that a proof raises itself is
 *   that proof's error; a real cancel is thrown again.
 * - A proof that ends the session it runs in (a FATAL) is that claim's failure, not the watch's: the claim is recorded
 *   refuted and halted, is not run again until it is asserted again, and the call goes on with the next claim. (Until
 *   the eighth review that session was the verifier's: the claim was marked in shared memory, and the next verify()
 *   recorded it.) A session another process ends (ninth review) was interrupted: nothing is judged, the claim stays due.
 * - (ninth review) A verdict is committed by the session that judged it, before its answer: the verifier writes
 *   nothing, and a transaction that has written may not verify. The verifier never waits without its deadlines.
 * - The watch trigger is C: it renders the row it fires for, so no caller can note a text that is not the row's.
 * - Every surface that shows verdicts (recall, disputes, replacement, truth_coverage, brief) is a C door that knows
 *   its caller: it shows a watch only to a role that may SELECT its table, and with row-level security it computes
 *   over the rows that role sees (every field, not only the result rows).
 * - A verdict is judged at READ COMMITTED, in a new snapshot of what is committed, and records when its row was
 *   read. An ended session halts the claim it was judging only.
 */
#include "postgres.h"

#include <dlfcn.h>
#include <signal.h>
#include <string.h>

#include "access/htup_details.h"
#include "access/tupconvert.h"
#include "access/xact.h"
#include "access/xlog.h"
#include "catalog/partition.h"
#include "catalog/pg_authid.h"
#include "catalog/pg_class.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_type.h"
#include "common/cryptohash.h"
#include "common/sha2.h"
#include "commands/trigger.h"
#include "datatype/timestamp.h"
#include "executor/executor.h"
#include "executor/spi.h"
#include "fmgr.h"
#include "funcapi.h"
#include "miscadmin.h"
#include "nodes/parsenodes.h"
#include "nodes/plannodes.h"
#include "utils/plancache.h"
#include "mb/pg_wchar.h"
#include "nodes/makefuncs.h"
#include "parser/parse_func.h"
#include "parser/parser.h"
#include "pgstat.h"
#include "port/atomics.h"
#include "postmaster/bgworker.h"
#include "storage/dsm.h"
#include "storage/ipc.h"
#include "storage/latch.h"
#include "storage/lmgr.h"
#include "storage/proc.h"
#include "storage/shm_mq.h"
#include "tcop/tcopprot.h"
#include "utils/acl.h"
#include "utils/array.h"
#include "utils/datum.h"
#include "utils/fmgrprotos.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/rel.h"
#include "utils/resowner.h"
#include "utils/rls.h"
#include "utils/snapmgr.h"
#include "utils/syscache.h"
#include "utils/timeout.h"
#include "utils/timestamp.h"
#include "utils/tuplestore.h"
#include "utils/typcache.h"
#include "utils/wait_event.h"

#include "phasevec_guard.h"

PG_FUNCTION_INFO_V1(phasevec_prove);
PG_FUNCTION_INFO_V1(phasevec_assert);
PG_FUNCTION_INFO_V1(phasevec_verify);
PG_FUNCTION_INFO_V1(phasevec_verify_one);
PG_FUNCTION_INFO_V1(phasevec_observe);
PG_FUNCTION_INFO_V1(phasevec_render);
PG_FUNCTION_INFO_V1(phasevec_brief);
PG_FUNCTION_INFO_V1(phasevec_door);
PG_FUNCTION_INFO_V1(phasevec_verdict);
PG_FUNCTION_INFO_V1(phasevec_adopt);

static TimeoutId prove_timeout = MAX_TIMEOUTS;
static volatile sig_atomic_t prove_fired = false;
static volatile sig_atomic_t prove_fired_waiting = false;	/* our timer fired while the proof waited for a lock */
static bool prove_in_progress = false;

static void
prove_timeout_handler(void)
{
	prove_fired = true;
	prove_fired_waiting = MyProc != NULL && MyProc->waitLock != NULL;
	InterruptPending = true;
	QueryCancelPending = true;
	SetLatch(MyLatch);
}

/* The wrapped proof, prepared, must be one SELECT, or the cost step and the run would not see the same thing. */
static void
check_one_select(SPIPlanPtr plan)
{
	List	   *sources = SPI_plan_get_plan_sources(plan);
	Node	   *stmt;

	if (list_length(sources) != 1)
		ereport(ERROR,
				(errcode(ERRCODE_SYNTAX_ERROR),
				 errmsg("a proof is one boolean expression; this one makes %d statements", list_length(sources))));
	stmt = ((CachedPlanSource *) linitial(sources))->raw_parse_tree ?
		((CachedPlanSource *) linitial(sources))->raw_parse_tree->stmt : NULL;
	if (stmt == NULL || !IsA(stmt, SelectStmt) || ((SelectStmt *) stmt)->intoClause != NULL)
		ereport(ERROR,
				(errcode(ERRCODE_SYNTAX_ERROR),
				 errmsg("a proof is one boolean expression, read by a plain SELECT")));
}

/*
 * The planner's total cost of a prepared query's plan, or -1 when it cannot be read. The plan is the one the query
 * then runs with: it is planned once (until 0.20.0 an EXPLAIN planned it, then the run planned it again).
 */
static double
estimated_cost(SPIPlanPtr plan)
{
	CachedPlan *cplan = SPI_plan_get_cached_plan(plan);
	double		cost = -1;

	if (cplan == NULL)
		return -1;
	if (list_length(cplan->stmt_list) == 1 && IsA(linitial(cplan->stmt_list), PlannedStmt) &&
		((PlannedStmt *) linitial(cplan->stmt_list))->planTree != NULL)
		cost = ((PlannedStmt *) linitial(cplan->stmt_list))->planTree->total_cost;
	ReleaseCachedPlan(cplan, NULL);
	return cost;
}

/* ------------------------------------------------------------------------------------------- who acts -- */

/* The owner of the C function being called: the extension's owner, who alone may run the internals. */
static Oid
function_owner(FunctionCallInfo fcinfo)
{
	HeapTuple	pt = SearchSysCache1(PROCOID, ObjectIdGetDatum(fcinfo->flinfo->fn_oid));
	Oid			owner;

	if (!HeapTupleIsValid(pt))
		elog(ERROR, "phasevec: cache lookup failed for function %u", fcinfo->flinfo->fn_oid);
	owner = ((Form_pg_proc) GETSTRUCT(pt))->proowner;
	ReleaseSysCache(pt);
	return owner;
}

typedef struct Who
{
	Oid			userid;
	int			sec;
	int			nest;			/* the nest level of the owner's pinned settings */
} Who;

/*
 * Step into the extension's owner to run its own SQL, as PostgreSQL's RI triggers do; an error puts the caller back.
 *
 * (sixteenth review) With the owner's identity, the owner's settings: the pins (guard_own_enter), in a nest level that
 * unbecome() closes. Until this cut become() changed only the user id, and every statement phasevec ran as its owner
 * resolved its names through the search_path of whoever happened to be connected: in a proof's session (a session of
 * the claim's author) the author's ALTER ROLE ... SET search_path put the author's own '=' for bytea in front of
 * pg_catalog's, CLAIM_LOCK_SQL's IS DISTINCT FROM ran it as the owner (a superuser), and the author made itself a
 * superuser and wrote a 'verified' for a false proof. And a 'day' of a reader's TimeZone stretched the freshness
 * horizon (_verdict_of): 27 hours of a '1 day' max_age read 'verified'. Every statement prepared or run in here (the
 * kept plans too: PostgreSQL plans a kept statement again when the search_path it was planned in is not the current
 * one) reads the same names and computes the same values, whoever calls and from whatever session.
 */
static void
become(Oid role, Who *was)
{
	GetUserIdAndSecContext(&was->userid, &was->sec);
	was->nest = guard_own_enter();
	SetUserIdAndSecContext(role, was->sec | SECURITY_LOCAL_USERID_CHANGE);
}

static void
unbecome(const Who *was)
{
	SetUserIdAndSecContext(was->userid, was->sec);
	guard_own_leave(was->nest);
}

static void
spi_connect(void)
{
	if (SPI_connect() != SPI_OK_CONNECT)
		elog(ERROR, "phasevec: SPI_connect failed");
}

/* --------------------------------------------------------------------------------------- the watched table -- */

typedef struct Target
{
	int32		watch;
	Oid			relid;
	Oid			relowner;
	char	   *src;			/* schema-qualified, quoted */
	char	   *key_col;		/* quoted */
	char	   *recipe;
	char	   *read_sql;		/* one row by key: text hash, row version */
	SPIPlanPtr	read_plan;		/* read_sql prepared (verify), or NULL */
	SPIPlanPtr	record_plan;	/* phasevec._truth_set prepared (verify), or NULL */
	/* a key column whose text form is its input form: rows are found through its own equality (an index) too */
	bool		typed;
	Oid			keytype;
	Oid			keyarray;
	FmgrInfo	keyin;
	Oid			keyioparam;
	int16		keylen;
	bool		keybyval;
	char		keyalign;
} Target;

/*
 * The text of a watched row exactly as every reader of it reads it (the recipe over the row, as text, NULL as ''),
 * hashed as phasevec.sources hashes it, and the row version (xmin and ctid) it was read from.
 */
#define READ_SQL \
	"SELECT pg_catalog.sha256(pg_catalog.convert_to(COALESCE((%s)::pg_catalog.text, ''), 'UTF8')), " \
	"r.xmin::pg_catalog.text OPERATOR(pg_catalog.||) '/' OPERATOR(pg_catalog.||) r.ctid::pg_catalog.text " \
	"FROM %s r WHERE r.%s::pg_catalog.text OPERATOR(pg_catalog.=) $1%s LIMIT 1"
#define READ_TYPED " AND r.%s OPERATOR(pg_catalog.=) $2"

/* Rows by key (keys NULL: every row): key, text, text hash. */
#define RENDER_SQL \
	"SELECT x.k, x.b, pg_catalog.sha256(pg_catalog.convert_to(COALESCE(x.b, ''), 'UTF8')) " \
	"FROM (SELECT r.%s::pg_catalog.text AS k, (%s)::pg_catalog.text AS b FROM %s r%s) x"
#define RENDER_WHERE " WHERE r.%s::pg_catalog.text OPERATOR(pg_catalog.=) ANY ($1)%s"
#define RENDER_TYPED " AND r.%s OPERATOR(pg_catalog.=) ANY ($2)"

/* The keys of the rows a reader sees, among some (keys NULL: all). */
#define VISIBLE_SQL "SELECT r.%s::pg_catalog.text FROM %s r%s"

#define TARGET_SQL \
	"SELECT w.id, c.oid, c.relowner, pg_catalog.format('%%I.%%I', n.nspname, c.relname), " \
	"w.key_col::pg_catalog.text, w.recipe, (SELECT a.atttypid FROM pg_catalog.pg_attribute a " \
	"WHERE a.attrelid OPERATOR(pg_catalog.=) c.oid AND a.attname OPERATOR(pg_catalog.=) w.key_col) " \
	"FROM phasevec.watches w " \
	"JOIN pg_catalog.pg_class c ON c.oid OPERATOR(pg_catalog.=) w.source " \
	"JOIN pg_catalog.pg_namespace n ON n.oid OPERATOR(pg_catalog.=) c.relnamespace " \
	"WHERE %s OPERATOR(pg_catalog.=) $1"

/*
 * A statement phasevec runs on every call (and the watch trigger on every row) is parsed and planned once per session
 * and kept; PostgreSQL plans it again when what it reads changes. Prepared at its first use, in the state its every
 * use runs in.
 */
static SPIPlanPtr
kept_plan(SPIPlanPtr *slot, const char *sql, int nargs, Oid *types)
{
	if (*slot == NULL)
	{
		SPIPlanPtr	p = SPI_prepare(sql, nargs, types);

		if (p == NULL)
			elog(ERROR, "phasevec: could not prepare a statement: %s", SPI_result_code_string(SPI_result));
		if (SPI_keepplan(p) != 0)
			elog(ERROR, "phasevec: could not keep a statement");
		*slot = p;
	}
	return *slot;
}

static SPIPlanPtr target_plan[2] = {NULL, NULL};	/* TARGET_SQL by name, by id */

/*
 * The watch and how to read its rows, by name (text) or by id (int4). SPI connected, as the owner. False when there
 * is no such watch and `missing_ok`.
 */
static bool
load_target_ext(Datum id, bool by_id, Target *t, MemoryContext keep, bool missing_ok)
{
	Oid			at[1] = {by_id ? INT4OID : TEXTOID};
	Datum		av[1] = {id};
	HeapTuple	tup;
	TupleDesc	td;
	bool		isnull;
	MemoryContext o;

	if (SPI_execute_plan(kept_plan(&target_plan[by_id ? 1 : 0], psprintf(TARGET_SQL, by_id ? "w.id" : "w.name"), 1, at),
						 av, NULL, true, 1) != SPI_OK_SELECT)
		elog(ERROR, "phasevec: the watch could not be read");
	if (SPI_processed != 1)
	{
		if (missing_ok)
			return false;
		if (by_id)
			ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT), errmsg("phasevec: no watch %d", DatumGetInt32(id))));
		ereport(ERROR, (errcode(ERRCODE_UNDEFINED_OBJECT),
						errmsg("phasevec: no watch named %s", TextDatumGetCString(id))));
	}
	tup = SPI_tuptable->vals[0];
	td = SPI_tuptable->tupdesc;
	o = MemoryContextSwitchTo(keep);
	memset(t, 0, sizeof(Target));
	t->watch = DatumGetInt32(SPI_getbinval(tup, td, 1, &isnull));
	t->relid = DatumGetObjectId(SPI_getbinval(tup, td, 2, &isnull));
	t->relowner = DatumGetObjectId(SPI_getbinval(tup, td, 3, &isnull));
	t->src = pstrdup(SPI_getvalue(tup, td, 4));
	t->key_col = pstrdup(quote_identifier(SPI_getvalue(tup, td, 5)));
	t->recipe = pstrdup(SPI_getvalue(tup, td, 6));
	t->keytype = DatumGetObjectId(SPI_getbinval(tup, td, 7, &isnull));
	/* types whose text output reads back as the same value, whatever the session's settings */
	t->typed = !isnull && (t->keytype == INT2OID || t->keytype == INT4OID || t->keytype == INT8OID ||
						   t->keytype == OIDOID || t->keytype == NUMERICOID || t->keytype == UUIDOID);
	if (t->typed)
	{
		Oid			typinput;

		getTypeInputInfo(t->keytype, &typinput, &t->keyioparam);
		fmgr_info_cxt(typinput, &t->keyin, keep);
		get_typlenbyvalalign(t->keytype, &t->keylen, &t->keybyval, &t->keyalign);
		t->keyarray = get_array_type(t->keytype);
		t->typed = OidIsValid(t->keyarray);
	}
	t->read_sql = psprintf(READ_SQL, t->recipe, t->src, t->key_col,
						   t->typed ? psprintf(READ_TYPED, t->key_col) : "");
	MemoryContextSwitchTo(o);
	return true;
}

static void
load_target(Datum id, bool by_id, Target *t, MemoryContext keep)
{
	(void) load_target_ext(id, by_id, t, keep, false);
}

/* A key as a value of the key column's type; false when it is not one (then no row has it). */
static bool
key_value(const Target *t, const char *key, Datum *out)
{
	ErrorSaveContext escontext = {T_ErrorSaveContext};

	return InputFunctionCallSafe((FmgrInfo *) &t->keyin, (char *) key, t->keyioparam, -1,
								 (Node *) &escontext, out);
}

/* The keys that are values of the key column's type, as an array of it. */
static ArrayType *
key_values(const Target *t, ArrayType *keys)
{
	Datum	   *d;
	bool	   *nulls;
	int			n;
	int			m = 0;
	Datum	   *v;

	deconstruct_array_builtin(keys, TEXTOID, &d, &nulls, &n);
	v = palloc(sizeof(Datum) * Max(n, 1));
	for (int i = 0; i < n; i++)
		if (!nulls[i] && key_value(t, TextDatumGetCString(d[i]), &v[m]))
			m++;
	return construct_array(v, m, t->keytype, t->keylen, t->keybyval, t->keyalign);
}

/* " WHERE ..." for rows by keys (NULL: no WHERE), with its parameters ($1 text[], and $2 typed). */
static char *
keys_where(const Target *t, ArrayType *keys, Oid *at, Datum *av, int *nargs)
{
	*nargs = 0;
	if (keys == NULL)
		return "";
	at[0] = TEXTARRAYOID;
	av[0] = PointerGetDatum(keys);
	*nargs = 1;
	if (!t->typed)
		return psprintf(RENDER_WHERE, t->key_col, "");
	at[1] = t->keyarray;
	av[1] = PointerGetDatum(key_values(t, keys));
	*nargs = 2;
	return psprintf(RENDER_WHERE, t->key_col, psprintf(RENDER_TYPED, t->key_col));
}

/* load_target as the extension's owner, from outside SPI. */
static void
load_target_as(Oid owner, Datum id, bool by_id, Target *t, MemoryContext keep)
{
	Who			was;

	become(owner, &was);
	spi_connect();
	load_target(id, by_id, t, keep);
	SPI_finish();
	unbecome(&was);
}

/* May this role read the watched table? (SELECT on the table itself, as for any reader of it.) */
static bool
may_read(const Target *t, Oid role)
{
	return pg_class_aclcheck(t->relid, role, ACL_SELECT) == ACLCHECK_OK;
}

static void
must_read(const Target *t, Oid role)
{
	if (!may_read(t, role))
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("phasevec: role \"%s\" may not read %s, the table of this watch",
						GetUserNameFromId(role, false), t->src)));
}

/* Does row-level security filter what this role sees of the table? */
static bool
rls_for(const Target *t, Oid role)
{
	return check_enable_rls(t->relid, role, true) == RLS_ENABLED;
}

static ArrayType *
text_array(char **v, int n)
{
	Datum	   *d = palloc(sizeof(Datum) * Max(n, 1));

	for (int i = 0; i < n; i++)
		d[i] = CStringGetTextDatum(v[i]);
	return construct_array_builtin(d, n, TEXTOID);
}

/*
 * The keys, among some (NULL: all), of the rows a role sees: read as that role, in the guard. Used only when
 * row-level security filters what the role sees. SPI connected. Returns the number found; keys in *out.
 */
static int
visible_keys(const Target *t, Oid role, GuardMode mode, const GuardEnv *env, ArrayType *among, char ***out,
			 MemoryContext keep)
{
	Guard		g;
	MemoryContext cx = CurrentMemoryContext;
	volatile int mark = guard_mark();
	int			n = 0;
	Oid			at[2];
	Datum		av[2];
	int			nargs;
	char	   *sql = psprintf(VISIBLE_SQL, t->key_col, t->src, keys_where(t, among, at, av, &nargs));

	PG_TRY();
	{
		guard_enter(&g, role, mode, env);
		if (SPI_execute_with_args(sql, nargs, at, av, NULL, true, 0) != SPI_OK_SELECT)
			elog(ERROR, "phasevec: the rows could not be read");
		*out = MemoryContextAlloc(keep, sizeof(char *) * Max(SPI_processed, 1));
		for (uint64 i = 0; i < SPI_processed; i++)
		{
			char	   *k = SPI_getvalue(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 1);

			if (k)
				(*out)[n++] = MemoryContextStrdup(keep, k);
		}
		guard_leave(&g);
	}
	PG_CATCH();
	{
		ReThrowError(guard_catch(mark, cx));
	}
	PG_END_TRY();
	return n;
}

static bool
key_visible(const Target *t, Oid role, GuardMode mode, const GuardEnv *env, const char *key)
{
	char	   *one[1] = {(char *) key};
	char	  **seen;

	return visible_keys(t, role, mode, env, text_array(one, 1), &seen, CurrentMemoryContext) > 0;
}

/* key_visible from outside SPI */
static bool
key_visible_out(const Target *t, Oid role, const char *key)
{
	bool		v;

	spi_connect();
	v = key_visible(t, role, GUARD_READER, NULL, key);
	SPI_finish();
	return v;
}

typedef struct Rendered
{
	int			n;
	char	  **key;
	char	  **body;			/* NULL when the recipe gives NULL */
	bytea	  **hash;
} Rendered;

/* Rows by key (keys NULL: all), rendered by the recipe as the table's owner, in the guard. SPI connected. */
static void
render_rows(const Target *t, ArrayType *keys, Rendered *out, MemoryContext keep)
{
	Guard		g;
	MemoryContext cx = CurrentMemoryContext;
	volatile int mark = guard_mark();
	Oid			at[2];
	Datum		av[2];
	int			nargs;
	char	   *sql = psprintf(RENDER_SQL, t->key_col, t->recipe, t->src, keys_where(t, keys, at, av, &nargs));

	memset(out, 0, sizeof(Rendered));
	PG_TRY();
	{
		MemoryContext o;

		guard_enter(&g, t->relowner, GUARD_RENDER, NULL);
		if (SPI_execute_with_args(sql, nargs, at, av, NULL, true, 0) != SPI_OK_SELECT)
			elog(ERROR, "phasevec: the rows could not be read");
		o = MemoryContextSwitchTo(keep);
		out->key = palloc(sizeof(char *) * Max(SPI_processed, 1));
		out->body = palloc(sizeof(char *) * Max(SPI_processed, 1));
		out->hash = palloc(sizeof(bytea *) * Max(SPI_processed, 1));
		for (uint64 i = 0; i < SPI_processed; i++)
		{
			HeapTuple	tup = SPI_tuptable->vals[i];
			TupleDesc	td = SPI_tuptable->tupdesc;
			char	   *k = SPI_getvalue(tup, td, 1);
			char	   *b = SPI_getvalue(tup, td, 2);
			bool		isnull;
			Datum		h = SPI_getbinval(tup, td, 3, &isnull);

			if (k == NULL)
				continue;
			out->key[out->n] = pstrdup(k);
			out->body[out->n] = b ? pstrdup(b) : NULL;
			out->hash[out->n] = DatumGetByteaPCopy(h);
			out->n++;
		}
		MemoryContextSwitchTo(o);
		guard_leave(&g);
	}
	PG_CATCH();
	{
		ReThrowError(guard_catch(mark, cx));
	}
	PG_END_TRY();
}

/* The rows a reader may have rendered: all of keys (or of the table) unless row-level security hides some. */
static ArrayType *
keys_for_reader(const Target *t, Oid reader, ArrayType *keys)
{
	char	  **seen;
	int			n;

	if (!rls_for(t, reader))
		return keys;
	n = visible_keys(t, reader, GUARD_READER, NULL, keys, &seen, CurrentMemoryContext);
	return text_array(seen, n);
}

static bool
same_bytes(const bytea *a, const bytea *b)
{
	if (a == NULL || b == NULL)
		return false;
	return VARSIZE_ANY_EXHDR(a) == VARSIZE_ANY_EXHDR(b) &&
		memcmp(VARDATA_ANY(a), VARDATA_ANY(b), VARSIZE_ANY_EXHDR(a)) == 0;
}

typedef struct Seen
{
	bool		found;
	bytea	   *hash;
	char	   *version;
} Seen;

/* Read one row (text hash, version) as the table's owner, in the guard. SPI connected. */
static void
read_row(const Target *t, const char *key, Seen *s, MemoryContext keep)
{
	Guard		g;
	MemoryContext cx = CurrentMemoryContext;
	volatile int mark = guard_mark();
	Oid			at[2] = {TEXTOID, t->keytype};
	Datum		av[2] = {CStringGetTextDatum(key), (Datum) 0};

	memset(s, 0, sizeof(Seen));
	if (t->typed && !key_value(t, key, &av[1]))
		return;					/* not a value of the key's type: no row has it */
	PG_TRY();
	{
		int			rc;

		guard_enter(&g, t->relowner, GUARD_RENDER, NULL);
		/* not read_only: each read takes a new snapshot (READ COMMITTED), or a row that moved would not show */
		if (t->read_plan)
			rc = SPI_execute_plan(t->read_plan, av, NULL, false, 1);
		else
			rc = SPI_execute_with_args(t->read_sql, t->typed ? 2 : 1, at, av, NULL, false, 1);
		if (rc != SPI_OK_SELECT)
			elog(ERROR, "phasevec: the watched row could not be read");
		if (SPI_processed == 1)
		{
			bool		isnull;
			Datum		d = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &isnull);
			char	   *v = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 2);
			MemoryContext o = MemoryContextSwitchTo(keep);

			s->found = true;
			s->hash = isnull ? NULL : DatumGetByteaPCopy(d);
			s->version = v ? pstrdup(v) : NULL;
			MemoryContextSwitchTo(o);
		}
		guard_leave(&g);
	}
	PG_CATCH();
	{
		ReThrowError(guard_catch(mark, cx));
	}
	PG_END_TRY();
}

/* Prepare read_sql once for a whole verify(), as the table's owner with the pinned settings. SPI connected. */
static void
prepare_read(Target *t)
{
	Guard		g;
	MemoryContext cx = CurrentMemoryContext;
	volatile int mark = guard_mark();
	Oid			at[2] = {TEXTOID, t->keytype};

	PG_TRY();
	{
		guard_enter(&g, t->relowner, GUARD_RENDER, NULL);
		t->read_plan = SPI_prepare(t->read_sql, t->typed ? 2 : 1, at);
		if (t->read_plan == NULL)
			elog(ERROR, "phasevec: the watched rows cannot be read: %s", SPI_result_code_string(SPI_result));
		SPI_keepplan(t->read_plan);
		guard_leave(&g);
	}
	PG_CATCH();
	{
		ReThrowError(guard_catch(mark, cx));
	}
	PG_END_TRY();
}

/* A claim's key as phasevec._truth_halted names it (sha256), and a _bind: 32 bytes each. */
#define HASH_LEN 32

static void
key_hash(const char *key, uint8 *out)
{
	pg_cryptohash_ctx *ctx = pg_cryptohash_create(PG_SHA256);

	if (pg_cryptohash_init(ctx) < 0 || pg_cryptohash_update(ctx, (const uint8 *) key, strlen(key)) < 0 ||
		pg_cryptohash_final(ctx, out, HASH_LEN) < 0)
		elog(ERROR, "phasevec: could not hash a key: %s", pg_cryptohash_error(ctx));
	pg_cryptohash_free(ctx);
}

/* ------------------------------------------------------------------------------------------- the judge -- */

typedef enum Outcome
{
	OUT_VERIFIED,
	OUT_REFUTED,
	OUT_UNPROVEN,				/* nothing judged: the author gone, or kept from the row: recorded 'unproven' */
	OUT_STALE,					/* nothing judged: the row is gone, or does not say what was asserted */
	OUT_MOVED,					/* the row changed while the proof ran: nothing recorded */
	OUT_NOT_JUDGED,				/* no session of its own could judge it (no background worker free): nothing
								 * recorded, it stays due */
	OUT_HALTED,					/* the proof ended its own session while it ran: refuted, and not run again */
	OUT_INTERRUPTED,			/* another process ended the proof's session while it ran: nothing judged */
	OUT_NO_VERDICT				/* (eleventh review) nothing judged: an error that is not the proof's answer (a
								 * lock, a resource of the server, the server itself: not_a_verdict()), or a
								 * session of its author that could not judge it. The verdict stays as it was,
								 * and serves only until its horizon (phasevec._verdict) */
} Outcome;

static const char *const outcome_name[] = {"verified", "refuted", "unproven", "stale", NULL, NULL, NULL, NULL, NULL};

typedef struct Judgment
{
	Outcome		out;
	char	   *err;
	TimestampTz at;				/* when the row was read for it: the state it judged */
} Judgment;

typedef struct Claim
{
	char	   *key;
	char	   *proof;
	Oid			author;			/* InvalidOid: asserted before 0.20.0 */
	bool		author_known;	/* the OID is still a role, with the name it had */
	bytea	   *asserted_for;
	GuardEnv   *env;			/* the author's settings, as recorded */
	bytea	   *bind;			/* phasevec._bind of the claim */
} Claim;

/* A cancel raised by the server's interrupt handler (ours, the caller's statement_timeout, a user's cancel)? */
static bool
from_interrupts(const ErrorData *e)
{
	return e->funcname != NULL && strcmp(e->funcname, "ProcessInterrupts") == 0;
}

/*
 * (tenth review) A deadlock the server found while the proof waited for a lock: the proof was chosen to give way, which
 * is not its answer. Raised by the deadlock check itself (a proof that raises SQLSTATE 40P01 is refuted as any error).
 * Since every worker holds its claim's row while it judges, an assert() of that claim waits for it, and a proof that
 * waits for a lock that assert's transaction holds deadlocks with it.
 */
static bool
from_deadlock(const ErrorData *e)
{
	return e->sqlerrcode == ERRCODE_T_R_DEADLOCK_DETECTED && e->funcname != NULL &&
		strcmp(e->funcname, "DeadLockReport") == 0;
}

static bool
user_request(const ErrorData *e)
{
	return e->message_id != NULL && strcmp(e->message_id, "canceling statement due to user request") == 0;
}

/*
 * (eleventh review) Only the proof's own logic decides. An error is the proof's answer (refuted) when it comes from
 * what the proof computes: its data (22), its constraints (23), its SQL and its rights (42), what it raises (P0), a
 * feature it may not use (0A), a cardinality (21), a program limit it reaches (54: a recursion too deep, a statement
 * too complex: the same proof reaches it again), and every other class. It is not an answer, and nothing is judged,
 * when it comes from the server or from other sessions:
 *
 *   08  connection exception           53  insufficient resources (out of shared memory: the lock table another
 *   40  transaction rollback               session filled; out of memory, disk full, too many connections)
 *       (serialization, deadlock)      55P03  lock not available (a lock another session holds)
 *   57  operator intervention          58  system error (I/O)
 *       (shutdown, cancel, crash)      F0  configuration file error
 *   HV  foreign data wrapper error     XX  internal error (the server's, or phasevec's own)
 *
 * Until the eleventh review only a lock wait, a deadlock and a lock_timeout were not answers: a role with no grants
 * filled the shared lock table with session advisory locks, the proof failed 'out of shared memory', and a true claim
 * was recorded refuted. One of these classes raised by the proof's own code (a PL/pgSQL RAISE ... USING ERRCODE)
 * is the proof's answer: refuted. When nothing is judged the verdict stays as it was, and serves only until its
 * horizon (phasevec._verdict): an error the proof does not decide can keep a claim from being judged, never decide
 * or keep its verdict past that.
 */
static bool
not_a_verdict(const ErrorData *e)
{
	if (e->funcname != NULL && strcmp(e->funcname, "exec_stmt_raise") == 0)
		return false;
	if (e->sqlerrcode == ERRCODE_LOCK_NOT_AVAILABLE)
		return true;
	switch (ERRCODE_TO_CATEGORY(e->sqlerrcode))
	{
		case ERRCODE_CONNECTION_EXCEPTION:
		case ERRCODE_TRANSACTION_ROLLBACK:
		case ERRCODE_INSUFFICIENT_RESOURCES:
		case ERRCODE_OPERATOR_INTERVENTION:
		case ERRCODE_SYSTEM_ERROR:
		case ERRCODE_CONFIG_FILE_ERROR:
		case ERRCODE_FDW_ERROR:
		case ERRCODE_INTERNAL_ERROR:
			return true;
		default:
			return false;
	}
}

/*
 * A verdict is about the state it read. A proof is judged in its own session, at READ COMMITTED, each statement in a
 * new snapshot (until the third cut of 0.20.0 it read its verifier's first snapshot under REPEATABLE READ, and a
 * verdict about an old state was recorded as reached now). The verifier chooses, takes and records the claims in its
 * own transaction, which must see what the writers committed since it began: READ COMMITTED too.
 */
static void
require_fresh_snapshots(void)
{
	if (IsolationUsesXactSnapshot())
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("phasevec: proofs are judged at READ COMMITTED, each in a new snapshot"),
				 errdetail("verify() chooses, takes and records its claims in this transaction: under REPEATABLE READ or "
						   "SERIALIZABLE it would choose them from the transaction's first snapshot."),
				 errhint("Verify outside the transaction, or in one at READ COMMITTED.")));
}

static void
require_clock(int timeout_ms)
{
	if (timeout_ms <= 0)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("phasevec: a proof runs under a clock: p_timeout_ms must be above 0")));
}

/*
 * (ninth review) A proof that waits for a lock another session holds, when its clock ends: until then refuted for its
 * time, so a session that held a table the proof reads (or a DDL queued before it) refuted true claims.
 */
#define LOCK_WAIT_ERR \
	"not judged: the proof was still waiting for a lock another session holds when its clock of %d ms ended"

/*
 * (twelfth review) Only the proof's own work can refute it by time. A wait for a lock another session held that was
 * granted before the clock ended counted against the proof: it then ended after its clock and was recorded refuted.
 * A session of a role with no grants held an advisory key the proof takes, or a writer held its table, and let go at
 * 0.85 to 1.02 s of a 1 s clock. Now a proof that waited for a lock at all, and ended after its clock, is not judged.
 * The wait's time is not taken off the clock instead: PostgreSQL records when a wait began, not how long it lasted,
 * and a sampled measure misses short waits, so no exact share of the time is the proof's own. PostgreSQL arms
 * DEADLOCK_TIMEOUT for every wait for a heavyweight lock (ProcSleep: a relation, a row's transaction, an advisory
 * key), and the time it was armed stays after the wait ends (get_timeout_start_time): a wait that began after the
 * clock did is one the proof made. The cost: an author can keep its own slow proof from being refuted by making it
 * wait for a lock, as it could by holding one past the clock; it is not judged, and past its horizon it reads
 * 'unproven', never 'verified'.
 */
#define LOCK_WAITED_ERR \
	"not judged: the proof waited for a lock another session held, and ended after its clock of %d ms: not all of " \
	"its time was its own"

static bool
lock_waited_since(TimestampTz since)
{
	return since != 0 && get_timeout_start_time(DEADLOCK_TIMEOUT) >= since;
}

/*
 * Read a claim's row before its proof is judged, in a subtransaction always rolled back, in the guard as the table's
 * owner, under a clock of its own (timeout_ms): its text must be the one asserted, and an author that row-level
 * security keeps from the row (author_rls) must still see it. True when the proof may be judged (`first` is what was
 * read); otherwise `j` says why not.
 *
 * (fifteenth review) This is a step of its own, in a transaction of its own, before the one that judges. Until this
 * cut it was the first step of judge(), in the transaction whose start is the proof's now(): the recipe of the row
 * (a function it calls reads another table) waited there for a lock another session held, and the proof then read a
 * clock from before the wait and a snapshot from after it. A heartbeat written during the wait was in the future of
 * that now(), and a true claim was recorded 'refuted' (the fourteenth review closed the same skew for the wait for the
 * claim's row). Nothing phasevec reads now sits between the proof's now() and the proof; and a wait here is not on
 * the proof's clock: its time is the read's own.
 */
static bool
judge_row(const Target *target, const char *key, bool author_rls, Oid as_role, GuardMode mode, const GuardEnv *env,
		  const bytea *asserted_for, int timeout_ms, Seen *first, Judgment *j)
{
	MemoryContext oldcontext = CurrentMemoryContext;
	ResourceOwner oldowner = CurrentResourceOwner;
	volatile int mark = guard_mark();
	volatile Outcome out = OUT_NO_VERDICT;
	const char *volatile err = NULL;
	volatile bool ready = false;
	volatile TimestampTz started = 0;

	memset(first, 0, sizeof(Seen));
	if (prove_in_progress)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("phasevec: a proof cannot run another proof")));
	if (prove_timeout == MAX_TIMEOUTS)
		prove_timeout = RegisterTimeout(USER_TIMEOUT, prove_timeout_handler);
	prove_fired = false;
	prove_fired_waiting = false;
	prove_in_progress = true;
	BeginInternalSubTransaction(NULL);
	MemoryContextSwitchTo(oldcontext);
	PG_TRY();
	{
		spi_connect();
		started = GetCurrentTimestamp();
		if (timeout_ms > 0)
			enable_timeout_after(prove_timeout, timeout_ms);
		read_row(target, key, first, oldcontext);

		/*
		 * A row that is gone or says something else is stale, not judged: the verdict stays bound to the text it
		 * judged, and reads 'unproven' only while the row does not say it (_verdict). Until the sixth review
		 * verify() wrote 'unproven' over it, and a writer that edited a row and put it back erased a refutation
		 * until the claim was due again (p_every).
		 */
		if (!first->found)
		{
			out = OUT_STALE;
			err = "the row is gone: there is nothing to judge";
		}
		else if (author_rls && !key_visible(target, as_role, mode, env, key))
		{
			out = OUT_UNPROVEN;
			err = "its author cannot see the row: there is nothing to judge";
		}
		else if (!same_bytes(first->hash, asserted_for))
		{
			out = OUT_STALE;
			err = "the row does not say what was asserted (it changed, or it was not readable then): assert it again";
		}
		else
			ready = true;
		if (timeout_ms > 0)
			disable_timeout(prove_timeout, false);
		SPI_finish();
		if (prove_fired)
		{
			prove_fired = false;
			QueryCancelPending = false;
		}
		RollbackAndReleaseCurrentSubTransaction();
		MemoryContextSwitchTo(oldcontext);
		CurrentResourceOwner = oldowner;
		prove_in_progress = false;
	}
	PG_CATCH();
	{
		ErrorData  *edata;
		bool		ours = prove_fired;
		bool		late = timeout_ms > 0 && started != 0 &&
			TimestampDifferenceExceeds(started, GetCurrentTimestamp(), timeout_ms);

		if (timeout_ms > 0)
			disable_timeout(prove_timeout, false);
		prove_fired = false;
		edata = guard_catch(mark, oldcontext);
		RollbackAndReleaseCurrentSubTransaction();
		MemoryContextSwitchTo(oldcontext);
		CurrentResourceOwner = oldowner;
		prove_in_progress = false;
		/* a real cancel that is not our timer's cancels the caller */
		if (edata->sqlerrcode == ERRCODE_QUERY_CANCELED && from_interrupts(edata) && (!ours || !user_request(edata)))
			ReThrowError(edata);
		if (ours)
			QueryCancelPending = false;
		ready = false;
		out = OUT_NO_VERDICT;
		err = (ours || late) ? psprintf("not judged: the row took longer than %d ms to read", timeout_ms) :
			psprintf("not judged: the row could not be read (%s)", edata->message);
		FreeErrorData(edata);
	}
	PG_END_TRY();

	j->out = out;
	j->err = err ? pstrdup(err) : NULL;
	j->at = ready ? 0 : started;
	return ready;
}

/*
 * Judge one proof, in a subtransaction always rolled back, under its own clock and cost cap. The proof runs in the
 * guard as as_role (its author; for the SQL of 0.14.2 to 0.19.0, the caller) with the author's settings. With a
 * target, the row was read before (judge_row: `first`), and is read again after the proof, in the guard as the
 * table's owner: it must not have changed since.
 */
static void
judge(const char *proof, int timeout_ms, double max_cost, Oid as_role, GuardMode mode, const GuardEnv *env,
	  const Target *target, const char *key, const Seen *first, Judgment *j)
{
	MemoryContext oldcontext = CurrentMemoryContext;
	ResourceOwner oldowner = CurrentResourceOwner;
	StringInfoData sql;
	volatile int mark = guard_mark();
	volatile Outcome out = OUT_REFUTED;
	const char *volatile err = NULL;
	volatile int phase = 1;		/* 1 proving, 2 reading the row again */
	volatile TimestampTz started = 0;

	j->at = 0;
	if (prove_in_progress)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("phasevec: a proof cannot run another proof")));
	if (prove_timeout == MAX_TIMEOUTS)
		prove_timeout = RegisterTimeout(USER_TIMEOUT, prove_timeout_handler);

	initStringInfo(&sql);
	appendStringInfo(&sql, "SELECT (%s)::boolean", proof);

	prove_fired = false;
	prove_fired_waiting = false;
	prove_in_progress = true;
	BeginInternalSubTransaction(NULL);
	MemoryContextSwitchTo(oldcontext);
	PG_TRY();
	{
		Seen		last;
		Guard		g;

		spi_connect();
		started = GetCurrentTimestamp();
		if (timeout_ms > 0)
			enable_timeout_after(prove_timeout, timeout_ms);
		{
			double		cost = -1;
			SPIPlanPtr	plan;

			guard_enter(&g, as_role, mode, env);
			plan = SPI_prepare(sql.data, 0, NULL);
			if (plan == NULL)
				elog(ERROR, "the proof could not be prepared: %s", SPI_result_code_string(SPI_result));
			check_one_select(plan);
			if (max_cost > 0)
			{
				cost = estimated_cost(plan);
				if (cost < 0)
					elog(ERROR, "the proof's cost could not be estimated: not run");
			}
			if (max_cost > 0 && cost > max_cost)
			{
				out = OUT_REFUTED;
				err = MemoryContextStrdup(oldcontext,
										  psprintf("the proof is estimated at %.0f, above the limit of %.0f: not run",
												   cost, max_cost));
			}
			else
			{
				bool		isnull;
				Datum		d;

				if (SPI_execute_plan(plan, NULL, NULL, false, 1) != SPI_OK_SELECT || SPI_processed != 1)
					ereport(ERROR,
							(errcode(ERRCODE_CARDINALITY_VIOLATION),
							 errmsg("the proof must return one row")));
				d = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &isnull);
				out = (!isnull && DatumGetBool(d)) ? OUT_VERIFIED : OUT_REFUTED;
				if (isnull)
					err = "the proof returned NULL";
			}
			guard_leave(&g);
			phase = 2;
			if (target)
			{
				read_row(target, key, &last, oldcontext);
				if (!last.found || !same_bytes(last.hash, first->hash) || last.version == NULL ||
					first->version == NULL || strcmp(last.version, first->version) != 0)
				{
					out = OUT_MOVED;
					err = "the row changed while the proof ran: nothing recorded";
				}
			}
		}
		if (timeout_ms > 0)
			disable_timeout(prove_timeout, false);
		SPI_finish();

		/*
		 * The clock bounds the verdict: past it (a proof that swallowed our cancel, or one that ended as the timer
		 * fired) the answer does not count.
		 */
		if ((out == OUT_VERIFIED || out == OUT_REFUTED) && timeout_ms > 0 && prove_fired && prove_fired_waiting)
		{
			out = OUT_NO_VERDICT;
			err = MemoryContextStrdup(oldcontext, psprintf(LOCK_WAIT_ERR, timeout_ms));
		}
		else if ((out == OUT_VERIFIED || out == OUT_REFUTED) && timeout_ms > 0 &&
				 (prove_fired || TimestampDifferenceExceeds(started, GetCurrentTimestamp(), timeout_ms)))
		{
			/* (twelfth review) past its clock, after a wait for a lock: not all of that time was its own */
			out = lock_waited_since(started) ? OUT_NO_VERDICT : OUT_REFUTED;
			err = MemoryContextStrdup(oldcontext,
									  out == OUT_NO_VERDICT ? psprintf(LOCK_WAITED_ERR, timeout_ms) :
									  psprintf("the proof took longer than %d ms", timeout_ms));
		}
		if (prove_fired)
		{
			/* our cancel, still pending or swallowed: the caller must not be canceled by it */
			prove_fired = false;
			QueryCancelPending = false;
		}
		RollbackAndReleaseCurrentSubTransaction();
		MemoryContextSwitchTo(oldcontext);
		CurrentResourceOwner = oldowner;
		prove_in_progress = false;
	}
	PG_CATCH();
	{
		ErrorData  *edata;
		bool		ours = prove_fired;
		bool		waiting = prove_fired && prove_fired_waiting;
		bool		late = timeout_ms > 0 && started != 0 &&
			TimestampDifferenceExceeds(started, GetCurrentTimestamp(), timeout_ms);
		bool		waited = lock_waited_since(started);

		if (timeout_ms > 0)
			disable_timeout(prove_timeout, false);
		prove_fired = false;
		edata = guard_catch(mark, oldcontext);
		RollbackAndReleaseCurrentSubTransaction();
		MemoryContextSwitchTo(oldcontext);
		CurrentResourceOwner = oldowner;
		prove_in_progress = false;

		/*
		 * A real cancel that is not our timer's (the caller's statement_timeout, a user's cancel) cancels the caller.
		 * A query_canceled the proof raised itself is the proof's own error, like any other.
		 */
		if (edata->sqlerrcode == ERRCODE_QUERY_CANCELED && from_interrupts(edata) && (!ours || !user_request(edata)))
			ReThrowError(edata);
		if (ours)
			QueryCancelPending = false;
		/*
		 * An error reading the row judged nothing; one in the proof refutes it only when it is the proof's own
		 * (not_a_verdict); one reading it again records nothing.
		 */
		out = phase == 1 ? OUT_REFUTED : OUT_MOVED;
		if ((waiting || from_deadlock(edata) ||
						   (edata->sqlerrcode == ERRCODE_LOCK_NOT_AVAILABLE && from_interrupts(edata))))
		{
			/* (ninth review) a lock another session holds: not the proof's answer, and no verdict */
			out = OUT_NO_VERDICT;
			err = waiting ? psprintf(LOCK_WAIT_ERR, timeout_ms) :
				from_deadlock(edata) ? psprintf("not judged: the proof waited for a lock in a deadlock, and gave way (%s)",
												edata->message) :
				psprintf("not judged: the proof waited for a lock longer than its session's lock_timeout (%s)",
						 edata->message);
		}
		else if ((ours || late) && waited)
		{
			/* (twelfth review) its clock ended after it waited for a lock: not all of that time was its own */
			out = OUT_NO_VERDICT;
			err = psprintf(LOCK_WAITED_ERR, timeout_ms);
		}
		else if (ours)
		{
			out = OUT_REFUTED;
			err = psprintf("the proof took longer than %d ms", timeout_ms);
		}
		else if (phase == 1 && not_a_verdict(edata))
		{
			/* (eleventh review) the server's error, or another session's doing: not the proof's answer */
			out = OUT_NO_VERDICT;
			err = psprintf("not judged: the proof failed for a reason that is not its own (SQLSTATE %s: %s)",
						   unpack_sql_state(edata->sqlerrcode), edata->message);
		}
		else if (late)
		{
			out = OUT_REFUTED;
			err = psprintf("the proof took longer than %d ms", timeout_ms);
		}
		else
			err = pstrdup(edata->message);
		FreeErrorData(edata);
	}
	PG_END_TRY();

	j->out = out;
	j->err = err ? pstrdup(err) : NULL;
	j->at = started;
}

/* phasevec._prove_c(proof text, timeout_ms int, max_cost float8, OUT ok boolean, OUT err text): the SQL of 0.14.2 to
 * 0.19.0 runs proofs through this, as the caller, with the clock above. */
Datum
phasevec_prove(PG_FUNCTION_ARGS)
{
	TupleDesc	tupdesc;
	Datum		values[2];
	bool		nulls[2] = {false, false};
	Judgment	j;

	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		elog(ERROR, "phasevec_prove: the result must be a row type");
	tupdesc = BlessTupleDesc(tupdesc);
	/* no setting pinned: the SQL of 0.14.2 to 0.19.0 ran proofs in the caller's settings */
	judge(text_to_cstring(PG_GETARG_TEXT_PP(0)), PG_GETARG_INT32(1), PG_GETARG_FLOAT8(2), GetUserId(), GUARD_ASIS,
		  NULL, NULL, NULL, NULL, &j);
	values[0] = BoolGetDatum(j.out == OUT_VERIFIED);
	if (j.err)
		values[1] = CStringGetTextDatum(j.err);
	else
		nulls[1] = true;
	PG_RETURN_DATUM(HeapTupleGetDatum(heap_form_tuple(tupdesc, values, nulls)));
}

/* -------------------------------------------------------------------------------- the proof's own session -- */

/*
 * A proof does not run in its verifier's session (0.20.0, eighth review). Each review until then found one more piece
 * of that session that decided verdicts: its temporary objects, its settings' values, which custom placeholders it
 * had, its uncommitted writes and DDL, its session_user, its application_name. Each was closed in place, and the next
 * one was open. Now verify() and verify_one() judge in a session of the proof's own: a background worker connected to
 * the database as the claim's author (BackgroundWorkerInitializeConnectionByOid, as a new session of the author
 * would: its session_user is the author, it has what postgresql.conf, ALTER SYSTEM and ALTER DATABASE/ROLE ... SET
 * give every new session of the author, its session_preload_libraries), with what its author's session had changed
 * on top (the claim's recorded settings, GUARD_AUTHOR). It reads only what is committed, each claim in a transaction
 * of its own at READ COMMITTED; it has no temporary object, no cursor, no prepared statement, nothing of the caller's.
 *
 * (ninth review) A verdict is a statement about a committed state that does not depend on its verifier's transaction:
 *
 * - The worker takes the claim's row, judges it and records the verdict in its own transaction, and commits it before
 *   it answers. Until the ninth review the verifier took and recorded the claims in its own transaction, and a verifier
 *   with an uncommitted write that refuted a claim committed, together with that write, a 'verified' the proof had
 *   reached on the state before it: no committed state ever made it true. The verifier writes nothing now (its
 *   transaction gets no transaction id from verify()), a ROLLBACK of it keeps the verdicts its proofs reached, and a
 *   transaction that has written (or holds DDL, or LOCK TABLE ... ACCESS EXCLUSIVE: they assign a transaction id) may
 *   not verify (require_no_writes): what it wrote would be judged as if absent.
 * - The verifier never blocks without its deadlines. A claim is sent without waiting (shm_mq_send nowait), in the
 *   loop that keeps the proof's clock and 5 s more, the start of a worker, p_budget and the lock checks; a claim larger
 *   than the queue goes in pieces, in the same loop. Until the ninth review a claim over 64 kB blocked the verifier
 *   inside shm_mq_send: behind a proof that catches query_canceled, or a worker waiting for a lock the verifier held,
 *   nothing ended it.
 * - A lock: a proof that waits for one the verifier holds, directly or through other sessions (an ALTER TABLE queued
 *   behind the verifier's read, which the proof queues behind in turn), would wait as long as the verifier waits for
 *   it: the verifier walks the waits (pg_blocking_pids, transitively) and stops with an error. Until the ninth review
 *   it saw only a direct wait: the proof waited for its clock, was recorded refuted, and the ALTER and every reader of
 *   the table waited n times the clock. A proof that waits for a lock of another session past its clock (or past its
 *   author's lock_timeout) is not judged, with the reason: a lock wait is not the proof's answer (until the eleventh
 *   review it was recorded 'unproven'; now the verdict stays, until its horizon).
 * - A session that ends while its proof runs is the proof's failure only when the proof ended it. The worker records
 *   who sent it SIGTERM (the kernel's si_pid: a sender cannot choose it). Ended by its own process (a FATAL the proof
 *   raised, its author's transaction_timeout) the claim is refuted and halted (phasevec._truth_halted) as before. Ended
 *   by another process (a role with pg_signal_backend, the author, the verifier from another session, a shutdown) it
 *   was interrupted: nothing is judged, the verdict stays (until its horizon), and the claim stays due, its turn
 *   spent (phasevec._truth_tried). Until the ninth review any ended session halted the claim: a role that may
 *   terminate a backend made a true claim refuted for good. A signaller can keep a claim from being judged, never
 *   decide its verdict.
 *
 * - One worker for a verify() call and an author, for as many of its claims as it may judge: a placeholder made in it
 *   stays (a proof's set_config, a recorded state that names one, a recipe that sets one), and a claim whose author
 *   did not have it is not judged there: that worker ends and the claim goes to a new one (guard_env_spent). The
 *   claims of one author are sent in the order that needs the fewest: those that name fewer placeholders first.
 * - What a verifier records without a proof (an author gone, or kept from the table; a halted, interrupted or late
 *   claim) is recorded by a worker too, in its own transaction: the current one, or a session of the owner.
 * - No worker free (max_worker_processes): the claim is not judged, nothing is recorded, it stays due, and the row
 *   verify() returns for it says so.
 *
 * (eleventh review) Three rules, for whatever stops judgment from moving:
 * - Safety does not depend on liveness: a verdict serves only while it is fresh, judged within its watch's max_age
 *   (phasevec._verdict); past it, it reads 'unproven', whatever kept it from being judged again (a row held by an
 *   open assert(), a lock, the server, no worker free, a verifier that does not run).
 * - The due queue is a fair rotation: a worker spends a claim's turn as it gets it, in a transaction of its own
 *   (record_attempt, phasevec.attempts), and verify() takes the oldest turns first (phasevec._truth_due).
 * - Only the proof's own logic decides its verdict: an error the server or another session causes is not an answer
 *   (not_a_verdict); nothing is judged, and the verdict stays until its horizon.
 *
 * (twelfth review) A turn is spent by a session its author cannot end. In the eleventh cut the author's own session
 * (the worker, connected as the author) spent it, as it got the claim: an author that terminated its own workers
 * before they did (pg_terminate_backend works on a role's own sessions) kept its claims unspent at the head of the
 * queue, and no other author's claim was tried again. Now the turns of a verify() call's claims are spent by a session
 * of the extension's owner, the keeper (one for the call, started when a claim first needs it), in a transaction of its
 * own committed before the claims are sent to their author's session; a claim that goes to a session of the owner
 * (a record of what the verifier found, a claim the owner asserted) is spent by that session. Whatever the author's
 * session then does, the claim's turn is spent. A role that may end the owner's sessions (a superuser; with
 * pg_signal_backend, when the owner is not one) can stop a call, and nothing more: nothing is judged or recorded, the
 * claims keep their turns, and the verdicts serve until their horizon. verify_one() names its claim, and its session
 * spends the turn itself: ending it leaves that claim's turn where it was, and no other claim waits behind it.
 */
#define PROOF_MAGIC		0x50565046
#define PROOF_PROTOCOL	4
#define PROOF_QUEUE		(64 * 1024)
#define PROOF_GRACE_MS	5000
#define PROOF_AHEAD		8		/* claims queued ahead of their answers, and no more than PROOF_QUEUE / 2 bytes */
#define PROOF_ERR_MAX	4000	/* an answer's error text: PROOF_AHEAD of them fit in PROOF_QUEUE */
#define PROOF_LOOK_MS	200		/* how often the verifier walks the lock waits */
#define PROOF_WAITS_MAX 64		/* sessions it walks through at most */

typedef struct ProofShared
{
	uint32		magic;
	uint32		protocol;
	Oid			db;
	Oid			author;			/* the role this session is of */
	Oid			owner;			/* the extension's owner: reads and writes phasevec's own tables */
	int32		watch;
	pg_atomic_uint32 judging;	/* 1 while the worker judges a claim */
	TimestampTz started;		/* when it began to (written before judging is set) */
	volatile int32 pid;			/* the worker's process */
	volatile int32 signaller;	/* the process that sent it SIGTERM first: 0 none, -1 unknown */
} ProofShared;

#define PROOF_REQ_OFF	MAXALIGN(sizeof(ProofShared))
#define PROOF_ANS_OFF	(PROOF_REQ_OFF + PROOF_QUEUE)
#define PROOF_SIZE		(PROOF_ANS_OFF + PROOF_QUEUE)

typedef enum ProofKind
{
	MSG_JUDGE = 1,				/* take the claim (verify()), judge it, record the verdict */
	MSG_RECORD = 2,				/* take the claim (verify()), record what the verifier found (no proof runs) */
	MSG_ATTEMPT = 3				/* (the keeper) spend the turns of these claims, in one transaction */
} ProofKind;

typedef enum ProofAnswer
{
	ANSWER_DONE,				/* judged and recorded, or recorded */
	ANSWER_SKIPPED,				/* not taken: another verify() holds it, or it is not due any more */
	ANSWER_SPENT,				/* this session may not judge it: a new one will */
	ANSWER_FAILED				/* an error outside the proof: nothing judged, nothing recorded */
} ProofAnswer;

typedef struct ProofSession
{
	Oid			author;
	dsm_segment *seg;
	ProofShared *sh;
	BackgroundWorkerHandle *handle;
	shm_mq_handle *req;
	shm_mq_handle *ans;
	bool		ended;			/* TerminateBackgroundWorker() was called for it */
} ProofSession;

typedef struct Msg
{
	const char *p;
	const char *end;
} Msg;

static void
put_int(StringInfo b, int64 v)
{
	appendBinaryStringInfo(b, (const char *) &v, sizeof(v));
}

static void
put_bytes(StringInfo b, const char *s, int64 len)
{
	put_int(b, s ? len : -1);
	if (s)
		appendBinaryStringInfo(b, s, len);
}

static void
put_str(StringInfo b, const char *s)
{
	put_bytes(b, s, s ? strlen(s) : 0);
}

static int64
get_int(Msg *m)
{
	int64		v;

	if (m->end - m->p < (ptrdiff_t) sizeof(v))
		elog(ERROR, "phasevec: a malformed message between a verifier and a proof's session");
	memcpy(&v, m->p, sizeof(v));
	m->p += sizeof(v);
	return v;
}

static char *
get_bytes(Msg *m, int64 *len)
{
	int64		n = get_int(m);
	char	   *s;

	if (n < 0)
		return NULL;
	if (m->end - m->p < n)
		elog(ERROR, "phasevec: a malformed message between a verifier and a proof's session");
	s = palloc(n + 1);
	memcpy(s, m->p, n);
	s[n] = '\0';
	m->p += n;
	if (len)
		*len = n;
	return s;
}

static bytea *
get_bytea(Msg *m)
{
	int64		n;
	char	   *s = get_bytes(m, &n);
	bytea	   *v;

	if (s == NULL)
		return NULL;
	v = palloc(VARHDRSZ + n);
	SET_VARSIZE(v, VARHDRSZ + n);
	memcpy(VARDATA(v), s, n);
	return v;
}

/* ------------------------------------------------------------------------------------------- the claims -- */

#define CLAIM_COLUMNS "key, proof, author, author_known, asserted_for, env, bind"

static void
claim_from(HeapTuple tup, TupleDesc td, Claim *c, MemoryContext keep)
{
	bool		isnull;
	Datum		d;
	MemoryContext o = MemoryContextSwitchTo(keep);

	memset(c, 0, sizeof(Claim));
	c->key = TextDatumGetCString(SPI_getbinval(tup, td, 1, &isnull));
	d = SPI_getbinval(tup, td, 2, &isnull);
	c->proof = isnull ? NULL : TextDatumGetCString(d);
	d = SPI_getbinval(tup, td, 3, &isnull);
	c->author = isnull ? InvalidOid : DatumGetObjectId(d);
	d = SPI_getbinval(tup, td, 4, &isnull);
	c->author_known = !isnull && DatumGetBool(d);
	d = SPI_getbinval(tup, td, 5, &isnull);
	c->asserted_for = isnull ? NULL : DatumGetByteaPCopy(d);
	d = SPI_getbinval(tup, td, 6, &isnull);
	c->env = guard_env_from(isnull ? NULL : DatumGetArrayTypeP(d));
	d = SPI_getbinval(tup, td, 7, &isnull);
	c->bind = isnull ? NULL : DatumGetByteaPCopy(d);
	MemoryContextSwitchTo(o);
}

/*
 * A claim as the worker gets it: what to do with it, how, and (MSG_RECORD) what to record. `every` (verify()): the
 * claim is taken by the rule of phasevec._truth_due; NULL (verify_one()): it is not taken.
 */
static void
claim_message(StringInfo b, ProofKind kind, const Claim *c, const Interval *every, Oid verifier, bool rls,
			  int timeout_ms, double max_cost, const Judgment *rec)
{
	int64		bits;

	initStringInfo(b);
	put_int(b, kind);
	put_bytes(b, (const char *) every, sizeof(Interval));
	put_int(b, verifier);
	put_int(b, timeout_ms);
	memcpy(&bits, &max_cost, sizeof(bits));
	put_int(b, bits);
	put_int(b, rls ? 1 : 0);
	put_str(b, c->key);
	put_str(b, c->proof);
	put_bytes(b, c->asserted_for ? VARDATA_ANY(c->asserted_for) : NULL,
			  c->asserted_for ? VARSIZE_ANY_EXHDR(c->asserted_for) : 0);
	put_bytes(b, c->bind ? VARDATA_ANY(c->bind) : NULL, c->bind ? VARSIZE_ANY_EXHDR(c->bind) : 0);
	put_int(b, c->env ? c->env->n : 0);
	for (int i = 0; c->env && i < c->env->n; i++)
	{
		put_str(b, c->env->name[i]);
		put_str(b, c->env->value[i]);
	}
	put_int(b, rec ? rec->out : OUT_NOT_JUDGED);
	put_int(b, rec ? rec->at : 0);
	put_str(b, rec ? rec->err : NULL);
}

#define RECORD_SQL "SELECT phasevec._truth_set($1, $2, $3, $4, $5, $6)"

/* Record a judgment through phasevec._truth_set, as the owner; the verdict as it reads now. */
static char *
record(Oid owner, const Target *t, const Claim *c, const Judgment *j)
{
	Oid			at[6] = {INT4OID, TEXTOID, TEXTOID, TEXTOID, BYTEAOID, TIMESTAMPTZOID};
	Datum		av[6];
	char		nulls[7] = "      ";
	const char *name = outcome_name[j->out];
	MemoryContext keep = CurrentMemoryContext;
	char	   *v = NULL;
	Who			was;

	av[0] = Int32GetDatum(t->watch);
	av[1] = CStringGetTextDatum(c->key);
	av[2] = name ? CStringGetTextDatum(name) : (Datum) 0;
	nulls[2] = name ? ' ' : 'n';
	av[3] = j->err ? CStringGetTextDatum(j->err) : (Datum) 0;
	nulls[3] = j->err ? ' ' : 'n';
	av[4] = c->bind ? PointerGetDatum(c->bind) : (Datum) 0;
	nulls[4] = c->bind ? ' ' : 'n';
	av[5] = TimestampTzGetDatum(j->at);
	nulls[5] = j->at != 0 ? ' ' : 'n';

	become(owner, &was);
	spi_connect();
	if ((t->record_plan ? SPI_execute_plan(t->record_plan, av, nulls, false, 1)
		 : SPI_execute_with_args(RECORD_SQL, 6, at, av, nulls, false, 1)) != SPI_OK_SELECT)
		elog(ERROR, "phasevec: the verdict was not recorded");
	if (SPI_processed == 1)
	{
		char	   *s = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1);

		if (s)
			v = MemoryContextStrdup(keep, s);
	}
	SPI_finish();
	unbecome(&was);
	return v;
}

/* A claim whose proof ended the session that ran it: refuted and halted (phasevec._truth_halted), as the owner. */
static bytea *
bytes32(const uint8 *b)
{
	bytea	   *v = (bytea *) palloc(VARHDRSZ + HASH_LEN);

	SET_VARSIZE(v, VARHDRSZ + HASH_LEN);
	memcpy(VARDATA(v), b, HASH_LEN);
	return v;
}

#define VERDICT_SQL \
	"SELECT phasevec._verdict_of(t) FROM phasevec.truth t WHERE t.watch OPERATOR(pg_catalog.=) $1 " \
	"AND t.key OPERATOR(pg_catalog.=) $2"

/* The verdict of a key as it reads now (after this transaction's own writes). SPI connected, as the owner. */
static char *
verdict_now(const Target *t, const char *key, MemoryContext keep)
{
	Oid			at[2] = {INT4OID, TEXTOID};
	Datum		av[2] = {Int32GetDatum(t->watch), CStringGetTextDatum(key)};

	if (SPI_execute_with_args(VERDICT_SQL, 2, at, av, NULL, false, 1) != SPI_OK_SELECT)
		elog(ERROR, "phasevec: the verdict could not be read");
	if (SPI_processed == 1)
	{
		char	   *s = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1);

		if (s)
			return MemoryContextStrdup(keep, s);
	}
	return NULL;
}

static char *
record_halted(Oid owner, Oid verifier, const Target *t, const Claim *c, const Judgment *j)
{
	MemoryContext keep = CurrentMemoryContext;
	uint8		kh[HASH_LEN];
	char	   *v = NULL;
	Who			was;

	if (c->bind == NULL || VARSIZE_ANY_EXHDR(c->bind) != HASH_LEN)
	{
		Judgment	r = *j;

		r.out = OUT_REFUTED;
		return record(owner, t, c, &r);
	}
	key_hash(c->key, kh);
	become(owner, &was);
	spi_connect();
	{
		Oid			at[5] = {INT4OID, BYTEAOID, BYTEAOID, OIDOID, TIMESTAMPTZOID};
		Datum		av[5] = {Int32GetDatum(t->watch), PointerGetDatum(bytes32(kh)), PointerGetDatum(c->bind),
		ObjectIdGetDatum(verifier), TimestampTzGetDatum(j->at)};

		if (SPI_execute_with_args("SELECT phasevec._truth_halted($1, $2, $3, $4, $5)", 5, at, av, NULL, false, 1)
			!= SPI_OK_SELECT)
			elog(ERROR, "phasevec: a halted proof could not be recorded");
	}
	v = verdict_now(t, c->key, keep);
	SPI_finish();
	unbecome(&was);
	return v;
}

/*
 * (eleventh review) What was tried and not judged (an interrupted session, an error that is not the proof's answer, a
 * session of its author that could not judge it): nothing about the verdict, which stays as it was and serves only
 * until its horizon; why, in phasevec.attempts (phasevec._truth_tried). Returns the verdict as it reads now.
 */
static char *
record_tried(Oid owner, const Target *t, const Claim *c, const Judgment *j)
{
	MemoryContext keep = CurrentMemoryContext;
	char	   *v = NULL;
	Who			was;
	Oid			at[4] = {INT4OID, TEXTOID, TEXTOID, BOOLOID};
	Datum		av[4] = {Int32GetDatum(t->watch), CStringGetTextDatum(c->key),
	j->err ? CStringGetTextDatum(j->err) : (Datum) 0, BoolGetDatum(j->out == OUT_INTERRUPTED)};
	char		nulls[5] = "    ";

	nulls[2] = j->err ? ' ' : 'n';
	become(owner, &was);
	spi_connect();
	if (SPI_execute_with_args("SELECT phasevec._truth_tried($1, $2, $3, $4)", 4, at, av, nulls, false, 1)
		!= SPI_OK_SELECT)
		elog(ERROR, "phasevec: what was tried could not be recorded");
	if (SPI_processed == 1)
	{
		char	   *s = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1);

		if (s)
			v = MemoryContextStrdup(keep, s);
	}
	SPI_finish();
	unbecome(&was);
	return v;
}

/*
 * (eleventh review) A claim's turn is spent when a worker gets it: before it is taken, judged or recorded, in a
 * transaction of its own, committed at once (phasevec.attempts, which only workers write: no other session holds its
 * rows). verify() takes the claims whose turn is oldest (phasevec._truth_due): whatever becomes of this attempt (judged,
 * kept from the claim by another transaction, an error that is not the proof's, a session that ends), the claim goes
 * behind every claim that waits, and no claim holds the head of the queue. SPI not connected; in a transaction.
 */
#define ATTEMPT_SQL "SELECT phasevec._truth_attempt($1, $2)"

static void
record_attempt(Oid owner, SPIPlanPtr plan, const Target *t, const Claim *c)
{
	Datum		av[2] = {Int32GetDatum(t->watch), CStringGetTextDatum(c->key)};
	Who			was;

	become(owner, &was);
	spi_connect();
	if (SPI_execute_plan(plan, av, NULL, false, 1) != SPI_OK_SELECT)
		elog(ERROR, "phasevec: an attempt could not be recorded");
	SPI_finish();
	unbecome(&was);
}

/* Record what was found: nothing for a claim not judged (the verdict as it reads now is returned). In a worker. */
static char *
record_judgment(Oid owner, Oid verifier, const Target *t, const Claim *c, const Judgment *j)
{
	if (j->out == OUT_HALTED)
		return record_halted(owner, verifier, t, c, j);
	if (j->out == OUT_INTERRUPTED || j->out == OUT_NO_VERDICT)
		return record_tried(owner, t, c, j);
	return record(owner, t, c, j);
}

/*
 * Take the claim's row before judging it, or leave it: another verify() (or an assert()) holds it. It must still be
 * due, by the rule of phasevec._truth_due (a stale claim once for each text it reads; one whose verdict and last
 * look are both older than p_every is due either way, and the row's text is not read for it). Without this, two
 * verify() calls of one watch locked the rows of their due lists in different orders when the table took writes
 * (in the fifth cut the watch trigger wrote verdict rows too) and deadlocked: 54-70% of the calls failed, and an
 * aborted call lost every verdict it had reached. With it no verify() waits on a verdict row, so none deadlocks on
 * one, and none judges a claim another is judging, or judged since its due list was read (it is no longer due).
 * Since the ninth review the worker takes it, in the transaction that judges and records it.
 *
 * (tenth review) Every worker takes the claim before it judges it, whatever it was sent for. verify_one() takes it
 * whether it is due or not, and waits for it (CLAIM_TAKE_SQL): in the ninth cut its worker judged first and then
 * waited for the row a verify() was judging, and after that one recorded 'refuted' it wrote its own older 'verified'
 * over it. Taken first, of two judgments of a claim the one that reads later commits later.
 */
/*
 * (sixteenth review) Every operator named by its schema: "a IS DISTINCT FROM b" is "a = b" looked up through
 * search_path (an author's '=' ran here as the owner), so it is written with pg_catalog's '=' (DISTINCT), and the
 * horizon is computed in UTC, not in the session's TimeZone (become() pins it too).
 */
#define DISTINCT(a, b) "COALESCE(NOT (" a " OPERATOR(pg_catalog.=) " b "), (" a " IS NULL) OPERATOR(pg_catalog.<>) (" b " IS NULL))"
#define LOCK_OLD(c) "t." c " IS NULL OR pg_catalog.timezone('UTC', t." c ") OPERATOR(pg_catalog.<) " \
	"(pg_catalog.timezone('UTC', pg_catalog.now()) OPERATOR(pg_catalog.-) $3)"
#define CLAIM_LOCK_SQL \
	"SELECT 1 FROM phasevec.truth t WHERE t.watch OPERATOR(pg_catalog.=) $1 AND t.key OPERATOR(pg_catalog.=) $2 " \
	"AND NOT t.halted AND ((" LOCK_OLD("verified_at") ") AND (" LOCK_OLD("looked_at") ") OR " \
	"(SELECT CASE WHEN t.verdict OPERATOR(pg_catalog.=) ANY ('{verified,refuted}'::pg_catalog.text[]) " \
	"AND " DISTINCT("t.asserted_for", "h") " THEN " LOCK_OLD("looked_at") " OR " DISTINCT("t.looked_for", "h") " " \
	"ELSE " LOCK_OLD("verified_at") " END " \
	"FROM (SELECT (SELECT s.text_hash FROM phasevec.sources s WHERE s.watch OPERATOR(pg_catalog.=) t.watch " \
	"AND s.key OPERATOR(pg_catalog.=) t.key) AS h) s)) FOR NO KEY UPDATE SKIP LOCKED"

#define CLAIM_TAKE_SQL \
	"SELECT 1 FROM phasevec.truth t WHERE t.watch OPERATOR(pg_catalog.=) $1 AND t.key OPERATOR(pg_catalog.=) $2 " \
	"FOR NO KEY UPDATE"

/*
 * (fourteenth review) verify_one() takes its claim without waiting, in the transaction that judges it; when another
 * holds it, it waits for it in a transaction of its own (CLAIM_TAKE_SQL), and tries again in a new one. In the
 * thirteenth cut it waited in the transaction that judged: the proof's now() was that transaction's start, from
 * before the wait, while its snapshot and its verified_at were from after it. A claim past due during the wait was
 * recorded 'verified' and served fresh for a whole max_age; a true one that read a row stamped after its now() was
 * recorded 'refuted'.
 */
#define CLAIM_TRY_SQL CLAIM_TAKE_SQL " SKIP LOCKED"

/* The proof's author is still a role, locked against DROP ROLE until this transaction ends. In a worker. */
static bool
author_still_there(Oid author)
{
	LockSharedObject(AuthIdRelationId, author, 0, AccessShareLock);
	return SearchSysCacheExists1(AUTHOID, ObjectIdGetDatum(author));
}

static bool
claim_taken(Oid owner, SPIPlanPtr plan, const Target *t, const Claim *c, const Interval *every)
{
	Datum		av[3] = {Int32GetDatum(t->watch), CStringGetTextDatum(c->key), PointerGetDatum(every)};
	bool		taken;
	Who			was;

	become(owner, &was);
	spi_connect();
	if (SPI_execute_plan(plan, av, NULL, false, 1) != SPI_OK_SELECT)
		elog(ERROR, "phasevec: a claim could not be taken");
	taken = SPI_processed == 1;
	SPI_finish();
	unbecome(&was);
	return taken;
}

/* ----------------------------------------------------------------------------------------- the worker -- */

static void
answer(shm_mq_handle *ans, ProofAnswer what, const Judgment *j, const char *err, const char *verdict)
{
	StringInfoData b;

	initStringInfo(&b);
	put_int(&b, what);
	put_int(&b, j ? j->out : OUT_NOT_JUDGED);
	put_int(&b, j ? j->at : 0);
	{
		const char *e = j ? j->err : err;

		/* an answer stays small: several may wait in the queue for a verifier that is sending */
		put_bytes(&b, e, e ? pg_mbcliplen(e, strlen(e), PROOF_ERR_MAX) : 0);
	}
	put_str(&b, verdict);
	(void) shm_mq_send(ans, b.len, b.data, false, true);
	pfree(b.data);
}

PGDLLEXPORT void phasevec_proof_main(Datum arg);

static ProofShared *volatile proof_self = NULL;

/*
 * SIGTERM in a proof's session: who sent it is kept, then PostgreSQL's own handler (die) runs. The kernel fills
 * si_pid: a process that terminates the worker cannot pass for the worker itself.
 */
/* The segment goes away as the worker exits: a SIGTERM that comes then has nowhere to note its sender. */
static void
proof_forget(dsm_segment *seg, Datum arg)
{
	proof_self = NULL;
}

static void
proof_signaller(int32 pid)
{
	ProofShared *sh = proof_self;

	if (sh != NULL && sh->signaller == 0)
		sh->signaller = pid > 0 ? pid : -1;
}

#if PG_VERSION_NUM >= 190000
/* PostgreSQL 19 passes the sender to every handler (pg_signal_info) */
static void
proof_sigterm(SIGNAL_ARGS)
{
	int			save_errno = errno;

	proof_signaller(pg_siginfo != NULL ? (int32) pg_siginfo->pid : 0);
	errno = save_errno;
	die(postgres_signal_arg, pg_siginfo);
}
#else
static void
proof_sigterm(int signo, siginfo_t *info, void *context)
{
	int			save_errno = errno;

	proof_signaller(info != NULL ? (int32) info->si_pid : 0);
	errno = save_errno;
	die(signo);
}
#endif

static SPIPlanPtr worker_lock_plan = NULL;
static SPIPlanPtr worker_take_plan = NULL;
static SPIPlanPtr worker_try_plan = NULL;
static SPIPlanPtr worker_attempt_plan = NULL;

/*
 * (tenth review) The session clocks a worker pins before it connects. A worker is phasevec's session, not its
 * author's: the database's and the role's defaults (ALTER DATABASE/ROLE ... SET, which an ordinary role may run for
 * itself) do not reach these. In the ninth cut an author that set its own transaction_timeout to 1 ms had every worker
 * of its claims end before it judged, and its claims kept their old 'verified'. The proof's clock is its only time
 * limit; a proof that waits for a lock is not judged at its clock, as before. Inside a proof none of these can be set
 * (the guard), and a claim's settings never carry them (not_replayed).
 */
static const char *const worker_clocks[] = {
	"transaction_timeout", "statement_timeout", "lock_timeout", "idle_in_transaction_session_timeout",
	"idle_session_timeout"
};

/* (thirteenth review) No parallel worker runs any part of a proof: see phasevec_proof_main. */
static const char *const worker_one_process[][2] = {
	{"max_parallel_workers_per_gather", "0"}, {"max_parallel_workers", "0"}, {"debug_parallel_query", "off"}
};

/*
 * The proof's own session: a background worker, a new session of the claim's author (or of the owner, to record
 * what needs no proof). Claims come in one at a time; each is taken, judged and recorded in a transaction of its own,
 * committed before its answer goes back. It ends when its verifier detaches, when a claim is not one it may judge (a
 * placeholder its author did not have), or on an error outside a proof.
 */
void
phasevec_proof_main(Datum arg)
{
	dsm_segment *seg;
	ProofShared *sh;
	shm_mq	   *mq;
	shm_mq_handle *req;
	shm_mq_handle *ans;
	Target		target;
	char	  **base;
	int			nbase;
	MemoryContext per;
	Who			was;

#if PG_VERSION_NUM >= 190000
	pqsignal(SIGTERM, proof_sigterm);
#else
	{
		struct sigaction sa;

		memset(&sa, 0, sizeof(sa));
		sa.sa_sigaction = proof_sigterm;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = SA_SIGINFO | SA_RESTART;
		sigaction(SIGTERM, &sa, NULL);
	}
#endif
	CurrentResourceOwner = ResourceOwnerCreate(NULL, "pg_phasevec proof");
	seg = dsm_attach(DatumGetUInt32(arg));
	if (seg == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("phasevec: a proof's session found its verifier gone")));
	sh = dsm_segment_address(seg);
	if (sh->magic != PROOF_MAGIC || sh->protocol != PROOF_PROTOCOL)
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("phasevec: a proof's session was started by another build of pg_phasevec")));
	sh->pid = MyProcPid;
	pg_write_barrier();
	on_dsm_detach(seg, proof_forget, (Datum) 0);
	proof_self = sh;
	BackgroundWorkerUnblockSignals();
	mq = (shm_mq *) ((char *) sh + PROOF_REQ_OFF);
	shm_mq_set_receiver(mq, MyProc);
	req = shm_mq_attach(mq, seg, NULL);
	mq = (shm_mq *) ((char *) sh + PROOF_ANS_OFF);
	shm_mq_set_sender(mq, MyProc);
	ans = shm_mq_attach(mq, seg, NULL);

	/*
	 * Pinned before the connection reads the database's and the role's settings: those come from a source of lower
	 * priority (PGC_S_DATABASE_USER and below), and are not applied over these.
	 */
	for (int i = 0; i < lengthof(worker_clocks); i++)
		SetConfigOption(worker_clocks[i], "0", PGC_SUSET, PGC_S_OVERRIDE);
	SetConfigOption("exit_on_error", "off", PGC_SUSET, PGC_S_OVERRIDE);
	/*
	 * (thirteenth review) A proof runs in one process: every wait it makes is this session's own, the one that judges
	 * it (lock_waited_since, prove_timeout_handler). A wait for a lock in a parallel worker of the proof was not seen:
	 * the leader waits on the Gather's queue, so a lock another session held past the clock got a true claim
	 * recorded refuted for its time. The author's role chose that (debug_parallel_query, or a parallel plan with
	 * parallel_leader_participation off). No planner setting of the author's, a SET in the proof or a function's SET
	 * clause, is applied over these (a lower source): no Gather is planned, and none forced by debug_parallel_query
	 * gets a worker. The planner's cost of a proof (its max_cost) is then the cost of a plan with no parallelism.
	 */
	for (int i = 0; i < lengthof(worker_one_process); i++)
		SetConfigOption(worker_one_process[i][0], worker_one_process[i][1], PGC_SUSET, PGC_S_OVERRIDE);
	/* a new session of the author: it may be a role that does not log in (the verifier may act as it) */
	BackgroundWorkerInitializeConnectionByOid(sh->db, sh->author, BGWORKER_BYPASS_ROLELOGINCHECK);
	process_session_preload_libraries();
	guard_proof_session();
	/*
	 * A verdict is committed by this session, one claim at a time: without waiting for its WAL to reach disk (a
	 * verdict lost to a crash leaves its claim due, and the next verify() judges it again).
	 */
	SetConfigOption("synchronous_commit", "off", PGC_SUSET, PGC_S_OVERRIDE);
	/* the placeholders every new session of the author has: from its configuration */
	base = guard_placeholders(&nbase);

	SetCurrentStatementStartTimestamp();
	StartTransactionCommand();
	PushActiveSnapshot(GetTransactionSnapshot());
	become(sh->owner, &was);
	spi_connect();
	load_target(Int32GetDatum(sh->watch), true, &target, TopMemoryContext);
	prepare_read(&target);
	{
		Oid			at[6] = {INT4OID, TEXTOID, TEXTOID, TEXTOID, BYTEAOID, TIMESTAMPTZOID};
		Oid			lt[3] = {INT4OID, TEXTOID, INTERVALOID};

		(void) kept_plan(&target.record_plan, RECORD_SQL, 6, at);
		(void) kept_plan(&worker_lock_plan, CLAIM_LOCK_SQL, 3, lt);
		(void) kept_plan(&worker_take_plan, CLAIM_TAKE_SQL, 2, lt);
		(void) kept_plan(&worker_try_plan, CLAIM_TRY_SQL, 2, lt);
		(void) kept_plan(&worker_attempt_plan, ATTEMPT_SQL, 2, lt);
	}
	SPI_finish();
	unbecome(&was);
	PopActiveSnapshot();
	CommitTransactionCommand();
	pgstat_report_activity(STATE_IDLE, NULL);

	per = AllocSetContextCreate(TopMemoryContext, "phasevec proof", ALLOCSET_DEFAULT_SIZES);
	for (;;)
	{
		Size		n;
		void	   *data;
		Msg			m;
		ProofKind	kind;
		Interval   *every;
		Oid			verifier;
		int			timeout_ms;
		double		max_cost;
		int64		bits;
		bool		rls;
		Claim		c;
		const char *spent;
		Judgment	j;
		ProofAnswer what = ANSWER_DONE;
		char	   *v = NULL;
		bool		ready = false;
		Seen		first = {0};

		MemoryContextReset(per);
		MemoryContextSwitchTo(per);
		if (shm_mq_receive(req, &n, &data, false) != SHM_MQ_SUCCESS)
			break;				/* the verifier is done, or gone */
		m.p = data;
		m.end = (const char *) data + n;
		memset(&c, 0, sizeof(c));
		kind = (ProofKind) get_int(&m);
		if (kind == MSG_ATTEMPT)
		{
			/* (twelfth review) the keeper: spend the turns of the claims about to go to their author's session */
			int64		nkeys = get_int(&m);

			PG_TRY();
			{
				SetCurrentStatementStartTimestamp();
				StartTransactionCommand();
				XactIsoLevel = XACT_READ_COMMITTED;
				XactReadOnly = RecoveryInProgress();
				PushActiveSnapshot(GetTransactionSnapshot());
				MemoryContextSwitchTo(per);
				pgstat_report_activity(STATE_RUNNING, "phasevec: spending the turns of claims");
				for (int64 i = 0; i < nkeys; i++)
				{
					memset(&c, 0, sizeof(c));
					c.key = get_bytes(&m, NULL);
					if (c.key == NULL)
						elog(ERROR, "phasevec: a malformed message between a verifier and a proof's session");
					record_attempt(sh->owner, worker_attempt_plan, &target, &c);
				}
				PopActiveSnapshot();
				CommitTransactionCommand();
			}
			PG_CATCH();
			{
				ErrorData  *e;

				MemoryContextSwitchTo(per);
				e = CopyErrorData();
				FlushErrorState();
				AbortCurrentTransaction();
				MemoryContextSwitchTo(per);
				answer(ans, ANSWER_FAILED, NULL, e->message, NULL);
				proc_exit(0);
			}
			PG_END_TRY();
			pgstat_report_activity(STATE_IDLE, NULL);
			MemoryContextSwitchTo(per);
			answer(ans, ANSWER_DONE, NULL, NULL, NULL);
			continue;
		}
		every = (Interval *) get_bytes(&m, NULL);
		verifier = (Oid) get_int(&m);
		timeout_ms = (int) get_int(&m);
		bits = get_int(&m);
		memcpy(&max_cost, &bits, sizeof(max_cost));
		rls = get_int(&m) != 0;
		c.key = get_bytes(&m, NULL);
		c.proof = get_bytes(&m, NULL);
		c.asserted_for = get_bytea(&m);
		c.bind = get_bytea(&m);
		c.env = palloc0(sizeof(GuardEnv));
		c.env->n = (int) get_int(&m);
		c.env->name = palloc(sizeof(char *) * Max(c.env->n, 1));
		c.env->value = palloc(sizeof(char *) * Max(c.env->n, 1));
		for (int i = 0; i < c.env->n; i++)
		{
			c.env->name[i] = get_bytes(&m, NULL);
			c.env->value[i] = get_bytes(&m, NULL);
		}
		j.out = (Outcome) get_int(&m);
		j.at = (TimestampTz) get_int(&m);
		j.err = get_bytes(&m, NULL);
		if (c.key == NULL || (kind == MSG_JUDGE && c.proof == NULL) || (kind != MSG_JUDGE && kind != MSG_RECORD))
			elog(ERROR, "phasevec: a malformed message between a verifier and a proof's session");

		/* a placeholder this session made for an earlier claim, which this claim's author did not have */
		if (kind == MSG_JUDGE && (spent = guard_env_spent(base, nbase, c.env)) != NULL)
		{
			answer(ans, ANSWER_SPENT, NULL, spent, NULL);
			break;
		}

		PG_TRY();
		{
			/*
			 * (eleventh review) the claim's turn is spent first, in a transaction of its own (record_attempt). (twelfth
			 * review) Here only by a session its author cannot end: a session of the owner, or verify_one()'s (it
			 * names its claim); a verify() claim sent to its author's session was spent by the call's keeper.
			 */
			if (every == NULL || sh->author == sh->owner)
			{
				SetCurrentStatementStartTimestamp();
				StartTransactionCommand();
				XactIsoLevel = XACT_READ_COMMITTED;
				XactReadOnly = RecoveryInProgress();
				PushActiveSnapshot(GetTransactionSnapshot());
				record_attempt(sh->owner, worker_attempt_plan, &target, &c);
				PopActiveSnapshot();
				CommitTransactionCommand();
				MemoryContextSwitchTo(per);
			}

			/*
			 * (fourteenth review) The claim is taken in the transaction that judges it without a wait in between:
			 * the proof's now() (this transaction's start), its snapshot and its verified_at are one instant.
			 * (fifteenth review) Nothing phasevec reads sits between them: the claim's row is read before, in a
			 * transaction of its own (judge_row), and a take that waited for a lock (phasevec.truth held by a
			 * LOCK or an ALTER) is let go and tried again in a new transaction.
			 */
			for (bool gone = false;;)
			{
				bool		taken;

				if (kind == MSG_JUDGE)
				{
					SetCurrentStatementStartTimestamp();
					StartTransactionCommand();
					XactIsoLevel = XACT_READ_COMMITTED;
					XactReadOnly = true;
					PushActiveSnapshot(GetTransactionSnapshot());
					MemoryContextSwitchTo(per);
					pgstat_report_activity(STATE_RUNNING, "phasevec: reading the row of a claim");
					ready = judge_row(&target, c.key, rls, sh->author, GUARD_AUTHOR, c.env, c.asserted_for, timeout_ms,
									  &first, &j);
					PopActiveSnapshot();
					CommitTransactionCommand();
					MemoryContextSwitchTo(per);
				}
				SetCurrentStatementStartTimestamp();
				StartTransactionCommand();
				/* each statement in a new snapshot, whatever default_transaction_isolation says; it records, so read-write */
				XactIsoLevel = XACT_READ_COMMITTED;
				XactReadOnly = RecoveryInProgress();
				PushActiveSnapshot(GetTransactionSnapshot());
				MemoryContextSwitchTo(per);
				pgstat_report_activity(STATE_RUNNING, "phasevec: judging a claim");
				taken = claim_taken(sh->owner, every ? worker_lock_plan : worker_try_plan, &target, &c, every);
				if (taken && lock_waited_since(GetCurrentTransactionStartTimestamp()))
				{
					PopActiveSnapshot();
					CommitTransactionCommand();
					MemoryContextSwitchTo(per);
					continue;
				}
				if (taken || every != NULL || gone)
				{
					if (!taken)
						what = ANSWER_SKIPPED;
					break;
				}
				PopActiveSnapshot();
				CommitTransactionCommand();
				/* held by another session: waited for here, in a transaction that judges nothing */
				SetCurrentStatementStartTimestamp();
				StartTransactionCommand();
				XactIsoLevel = XACT_READ_COMMITTED;
				XactReadOnly = RecoveryInProgress();
				PushActiveSnapshot(GetTransactionSnapshot());
				MemoryContextSwitchTo(per);
				pgstat_report_activity(STATE_RUNNING, "phasevec: waiting for a claim another session holds");
				gone = !claim_taken(sh->owner, worker_take_plan, &target, &c, NULL);
				PopActiveSnapshot();
				CommitTransactionCommand();
				MemoryContextSwitchTo(per);
			}
			if (what != ANSWER_SKIPPED)
			{
				if (kind == MSG_JUDGE)
				{
					/*
					 * (sixteenth review) A proof is judged, and its verdict recorded, only while its author is a role:
					 * the role is locked here until this transaction commits (DROP ROLE takes it exclusively, so it
					 * waits for the verdict), and one dropped before is found gone. In the fifteenth cut a call went on
					 * running the proofs of a role dropped mid-call, and stamped 'verified' in its name.
					 */
					if (ready && sh->author != sh->owner)
					{
						if (!author_still_there(sh->author))
						{
							ready = false;
							memset(&j, 0, sizeof(j));
							j.out = OUT_UNPROVEN;
							j.err = "the author of this proof was dropped during the call: nothing is judged in its "
								"name; assert it again, or adopt it naming its author (phasevec.adopt)";
						}
						else if (lock_waited_since(GetCurrentTransactionStartTimestamp()))
						{
							/* a DROP ROLE of the author held it, and was rolled back: this transaction's now() is old */
							ready = false;
							memset(&j, 0, sizeof(j));
							j.out = OUT_NO_VERDICT;
							j.err = "not judged: a DROP ROLE of its author held the role, and was rolled back";
						}
					}
					if (ready)
					{
						sh->started = GetCurrentTimestamp();
						pg_write_barrier();
						pg_atomic_write_u32(&sh->judging, 1);
						judge(c.proof, timeout_ms, max_cost, sh->author, GUARD_AUTHOR, c.env, &target, c.key, &first,
							  &j);
						pg_atomic_write_u32(&sh->judging, 0);
					}
					/* stamped with the proof's own now(): a verdict is never fresher than the clock it read */
					if (j.at != 0)
						j.at = GetCurrentTransactionStartTimestamp();
				}
				v = record_judgment(sh->owner, verifier, &target, &c, &j);
			}
		}
		PG_CATCH();
		{
			ErrorData  *e;

			pg_atomic_write_u32(&sh->judging, 0);
			MemoryContextSwitchTo(per);
			e = CopyErrorData();
			FlushErrorState();
			AbortCurrentTransaction();
			MemoryContextSwitchTo(per);
			answer(ans, ANSWER_FAILED, NULL, e->message, NULL);
			proc_exit(0);
		}
		PG_END_TRY();
		PopActiveSnapshot();
		CommitTransactionCommand();
		pgstat_report_activity(STATE_IDLE, NULL);
		MemoryContextSwitchTo(per);
		answer(ans, what, &j, NULL, v);
	}
	proc_exit(0);
}

/* ------------------------------------------------------------------------------------- the verifier's side -- */

/*
 * The worker of the verify() call running now (one at a time), in TopMemoryContext. One whose verifier ends (an
 * error, a cancel, the session's end) is ended with it.
 */
static ProofSession *proof_cur = NULL;

/* (twelfth review) The call's keeper: a session of the owner that spends its claims' turns. */
static ProofSession *keeper_cur = NULL;

/*
 * (fourteenth review) A session this verifier is waiting for to leave (proof_stop): no longer the call's, still to be
 * freed. A cancel during the wait leaves it here, and the cleanup of the call ends and frees it.
 */
static ProofSession *proof_leaving = NULL;

static void
proof_on_exit(int code, Datum arg)
{
	ProofSession **all[] = {&proof_cur, &keeper_cur, &proof_leaving};

	for (int i = 0; i < lengthof(all); i++)
	{
		if (*all[i] != NULL)
			TerminateBackgroundWorker((*all[i])->handle);
		*all[i] = NULL;
	}
}

/* The library this verifier runs: the worker loads the very same file. */
static const char *
library_path(void)
{
	static char path[MAXPGPATH];

	if (path[0] == '\0')
	{
		Dl_info		info;

		if (dladdr((void *) phasevec_proof_main, &info) != 0 && info.dli_fname != NULL &&
			strlen(info.dli_fname) < MAXPGPATH)
			strlcpy(path, info.dli_fname, MAXPGPATH);
		else
			strlcpy(path, "pg_phasevec", MAXPGPATH);
	}
	return path;
}

static ProofSession *
proof_start(Oid owner, int32 watch, Oid author, char **why)
{
	static bool hooked = false;
	ProofSession *ps = MemoryContextAllocZero(TopMemoryContext, sizeof(ProofSession));
	BackgroundWorker w;
	shm_mq	   *mq;
	MemoryContext o;
	MemoryContext scratch;
	bool		started;

	/*
	 * (fifteenth review) What a session keeps (the segment, its queues, the worker's handle) is in TopMemoryContext;
	 * what only starts it is not. dsm_create() with dynamic_shared_memory_type = mmap allocates a zeroed buffer
	 * of 8 kB in the current context and never frees it, and the worker's name is looked up into a new string: done in
	 * TopMemoryContext, every verify_one() left 8 kB (mmap) or 24 bytes behind, for as long as the session lived.
	 */
	scratch = AllocSetContextCreate(CurrentMemoryContext, "phasevec proof start", ALLOCSET_SMALL_SIZES);
	o = MemoryContextSwitchTo(scratch);
	ps->author = author;
	ps->seg = dsm_create(PROOF_SIZE, 0);
	MemoryContextSwitchTo(TopMemoryContext);
	ps->sh = dsm_segment_address(ps->seg);
	memset(ps->sh, 0, sizeof(ProofShared));
	ps->sh->magic = PROOF_MAGIC;
	ps->sh->protocol = PROOF_PROTOCOL;
	ps->sh->db = MyDatabaseId;
	ps->sh->author = author;
	ps->sh->owner = owner;
	ps->sh->watch = watch;
	pg_atomic_init_u32(&ps->sh->judging, 0);
	mq = shm_mq_create((char *) ps->sh + PROOF_REQ_OFF, PROOF_QUEUE);
	shm_mq_set_sender(mq, MyProc);
	ps->req = shm_mq_attach(mq, ps->seg, NULL);
	mq = shm_mq_create((char *) ps->sh + PROOF_ANS_OFF, PROOF_QUEUE);
	shm_mq_set_receiver(mq, MyProc);
	ps->ans = shm_mq_attach(mq, ps->seg, NULL);

	memset(&w, 0, sizeof(w));
	w.bgw_flags = BGWORKER_SHMEM_ACCESS | BGWORKER_BACKEND_DATABASE_CONNECTION;
	w.bgw_start_time = BgWorkerStart_ConsistentState;
	w.bgw_restart_time = BGW_NEVER_RESTART;
	strlcpy(w.bgw_library_name, library_path(), sizeof(w.bgw_library_name));
	strlcpy(w.bgw_function_name, "phasevec_proof_main", BGW_MAXLEN);
	{
		char	   *name;

		MemoryContextSwitchTo(scratch);
		name = GetUserNameFromId(author, true);
		snprintf(w.bgw_name, BGW_MAXLEN, "pg_phasevec proof as %s", name ? name : "a role that is gone");
		MemoryContextSwitchTo(TopMemoryContext);
	}
	strlcpy(w.bgw_type, "pg_phasevec proof", BGW_MAXLEN);
	w.bgw_main_arg = UInt32GetDatum(dsm_segment_handle(ps->seg));
	w.bgw_notify_pid = MyProcPid;
	started = RegisterDynamicBackgroundWorker(&w, &ps->handle);
	MemoryContextSwitchTo(o);
	MemoryContextDelete(scratch);
	if (!started)
	{
		shm_mq_detach(ps->req);
		shm_mq_detach(ps->ans);
		dsm_detach(ps->seg);
		pfree(ps);
		*why = psprintf("not judged: no background worker is free to run its proof in a session of its own "
						"(max_worker_processes is %d): nothing is recorded, and it stays due", max_worker_processes);
		return NULL;
	}
	shm_mq_set_handle(ps->req, ps->handle);
	shm_mq_set_handle(ps->ans, ps->handle);
	if (!hooked)
	{
		before_shmem_exit(proof_on_exit, (Datum) 0);
		hooked = true;
	}
	return ps;
}

/*
 * Done with the worker in `*slot`: detached (it ends by itself), or ended now (it may be inside a proof, or gone
 * already). An ended one is waited for (`wait`: not on the way out of an error), up to PROOF_GRACE_MS, so that the
 * claim's row it took and its slot of max_worker_processes are free again for the session that records it.
 *
 * (fourteenth review) Safe to call again on what is left of it, at any point: each part is cleared before it is freed,
 * and nothing that can be interrupted runs while the session is the call's. In the thirteenth cut the wait (it
 * checks for interrupts) ran with the queues freed and the session still in proof_cur; a cancel there reached the
 * cleanup of verify(), which freed the queues again: the server PANICked (stuck spinlock in shm_mq_detach_internal)
 * and restarted, at the hands of any role that may call verify(). Now the session leaves the call's slot first and
 * waits in proof_leaving, which the cleanup of the call (proof_stop_all) ends and frees.
 */
static void
proof_stop(ProofSession **slot, bool end_it, bool wait)
{
	ProofSession *ps = *slot;
	shm_mq_handle *h;
	dsm_segment *seg;

	if (ps == NULL)
		return;
	if (end_it && !ps->ended)
	{
		ps->ended = true;
		TerminateBackgroundWorker(ps->handle);
	}
	/* detached first: a worker that is not ended leaves when it finds its verifier gone */
	if ((h = ps->req) != NULL)
	{
		ps->req = NULL;
		shm_mq_detach(h);
	}
	if ((h = ps->ans) != NULL)
	{
		ps->ans = NULL;
		shm_mq_detach(h);
	}
	if (wait && slot != &proof_leaving)
	{
		TimestampTz t0 = GetCurrentTimestamp();
		pid_t		pid;

		/* one at a time: one still here (it cannot be: its wait ended, or its call did) is ended now */
		proof_stop(&proof_leaving, true, false);
		proof_leaving = ps;
		*slot = NULL;
		slot = &proof_leaving;
		while (GetBackgroundWorkerPid(ps->handle, &pid) != BGWH_STOPPED &&
			   !TimestampDifferenceExceeds(t0, GetCurrentTimestamp(), PROOF_GRACE_MS))
		{
			(void) WaitLatch(MyLatch, WL_LATCH_SET | WL_TIMEOUT | WL_EXIT_ON_PM_DEATH, 10, PG_WAIT_EXTENSION);
			ResetLatch(MyLatch);
			CHECK_FOR_INTERRUPTS();
		}
	}
	*slot = NULL;
	seg = ps->seg;
	ps->seg = NULL;
	if (seg != NULL)
		dsm_detach(seg);
	pfree(ps->handle);
	pfree(ps);
}

/* The end of a call (`end_it`: on its way out of an error): every session it has, or is waiting for, is let go. */
static void
proof_stop_all(bool end_it)
{
	proof_stop(&proof_cur, end_it, false);
	proof_stop(&keeper_cur, end_it, false);
	proof_stop(&proof_leaving, true, false);
}

/*
 * Does the worker wait for a lock this session holds, directly or through the sessions it waits for (an ALTER TABLE
 * queued behind this transaction's read, which the proof queues behind)? It would wait as long as this waits for it.
 * Returns the first session on the way (MyProcPid when the worker waits for this one itself), or 0.
 */
static int
waits_for_us(ProofSession *ps)
{
	pid_t		pid;
	int			seen[PROOF_WAITS_MAX];
	int			via[PROOF_WAITS_MAX];
	int			n = 0;

	if (GetBackgroundWorkerPid(ps->handle, &pid) != BGWH_STARTED)
		return 0;
	seen[n] = (int) pid;
	via[n++] = 0;
	for (int i = 0; i < n; i++)
	{
		ArrayType  *a = DatumGetArrayTypeP(DirectFunctionCall1(pg_blocking_pids, Int32GetDatum(seen[i])));
		Datum	   *d;
		bool	   *nulls;
		int			nb;

		deconstruct_array_builtin(a, INT4OID, &d, &nulls, &nb);
		for (int k = 0; k < nb; k++)
		{
			int			b;
			bool		known = false;

			if (nulls[k])
				continue;
			b = DatumGetInt32(d[k]);
			if (b == MyProcPid)
				return i == 0 ? MyProcPid : via[i];
			for (int s = 0; s < n && !known; s++)
				known = seen[s] == b;
			if (!known && n < PROOF_WAITS_MAX)
			{
				seen[n] = b;
				via[n++] = i == 0 ? b : via[i];
			}
		}
	}
	return 0;
}

/* A claim queued for the worker, and not yet answered. */
typedef struct Sent
{
	const Claim *c;
	ProofKind	kind;
	bool		rls;
	Judgment	rec;			/* MSG_RECORD: what to record */
	int			tries;
	bool		spent;			/* its turn is spent by a session its author cannot end (twelfth review) */
	bool		spending;		/* in the keeper's batch, not answered yet */
	StringInfoData msg;
} Sent;

/* The claims of a call on their way to its worker (proof_cur), in the order they are answered. */
typedef struct Line
{
	Oid			owner;
	Oid			caller;
	const Target *t;
	const Interval *every;		/* verify(): claims are taken by this rule; verify_one(): NULL */
	int			timeout_ms;
	double		max_cost;
	Sent		q[PROOF_AHEAD];
	int			qh;
	int			qn;
	int			nsent;			/* of q, from its head: sent whole to proof_cur */
	Size		queued;			/* the bytes of q */
	TimestampTz since;			/* the head waits for an answer since */
	TimestampTz looked;			/* the lock waits were last walked */
	Oid			unjudgeable;	/* an author no session of which could start in this call (tenth review) */
	char	   *unjudgeable_why;
	/* (twelfth review) the keeper's batch: the turns it is spending, since when, and how often it failed */
	StringInfoData spend_msg;
	int			spend_n;
	bool		spend_sent;
	TimestampTz spend_since;
	int			keeper_tries;
	MemoryContext cx;
} Line;

/* What became of a claim. */
typedef struct Done
{
	const Claim *c;
	ProofKind	kind;
	Judgment	j;
	char	   *verdict;		/* as it reads now: the worker's, after it recorded */
	bool		recorded;		/* a worker took it and recorded what it found */
	bool		skipped;		/* not taken: another verify() holds it, or it is not due any more */
	bool		stuck;			/* no session took it in time: the call stops */
} Done;

static void
line_message(Line *l, Sent *s)
{
	MemoryContext o = MemoryContextSwitchTo(l->cx);

	if (s->msg.data != NULL)
		pfree(s->msg.data);
	claim_message(&s->msg, s->kind, s->c, l->every, l->caller, s->rls, l->timeout_ms, l->max_cost,
				  s->kind == MSG_RECORD ? &s->rec : NULL);
	MemoryContextSwitchTo(o);
}

/*
 * Queue a claim, unless it would make the queued bytes more than half the queue (a claim larger than that goes alone,
 * in pieces). False: not queued, try again once the queue has drained.
 */
static bool
line_push(Line *l, const Claim *c, ProofKind kind, bool rls, const Judgment *rec)
{
	Sent	   *s = &l->q[(l->qh + l->qn) % PROOF_AHEAD];

	Assert(l->qn < PROOF_AHEAD);
	memset(s, 0, sizeof(Sent));
	s->c = c;
	s->kind = kind;
	s->rls = rls;
	if (rec)
		s->rec = *rec;
	if (s->rec.err)
		s->rec.err = MemoryContextStrdup(l->cx, s->rec.err);
	line_message(l, s);
	if (l->qn > 0 && l->queued + s->msg.len > PROOF_QUEUE / 2)
	{
		pfree(s->msg.data);
		return false;
	}
	if (l->qn == 0)
		l->since = GetCurrentTimestamp();
	l->queued += s->msg.len;
	l->qn++;
	return true;
}

static void
line_pop(Line *l)
{
	Sent	   *s = &l->q[l->qh];

	l->queued -= s->msg.len;
	pfree(s->msg.data);
	s->msg.data = NULL;
	l->qh = (l->qh + 1) % PROOF_AHEAD;
	l->qn--;
	if (l->nsent > 0)
		l->nsent--;
	l->since = GetCurrentTimestamp();
}

/* The author whose proofs are queued (one at a time), or InvalidOid when only records are. */
static Oid
line_author(const Line *l)
{
	for (int i = 0; i < l->qn; i++)
	{
		const Sent *s = &l->q[(l->qh + i) % PROOF_AHEAD];

		if (s->kind == MSG_JUDGE)
			return s->c->author;
	}
	return InvalidOid;
}

/* May a claim of `author` join the queue now? One worker at a time: another author's claims wait until it drains. */
static bool
line_takes(const Line *l, Oid author)
{
	Oid			now = proof_cur ? proof_cur->author : line_author(l);

	return l->qn == 0 || !OidIsValid(now) || now == author;
}

/*
 * The worker is done: the claims it had not answered go to the next one. One that is not ended (another author's
 * claims come next) is waited for too: (thirteenth review) its slot is the one the next author's session takes, and
 * with no other free that one did not start, and its claims were not judged.
 */
static void
line_restart(Line *l, bool end_it)
{
	proof_stop(&proof_cur, end_it, true);
	l->nsent = 0;
	l->since = GetCurrentTimestamp();
}

/* A queued claim becomes a record of what the verifier found (a halted, interrupted, late or unjudged claim). */
static void
sent_to_record(Line *l, Sent *s, const Judgment *j)
{
	s->kind = MSG_RECORD;
	s->rec = *j;
	s->rec.err = j->err ? MemoryContextStrdup(l->cx, j->err) : NULL;
	s->tries = 0;
	l->queued -= s->msg.len;
	line_message(l, s);
	l->queued += s->msg.len;
}

/* The head becomes a record of what the verifier found, for a new worker. */
static void
line_to_record(Line *l, const Judgment *j)
{
	sent_to_record(l, &l->q[l->qh], j);
}

/*
 * (tenth review) The head could not be judged for its author's sake: it is recorded so (OUT_NO_VERDICT: its turn is
 * spent, its verdict stays as it was until its horizon), by a new worker. `author_wide` (no session of its author
 * could start): so is every claim of that author queued in this call, and every one queued later (verify()), with no
 * session of its author tried again. In the ninth cut nothing was recorded: such a claim kept its verdict for good
 * and, being the oldest, the head of the queue.
 */
static void
line_unjudged(Line *l, const char *why, bool author_wide)
{
	Oid			author = l->q[l->qh].c->author;
	Judgment	j;

	j.out = OUT_NO_VERDICT;
	j.at = 0;
	j.err = (char *) why;
	line_to_record(l, &j);
	if (!author_wide)
		return;
	l->unjudgeable = author;
	l->unjudgeable_why = MemoryContextStrdup(l->cx, why);
	j.err = psprintf("%s (an earlier claim of its author, in this call)", why);
	for (int i = 1; i < l->qn; i++)
	{
		Sent	   *s = &l->q[(l->qh + i) % PROOF_AHEAD];

		if (s->kind == MSG_JUDGE && s->c->author == author)
			sent_to_record(l, s, &j);
	}
}

/* Is a queued claim's turn not spent yet? */
static bool
line_unspent(const Line *l)
{
	for (int i = 0; i < l->qn; i++)
		if (!l->q[(l->qh + i) % PROOF_AHEAD].spent)
			return true;
	return false;
}

/* Done with the call's keeper: detached (it ends by itself), or ended now. */
static void
keeper_stop(bool end_it)
{
	proof_stop(&keeper_cur, end_it, false);
}

/*
 * (twelfth review) Spend, through the keeper, the turns of the claims queued for their author's session, without
 * waiting: a batch at a time (every queued claim not spent yet), sent, then its answer read on later rounds. A claim is
 * sent to its author's session only once its turn is spent. Returns NULL, or why the head's turn cannot be spent (no
 * worker free for the keeper; the keeper ended, or did not answer within PROOF_GRACE_MS, twice): then the head is not
 * tried, nothing is recorded, it keeps its turn, and with `*stop` the call stops (a role that may end the owner's
 * sessions ends them).
 */
static const char *
line_spend(Line *l, bool *stop)
{
	Sent	   *h = &l->q[l->qh];
	shm_mq_result r;
	Size		n;
	void	   *data;
	int			batch = 0;

	*stop = false;
	if (l->spend_n == 0)
	{
		int			ready = 0;

		for (int i = 0; i < l->qn; i++)
		{
			Sent	   *s = &l->q[(l->qh + i) % PROOF_AHEAD];

			batch += !s->spent;
			ready += s->spent;
		}
		/*
		 * A batch when the worker is about to run out of spent claims, or half a queue is waiting: one transaction
		 * of the keeper for several claims, and the worker never idle for it.
		 */
		if (batch == 0 || (ready > 2 && batch < PROOF_AHEAD / 2))
			return NULL;
		/* (thirteenth review) not before the session that tries them runs (line_next) */
		if (proof_cur == NULL && OidIsValid(line_author(l)))
			return NULL;
		if (keeper_cur == NULL)
		{
			char	   *why = NULL;

			keeper_cur = proof_start(l->owner, l->t->watch, l->owner, &why);
			if (keeper_cur == NULL)
				return h->spent ? NULL :
					psprintf("not judged: no background worker is free for the session that spends the claims' turns "
							 "(verify() needs two at a time, that one and one of the proof's author; "
							 "max_worker_processes is %d): nothing is recorded, and it keeps its turn",
							 max_worker_processes);
		}
		{
			MemoryContext o = MemoryContextSwitchTo(l->cx);

			initStringInfo(&l->spend_msg);
			put_int(&l->spend_msg, MSG_ATTEMPT);
			put_int(&l->spend_msg, batch);
			for (int i = 0; i < l->qn; i++)
			{
				Sent	   *s = &l->q[(l->qh + i) % PROOF_AHEAD];

				if (s->spent)
					continue;
				put_str(&l->spend_msg, s->c->key);
				s->spending = true;
			}
			MemoryContextSwitchTo(o);
		}
		l->spend_n = batch;
		l->spend_sent = false;
		l->spend_since = GetCurrentTimestamp();
	}
	if (!l->spend_sent)
	{
		r = shm_mq_send(keeper_cur->req, l->spend_msg.len, l->spend_msg.data, true, true);
		if (r == SHM_MQ_DETACHED)
			goto failed;
		l->spend_sent = r == SHM_MQ_SUCCESS;
	}
	if (l->spend_sent)
	{
		r = shm_mq_receive(keeper_cur->ans, &n, &data, true);
		if (r == SHM_MQ_DETACHED)
			goto failed;
		if (r == SHM_MQ_SUCCESS)
		{
			Msg			m;

			m.p = data;
			m.end = (const char *) data + n;
			if ((ProofAnswer) get_int(&m) != ANSWER_DONE)
				goto failed;
			for (int i = 0; i < l->qn; i++)
			{
				Sent	   *s = &l->q[(l->qh + i) % PROOF_AHEAD];

				if (s->spending)
					s->spent = true;
				s->spending = false;
			}
			l->spend_n = 0;
			l->keeper_tries = 0;
			pfree(l->spend_msg.data);
			l->spend_msg.data = NULL;
			return NULL;
		}
	}
	if (!TimestampDifferenceExceeds(l->spend_since, GetCurrentTimestamp(), PROOF_GRACE_MS))
		return NULL;

failed:
	/* what it was spending is spent again by a new keeper (an attempt it did commit is only spent twice) */
	for (int i = 0; i < l->qn; i++)
		l->q[(l->qh + i) % PROOF_AHEAD].spending = false;
	l->spend_n = 0;
	if (l->spend_msg.data)
		pfree(l->spend_msg.data);
	l->spend_msg.data = NULL;
	keeper_stop(true);
	if (++l->keeper_tries > 1 && !h->spent)
	{
		*stop = true;
		return psprintf("not judged: phasevec's own session that spends the claims' turns ended, or did not answer "
						"within %d ms, before this claim's was spent: nothing is recorded, and it keeps its turn",
						PROOF_GRACE_MS);
	}
	return NULL;
}

static void
line_done(Line *l, Done *d, Outcome out, const char *err)
{
	d->c = l->q[l->qh].c;
	d->kind = l->q[l->qh].kind;
	d->j.out = out;
	d->j.err = err ? pstrdup(err) : NULL;
	d->j.at = 0;
	d->verdict = NULL;
	d->recorded = false;
	d->skipped = false;
	d->stuck = false;
	line_pop(l);
}

/*
 * Drive the queue until its head is done with: send what fits without waiting, read answers, and keep every deadline
 * (the proof's clock and PROOF_GRACE_MS more; as long again for a worker to take a claim it was sent) and the lock
 * check. Workers are started, replaced and ended here. The queue is not empty.
 */
static void
line_next(Line *l, Done *d)
{
	static uint32 wait_event = 0;

	if (wait_event == 0)
		wait_event = WaitEventExtensionNew("PhasevecProof");
	memset(d, 0, sizeof(Done));
	for (;;)
	{
		Sent	   *h = &l->q[l->qh];
		Oid			author = line_author(l);
		shm_mq_result r;
		Size		n;
		void	   *data;
		TimestampTz now;
		/*
		 * (twelfth review) verify()'s claims for an author's session (the author of the proofs queued, or the session
		 * at hand when only records are): spent first, by the keeper
		 */
		bool		keeps = l->every != NULL &&
			(OidIsValid(author) ? author != l->owner : proof_cur != NULL && proof_cur->author != l->owner);

		/* a worker for what is queued: the author of its proofs, or (records only) any, or a session of the owner */
		if (proof_cur != NULL && OidIsValid(author) && proof_cur->author != author)
		{
			if (l->nsent > 0)
				elog(ERROR, "phasevec: claims of two authors were sent to one session");
			line_restart(l, false);
		}
		if (keeps)
		{
			bool		stop;
			const char *why;

			/*
			 * (thirteenth review) Every session the step needs runs before a turn is spent: the author's, then the
			 * keeper (line_spend). The keeper started first took the last free slot and spent the turns of the whole
			 * batch; then no session of the author could start, and each claim of the batch was 'not judged' with its
			 * turn spent: an author holding a slot on every other call kept chosen claims of another from ever being
			 * tried. Now a session that cannot start leaves the claims their turns. The author's session gets
			 * nothing before the head's turn is spent (below): ending it then only starts another.
			 */
			if (proof_cur == NULL && OidIsValid(author) && line_unspent(l))
			{
				char	   *nowhy = NULL;

				proof_cur = proof_start(l->owner, l->t->watch, author, &nowhy);
				l->nsent = 0;
				if (proof_cur == NULL)
				{
					line_done(l, d, OUT_NOT_JUDGED, nowhy);
					return;
				}
				l->since = GetCurrentTimestamp();
			}
			why = line_spend(l, &stop);

			if (why != NULL)
			{
				line_done(l, d, OUT_NOT_JUDGED, why);
				d->stuck = stop;
				return;
			}
			/* its author's session starts once the head's turn is spent: nothing it can end comes first */
			if (!h->spent && proof_cur == NULL)
			{
				(void) WaitLatch(MyLatch, WL_LATCH_SET | WL_TIMEOUT | WL_EXIT_ON_PM_DEATH, 10, wait_event);
				ResetLatch(MyLatch);
				CHECK_FOR_INTERRUPTS();
				continue;
			}
		}
		if (proof_cur == NULL)
		{
			char	   *why = NULL;

			proof_cur = proof_start(l->owner, l->t->watch, OidIsValid(author) ? author : l->owner, &why);
			l->nsent = 0;
			if (proof_cur == NULL)
			{
				/*
				 * A record (a halt, an interruption) waits a while for a slot: the worker that ended is leaving one,
				 * and other verifiers may take it first. A proof does not: it stays due.
				 */
				if (h->kind == MSG_RECORD && !TimestampDifferenceExceeds(l->since, GetCurrentTimestamp(), PROOF_GRACE_MS))
				{
					(void) WaitLatch(MyLatch, WL_LATCH_SET | WL_TIMEOUT | WL_EXIT_ON_PM_DEATH, 20, wait_event);
					ResetLatch(MyLatch);
					CHECK_FOR_INTERRUPTS();
					continue;
				}
				/*
				 * (thirteenth review) A claim whose turn is spent finds no slot only when its author's session was
				 * started for it and then ended (its proof ended or overran it, a placeholder, its author ended it):
				 * not tried, and its turn stays spent, as when its author ends the session that has it.
				 */
				line_done(l, d, OUT_NOT_JUDGED, h->kind == MSG_RECORD ?
						  psprintf("%s (%s)", h->rec.err ? h->rec.err : "nothing judged",
								   "not recorded: no background worker was free to record it") :
						  keeps && h->spent ?
						  psprintf("not judged: no background worker was free for a new session of its author after "
								   "the one started for it ended (max_worker_processes is %d): nothing is recorded, its "
								   "turn is spent, and its verdict stays as it was until its horizon",
								   max_worker_processes) : why);
				return;
			}
			l->since = GetCurrentTimestamp();
		}

		/* send what fits, without waiting; a message cut by a full queue goes on from where it was */
		while (l->nsent < l->qn)
		{
			Sent	   *s = &l->q[(l->qh + l->nsent) % PROOF_AHEAD];

			if (keeps && !s->spent)
				break;			/* (twelfth review) not before its turn is spent */
			r = shm_mq_send(proof_cur->req, s->msg.len, s->msg.data, true, true);
			if (r != SHM_MQ_SUCCESS)
				break;			/* WOULD_BLOCK: later; DETACHED: seen on the answers' queue */
			l->nsent++;
		}

		r = shm_mq_receive(proof_cur->ans, &n, &data, true);
		if (r == SHM_MQ_SUCCESS)
		{
			Msg			m;
			ProofAnswer what;
			Judgment	j;
			char	   *v;

			m.p = data;
			m.end = (const char *) data + n;
			what = (ProofAnswer) get_int(&m);
			j.out = (Outcome) get_int(&m);
			j.at = (TimestampTz) get_int(&m);
			j.err = get_bytes(&m, NULL);
			v = get_bytes(&m, NULL);
			if (what == ANSWER_DONE || what == ANSWER_SKIPPED)
			{
				d->c = h->c;
				d->kind = h->kind;
				d->j = j;
				d->verdict = v;
				d->recorded = what == ANSWER_DONE;
				d->skipped = what == ANSWER_SKIPPED;
				line_pop(l);
				return;
			}
			h->tries++;
			if (what == ANSWER_SPENT)
			{
				/* a spent worker ends by itself; a new one starts with no placeholder but its configuration's */
				line_restart(l, true);
				if (h->tries > 2)
				{
					if (h->kind == MSG_JUDGE)
					{
						line_unjudged(l, "not judged: a new session of its author has a custom setting its author's "
									  "session did not", false);
						continue;
					}
					line_done(l, d, OUT_NOT_JUDGED,
							  "not judged: a new session of its author has a custom setting its author's session did not");
					return;
				}
				continue;
			}
			/* failed: an error outside the proof, nothing judged; once more in a new worker */
			line_restart(l, true);
			if (h->tries > 1)
			{
				const char *why = psprintf("not judged: %s", j.err ? j.err : "its session failed");

				if (h->kind == MSG_JUDGE)
				{
					line_unjudged(l, why, false);
					continue;
				}
				line_done(l, d, OUT_NOT_JUDGED, why);
				return;
			}
			continue;
		}
		if (r == SHM_MQ_DETACHED)
		{
			ProofShared *sh = proof_cur->sh;

			pg_read_barrier();
			if (l->nsent > 0 && h->kind == MSG_JUDGE && pg_atomic_read_u32(&sh->judging) != 0)
			{
				Judgment	j;
				int32		by = sh->signaller;

				j.at = sh->started;
				if (by == 0 || by == sh->pid)
				{
					/* the proof ended the session it ran in: its own FATAL, its author's transaction_timeout */
					j.out = OUT_HALTED;
					j.err = "the proof ended the session that ran it: refuted, and not run again until it is asserted again";
				}
				else
				{
					j.out = OUT_INTERRUPTED;
					j.err = by > 0 ?
						psprintf("interrupted: the session that ran its proof was terminated by another process (pid %d) "
								 "while it ran: nothing is judged, and it stays due", by) :
						"interrupted: the session that ran its proof was terminated (by a sender not known) while it "
						"ran: nothing is judged, and it stays due";
				}
				line_restart(l, true);
				line_to_record(l, &j);
				continue;
			}
			/*
			 * (twelfth review) Nothing sent to it, the head's turn not spent yet: the keeper decides that, not a
			 * session its author can end. A new one starts once it is spent.
			 */
			if (keeps && !h->spent)
			{
				line_restart(l, true);
				continue;
			}
			/* gone before it began, or between claims: nothing judged; once more in a new worker */
			h->tries++;
			{
				int32		by = sh->signaller;
				int32		self = sh->pid;

				line_restart(l, true);
				if (h->tries > 1)
				{
					/*
					 * (tenth review) Twice, and not ended by another process: a session of its author does not start
					 * (its configuration, its connection). Recorded, for this claim and the author's others.
					 */
					if (h->kind == MSG_JUDGE && (by == 0 || by == self))
					{
						line_unjudged(l, "not judged: a new session of its author ended before it judged (see the server "
									  "log): its verdict stays as it was, and serves only until its horizon", true);
						continue;
					}
					line_done(l, d, OUT_NOT_JUDGED, h->spent ?
							  "not judged: the proof's own session was ended before it began: nothing is judged, its turn "
							  "is spent (twelfth review), and its verdict stays as it was until its horizon" :
							  "not judged: the proof's own session ended before it began (see the server log): nothing is "
							  "recorded, and it stays due");
					return;
				}
			}
			continue;
		}

		now = GetCurrentTimestamp();
		if (l->nsent > 0 && h->kind == MSG_JUDGE && pg_atomic_read_u32(&proof_cur->sh->judging) != 0)
		{
			pg_read_barrier();
			if (now - proof_cur->sh->started >= ((int64) l->timeout_ms + PROOF_GRACE_MS) * 1000)
			{
				Judgment	j;

				j.out = OUT_REFUTED;
				j.at = proof_cur->sh->started;
				j.err = psprintf("the proof took longer than %d ms (its session did not answer, and was ended)",
								 l->timeout_ms);
				line_restart(l, true);
				line_to_record(l, &j);
				continue;
			}
		}
		else if (now - l->since >= ((int64) l->timeout_ms + PROOF_GRACE_MS) * 1000)
		{
			/* a session that does not take what it is sent (it waits for a lock as it starts, or to record) */
			line_restart(l, true);
			line_done(l, d, OUT_NOT_JUDGED,
					  psprintf("not judged: the proof's own session did not take it within %lld ms: nothing is "
							   "recorded, and it stays due", (long long) l->timeout_ms + PROOF_GRACE_MS));
			d->stuck = true;
			return;
		}
		if (TimestampDifferenceExceeds(l->looked, now, PROOF_LOOK_MS))
		{
			int			via;

			l->looked = now;
			if ((via = waits_for_us(proof_cur)) != 0)
			{
				const char *key = h->c->key;

				line_restart(l, true);
				ereport(ERROR,
						(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
						 errmsg("phasevec: the proof of key %s waits for a lock this transaction holds", key),
						 via == MyProcPid ?
						 errdetail("A proof runs in a session of its own, which reads what is committed; this "
								   "transaction locked something it reads (an advisory lock, LOCK TABLE).") :
						 errdetail("It waits for process %d, which waits for this transaction: a proof runs in a "
								   "session of its own, and this transaction holds a lock (a read of a table, an "
								   "advisory lock) that a session queued before the proof waits for.", via),
						 errhint("Verify in a transaction of its own, that has read and locked nothing.")));
			}
		}
		(void) WaitLatch(MyLatch, WL_LATCH_SET | WL_TIMEOUT | WL_EXIT_ON_PM_DEATH, 100, wait_event);
		ResetLatch(MyLatch);
		CHECK_FOR_INTERRUPTS();
	}
}

typedef struct Readers
{
	int			n;
	Oid			role[64];
	bool		reads[64];
	bool		rls[64];
} Readers;

/* May the author still read the table (cached for one call), and does row-level security apply to it? */
static bool
author_reads(Readers *r, const Target *t, Oid author, bool *rls)
{
	for (int i = 0; i < r->n; i++)
		if (r->role[i] == author)
		{
			*rls = r->rls[i];
			return r->reads[i];
		}
	{
		bool		reads = may_read(t, author);

		*rls = reads && rls_for(t, author);
		if (r->n < 64)
		{
			r->role[r->n] = author;
			r->reads[r->n] = reads;
			r->rls[r->n] = *rls;
			r->n++;
		}
		return reads;
	}
}

/*
 * How a claim goes to a worker: a proof to judge, or (an author gone, or kept from the table) 'unproven' to record,
 * with no proof run.
 */
static ProofKind
claim_kind(const Claim *c, const Target *t, Readers *readers, bool *rls, Judgment *rec)
{
	*rls = false;
	memset(rec, 0, sizeof(Judgment));
	if (!c->author_known)
	{
		rec->out = OUT_UNPROVEN;
		rec->err = "the author of this proof is gone (dropped, or its name is another role's now): "
			"assert it again, or adopt it naming its author (phasevec.adopt)";
		return MSG_RECORD;
	}
	if (!author_reads(readers, t, c->author, rls))
	{
		rec->out = OUT_UNPROVEN;
		rec->err = psprintf("its author \"%s\" may no longer read %s: nothing is judged",
							GetUserNameFromId(c->author, false), t->src);
		return MSG_RECORD;
	}
	return MSG_JUDGE;
}

static int64
interval_usec(const Interval *iv)
{
	if (INTERVAL_NOT_FINITE(iv))
		return INTERVAL_IS_NOBEGIN(iv) ? 0 : PG_INT64_MAX;
	return iv->time + (int64) iv->day * USECS_PER_DAY + (int64) iv->month * DAYS_PER_MONTH * USECS_PER_DAY;
}

/* A proof (in its own session, or a recipe or a policy anywhere) cannot verify. */
static void
refuse_inside_proof(void)
{
	if (prove_in_progress || guard_active())
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("phasevec: a proof cannot run another proof")));
}

/*
 * (ninth review) A verdict is about a committed state that does not depend on its verifier's transaction. The proofs
 * read what is committed; a transaction that has written (it has a transaction id: a write, DDL, LOCK TABLE ... ACCESS
 * EXCLUSIVE) would have them judge a state it is about to replace, as if its writes were not there. Until the ninth
 * review such a verifier committed, together with its write, a 'verified' its write refutes. verify() itself writes
 * nothing in the caller's transaction: it may verify again in it.
 */
static void
require_no_writes(const char *what)
{
	/*
	 * (sixteenth review) verify() records what it judges, in sessions of its own that commit each verdict (and start
	 * background workers): its writes are not this transaction's, and READ ONLY did not stop them. A transaction (or a
	 * session, default_transaction_read_only; or a standby) that says it writes nothing records nothing through
	 * verify() either. yggdrasil's read-only acts ran every ygg_lector proof and committed 610 verdicts.
	 */
	PreventCommandIfReadOnly(what);
	PreventCommandDuringRecovery(what);
	if (TransactionIdIsValid(GetTopTransactionIdIfAny()))
		ereport(ERROR,
				(errcode(ERRCODE_ACTIVE_SQL_TRANSACTION),
				 errmsg("phasevec: proofs judge what is committed, and this transaction has written"),
				 errdetail("A proof runs in a session of its own and does not see this transaction's writes or DDL: "
						   "it would judge the state they replace, and its verdict would stand beside them."),
				 errhint("Verify in a transaction of its own, or before this transaction writes.")));
}

/*
 * The order a verify() call judges its claims in: those of one author together (one worker each), and among them
 * those that name fewer custom settings first (a worker that made one for a claim is not reused for a claim whose
 * author did not have it). Otherwise as _truth_due gave them.
 */
typedef struct Turn
{
	int			at;				/* in the due list */
	int			author;			/* the first place of its author in the due list */
	int			ncustom;
	char	   *custom;			/* the custom settings its author's session had, by name */
} Turn;

static int
turn_cmp(const void *a, const void *b)
{
	const Turn *x = (const Turn *) a;
	const Turn *y = (const Turn *) b;
	int			r;

	if (x->author != y->author)
		return x->author < y->author ? -1 : 1;
	if (x->ncustom != y->ncustom)
		return x->ncustom < y->ncustom ? -1 : 1;
	if ((r = strcmp(x->custom, y->custom)) != 0)
		return r;
	return x->at < y->at ? -1 : x->at > y->at ? 1 : 0;
}

static Turn *
turns(const Claim *claims, int n)
{
	Turn	   *t = palloc(sizeof(Turn) * Max(n, 1));

	for (int i = 0; i < n; i++)
	{
		StringInfoData s;

		t[i].at = i;
		t[i].author = i;
		for (int k = 0; k < i; k++)
			if (claims[k].author == claims[i].author)
			{
				t[i].author = t[k].author;
				break;
			}
		initStringInfo(&s);
		t[i].ncustom = 0;
		for (int e = 0; claims[i].env && e < claims[i].env->n; e++)
			if (strchr(claims[i].env->name[e], '.') != NULL)
			{
				appendStringInfo(&s, "%s,", claims[i].env->name[e]);
				t[i].ncustom++;
			}
		t[i].custom = s.data;
	}
	qsort(t, n, sizeof(Turn), turn_cmp);
	return t;
}

/* The verdict of a key as it reads now, read by the verifier (it writes nothing). */
static char *
verdict_as_owner(Oid owner, const Target *t, const char *key)
{
	MemoryContext keep = CurrentMemoryContext;
	char	   *v;
	Who			was;

	become(owner, &was);
	spi_connect();
	v = verdict_now(t, key, keep);
	SPI_finish();
	unbecome(&was);
	return v;
}

/* The row verify() returns for a claim done with: key, the verdict as it reads now, the error. None when skipped. */
static void
emit(ReturnSetInfo *rsinfo, Oid owner, const Target *t, const Done *d)
{
	Datum		values[3];
	bool		nulls[3] = {false, false, false};
	char	   *v = d->verdict;
	const char *err = d->j.err;

	if (d->skipped && d->kind == MSG_JUDGE)
		return;
	if (d->skipped)
		err = psprintf("%s (not recorded: another verify() holds the claim, or judged it since)",
					   err ? err : "nothing judged");
	if (!d->recorded)
		v = verdict_as_owner(owner, t, d->c->key);
	values[0] = CStringGetTextDatum(d->c->key);
	values[1] = v ? CStringGetTextDatum(v) : (Datum) 0;
	nulls[1] = v == NULL;
	values[2] = err ? CStringGetTextDatum(err) : (Datum) 0;
	nulls[2] = err == NULL;
	tuplestore_putvalues(rsinfo->setResult, rsinfo->setDesc, values, nulls);
}

/*
 * phasevec.verify(watch text, n int, every interval, budget interval, timeout_ms int, max_cost float8)
 *   RETURNS TABLE (key text, verdict text, error text)
 * The due proofs whose author the caller may act as (a gone author's claim is set unproven by anyone), oldest
 * first, while the budget lasts. Each proof runs in a session of its own, a new session of its author with its
 * author's settings, which takes the claim, judges it and commits the verdict.
 */
Datum
phasevec_verify(PG_FUNCTION_ARGS)
{
	ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
	Oid			caller = GetUserId();
	Oid			owner = function_owner(fcinfo);
	MemoryContext keep = CurrentMemoryContext;
	MemoryContext per;
	Target		target;
	Claim	   *claims = NULL;
	uint64		nclaims = 0;
	int64		budget_us;
	TimestampTz t0;
	Who			was;
	Readers		readers = {0};
	Turn	   *order;
	Line		l;

	for (int i = 0; i < 6; i++)
		if (PG_ARGISNULL(i))
			ereport(ERROR, (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED), errmsg("phasevec: verify() takes no NULL argument")));
	memset(&l, 0, sizeof(l));
	l.timeout_ms = PG_GETARG_INT32(4);
	l.max_cost = PG_GETARG_FLOAT8(5);
	require_clock(l.timeout_ms);
	refuse_inside_proof();
	require_fresh_snapshots();
	require_no_writes("phasevec.verify()");
	budget_us = interval_usec(PG_GETARG_INTERVAL_P(3));
	InitMaterializedSRF(fcinfo, 0);

	become(owner, &was);
	spi_connect();
	load_target(PG_GETARG_DATUM(0), false, &target, keep);
	{
		Oid			at[4] = {INT4OID, INT4OID, INTERVALOID, OIDOID};
		Datum		av[4] = {Int32GetDatum(target.watch), PG_GETARG_DATUM(1), PG_GETARG_DATUM(2),
		ObjectIdGetDatum(caller)};

		if (SPI_execute_with_args("SELECT " CLAIM_COLUMNS " FROM phasevec._truth_due($1, $2, $3, $4)",
								  4, at, av, NULL, true, 0) != SPI_OK_SELECT)
			elog(ERROR, "phasevec: the due proofs could not be read");
		nclaims = SPI_processed;
		claims = MemoryContextAlloc(keep, sizeof(Claim) * Max(nclaims, 1));
		for (uint64 i = 0; i < nclaims; i++)
			claim_from(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, &claims[i], keep);
	}
	SPI_finish();
	unbecome(&was);

	per = AllocSetContextCreate(CurrentMemoryContext, "phasevec verify", ALLOCSET_DEFAULT_SIZES);
	l.cx = AllocSetContextCreate(CurrentMemoryContext, "phasevec verify queue", ALLOCSET_DEFAULT_SIZES);
	l.owner = owner;
	l.caller = caller;
	l.t = &target;
	l.every = PG_GETARG_INTERVAL_P(2);
	t0 = GetCurrentTimestamp();
	order = turns(claims, (int) nclaims);
	PG_TRY();
	{
		uint64		k = 0;
		bool		over = false;
		bool		stuck = false;

		for (;;)
		{
			Done		d;

			/* queue the next claims while the budget lasts (a claim queued is judged, or said not to be) */
			while (l.qn < PROOF_AHEAD && k < (uint64) nclaims && !over && !stuck)
			{
				const Claim *c = &claims[order[k].at];
				bool		rls;
				Judgment	rec;
				ProofKind	kind;

				if (GetCurrentTimestamp() - t0 >= budget_us)
				{
					over = true;
					break;
				}
				/* _truth_due already left out the authors the caller may not act as; checked again here */
				if (c->author_known && !has_privs_of_role(caller, c->author))
				{
					k++;
					continue;
				}
				kind = claim_kind(c, &target, &readers, &rls, &rec);
				if (kind == MSG_JUDGE && OidIsValid(l.unjudgeable) && c->author == l.unjudgeable)
				{
					/* no session of its author started in this call: recorded so, not tried again */
					kind = MSG_RECORD;
					rec.out = OUT_NO_VERDICT;
					rec.at = 0;
					rec.err = psprintf("%s (an earlier claim of its author, in this call)", l.unjudgeable_why);
				}
				if (kind == MSG_JUDGE && !line_takes(&l, c->author))
					break;
				if (!line_push(&l, c, kind, rls, &rec))
					break;
				k++;
			}
			if (l.qn == 0)
				break;
			{
				MemoryContext o = MemoryContextSwitchTo(per);

				if (stuck)
				{
					/* a session did not take a claim in time: the rest are not sent to another */
					line_done(&l, &d, OUT_NOT_JUDGED,
							  "not judged: a proof's own session did not take an earlier claim of this call in time: "
							  "nothing is recorded, and it stays due");
				}
				else
					line_next(&l, &d);
				stuck = stuck || d.stuck;
				emit(rsinfo, owner, &target, &d);
				MemoryContextSwitchTo(o);
				MemoryContextReset(per);
			}
		}
	}
	PG_CATCH();
	{
		proof_stop_all(true);
		PG_RE_THROW();
	}
	PG_END_TRY();
	proof_stop_all(false);
	MemoryContextDelete(l.cx);
	MemoryContextDelete(per);
	return (Datum) 0;
}

/*
 * phasevec.verify_one(watch text, key text, timeout_ms int, max_cost float8) RETURNS text
 * One key, now or out of turn, as its author, in a session of its own. NULL when the key has no proof or was
 * replaced; an error when the proof has no author, the caller may not act as it, or no session could judge it.
 */
Datum
phasevec_verify_one(PG_FUNCTION_ARGS)
{
	Oid			caller = GetUserId();
	Oid			owner = function_owner(fcinfo);
	MemoryContext keep = CurrentMemoryContext;
	Target		target;
	Claim		c;
	Done		d;
	Who			was;
	Readers		readers = {0};
	Line		l;
	bool		rls;
	Judgment	rec;
	ProofKind	kind;

	for (int i = 0; i < 4; i++)
		if (PG_ARGISNULL(i))
			ereport(ERROR, (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED), errmsg("phasevec: verify_one() takes no NULL argument")));
	memset(&l, 0, sizeof(l));
	l.timeout_ms = PG_GETARG_INT32(2);
	l.max_cost = PG_GETARG_FLOAT8(3);
	require_clock(l.timeout_ms);
	refuse_inside_proof();
	require_fresh_snapshots();
	require_no_writes("phasevec.verify_one()");

	become(owner, &was);
	spi_connect();
	load_target(PG_GETARG_DATUM(0), false, &target, keep);
	{
		Oid			at[2] = {INT4OID, TEXTOID};
		Datum		av[2] = {Int32GetDatum(target.watch), PG_GETARG_DATUM(1)};

		if (SPI_execute_with_args("SELECT " CLAIM_COLUMNS " FROM phasevec._truth_of($1, $2)",
								  2, at, av, NULL, true, 1) != SPI_OK_SELECT)
			elog(ERROR, "phasevec: the proof could not be read");
		if (SPI_processed != 1)
		{
			SPI_finish();
			unbecome(&was);
			PG_RETURN_NULL();
		}
		claim_from(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, &c, keep);
	}
	SPI_finish();
	unbecome(&was);

	if (!OidIsValid(c.author))
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("phasevec: the proof of key %s has no author (asserted before 0.20.0): assert it again", c.key),
				 errhint("phasevec.adopt(watch, author) asserts again, naming their author, the proofs of a watch whose author is unknown or gone.")));
	if (c.author_known && !has_privs_of_role(caller, c.author))
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("phasevec: role \"%s\" cannot run a proof as its author \"%s\"",
						GetUserNameFromId(caller, false), GetUserNameFromId(c.author, false)),
				 errhint("Proofs run with their author's rights: verify as the author or as a role that has its privileges.")));
	l.cx = AllocSetContextCreate(CurrentMemoryContext, "phasevec verify queue", ALLOCSET_DEFAULT_SIZES);
	l.owner = owner;
	l.caller = caller;
	l.t = &target;
	l.every = NULL;
	kind = claim_kind(&c, &target, &readers, &rls, &rec);
	(void) line_push(&l, &c, kind, rls, &rec);
	PG_TRY();
	{
		line_next(&l, &d);
	}
	PG_CATCH();
	{
		proof_stop_all(true);
		PG_RE_THROW();
	}
	PG_END_TRY();
	proof_stop_all(false);
	if (!d.recorded || d.j.out == OUT_INTERRUPTED || d.j.out == OUT_NO_VERDICT)
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("phasevec: verify_one() could not judge key %s", c.key),
				 errdetail("%s.", d.j.err ? d.j.err : "nothing judged")));
	if (d.verdict == NULL)
		PG_RETURN_NULL();
	PG_RETURN_TEXT_P(cstring_to_text(d.verdict));
}

/* -------------------------------------------------------------------------------------- asserting a claim -- */

/*
 * Record a claim as `author`: what it vouches for is the row's text as the recipe renders it now (as the table's
 * owner, in the pinned settings), and the proof will run with `env`, the settings it was written in. The author must
 * read the table, and with row-level security see the row; a key with no row it sees is bound to no text, and its
 * proof never verifies until asserted again. SPI connected, as anyone; writes as the owner.
 */
static void
assert_claim(Oid owner, Oid author, Datum watch, Datum key, Datum proof, bool proof_null, Datum topic,
			 bool topic_null, Datum support, bool support_null, Datum expires, bool expires_null, ArrayType *env)
{
	MemoryContext keep = CurrentMemoryContext;
	Oid			types[9] = {TEXTOID, TEXTOID, TEXTOID, TEXTOID, JSONBOID, TIMESTAMPTZOID, OIDOID, BYTEAOID,
	TEXTARRAYOID};
	Datum		values[9];
	char		nulls[10] = "         ";
	bytea	   *seen = NULL;
	Who			was;
	Target		t;

	become(owner, &was);
	load_target(watch, false, &t, keep);
	unbecome(&was);
	if (!proof_null)
	{
		char	   *k = TextDatumGetCString(key);
		char	   *one[1] = {k};
		Rendered	r;

		must_read(&t, author);
		if (!rls_for(&t, author) || key_visible(&t, author, GUARD_READER, NULL, k))
		{
			render_rows(&t, text_array(one, 1), &r, keep);
			if (r.n > 0)
				seen = r.hash[0];
		}
	}
	values[0] = watch;
	values[1] = key;
	values[2] = proof;
	nulls[2] = proof_null ? 'n' : ' ';
	values[3] = topic;
	nulls[3] = topic_null ? 'n' : ' ';
	values[4] = support;
	nulls[4] = support_null ? 'n' : ' ';
	values[5] = expires;
	nulls[5] = expires_null ? 'n' : ' ';
	values[6] = ObjectIdGetDatum(author);
	values[7] = seen ? PointerGetDatum(seen) : (Datum) 0;
	nulls[7] = seen ? ' ' : 'n';
	values[8] = PointerGetDatum(env);

	become(owner, &was);
	if (SPI_execute_with_args("SELECT phasevec._assert_set($1, $2, $3, $4, $5, $6, $7, $8, $9)",
							  9, types, values, nulls, false, 1) != SPI_OK_SELECT)
		elog(ERROR, "phasevec: the claim was not recorded");
	unbecome(&was);
}

/*
 * phasevec.assert(watch text, key text, proof text, topic text, support jsonb, expires_at timestamptz)
 * Records the claim with its author, the current user of the CALLER (a SECURITY DEFINER wrapper vouches with its
 * owner's rights, and that owner is the author), and the caller's settings, which the proof will run with.
 */
Datum
phasevec_assert(PG_FUNCTION_ARGS)
{
	Oid			author = GetUserId();
	Oid			owner = function_owner(fcinfo);

	if (PG_ARGISNULL(0) || PG_ARGISNULL(1))
		ereport(ERROR, (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED), errmsg("phasevec: a claim needs a watch and a key")));
	spi_connect();
	assert_claim(owner, author, PG_GETARG_DATUM(0), PG_GETARG_DATUM(1),
				 PG_ARGISNULL(2) ? (Datum) 0 : PG_GETARG_DATUM(2), PG_ARGISNULL(2),
				 PG_ARGISNULL(3) ? (Datum) 0 : PG_GETARG_DATUM(3), PG_ARGISNULL(3),
				 PG_ARGISNULL(4) ? (Datum) 0 : PG_GETARG_DATUM(4), PG_ARGISNULL(4),
				 PG_ARGISNULL(5) ? (Datum) 0 : PG_GETARG_DATUM(5), PG_ARGISNULL(5),
				 guard_env_now());
	SPI_finish();
	PG_RETURN_VOID();
}

static bool
in_text_array(ArrayType *a, const char *s)
{
	Datum	   *d;
	bool	   *nulls;
	int			n;

	if (a == NULL)
		return false;
	deconstruct_array_builtin(a, TEXTOID, &d, &nulls, &n);
	for (int i = 0; i < n; i++)
		if (!nulls[i] && strcmp(TextDatumGetCString(d[i]), s) == 0)
			return true;
	return false;
}

/*
 * phasevec.adopt(watch text, author regrole, keys text[] DEFAULT NULL, superuser_keys text[] DEFAULT NULL)
 *   RETURNS TABLE (key text, proof text, former_author text, adopted boolean, note text)
 * Asserts again, in the name of `author`, the proofs of a watch whose author is unknown (asserted before 0.20.0) or
 * gone (dropped, or its name is another role's now); with keys, only those. Authority is never handed over
 * silently: the new author is named, the caller must already hold its privileges (be it, SET ROLE to it, or be
 * granted it), every proof is returned with its former author, and a superuser becomes the author of a key only when
 * that key is named in superuser_keys (an orphaned proof may be anyone's SQL, a role can orphan its own on purpose,
 * and as a superuser's it would run with every right). The proofs run with the caller's settings.
 */
Datum
phasevec_adopt(PG_FUNCTION_ARGS)
{
	ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
	Oid			caller = GetUserId();
	Oid			owner = function_owner(fcinfo);
	Oid			author;
	ArrayType  *keys = PG_ARGISNULL(2) ? NULL : PG_GETARG_ARRAYTYPE_P(2);
	ArrayType  *su_keys = PG_ARGISNULL(3) ? NULL : PG_GETARG_ARRAYTYPE_P(3);
	bool		su;
	MemoryContext keep = CurrentMemoryContext;
	Target		t;
	Who			was;
	SPITupleTable *orphans;
	uint64		norphans;
	ArrayType  *env = guard_env_now();

	if (PG_ARGISNULL(0) || PG_ARGISNULL(1))
		ereport(ERROR,
				(errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED),
				 errmsg("phasevec: adopt() takes a watch and the role that is to be the author of its proofs")));
	author = PG_GETARG_OID(1);
	if (!has_privs_of_role(caller, author))
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("phasevec: role \"%s\" cannot make \"%s\" the author of proofs",
						GetUserNameFromId(caller, false), GetUserNameFromId(author, false)),
				 errhint("Adopt as that role (SET ROLE), or as a role that has its privileges.")));
	su = superuser_arg(author);
	InitMaterializedSRF(fcinfo, 0);

	spi_connect();
	become(owner, &was);
	load_target(PG_GETARG_DATUM(0), false, &t, keep);
	{
		Oid			at[1] = {INT4OID};
		Datum		av[1] = {Int32GetDatum(t.watch)};

		if (SPI_execute_with_args("SELECT x.key, x.proof, x.topic, x.support, x.expires_at, x.asserted_by::pg_catalog.text "
								  "FROM phasevec.truth x WHERE x.watch OPERATOR(pg_catalog.=) $1 "
								  "AND x.proof IS NOT NULL AND x.verdict OPERATOR(pg_catalog.<>) 'replaced' "
								  "AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles r "
								  "WHERE r.oid OPERATOR(pg_catalog.=) x.asserted_by_oid "
								  "AND r.rolname OPERATOR(pg_catalog.=) x.asserted_by) ORDER BY x.key",
								  1, at, av, NULL, true, 0) != SPI_OK_SELECT)
			elog(ERROR, "phasevec: the proofs could not be read");
	}
	unbecome(&was);
	orphans = SPI_tuptable;
	norphans = SPI_processed;
	must_read(&t, author);
	for (uint64 i = 0; i < norphans; i++)
	{
		HeapTuple	tup = orphans->vals[i];
		TupleDesc	td = orphans->tupdesc;
		bool		n_key,
					n_proof,
					n_topic,
					n_support,
					n_exp;
		Datum		key = SPI_getbinval(tup, td, 1, &n_key);
		Datum		proof = SPI_getbinval(tup, td, 2, &n_proof);
		Datum		topic = SPI_getbinval(tup, td, 3, &n_topic);
		Datum		support = SPI_getbinval(tup, td, 4, &n_support);
		Datum		exp = SPI_getbinval(tup, td, 5, &n_exp);
		char	   *former = SPI_getvalue(tup, td, 6);
		char	   *k = TextDatumGetCString(key);
		Datum		values[5];
		bool		nulls[5] = {false, false, false, false, false};
		bool		adopted = false;
		const char *note;

		if (keys && !in_text_array(keys, k))
			continue;
		if (su && !in_text_array(su_keys, k))
			note = "not adopted: its author would be a superuser; name the key in superuser_keys to adopt it";
		else
		{
			assert_claim(owner, author, PG_GETARG_DATUM(0), key, proof, n_proof, topic, n_topic,
						 support, n_support, exp, n_exp, env);
			adopted = true;
			note = su ? "adopted: it runs with a superuser's rights" : "adopted";
		}
		values[0] = CStringGetTextDatum(k);
		values[1] = proof;
		nulls[1] = n_proof;
		values[2] = former ? CStringGetTextDatum(former) : (Datum) 0;
		nulls[2] = former == NULL;
		values[3] = BoolGetDatum(adopted);
		values[4] = CStringGetTextDatum(note);
		{
			MemoryContext o = MemoryContextSwitchTo(rsinfo->econtext->ecxt_per_query_memory);

			tuplestore_putvalues(rsinfo->setResult, rsinfo->setDesc, values, nulls);
			MemoryContextSwitchTo(o);
		}
	}
	SPI_finish();
	return (Datum) 0;
}

/* --------------------------------------------------------------------------------------- the watch trigger -- */

/*
 * phasevec._observe(): the watch trigger, AFTER INSERT OR UPDATE OR DELETE FOR EACH ROW, with the watch's id as its
 * first argument. It belongs to that watch's table and to no other; it renders the row it fires for (the recipe as
 * the table's owner, in the guard and the pinned settings) and notes it, or forgets the key a row left. Nothing a
 * caller passes reaches phasevec.sources: in the first cuts of 0.20.0 _note() took a key and a hash from whoever
 * called it, and a writer limited by row-level security, or holding UPDATE on one column, forged, invented and
 * forgot the keys of every row of the watch.
 */
#define OBSERVE_SQL \
	"SELECT x.ok, x.nk, x.b, pg_catalog.sha256(pg_catalog.convert_to(COALESCE(x.b, ''), 'UTF8')) FROM " \
	"(SELECT ($1).%s::pg_catalog.text AS ok, r.%s::pg_catalog.text AS nk, (%s)::pg_catalog.text AS b " \
	"FROM (SELECT ($2).*) r) x"
#define OBSERVE_OLD_SQL "SELECT ($1).%s::pg_catalog.text"

static SPIPlanPtr note_set_plan = NULL;

static void
note_set(int32 watch, const char *key, Datum hash, bool hash_null, const char *body)
{
	Oid			at[4] = {INT4OID, TEXTOID, BYTEAOID, TEXTOID};
	Datum		av[4] = {Int32GetDatum(watch), CStringGetTextDatum(key), hash,
	body ? CStringGetTextDatum(body) : (Datum) 0};
	char		nulls[5] = {' ', ' ', hash_null ? 'n' : ' ', body ? ' ' : 'n', '\0'};

	if (SPI_execute_plan(kept_plan(&note_set_plan, "SELECT phasevec._note_set($1, $2, $3, $4)", 4, at),
						 av, nulls, false, 1) != SPI_OK_SELECT)
		elog(ERROR, "phasevec: the row was not noted");
}

/*
 * The watch trigger's reading of a row, prepared once per watch and row type (a partition's row is read as one of
 * the watch's table) and kept: prepared inside the guard, as the table's owner in the pinned settings, as it always
 * runs. A watch whose recipe, key column or table owner changed is prepared again, and so is one whose table's
 * columns changed: the plan binds them. "(SELECT ($2).*) r" is expanded by column number when it is parsed, and the
 * composite parameter gives the plan cache no dependency on the table, so in the fifth cut a session that wrote
 * before a RENAME, DROP and ADD, or ALTER COLUMN TYPE kept hashing the old column (a changed row stayed 'fresh'), or
 * failed every later write with "attribute N has wrong type", until it reconnected. The plan is kept with the row
 * type it was parsed for (names, types, typmods, collations, dropped columns: equalRowTypes), and parsed again when
 * the table's is another.
 */
typedef struct ObserveKey
{
	int32		watch;
	Oid			rowtype;
} ObserveKey;

typedef struct ObservePlans
{
	ObserveKey	key;
	Oid			relowner;
	char	   *key_col;
	char	   *recipe;
	TupleDesc	desc;			/* the table's columns when it was parsed */
	SPIPlanPtr	plan[2];		/* the old row's key; the new row's keys, text and hash */
} ObservePlans;

static HTAB *observe_plans = NULL;

static SPIPlanPtr
observe_plan(const Target *t, Oid rowtype, TupleDesc desc, bool new_row)
{
	ObserveKey	k;
	ObservePlans *e;
	bool		found;
	Oid			at[2] = {rowtype, rowtype};

	if (observe_plans == NULL)
	{
		HASHCTL		ctl;

		ctl.keysize = sizeof(ObserveKey);
		ctl.entrysize = sizeof(ObservePlans);
		observe_plans = hash_create("phasevec watch trigger plans", 16, &ctl, HASH_ELEM | HASH_BLOBS);
	}
	memset(&k, 0, sizeof(k));
	k.watch = t->watch;
	k.rowtype = rowtype;
	e = hash_search(observe_plans, &k, HASH_ENTER, &found);
	if (!found)
	{
		e->key_col = e->recipe = NULL;
		e->desc = NULL;
		e->plan[0] = e->plan[1] = NULL;
	}
	if (e->key_col == NULL || e->recipe == NULL || e->desc == NULL || e->relowner != t->relowner ||
		strcmp(e->key_col, t->key_col) != 0 || strcmp(e->recipe, t->recipe) != 0 || !equalRowTypes(e->desc, desc))
	{
		MemoryContext o;

		for (int i = 0; i < 2; i++)
			if (e->plan[i] != NULL)
				SPI_freeplan(e->plan[i]);
		e->plan[0] = e->plan[1] = NULL;
		if (e->key_col)
			pfree(e->key_col);
		if (e->recipe)
			pfree(e->recipe);
		if (e->desc)
			FreeTupleDesc(e->desc);
		e->key_col = e->recipe = NULL;
		e->desc = NULL;
		e->relowner = t->relowner;
		e->key_col = MemoryContextStrdup(TopMemoryContext, t->key_col);
		e->recipe = MemoryContextStrdup(TopMemoryContext, t->recipe);
		o = MemoryContextSwitchTo(TopMemoryContext);
		e->desc = CreateTupleDescCopy(desc);
		MemoryContextSwitchTo(o);
	}
	if (new_row)
		return kept_plan(&e->plan[1], psprintf(OBSERVE_SQL, t->key_col, t->key_col, t->recipe), 2, at);
	return kept_plan(&e->plan[0], psprintf(OBSERVE_OLD_SQL, t->key_col), 1, at);
}

Datum
phasevec_observe(PG_FUNCTION_ARGS)
{
	TriggerData *td = (TriggerData *) fcinfo->context;
	Oid			owner = function_owner(fcinfo);
	MemoryContext keep = CurrentMemoryContext;
	Relation	rel;
	HeapTuple	oldt = NULL;
	HeapTuple	newt = NULL;
	char	   *old_key = NULL;
	char	   *new_key = NULL;
	char	   *body = NULL;
	Datum		hash = (Datum) 0;
	int32		watch;
	Target		t;
	Who			was;

	if (!CALLED_AS_TRIGGER(fcinfo))
		ereport(ERROR, (errcode(ERRCODE_E_R_I_E_TRIGGER_PROTOCOL_VIOLATED),
						errmsg("phasevec: _observe() is the watch trigger, not a function to call")));
	if (!TRIGGER_FIRED_AFTER(td->tg_event) || !TRIGGER_FIRED_FOR_ROW(td->tg_event) ||
		td->tg_trigger->tgnargs < 1)
		ereport(ERROR, (errcode(ERRCODE_E_R_I_E_TRIGGER_PROTOCOL_VIOLATED),
						errmsg("phasevec: _observe() runs AFTER each row, with the watch's id")));
	rel = td->tg_relation;
	watch = pg_strtoint32(td->tg_trigger->tgargs[0]);
	if (TRIGGER_FIRED_BY_INSERT(td->tg_event))
		newt = td->tg_trigtuple;
	else if (TRIGGER_FIRED_BY_UPDATE(td->tg_event))
	{
		oldt = td->tg_trigtuple;
		newt = td->tg_newtuple;
	}
	else if (TRIGGER_FIRED_BY_DELETE(td->tg_event))
		oldt = td->tg_trigtuple;
	else
		ereport(ERROR, (errcode(ERRCODE_E_R_I_E_TRIGGER_PROTOCOL_VIOLATED),
						errmsg("phasevec: _observe() notes inserts, updates and deletes")));

	spi_connect();
	become(owner, &was);
	load_target(Int32GetDatum(watch), true, &t, keep);
	unbecome(&was);
	/* its watch's table, or a partition of it (a trigger on a partitioned table fires on the partition) */
	if (t.relid != RelationGetRelid(rel) &&
		!(rel->rd_rel->relispartition && list_member_oid(get_partition_ancestors(RelationGetRelid(rel)), t.relid)))
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("phasevec: trigger \"%s\" on %s is not watch %d's: that watch reads %s",
						td->tg_trigger->tgname, RelationGetRelationName(rel), watch, t.src)));
	{
		Guard		g;
		MemoryContext cx = CurrentMemoryContext;
		volatile int mark = guard_mark();
		Oid			rowtype = RelationGetForm(rel)->reltype;
		TupleDesc	desc = RelationGetDescr(rel);

		/*
		 * A partition's row is read as a row of the watch's table, in its columns and their order: the recipe sees
		 * the same r here as in _render() and verify(), which read the table. Until the sixth review it saw the
		 * partition's own row type, and a partition whose columns stood in another order (attached, or after a DROP
		 * and ADD) noted a whole-row recipe's text (r::text, row_to_json(r)) in that order: its claims never read
		 * as the text asserted, and its rows were indexed with that text.
		 */
		if (t.relid != RelationGetRelid(rel))
		{
			TupleDesc	tdesc = lookup_rowtype_tupdesc_copy(get_rel_type_id(t.relid), -1);
			TupleConversionMap *map = convert_tuples_by_name(desc, tdesc);

			if (map != NULL)
			{
				if (oldt)
					oldt = execute_attr_map_tuple(oldt, map);
				if (newt)
					newt = execute_attr_map_tuple(newt, map);
			}
			desc = tdesc;
			rowtype = tdesc->tdtypeid;
		}

		PG_TRY();
		{
			Datum		av[2];
			char		nulls[3] = {oldt ? ' ' : 'n', newt ? ' ' : 'n', '\0'};
			MemoryContext o;

			av[0] = oldt ? heap_copy_tuple_as_datum(oldt, desc) : (Datum) 0;
			av[1] = newt ? heap_copy_tuple_as_datum(newt, desc) : (Datum) 0;
			guard_enter(&g, t.relowner, GUARD_RENDER, NULL);
			if (SPI_execute_plan(observe_plan(&t, rowtype, desc, newt != NULL), av, nulls, true, 1)
				!= SPI_OK_SELECT || SPI_processed != 1)
				elog(ERROR, "phasevec: the row could not be read");
			o = MemoryContextSwitchTo(keep);
			{
				HeapTuple	tup = SPI_tuptable->vals[0];
				TupleDesc	rd = SPI_tuptable->tupdesc;
				char	   *s = SPI_getvalue(tup, rd, 1);

				old_key = s ? pstrdup(s) : NULL;
				if (newt)
				{
					bool		isnull;

					s = SPI_getvalue(tup, rd, 2);
					new_key = s ? pstrdup(s) : NULL;
					s = SPI_getvalue(tup, rd, 3);
					body = s ? pstrdup(s) : NULL;
					hash = datumCopy(SPI_getbinval(tup, rd, 4, &isnull), false, -1);
				}
			}
			MemoryContextSwitchTo(o);
			guard_leave(&g);
		}
		PG_CATCH();
		{
			ReThrowError(guard_catch(mark, cx));
		}
		PG_END_TRY();
	}
	become(owner, &was);
	if (old_key != NULL && (new_key == NULL || strcmp(old_key, new_key) != 0))
		note_set(t.watch, old_key, (Datum) 0, true, NULL);
	if (new_key != NULL)
		note_set(t.watch, new_key, hash, false, body);
	unbecome(&was);
	SPI_finish();
	return PointerGetDatum(NULL);
}

/* --------------------------------------------------------------------------------------- reading the rows -- */

/*
 * phasevec._render(watch text, keys text[]) RETURNS TABLE (key text, body text, text_hash bytea)
 * The rows of a watch (keys NULL: all of them) as its recipe renders them: as the table's owner, in the guard and
 * the pinned settings. For a caller that may SELECT the table, and with row-level security only the rows it sees.
 * next(), lexical(), audit_sample() and watch() read through it.
 */
Datum
phasevec_render(PG_FUNCTION_ARGS)
{
	ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
	Oid			caller = GetUserId();
	Oid			owner = function_owner(fcinfo);
	MemoryContext keep = CurrentMemoryContext;
	ArrayType  *keys = PG_ARGISNULL(1) ? NULL : PG_GETARG_ARRAYTYPE_P(1);
	Target		t;
	Rendered	r;
	int			nest;

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();
	InitMaterializedSRF(fcinfo, 0);
	load_target_as(owner, PG_GETARG_DATUM(0), false, &t, keep);
	must_read(&t, caller);
	nest = guard_pin_settings();
	spi_connect();
	keys = keys_for_reader(&t, caller, keys);
	render_rows(&t, keys, &r, keep);
	SPI_finish();
	guard_unpin_settings(nest);
	for (int i = 0; i < r.n; i++)
	{
		Datum		values[3] = {CStringGetTextDatum(r.key[i]), r.body[i] ? CStringGetTextDatum(r.body[i]) : (Datum) 0,
		PointerGetDatum(r.hash[i])};
		bool		nulls[3] = {false, r.body[i] == NULL, false};

		tuplestore_putvalues(rsinfo->setResult, rsinfo->setDesc, values, nulls);
	}
	return (Datum) 0;
}

/*
 * phasevec.brief(watch text, budget int) RETURNS TABLE (key text, verdict text, net_use bigint, line text)
 * What a watch still holds as true, best first, inside a character budget: for a caller that may SELECT the table
 * (and with row-level security, its rows), nothing for anyone else. The line is the row's text as the recipe renders
 * it (as the table's owner, in the guard); a key reads 'verified' only if that line is the text its verdict judged.
 * Until 0.20.0 brief() ran the recipe with its caller's full rights and settings: a table owner's cast made a
 * superuser reading a brief grant it superuser.
 */
#define BRIEF_CHUNK 256

Datum
phasevec_brief(PG_FUNCTION_ARGS)
{
	ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
	Oid			caller = GetUserId();
	Oid			owner = function_owner(fcinfo);
	MemoryContext keep = CurrentMemoryContext;
	int32		budget;
	int64		used = 0;
	Target		t;
	Who			was;
	char	  **key;
	char	  **verdict;
	int64	   *net;
	bytea	  **judged;
	uint64		n;
	int			nest;

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();
	budget = PG_ARGISNULL(1) ? 0 : PG_GETARG_INT32(1);
	if (budget < 1)
		ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE), errmsg("phasevec: a brief needs a positive budget")));
	InitMaterializedSRF(fcinfo, 0);
	load_target_as(owner, PG_GETARG_DATUM(0), false, &t, keep);
	if (!may_read(&t, caller))
		return (Datum) 0;

	spi_connect();
	become(owner, &was);
	{
		Oid			at[1] = {TEXTOID};
		Datum		av[1] = {PG_GETARG_DATUM(0)};
		MemoryContext o;

		if (SPI_execute_with_args("SELECT key, verdict, net_use, judged FROM phasevec._brief_keys($1)",
								  1, at, av, NULL, true, 0) != SPI_OK_SELECT)
			elog(ERROR, "phasevec: the keys of the brief could not be read");
		n = SPI_processed;
		o = MemoryContextSwitchTo(keep);
		key = palloc(sizeof(char *) * Max(n, 1));
		verdict = palloc(sizeof(char *) * Max(n, 1));
		net = palloc(sizeof(int64) * Max(n, 1));
		judged = palloc(sizeof(bytea *) * Max(n, 1));
		for (uint64 i = 0; i < n; i++)
		{
			HeapTuple	tup = SPI_tuptable->vals[i];
			TupleDesc	td = SPI_tuptable->tupdesc;
			bool		isnull;
			Datum		d;

			key[i] = pstrdup(SPI_getvalue(tup, td, 1));
			verdict[i] = pstrdup(SPI_getvalue(tup, td, 2));
			net[i] = DatumGetInt64(SPI_getbinval(tup, td, 3, &isnull));
			d = SPI_getbinval(tup, td, 4, &isnull);
			judged[i] = isnull ? NULL : DatumGetByteaPCopy(d);
		}
		MemoryContextSwitchTo(o);
	}
	unbecome(&was);

	nest = guard_pin_settings();
	for (uint64 from = 0; from < n && used < budget; from += BRIEF_CHUNK)
	{
		int			m = (int) Min((uint64) BRIEF_CHUNK, n - from);
		Rendered	r;
		ArrayType  *keys = keys_for_reader(&t, caller, text_array(key + from, m));

		render_rows(&t, keys, &r, keep);
		for (int i = 0; i < m && used < budget; i++)
		{
			uint64		x = from + i;
			int			at = -1;
			int64		len;
			Datum		values[4];
			bool		nulls[4] = {false, false, false, false};

			for (int y = 0; y < r.n && at < 0; y++)
				if (strcmp(r.key[y], key[x]) == 0)
					at = y;
			if (at < 0 || r.body[at] == NULL)
				continue;		/* gone, or hidden from the caller, or NULL */
			len = DatumGetInt32(DirectFunctionCall1(textlen, CStringGetTextDatum(r.body[at])));
			if (used + len > budget)
				continue;
			used += len;
			values[0] = CStringGetTextDatum(key[x]);
			/* 0.20.0: the verdict is about a text; this is the text served */
			values[1] = CStringGetTextDatum(strcmp(verdict[x], "verified") == 0 && !same_bytes(judged[x], r.hash[at])
											? "unproven" : verdict[x]);
			values[2] = Int64GetDatum(net[x]);
			values[3] = CStringGetTextDatum(r.body[at]);
			tuplestore_putvalues(rsinfo->setResult, rsinfo->setDesc, values, nulls);
		}
	}
	SPI_finish();
	guard_unpin_settings(nest);
	return (Datum) 0;
}

/* ------------------------------------------------------------------------------------ the door to verdicts -- */

/*
 * The SQL functions recall, disputes, replacement and truth_coverage are this one C function. It knows who calls
 * it; it shows a watch (the first argument) only to a role that may SELECT its table, and nothing to anyone else;
 * then it runs phasevec._door_<name>(the same arguments, and the keys of the rows the role sees) as the extension's
 * owner. With row-level security on the table for that role, the body computes over those keys only, and of its
 * result only the rows whose keys (columns key, key_a, key_b) the role sees are shown. Until 0.20.0 these were SECURITY DEFINER and open
 * to PUBLIC: any role with USAGE on the schema read the keys, verdicts, topics, reasons and support of every watch.
 */
Datum
phasevec_door(PG_FUNCTION_ARGS)
{
	ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
	Oid			caller = GetUserId();
	Oid			owner = function_owner(fcinfo);
	MemoryContext keep = CurrentMemoryContext;
	HeapTuple	pt;
	Form_pg_proc pf;
	char	   *name;
	int			nargs;
	Oid		   *argtypes;
	Datum	   *args;
	char	   *nulls;
	StringInfoData q;
	Target		t;
	Who			was;
	bool		rls;
	TupleDesc	rtd;
	int			keycols[3];
	int			nkeycols = 0;
	int			keyarg = -1;
	ArrayType  *visible = NULL;
	char	  **seen = NULL;
	int			nseen = 0;

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();
	pt = SearchSysCache1(PROCOID, ObjectIdGetDatum(fcinfo->flinfo->fn_oid));
	if (!HeapTupleIsValid(pt))
		elog(ERROR, "phasevec: cache lookup failed for function %u", fcinfo->flinfo->fn_oid);
	pf = (Form_pg_proc) GETSTRUCT(pt);
	name = pstrdup(NameStr(pf->proname));
	nargs = pf->pronargs;
	argtypes = palloc(sizeof(Oid) * nargs);
	memcpy(argtypes, pf->proargtypes.values, sizeof(Oid) * nargs);
	{
		Oid		   *types;
		char	  **names;
		char	   *modes;
		int			n = get_func_arg_info(pt, &types, &names, &modes);

		for (int i = 0; names && i < n && i < nargs; i++)
			if (names[i] && strcmp(names[i], "p_key") == 0)
				keyarg = i;
	}
	ReleaseSysCache(pt);
	InitMaterializedSRF(fcinfo, 0);

	load_target_as(owner, PG_GETARG_DATUM(0), false, &t, keep);
	if (!may_read(&t, caller))
		return (Datum) 0;
	rls = rls_for(&t, caller);
	/* a key asked about is a row too: one the caller does not see gets nothing */
	if (rls && keyarg >= 0 && (PG_ARGISNULL(keyarg) || !key_visible_out(&t, caller, TextDatumGetCString(PG_GETARG_DATUM(keyarg)))))
		return (Datum) 0;

	/*
	 * With row-level security the body computes over the keys of the rows the caller sees (its last argument), so no
	 * field carries a hidden row: not the rows, not disputed_by, not a replacement chain or its reasons, not a count.
	 * Until the third cut of 0.20.0 only the result rows were filtered, and disputed_by named hidden keys.
	 */
	spi_connect();
	if (rls)
	{
		nseen = visible_keys(&t, caller, GUARD_READER, NULL, NULL, &seen, CurrentMemoryContext);
		visible = text_array(seen, nseen);
	}
	args = palloc(sizeof(Datum) * (nargs + 1));
	nulls = palloc(nargs + 2);
	initStringInfo(&q);
	appendStringInfo(&q, "SELECT * FROM phasevec.%s(", quote_identifier(psprintf("_door_%s", name)));
	for (int i = 0; i < nargs; i++)
	{
		args[i] = PG_ARGISNULL(i) ? (Datum) 0 : PG_GETARG_DATUM(i);
		nulls[i] = PG_ARGISNULL(i) ? 'n' : ' ';
		appendStringInfo(&q, "$%d, ", i + 1);
	}
	argtypes = repalloc(argtypes, sizeof(Oid) * (nargs + 1));
	argtypes[nargs] = TEXTARRAYOID;
	args[nargs] = visible ? PointerGetDatum(visible) : (Datum) 0;
	nulls[nargs] = visible ? ' ' : 'n';
	nulls[nargs + 1] = '\0';
	appendStringInfo(&q, "$%d)", nargs + 1);

	become(owner, &was);
	if (SPI_execute_with_args(q.data, nargs + 1, argtypes, args, nulls, true, 0) != SPI_OK_SELECT)
		elog(ERROR, "phasevec: %s could not be read", name);
	unbecome(&was);
	rtd = SPI_tuptable->tupdesc;
	for (int c = 0; c < rtd->natts && nkeycols < 3; c++)
	{
		const char *cn = NameStr(TupleDescAttr(rtd, c)->attname);

		if (strcmp(cn, "key") == 0 || strcmp(cn, "key_a") == 0 || strcmp(cn, "key_b") == 0)
			keycols[nkeycols++] = c + 1;
	}
	{
		SPITupleTable *res = SPI_tuptable;
		uint64		nres = SPI_processed;

		for (uint64 i = 0; i < nres; i++)
		{
			bool		show = true;
			Datum	   *values = palloc(sizeof(Datum) * rtd->natts);
			bool	   *isnull = palloc(sizeof(bool) * rtd->natts);

			/* and, again, a row whose key the caller does not see is not shown */
			for (int c = 0; visible && c < nkeycols && show; c++)
			{
				char	   *k = SPI_getvalue(res->vals[i], rtd, keycols[c]);
				bool		found = (k == NULL);

				for (int v = 0; v < nseen && !found; v++)
					found = strcmp(seen[v], k) == 0;
				show = found;
			}
			if (!show)
				continue;
			heap_deform_tuple(res->vals[i], rtd, values, isnull);
			tuplestore_putvalues(rsinfo->setResult, rsinfo->setDesc, values, isnull);
		}
	}
	SPI_finish();
	return (Datum) 0;
}

/* --------------------------------------------------------------------------------- the verdict of a row -- */

/*
 * phasevec._verdict(t phasevec.truth), for SQL that reads phasevec.truth directly: the truth a claim has now. (fifteenth
 * review) Until this cut it was SQL that ran as its caller: it read phasevec.watches and phasevec.sources and called
 * phasevec._bind, which 0.20.0 closes to PUBLIC, so a role granted phasevec.truth and the watched table (yggdrasil's
 * read-only reader) got "permission denied for function _bind" as soon as verify() wrote a fresh verdict, and one not
 * granted the extension's tables got "permission denied for table watches". It is a door now, with the rule of the
 * others: a claim's verdict is shown to a role that may SELECT its watch's table (and, when row-level security filters
 * that table for the role, see the claim's row), and NULL to anyone else; then it is computed (phasevec._verdict_of,
 * the owner's) as the extension's owner. Its argument is whatever row the caller gives it: one made up for a table the
 * caller may not read gets NULL, so it is no way to test what a hidden row says.
 */
/*
 * (sixteenth review) Nothing about who may see is kept from one call to the next: the caller's SELECT on the table and
 * whether row-level security filters it are checked on every call (two syscache lookups), the row's key under that
 * security too. The fifteenth cut decided once per (watch, role) and kept the decision in fn_extra, which a PL/pgSQL
 * expression keeps for its whole transaction: after a REVOKE or an ENABLE ROW LEVEL SECURITY committed by another
 * session (which a new query, and has_table_privilege, already saw) the kept expression went on answering, and a
 * forged row then told whether a guess was the hidden row's text (10000 guesses in 0.1 s). What is kept is only which
 * table a watch reads (a watch never changes its table: watch() makes a new one), in a few fixed slots: the fifteenth
 * cut kept a whole copy of the watch (its recipe, its statement) per miss in the query's memory, and a query over 17
 * watches in turn grew by ~0.8 kB a row (1 GB for 40000 rows of 20 watches with an 8 kB recipe). Under row-level
 * security the watch is read for the call, in memory that ends with it.
 */
#define VERDICT_SEEN 64

typedef struct VerdictWatch
{
	int32		watch;
	bool		known;			/* there is such a watch */
	Oid			relid;			/* its table */
} VerdictWatch;

typedef struct VerdictCache
{
	Oid			owner;
	Oid			rowtype;
	FmgrInfo	of;				/* phasevec._verdict_of */
	int			n;
	int			next;
	VerdictWatch w[VERDICT_SEEN];
} VerdictCache;

/* May the caller see the claim (watch, key) now? */
static bool
verdict_shown(VerdictCache *vc, int32 watch, Datum keyd, Oid caller)
{
	VerdictWatch *vw = NULL;
	bool		shown;
	Who			was;

	for (int i = 0; i < vc->n && vw == NULL; i++)
		if (vc->w[i].watch == watch)
			vw = &vc->w[i];
	if (vw == NULL)
	{
		MemoryContext cx = AllocSetContextCreate(CurrentMemoryContext, "phasevec _verdict", ALLOCSET_SMALL_SIZES);
		MemoryContext o = MemoryContextSwitchTo(cx);
		Target		t;
		bool		known;

		become(vc->owner, &was);
		spi_connect();
		known = load_target_ext(Int32GetDatum(watch), true, &t, cx, true);
		SPI_finish();
		unbecome(&was);
		MemoryContextSwitchTo(o);
		if (vc->n < VERDICT_SEEN)
			vw = &vc->w[vc->n++];
		else
		{
			vw = &vc->w[vc->next];
			vc->next = (vc->next + 1) % VERDICT_SEEN;
		}
		vw->watch = watch;
		vw->known = known;
		vw->relid = known ? t.relid : InvalidOid;
		MemoryContextDelete(cx);
	}
	if (!vw->known)
		return false;
	/* a table dropped since (the watch goes with it at commit) shows nothing */
	{
		bool		missing = false;

		shown = pg_class_aclcheck_ext(vw->relid, caller, ACL_SELECT, &missing) == ACLCHECK_OK && !missing;
	}
	if (!shown)
		return false;
	/* a key is a row too: one row-level security hides from the caller gets nothing */
	if (check_enable_rls(vw->relid, caller, true) == RLS_ENABLED)
	{
		MemoryContext cx = AllocSetContextCreate(CurrentMemoryContext, "phasevec _verdict", ALLOCSET_SMALL_SIZES);
		MemoryContext o = MemoryContextSwitchTo(cx);
		Target		t;

		become(vc->owner, &was);
		spi_connect();
		shown = load_target_ext(Int32GetDatum(watch), true, &t, cx, true) && t.relid == vw->relid;
		SPI_finish();
		unbecome(&was);
		if (shown)
			shown = key_visible_out(&t, caller, TextDatumGetCString(keyd));
		MemoryContextSwitchTo(o);
		MemoryContextDelete(cx);
	}
	return shown;
}

Datum
phasevec_verdict(PG_FUNCTION_ARGS)
{
	VerdictCache *vc = (VerdictCache *) fcinfo->flinfo->fn_extra;
	MemoryContext mcxt = fcinfo->flinfo->fn_mcxt;
	Oid			caller = GetUserId();
	HeapTupleHeader th;
	bool		isnull;
	int32		watch;
	Datum		keyd;
	Who			was;
	Datum		res;

	if (PG_ARGISNULL(0))
		PG_RETURN_NULL();
	th = PG_GETARG_HEAPTUPLEHEADER(0);
	watch = DatumGetInt32(GetAttributeByName(th, "watch", &isnull));
	if (isnull)
		PG_RETURN_NULL();
	keyd = GetAttributeByName(th, "key", &isnull);
	if (isnull)
		PG_RETURN_NULL();

	if (vc == NULL)
	{
		vc = MemoryContextAllocZero(mcxt, sizeof(VerdictCache));
		vc->owner = function_owner(fcinfo);
		fcinfo->flinfo->fn_extra = vc;
	}
	if (vc->rowtype != HeapTupleHeaderGetTypeId(th))
	{
		Oid			argt = HeapTupleHeaderGetTypeId(th);
		Oid			of = LookupFuncName(list_make2(makeString(pstrdup("phasevec")), makeString(pstrdup("_verdict_of"))),
										1, &argt, false);

		fmgr_info_cxt(of, &vc->of, mcxt);
		vc->rowtype = argt;
	}

	if (!verdict_shown(vc, watch, keyd, caller))
		PG_RETURN_NULL();

	become(vc->owner, &was);
	{
		LOCAL_FCINFO(inner, 1);

		InitFunctionCallInfoData(*inner, &vc->of, 1, InvalidOid, NULL, NULL);
		inner->args[0].value = PG_GETARG_DATUM(0);
		inner->args[0].isnull = false;
		res = FunctionCallInvoke(inner);
		isnull = inner->isnull;
	}
	unbecome(&was);
	if (isnull)
		PG_RETURN_NULL();
	PG_RETURN_DATUM(res);
}
