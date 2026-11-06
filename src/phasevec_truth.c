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
 * - A proof that ends the session it runs in (a FATAL, a terminated backend) is that claim's failure, not the
 *   watch's: its verifier records the claim refuted and halted, does not run it again until it is asserted again,
 *   and goes on with the next claim. (Until the eighth review that session was the verifier's: the claim was marked
 *   in shared memory, and the next verify() recorded it.)
 * - The watch trigger is C: it renders the row it fires for, so no caller can note a text that is not the row's.
 * - Every surface that shows verdicts (recall, disputes, replacement, truth_coverage, brief) is a C door that knows
 *   its caller: it shows a watch only to a role that may SELECT its table, and with row-level security it computes
 *   over the rows that role sees (every field, not only the result rows).
 * - A verdict is judged at READ COMMITTED, in a new snapshot of what is committed, and records when its row was
 *   read. An ended session halts the claim it was judging only.
 */
#include "postgres.h"

#include <dlfcn.h>
#include <string.h>

#include "access/htup_details.h"
#include "access/tupconvert.h"
#include "access/xact.h"
#include "catalog/partition.h"
#include "catalog/pg_authid.h"
#include "catalog/pg_class.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_type.h"
#include "common/cryptohash.h"
#include "common/sha2.h"
#include "commands/trigger.h"
#include "datatype/timestamp.h"
#include "executor/spi.h"
#include "fmgr.h"
#include "funcapi.h"
#include "miscadmin.h"
#include "nodes/parsenodes.h"
#include "nodes/plannodes.h"
#include "utils/plancache.h"
#include "mb/pg_wchar.h"
#include "parser/parser.h"
#include "pgstat.h"
#include "port/atomics.h"
#include "postmaster/bgworker.h"
#include "storage/dsm.h"
#include "storage/ipc.h"
#include "storage/latch.h"
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
PG_FUNCTION_INFO_V1(phasevec_adopt);

static TimeoutId prove_timeout = MAX_TIMEOUTS;
static volatile sig_atomic_t prove_fired = false;
static bool prove_in_progress = false;

static void
prove_timeout_handler(void)
{
	prove_fired = true;
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
} Who;

/* Step into the extension's owner to run its own SQL, as PostgreSQL's RI triggers do; an error puts the caller back. */
static void
become(Oid role, Who *was)
{
	GetUserIdAndSecContext(&was->userid, &was->sec);
	SetUserIdAndSecContext(role, was->sec | SECURITY_LOCAL_USERID_CHANGE);
}

static void
unbecome(const Who *was)
{
	SetUserIdAndSecContext(was->userid, was->sec);
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

/* The watch and how to read its rows, by name (text) or by id (int4). SPI connected, as the owner. */
static void
load_target(Datum id, bool by_id, Target *t, MemoryContext keep)
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
	OUT_UNPROVEN,				/* nothing judged: the author gone, or kept from the row */
	OUT_STALE,					/* nothing judged: the row is gone, or does not say what was asserted */
	OUT_MOVED,					/* the row changed while the proof ran: nothing recorded */
	OUT_NOT_JUDGED,				/* no session of its own could judge it (no background worker free): nothing
								 * recorded, it stays due */
	OUT_HALTED					/* the proof's own session ended while it ran: refuted, and not run again */
} Outcome;

static const char *const outcome_name[] = {"verified", "refuted", "unproven", "stale", NULL, NULL, NULL};

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

static bool
user_request(const ErrorData *e)
{
	return e->message_id != NULL && strcmp(e->message_id, "canceling statement due to user request") == 0;
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
 * Judge one proof, in a subtransaction always rolled back, under its own clock and cost cap. The proof runs in the
 * guard as as_role (its author; for the SQL of 0.14.2 to 0.19.0, the caller) with the author's settings. With a
 * target, the row is read before and after the proof, in the guard as the table's owner: its text must be the one
 * asserted, and it must not change while the proof runs; and an author that row-level security keeps from the row
 * (author_rls) must still see it.
 */
static void
judge(const char *proof, int timeout_ms, double max_cost, Oid as_role, GuardMode mode, const GuardEnv *env,
	  const Target *target, bool author_rls, const char *key, const bytea *asserted_for, Judgment *j)
{
	MemoryContext oldcontext = CurrentMemoryContext;
	ResourceOwner oldowner = CurrentResourceOwner;
	StringInfoData sql;
	volatile int mark = guard_mark();
	volatile Outcome out = OUT_REFUTED;
	const char *volatile err = NULL;
	volatile int phase = 1;		/* 0 reading the row, 1 proving, 2 reading it again */
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
	prove_in_progress = true;
	BeginInternalSubTransaction(NULL);
	MemoryContextSwitchTo(oldcontext);
	PG_TRY();
	{
		Seen		first = {0};
		Seen		last;
		bool		ready = true;
		Guard		g;

		spi_connect();
		started = GetCurrentTimestamp();
		if (timeout_ms > 0)
			enable_timeout_after(prove_timeout, timeout_ms);
		if (target)
		{
			phase = 0;
			read_row(target, key, &first, oldcontext);
			phase = 1;

			/*
			 * A row that is gone or says something else is stale, not judged: the verdict stays bound to the text it
			 * judged, and reads 'unproven' only while the row does not say it (_verdict). Until the sixth review
			 * verify() wrote 'unproven' over it, and a writer that edited a row and put it back erased a refutation
			 * until the claim was due again (p_every).
			 */
			if (!first.found)
			{
				out = OUT_STALE;
				err = "the row is gone: there is nothing to judge";
				ready = false;
			}
			else if (author_rls && !key_visible(target, as_role, mode, env, key))
			{
				out = OUT_UNPROVEN;
				err = "its author cannot see the row: there is nothing to judge";
				ready = false;
			}
			else if (!same_bytes(first.hash, asserted_for))
			{
				out = OUT_STALE;
				err = "the row does not say what was asserted (it changed, or it was not readable then): assert it again";
				ready = false;
			}
		}
		if (ready)
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
					elog(ERROR, "the proof must return one row");
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
				if (!last.found || !same_bytes(last.hash, first.hash) || last.version == NULL ||
					first.version == NULL || strcmp(last.version, first.version) != 0)
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
		if ((out == OUT_VERIFIED || out == OUT_REFUTED) && timeout_ms > 0 &&
			(prove_fired || TimestampDifferenceExceeds(started, GetCurrentTimestamp(), timeout_ms)))
		{
			out = OUT_REFUTED;
			err = MemoryContextStrdup(oldcontext, psprintf("the proof took longer than %d ms", timeout_ms));
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

		/*
		 * A real cancel that is not our timer's (the caller's statement_timeout, a user's cancel) cancels the caller.
		 * A query_canceled the proof raised itself is the proof's own error, like any other.
		 */
		if (edata->sqlerrcode == ERRCODE_QUERY_CANCELED && from_interrupts(edata) && (!ours || !user_request(edata)))
			ReThrowError(edata);
		if (ours)
			QueryCancelPending = false;
		/* an error reading the row judged nothing; one in the proof refutes it; one reading it again records nothing */
		out = phase == 0 ? OUT_UNPROVEN : phase == 1 ? OUT_REFUTED : OUT_MOVED;
		if ((ours || late) && phase != 0)
		{
			out = OUT_REFUTED;
			err = psprintf("the proof took longer than %d ms", timeout_ms);
		}
		else if (ours || late)
			err = psprintf("the row took longer than %d ms to read", timeout_ms);
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
		  NULL, NULL, false, NULL, NULL, &j);
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
 * The verifier only chooses the claims, takes them, sends each one to the worker (shm_mq) and records what comes back.
 *
 * - One worker for a verify() call and an author, for as many of its claims as it may judge: a placeholder made in it
 *   stays (a proof's set_config, a recorded state that names one, a recipe that sets one), and a claim whose author
 *   did not have it is not judged there: that worker ends and the claim goes to a new one (guard_env_spent). The
 *   claims of one author are sent in the order that needs the fewest: those that name fewer placeholders first.
 * - A proof that ends its session (a FATAL, a backend terminated) ends the worker, not the verifier: the claim is
 *   recorded refuted and halted (phasevec._truth_halted) by the verifier, which goes on with the next claim.
 * - The clock: the worker runs each proof under its own timer, as before; the verifier waits for the answer no
 *   longer than that and PROOF_GRACE_MS more, then ends the worker and records the claim refuted for its time. A
 *   proof that waits for a lock the verifier's own transaction holds would wait forever: the verifier sees it
 *   (pg_blocking_pids) and stops with an error. A verifier that is canceled or ends ends its worker.
 * - No worker free (max_worker_processes): the claim is not judged, nothing is recorded, it stays due, and the row
 *   verify() returns for it says so.
 */
#define PROOF_MAGIC		0x50565046
#define PROOF_PROTOCOL	1
#define PROOF_QUEUE		(64 * 1024)
#define PROOF_GRACE_MS	5000
#define PROOF_AHEAD		8		/* claims sent ahead of their answers, and no more than PROOF_QUEUE / 2 bytes */
#define PROOF_ERR_MAX	4000	/* an answer's error text: PROOF_AHEAD of them fit in PROOF_QUEUE */

typedef struct ProofShared
{
	uint32		magic;
	uint32		protocol;
	Oid			db;
	Oid			author;
	Oid			owner;			/* the extension's owner: reads phasevec's own tables */
	int32		watch;
	pg_atomic_uint32 judging;	/* 1 while the worker judges a claim */
	TimestampTz started;		/* when it began to (written before judging is set) */
} ProofShared;

#define PROOF_REQ_OFF	MAXALIGN(sizeof(ProofShared))
#define PROOF_ANS_OFF	(PROOF_REQ_OFF + PROOF_QUEUE)
#define PROOF_SIZE		(PROOF_ANS_OFF + PROOF_QUEUE)

typedef enum ProofAnswer
{
	ANSWER_JUDGED,
	ANSWER_SPENT,				/* this session may not judge it: a new one will */
	ANSWER_FAILED				/* an error outside the proof: nothing judged */
} ProofAnswer;

typedef struct ProofSession
{
	Oid			author;
	dsm_segment *seg;
	ProofShared *sh;
	BackgroundWorkerHandle *handle;
	shm_mq_handle *req;
	shm_mq_handle *ans;
} ProofSession;

typedef enum ProofStatus
{
	PS_JUDGED,					/* *j is the judgment */
	PS_SPENT,					/* to a new session */
	PS_ENDED,					/* the proof ended its session: halted */
	PS_LATE,					/* no answer in time: the session was ended, refuted for its time */
	PS_FAILED					/* nothing judged: j->err says why */
} ProofStatus;

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

static void
answer(shm_mq_handle *ans, ProofAnswer what, const Judgment *j, const char *err)
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
	(void) shm_mq_send(ans, b.len, b.data, false, true);
	pfree(b.data);
}

PGDLLEXPORT void phasevec_proof_main(Datum arg);

/*
 * The proof's own session: a background worker, a new session of the claim's author. Claims come in one at a time;
 * each is judged in a transaction of its own and its judgment goes back. It ends when its verifier detaches, when a
 * claim is not one it may judge (a placeholder its author did not have), or on an error outside a proof.
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

	pqsignal(SIGTERM, die);
	BackgroundWorkerUnblockSignals();
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
	mq = (shm_mq *) ((char *) sh + PROOF_REQ_OFF);
	shm_mq_set_receiver(mq, MyProc);
	req = shm_mq_attach(mq, seg, NULL);
	mq = (shm_mq *) ((char *) sh + PROOF_ANS_OFF);
	shm_mq_set_sender(mq, MyProc);
	ans = shm_mq_attach(mq, seg, NULL);

	/* a new session of the author: it may be a role that does not log in (the verifier may act as it) */
	BackgroundWorkerInitializeConnectionByOid(sh->db, sh->author, BGWORKER_BYPASS_ROLELOGINCHECK);
	process_session_preload_libraries();
	guard_proof_session();
	/* the placeholders every new session of the author has: from its configuration */
	base = guard_placeholders(&nbase);

	SetCurrentStatementStartTimestamp();
	StartTransactionCommand();
	PushActiveSnapshot(GetTransactionSnapshot());
	become(sh->owner, &was);
	spi_connect();
	load_target(Int32GetDatum(sh->watch), true, &target, TopMemoryContext);
	prepare_read(&target);
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
		int			timeout_ms;
		double		max_cost;
		int64		bits;
		bool		rls;
		char	   *key;
		char	   *proof;
		bytea	   *asserted_for = NULL;
		char	   *af;
		int64		aflen;
		GuardEnv   *env;
		const char *spent;
		Judgment	j;

		MemoryContextReset(per);
		MemoryContextSwitchTo(per);
		if (shm_mq_receive(req, &n, &data, false) != SHM_MQ_SUCCESS)
			break;				/* the verifier is done, or gone */
		m.p = data;
		m.end = (const char *) data + n;
		timeout_ms = (int) get_int(&m);
		bits = get_int(&m);
		memcpy(&max_cost, &bits, sizeof(max_cost));
		rls = get_int(&m) != 0;
		key = get_bytes(&m, NULL);
		proof = get_bytes(&m, NULL);
		af = get_bytes(&m, &aflen);
		if (af)
		{
			asserted_for = palloc(VARHDRSZ + aflen);
			SET_VARSIZE(asserted_for, VARHDRSZ + aflen);
			memcpy(VARDATA(asserted_for), af, aflen);
		}
		env = palloc0(sizeof(GuardEnv));
		env->n = (int) get_int(&m);
		env->name = palloc(sizeof(char *) * Max(env->n, 1));
		env->value = palloc(sizeof(char *) * Max(env->n, 1));
		for (int i = 0; i < env->n; i++)
		{
			env->name[i] = get_bytes(&m, NULL);
			env->value[i] = get_bytes(&m, NULL);
		}
		if (key == NULL || proof == NULL)
			elog(ERROR, "phasevec: a malformed message between a verifier and a proof's session");

		/* a placeholder this session made for an earlier claim, which this claim's author did not have */
		spent = guard_env_spent(base, nbase, env);
		if (spent != NULL)
		{
			answer(ans, ANSWER_SPENT, NULL, spent);
			break;
		}

		SetCurrentStatementStartTimestamp();
		StartTransactionCommand();
		/* each statement of the proof in a new snapshot, whatever default_transaction_isolation says */
		XactIsoLevel = XACT_READ_COMMITTED;
		PushActiveSnapshot(GetTransactionSnapshot());
		MemoryContextSwitchTo(per);
		pgstat_report_activity(STATE_RUNNING, "phasevec: judging a claim");
		sh->started = GetCurrentTimestamp();
		pg_write_barrier();
		pg_atomic_write_u32(&sh->judging, 1);
		PG_TRY();
		{
			judge(proof, timeout_ms, max_cost, sh->author, GUARD_AUTHOR, env, &target, rls, key, asserted_for, &j);
		}
		PG_CATCH();
		{
			ErrorData  *e;

			MemoryContextSwitchTo(per);
			e = CopyErrorData();
			FlushErrorState();
			AbortCurrentTransaction();
			pg_atomic_write_u32(&sh->judging, 0);
			MemoryContextSwitchTo(per);
			answer(ans, ANSWER_FAILED, NULL, e->message);
			proc_exit(0);
		}
		PG_END_TRY();
		pg_atomic_write_u32(&sh->judging, 0);
		PopActiveSnapshot();
		CommitTransactionCommand();
		pgstat_report_activity(STATE_IDLE, NULL);
		MemoryContextSwitchTo(per);
		answer(ans, ANSWER_JUDGED, &j, NULL);
	}
	proc_exit(0);
}

/*
 * The verifier's side: the worker of the verify() call running now (one at a time), in TopMemoryContext. One whose
 * verifier ends (an error, a cancel, the session's end) is ended with it.
 */
static ProofSession *proof_cur = NULL;

static void
proof_on_exit(int code, Datum arg)
{
	if (proof_cur != NULL)
		TerminateBackgroundWorker(proof_cur->handle);
	proof_cur = NULL;
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
	MemoryContext o = MemoryContextSwitchTo(TopMemoryContext);
	bool		started;

	ps->author = author;
	ps->seg = dsm_create(PROOF_SIZE, 0);
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
		char	   *name = GetUserNameFromId(author, true);

		snprintf(w.bgw_name, BGW_MAXLEN, "pg_phasevec proof as %s", name ? name : "a role that is gone");
	}
	strlcpy(w.bgw_type, "pg_phasevec proof", BGW_MAXLEN);
	w.bgw_main_arg = UInt32GetDatum(dsm_segment_handle(ps->seg));
	w.bgw_notify_pid = MyProcPid;
	started = RegisterDynamicBackgroundWorker(&w, &ps->handle);
	MemoryContextSwitchTo(o);
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

/* Done with a worker: detached (it ends by itself), or ended now (it may be inside a proof). */
static void
proof_stop(ProofSession *ps, bool end_it)
{
	if (ps == NULL)
		return;
	if (end_it)
		TerminateBackgroundWorker(ps->handle);
	shm_mq_detach(ps->req);
	shm_mq_detach(ps->ans);
	dsm_detach(ps->seg);
	pfree(ps->handle);
	pfree(ps);
}

/* Does the worker wait for a lock this transaction holds? It would wait for as long as this waits for it. */
static bool
waits_for_us(ProofSession *ps)
{
	pid_t		pid;
	ArrayType  *a;
	Datum	   *d;
	bool	   *nulls;
	int			n;
	bool		ours = false;

	if (GetBackgroundWorkerPid(ps->handle, &pid) != BGWH_STARTED)
		return false;
	a = DatumGetArrayTypeP(DirectFunctionCall1(pg_blocking_pids, Int32GetDatum((int32) pid)));
	deconstruct_array_builtin(a, INT4OID, &d, &nulls, &n);
	for (int i = 0; i < n && !ours; i++)
		ours = !nulls[i] && DatumGetInt32(d[i]) == MyProcPid;
	return ours;
}

/* The worker is gone (it detached): inside a proof it ended there; before one, nothing was judged. */
static ProofStatus
proof_gone(ProofSession *ps, Judgment *j)
{
	pg_read_barrier();
	if (pg_atomic_read_u32(&ps->sh->judging) != 0)
	{
		j->out = OUT_HALTED;
		j->at = ps->sh->started;
		j->err = "the session that ran this proof ended while it ran: not run again until it is asserted again";
		return PS_ENDED;
	}
	j->out = OUT_NOT_JUDGED;
	j->err = "not judged: the proof's own session ended before it began (see the server log): nothing is "
		"recorded, and it stays due";
	return PS_FAILED;
}

/* A claim, as sent to the worker: its size counts against what may be sent ahead (PROOF_AHEAD). */
static Size
proof_send(ProofSession *ps, const Claim *c, bool rls, int timeout_ms, double max_cost)
{
	StringInfoData b;
	int64		bits;
	Size		size;

	initStringInfo(&b);
	put_int(&b, timeout_ms);
	memcpy(&bits, &max_cost, sizeof(bits));
	put_int(&b, bits);
	put_int(&b, rls ? 1 : 0);
	put_str(&b, c->key);
	put_str(&b, c->proof);
	put_bytes(&b, c->asserted_for ? VARDATA_ANY(c->asserted_for) : NULL,
			  c->asserted_for ? VARSIZE_ANY_EXHDR(c->asserted_for) : 0);
	put_int(&b, c->env ? c->env->n : 0);
	for (int i = 0; c->env && i < c->env->n; i++)
	{
		put_str(&b, c->env->name[i]);
		put_str(&b, c->env->value[i]);
	}
	/* a worker gone before it reads it: proof_answer() finds it detached */
	(void) shm_mq_send(ps->req, b.len, b.data, false, true);
	size = b.len;
	pfree(b.data);
	return size;
}

/* The answer for the oldest claim sent and not answered (the worker judges them in the order sent). */
static ProofStatus
proof_answer(ProofSession *ps, const Claim *c, int timeout_ms, Judgment *j)
{
	static uint32 wait_event = 0;
	Size		n;
	void	   *data;
	Msg			m;
	ProofAnswer what;
	TimestampTz waiting;
	TimestampTz looked;

	if (wait_event == 0)
		wait_event = WaitEventExtensionNew("PhasevecProof");
	waiting = looked = GetCurrentTimestamp();
	for (;;)
	{
		shm_mq_result r = shm_mq_receive(ps->ans, &n, &data, true);
		TimestampTz now;

		if (r == SHM_MQ_SUCCESS)
			break;
		if (r == SHM_MQ_DETACHED)
			return proof_gone(ps, j);
		now = GetCurrentTimestamp();
		if (pg_atomic_read_u32(&ps->sh->judging) != 0)
		{
			pg_read_barrier();
			if (TimestampDifferenceExceeds(ps->sh->started, now, timeout_ms + PROOF_GRACE_MS))
			{
				j->out = OUT_REFUTED;
				j->at = ps->sh->started;
				j->err = psprintf("the proof took longer than %d ms (its session did not answer, and was ended)",
								  timeout_ms);
				return PS_LATE;
			}
		}
		else if (TimestampDifferenceExceeds(waiting, now, timeout_ms + PROOF_GRACE_MS))
		{
			j->out = OUT_NOT_JUDGED;
			j->err = psprintf("not judged: the proof's own session did not take it within %d ms: nothing is "
							  "recorded, and it stays due", timeout_ms + PROOF_GRACE_MS);
			return PS_FAILED;
		}
		if (TimestampDifferenceExceeds(looked, now, 200))
		{
			looked = now;
			if (waits_for_us(ps))
			{
				TerminateBackgroundWorker(ps->handle);
				ereport(ERROR,
						(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
						 errmsg("phasevec: the proof of key %s waits for a lock this transaction holds", c->key),
						 errdetail("A proof runs in a session of its own, which reads what is committed; this "
								   "transaction locked something it reads (LOCK TABLE, or DDL not yet committed)."),
						 errhint("Verify outside this transaction, or after it commits.")));
			}
		}
		(void) WaitLatch(MyLatch, WL_LATCH_SET | WL_TIMEOUT | WL_EXIT_ON_PM_DEATH, 100, wait_event);
		ResetLatch(MyLatch);
		CHECK_FOR_INTERRUPTS();
	}
	m.p = data;
	m.end = (const char *) data + n;
	what = (ProofAnswer) get_int(&m);
	j->out = (Outcome) get_int(&m);
	j->at = (TimestampTz) get_int(&m);
	j->err = get_bytes(&m, NULL);
	if (what == ANSWER_SPENT)
		return PS_SPENT;
	if (what == ANSWER_FAILED)
	{
		j->out = OUT_NOT_JUDGED;
		j->err = psprintf("not judged: %s", j->err ? j->err : "its session failed");
		return PS_FAILED;
	}
	return PS_JUDGED;
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
	"SELECT phasevec._verdict(t) FROM phasevec.truth t WHERE t.watch OPERATOR(pg_catalog.=) $1 " \
	"AND t.key OPERATOR(pg_catalog.=) $2"

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
	{
		Oid			at[2] = {INT4OID, TEXTOID};
		Datum		av[2] = {Int32GetDatum(t->watch), CStringGetTextDatum(c->key)};

		if (SPI_execute_with_args(VERDICT_SQL, 2, at, av, NULL, false, 1) != SPI_OK_SELECT)
			elog(ERROR, "phasevec: the verdict could not be read");
		if (SPI_processed == 1)
		{
			char	   *s = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1);

			if (s)
				v = MemoryContextStrdup(keep, s);
		}
	}
	SPI_finish();
	unbecome(&was);
	return v;
}

/* Record what judge_claim() found: nothing for a claim not judged (the verdict as it reads now is returned). */
static char *
record_judgment(Oid owner, Oid verifier, const Target *t, const Claim *c, const Judgment *j)
{
	if (j->out == OUT_HALTED)
		return record_halted(owner, verifier, t, c, j);
	return record(owner, t, c, j);
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
 * Judge one claim in a session of its own (proof_cur: the worker of this call, started or replaced as needed), and
 * wait for it: verify_one(). A claim whose author is gone, or may no longer read the table, is set unproven here,
 * with no worker (verify() asks this for those too; it sends the others ahead itself).
 */
static void
judge_claim(const Claim *c, int timeout_ms, double max_cost, const Target *t, Readers *readers, Oid owner,
			Judgment *j)
{
	ProofSession **ps = &proof_cur;
	bool		rls = false;

	j->err = NULL;
	j->at = 0;
	if (!c->author_known)
	{
		j->out = OUT_UNPROVEN;
		j->err = pstrdup("the author of this proof is gone (dropped, or its name is another role's now): "
						 "assert it again, or adopt it naming its author (phasevec.adopt)");
		return;
	}
	if (!author_reads(readers, t, c->author, &rls))
	{
		j->out = OUT_UNPROVEN;
		j->err = psprintf("its author \"%s\" may no longer read %s: nothing is judged",
						  GetUserNameFromId(c->author, false), t->src);
		return;
	}
	for (int attempt = 0;; attempt++)
	{
		ProofStatus st;
		char	   *why = NULL;

		if (*ps != NULL && (*ps)->author != c->author)
		{
			proof_stop(*ps, false);
			*ps = NULL;
		}
		if (*ps == NULL && (*ps = proof_start(owner, t->watch, c->author, &why)) == NULL)
		{
			j->out = OUT_NOT_JUDGED;
			j->err = why;
			return;
		}
		(void) proof_send(*ps, c, rls, timeout_ms, max_cost);
		st = proof_answer(*ps, c, timeout_ms, j);
		if (st == PS_JUDGED)
			return;
		/* a worker that is spent ends by itself; one that failed, ended or was late, now */
		proof_stop(*ps, st != PS_SPENT);
		*ps = NULL;
		if (st == PS_ENDED || st == PS_LATE)
			return;
		/* a new worker starts with no placeholder but its configuration's: it is not spent */
		if ((st == PS_SPENT && attempt < 2) || (st == PS_FAILED && attempt < 1))
			continue;
		if (st == PS_SPENT)
		{
			j->out = OUT_NOT_JUDGED;
			j->err = "not judged: a new session of its author has a custom setting its author's session did not";
		}
		return;
	}
}

/*
 * Take the claim's row before judging it, or leave it: another verify() (or an assert()) holds it. It must still be
 * due, by the rule of phasevec._truth_due (a stale claim once for each text it reads; one whose verdict and last
 * look are both older than p_every is due either way, and the row's text is not read for it). Without this, two
 * verify() calls of one watch locked the rows of their due lists in different orders when the table took writes
 * (in the fifth cut the watch trigger wrote verdict rows too) and deadlocked: 54-70% of the calls failed, and an
 * aborted call lost every verdict it had reached. With it no verify() waits on a verdict row, so none deadlocks on
 * one, and none judges a claim another is judging, or judged since its due list was read (it is no longer due).
 */
#define LOCK_OLD(c) "t." c " IS NULL OR t." c " OPERATOR(pg_catalog.<) (pg_catalog.now() OPERATOR(pg_catalog.-) $3)"
#define CLAIM_LOCK_SQL \
	"SELECT 1 FROM phasevec.truth t WHERE t.watch OPERATOR(pg_catalog.=) $1 AND t.key OPERATOR(pg_catalog.=) $2 " \
	"AND NOT t.halted AND ((" LOCK_OLD("verified_at") ") AND (" LOCK_OLD("looked_at") ") OR " \
	"(SELECT CASE WHEN t.verdict OPERATOR(pg_catalog.=) ANY ('{verified,refuted}'::pg_catalog.text[]) " \
	"AND t.asserted_for IS DISTINCT FROM h THEN " LOCK_OLD("looked_at") " OR t.looked_for IS DISTINCT FROM h " \
	"ELSE " LOCK_OLD("verified_at") " END " \
	"FROM (SELECT (SELECT s.text_hash FROM phasevec.sources s WHERE s.watch OPERATOR(pg_catalog.=) t.watch " \
	"AND s.key OPERATOR(pg_catalog.=) t.key) AS h) s)) FOR NO KEY UPDATE SKIP LOCKED"

static bool
claim_taken(Oid owner, SPIPlanPtr plan, const Target *t, const Claim *c, Datum every)
{
	Datum		av[3] = {Int32GetDatum(t->watch), CStringGetTextDatum(c->key), every};
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

/* A claim sent to the worker and not yet answered. */
typedef struct Sent
{
	const Claim *c;
	bool		rls;
	int			tries;
	Size		size;
} Sent;

/* Record a judgment and return its row: key, the verdict as it reads now, the error. */
static void
emit(ReturnSetInfo *rsinfo, Oid owner, Oid caller, const Target *t, const Claim *c, const Judgment *j)
{
	char	   *v = record_judgment(owner, caller, t, c, j);
	Datum		values[3];
	bool		nulls[3] = {false, false, false};

	values[0] = CStringGetTextDatum(c->key);
	values[1] = v ? CStringGetTextDatum(v) : (Datum) 0;
	nulls[1] = v == NULL;
	values[2] = j->err ? CStringGetTextDatum(j->err) : (Datum) 0;
	nulls[2] = j->err == NULL;
	tuplestore_putvalues(rsinfo->setResult, rsinfo->setDesc, values, nulls);
}

/*
 * phasevec.verify(watch text, n int, every interval, budget interval, timeout_ms int, max_cost float8)
 *   RETURNS TABLE (key text, verdict text, error text)
 * The due proofs whose author the caller may act as (a gone author's claim is set unproven by anyone), oldest
 * first, while the budget lasts. Each proof runs in a session of its own, a new session of its author with its
 * author's settings; the verdicts are recorded in the caller's transaction.
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
	int			timeout_ms;
	double		max_cost;
	int64		budget_us;
	TimestampTz t0;
	Who			was;
	Readers		readers = {0};
	SPIPlanPtr	lock_plan = NULL;
	Turn	   *order;
	MemoryContext take;

	for (int i = 0; i < 6; i++)
		if (PG_ARGISNULL(i))
			ereport(ERROR, (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED), errmsg("phasevec: verify() takes no NULL argument")));
	timeout_ms = PG_GETARG_INT32(4);
	max_cost = PG_GETARG_FLOAT8(5);
	require_clock(timeout_ms);
	require_fresh_snapshots();
	refuse_inside_proof();
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
	t0 = GetCurrentTimestamp();
	if (nclaims > 0)
	{
		Oid			at[6] = {INT4OID, TEXTOID, TEXTOID, TEXTOID, BYTEAOID, TIMESTAMPTZOID};
		Oid			lt[3] = {INT4OID, TEXTOID, INTERVALOID};

		spi_connect();
		become(owner, &was);
		target.record_plan = SPI_prepare(RECORD_SQL, 6, at);
		if (target.record_plan == NULL)
			elog(ERROR, "phasevec: verdicts cannot be recorded: %s", SPI_result_code_string(SPI_result));
		SPI_keepplan(target.record_plan);
		lock_plan = SPI_prepare(CLAIM_LOCK_SQL, 3, lt);
		if (lock_plan == NULL)
			elog(ERROR, "phasevec: claims cannot be taken: %s", SPI_result_code_string(SPI_result));
		SPI_keepplan(lock_plan);
		unbecome(&was);
		SPI_finish();
	}
	order = turns(claims, (int) nclaims);
	take = AllocSetContextCreate(CurrentMemoryContext, "phasevec take", ALLOCSET_DEFAULT_SIZES);
	PG_TRY();
	{
		/*
		 * Up to PROOF_AHEAD claims are taken and sent ahead of their answers: the worker judges the next one while
		 * this records the last. Answers come in the order sent; a worker that ends (spent, failed, ended by its
		 * proof, late) takes with it the claims sent after the one it was on, which go to the next one.
		 */
		Sent		q[PROOF_AHEAD];
		int			qh = 0;
		int			qn = 0;
		Size		qbytes = 0;
		uint64		k = 0;
		bool		over = false;

		for (;;)
		{
			Judgment	j;
			Sent	   *f;
			ProofStatus st;

			while (qn < PROOF_AHEAD && k < (uint64) nclaims && !over)
			{
				const Claim *c = &claims[order[k].at];
				bool		rls = false;
				bool		taken;
				MemoryContext o;

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
				/* one worker at a time: another author's claims wait for this one's answers */
				if (qn > 0 && c->author_known && proof_cur != NULL && proof_cur->author != c->author)
					break;
				/* and so many bytes at most (the worker answers only as fast as this reads) */
				if (qn > 0 && qbytes >= PROOF_QUEUE / 2)
					break;
				o = MemoryContextSwitchTo(take);
				taken = claim_taken(owner, lock_plan, &target, c, PG_GETARG_DATUM(2));
				MemoryContextSwitchTo(o);
				MemoryContextReset(take);
				k++;
				if (!taken)
					continue;
				o = MemoryContextSwitchTo(per);
				if (!c->author_known || !author_reads(&readers, &target, c->author, &rls))
				{
					/* no worker: set unproven here */
					judge_claim(c, timeout_ms, max_cost, &target, &readers, owner, &j);
					emit(rsinfo, owner, caller, &target, c, &j);
				}
				else
				{
					if (proof_cur != NULL && proof_cur->author != c->author)
					{
						proof_stop(proof_cur, false);
						proof_cur = NULL;
					}
					if (proof_cur == NULL)
					{
						char	   *why = NULL;

						proof_cur = proof_start(owner, target.watch, c->author, &why);
						if (proof_cur == NULL)
						{
							j.out = OUT_NOT_JUDGED;
							j.err = why;
							j.at = 0;
							emit(rsinfo, owner, caller, &target, c, &j);
						}
					}
					if (proof_cur != NULL)
					{
						Sent	   *n = &q[(qh + qn) % PROOF_AHEAD];

						n->c = c;
						n->rls = rls;
						n->tries = 0;
						n->size = proof_send(proof_cur, c, rls, timeout_ms, max_cost);
						qbytes += n->size;
						qn++;
					}
				}
				MemoryContextSwitchTo(o);
				MemoryContextReset(per);
			}
			if (qn == 0)
				break;

			/* the answer for the oldest */
			f = &q[qh];
			{
				MemoryContext o = MemoryContextSwitchTo(per);

				st = proof_answer(proof_cur, f->c, timeout_ms, &j);
				if (st == PS_JUDGED || st == PS_ENDED || st == PS_LATE ||
					(st == PS_FAILED && f->tries >= 1) || (st == PS_SPENT && f->tries >= 2))
				{
					if (st == PS_SPENT)
					{
						j.out = OUT_NOT_JUDGED;
						j.err = "not judged: a new session of its author has a custom setting its author's session "
							"did not";
					}
					emit(rsinfo, owner, caller, &target, f->c, &j);
					qbytes -= f->size;
					qh = (qh + 1) % PROOF_AHEAD;
					qn--;
				}
				else
					f->tries++;
				MemoryContextSwitchTo(o);
				MemoryContextReset(per);
			}
			if (st == PS_JUDGED)
				continue;
			/* the worker is done: what it had not answered goes to a new one */
			proof_stop(proof_cur, st != PS_SPENT);
			proof_cur = NULL;
			if (qn > 0)
			{
				char	   *why = NULL;

				proof_cur = proof_start(owner, target.watch, q[qh].c->author, &why);
				for (int i = 0; i < qn; i++)
				{
					Sent	   *r = &q[(qh + i) % PROOF_AHEAD];

					if (proof_cur != NULL)
						(void) proof_send(proof_cur, r->c, r->rls, timeout_ms, max_cost);
					else
					{
						MemoryContext o = MemoryContextSwitchTo(per);

						j.out = OUT_NOT_JUDGED;
						j.err = why;
						j.at = 0;
						emit(rsinfo, owner, caller, &target, r->c, &j);
						MemoryContextSwitchTo(o);
						MemoryContextReset(per);
					}
				}
				if (proof_cur == NULL)
				{
					qn = 0;
					qbytes = 0;
				}
			}
		}
	}
	PG_CATCH();
	{
		proof_stop(proof_cur, true);
		proof_cur = NULL;
		PG_RE_THROW();
	}
	PG_END_TRY();
	proof_stop(proof_cur, false);
	proof_cur = NULL;
	if (target.record_plan)
		SPI_freeplan(target.record_plan);
	if (lock_plan)
		SPI_freeplan(lock_plan);
	MemoryContextDelete(take);
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
	Judgment	j;
	char	   *v;
	int			timeout_ms;
	Who			was;
	Readers		readers = {0};

	for (int i = 0; i < 4; i++)
		if (PG_ARGISNULL(i))
			ereport(ERROR, (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED), errmsg("phasevec: verify_one() takes no NULL argument")));
	timeout_ms = PG_GETARG_INT32(2);
	require_clock(timeout_ms);
	require_fresh_snapshots();
	refuse_inside_proof();

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
	PG_TRY();
	{
		judge_claim(&c, timeout_ms, PG_GETARG_FLOAT8(3), &target, &readers, owner, &j);
	}
	PG_CATCH();
	{
		proof_stop(proof_cur, true);
		proof_cur = NULL;
		PG_RE_THROW();
	}
	PG_END_TRY();
	proof_stop(proof_cur, false);
	proof_cur = NULL;
	if (j.out == OUT_NOT_JUDGED)
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("phasevec: verify_one() could not judge key %s", c.key),
				 errdetail("%s.", j.err)));
	v = record_judgment(owner, caller, &target, &c, &j);
	if (v == NULL)
		PG_RETURN_NULL();
	PG_RETURN_TEXT_P(cstring_to_text(v));
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
