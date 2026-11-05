/*
 * pg_phasevec 0.14.2: a proof with its own clock.
 *
 * statement_timeout is armed when a top-level statement starts, so a PL/pgSQL verify() could not cut one slow proof
 * among many. Here the proof runs inside an internal subtransaction (always rolled back), read-only, with a timer of
 * its own (a USER_TIMEOUT): when it fires, the proof is canceled, the subtransaction is undone and the proof is
 * refuted for its time. A cancel that is NOT ours (the caller statement_timeout, a user Ctrl-C) is thrown again, as
 * always. Before running, the planner estimates the proof (EXPLAIN): one above max_cost is refuted without running.
 *
 * 0.20.0:
 * - A proof is ONE boolean expression. It is spliced into "SELECT (%s)::boolean", so a proof such as
 *   "true); SELECT (pg_sleep(3600) IS NULL" made two statements: the cost step ran the second one with no timer and
 *   read no cost from it, and -1 passed the cap. The wrapped text is now parsed first and must be exactly one SELECT;
 *   a cost that cannot be read is refused, and the clock runs from before the estimate (planning can run immutable
 *   functions) to the end of the run.
 * - A proof runs as its AUTHOR (phasevec_prove_as), not as whoever verifies it: the verifier used to lend its own
 *   rights to text someone else wrote (a confused deputy). assert() records who said it (phasevec_assert), and only
 *   a caller that already holds the author's privileges may run the proof in the author's name, so no proof runs
 *   with more rights than its author has, and no caller gains any. The run is a security-restricted operation.
 *   phasevec_prove (the 0.14.2 entry point, kept for the SQL of 0.14.2 .. 0.19.0) still runs as the caller.
 */
#include "postgres.h"

#include <stdlib.h>
#include <string.h>

#include "access/htup_details.h"
#include "access/xact.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_type.h"
#include "executor/spi.h"
#include "fmgr.h"
#include "funcapi.h"
#include "miscadmin.h"
#include "nodes/parsenodes.h"
#include "parser/parser.h"
#include "storage/latch.h"
#include "utils/acl.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/memutils.h"
#include "utils/resowner.h"
#include "utils/syscache.h"
#include "utils/timeout.h"

PG_FUNCTION_INFO_V1(phasevec_prove);
PG_FUNCTION_INFO_V1(phasevec_prove_as);
PG_FUNCTION_INFO_V1(phasevec_assert);

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

/* The wrapped proof must be one SELECT, or the cost step and the run would not see the same thing. */
static void
check_one_select(const char *sql)
{
	List	   *raw = raw_parser(sql, RAW_PARSE_DEFAULT);
	Node	   *stmt;

	if (list_length(raw) != 1)
		ereport(ERROR,
				(errcode(ERRCODE_SYNTAX_ERROR),
				 errmsg("a proof is one boolean expression; this one makes %d statements", list_length(raw))));
	stmt = linitial_node(RawStmt, raw)->stmt;
	if (!IsA(stmt, SelectStmt) || ((SelectStmt *) stmt)->intoClause != NULL)
		ereport(ERROR,
				(errcode(ERRCODE_SYNTAX_ERROR),
				 errmsg("a proof is one boolean expression, read by a plain SELECT")));
}

/* The planner total cost of a query (EXPLAIN, FORMAT JSON), or -1 when it cannot be read. */
static double
estimated_cost(const char *sql)
{
	StringInfoData q;
	char	   *plan;
	char	   *at;
	const char *label = "\"Total Cost\": ";

	initStringInfo(&q);
	appendStringInfo(&q, "EXPLAIN (FORMAT JSON) %s", sql);
	if (SPI_execute(q.data, false, 0) < 0 || SPI_tuptable == NULL || SPI_processed < 1)
		return -1;
	plan = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1);
	at = plan ? strstr(plan, label) : NULL;
	return at ? strtod(at + strlen(label), NULL) : -1;
}

/*
 * Run one proof: read-only, in a subtransaction always rolled back, under its own clock and cost cap. With a valid
 * as_role, the proof runs as that role, in a security-restricted operation; the subtransaction's rollback puts the
 * caller's identity back (and so does any error).
 */
static Datum
prove(FunctionCallInfo fcinfo, const char *proof, int timeout_ms, double max_cost, Oid as_role)
{
	TupleDesc	tupdesc;
	Datum		values[2];
	bool		nulls[2] = {false, false};
	volatile bool ok = false;
	char	   *volatile err = NULL;
	StringInfoData sql;
	MemoryContext oldcontext = CurrentMemoryContext;
	ResourceOwner oldowner = CurrentResourceOwner;
	bool		nested = prove_in_progress;
	int			my_timeout = nested ? 0 : timeout_ms;
	Oid			save_userid;
	int			save_sec_context;

	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		elog(ERROR, "phasevec_prove: the result must be a row type");
	tupdesc = BlessTupleDesc(tupdesc);
	if (prove_timeout == MAX_TIMEOUTS)
		prove_timeout = RegisterTimeout(USER_TIMEOUT, prove_timeout_handler);

	initStringInfo(&sql);
	appendStringInfo(&sql, "SELECT (%s)::boolean", proof);
	GetUserIdAndSecContext(&save_userid, &save_sec_context);

	prove_fired = false;
	prove_in_progress = true;
	BeginInternalSubTransaction(NULL);
	MemoryContextSwitchTo(oldcontext);
	PG_TRY();
	{
		double		cost = -1;
		bool		isnull;
		Datum		d;

		if (OidIsValid(as_role))
			SetUserIdAndSecContext(as_role, save_sec_context | SECURITY_LOCAL_USERID_CHANGE |
								   SECURITY_RESTRICTED_OPERATION);
		(void) set_config_option("transaction_read_only", "on", PGC_USERSET, PGC_S_SESSION,
								 GUC_ACTION_LOCAL, true, 0, false);
		check_one_select(sql.data);
		if (SPI_connect() != SPI_OK_CONNECT)
			elog(ERROR, "phasevec_prove: SPI_connect failed");
		if (my_timeout > 0)
			enable_timeout_after(prove_timeout, my_timeout);
		if (max_cost > 0)
		{
			cost = estimated_cost(sql.data);
			if (cost < 0)
				elog(ERROR, "the proof's cost could not be estimated: not run");
		}
		if (max_cost > 0 && cost > max_cost)
		{
			char		buf[160];

			snprintf(buf, sizeof buf, "the proof is estimated at %.0f, above the limit of %.0f: not run", cost, max_cost);
			err = MemoryContextStrdup(oldcontext, buf);
			ok = false;
		}
		else
		{
			if (SPI_execute(sql.data, false, 1) != SPI_OK_SELECT || SPI_processed != 1)
				elog(ERROR, "the proof must return one row");
			d = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &isnull);
			ok = !isnull && DatumGetBool(d);
			if (isnull)
				err = MemoryContextStrdup(oldcontext, "the proof returned NULL");
		}
		if (my_timeout > 0)
			disable_timeout(prove_timeout, false);
		SPI_finish();
		/* our timer fired as the proof ended: the answer stands, and the caller must not be canceled by it */
		if (prove_fired)
		{
			prove_fired = false;
			QueryCancelPending = false;
		}
		RollbackAndReleaseCurrentSubTransaction();
		MemoryContextSwitchTo(oldcontext);
		CurrentResourceOwner = oldowner;
		SetUserIdAndSecContext(save_userid, save_sec_context);
		prove_in_progress = nested;
	}
	PG_CATCH();
	{
		ErrorData  *edata;
		bool		ours = prove_fired;

		if (my_timeout > 0)
			disable_timeout(prove_timeout, false);
		prove_fired = false;
		MemoryContextSwitchTo(oldcontext);
		edata = CopyErrorData();
		FlushErrorState();
		RollbackAndReleaseCurrentSubTransaction();
		MemoryContextSwitchTo(oldcontext);
		CurrentResourceOwner = oldowner;
		SetUserIdAndSecContext(save_userid, save_sec_context);
		prove_in_progress = nested;
		if (edata->sqlerrcode == ERRCODE_QUERY_CANCELED && !ours)
			ReThrowError(edata);
		ok = false;
		if (ours)
		{
			char		buf[96];

			snprintf(buf, sizeof buf, "the proof took longer than %d ms", timeout_ms);
			err = pstrdup(buf);
		}
		else
			err = pstrdup(edata->message);
		FreeErrorData(edata);
	}
	PG_END_TRY();

	values[0] = BoolGetDatum(ok);
	if (err)
		values[1] = CStringGetTextDatum(err);
	else
		nulls[1] = true;
	PG_RETURN_DATUM(HeapTupleGetDatum(heap_form_tuple(tupdesc, values, nulls)));
}

/* phasevec._prove_c(proof text, timeout_ms int, max_cost float8, OUT ok boolean, OUT err text): as the caller */
Datum
phasevec_prove(PG_FUNCTION_ARGS)
{
	return prove(fcinfo, text_to_cstring(PG_GETARG_TEXT_PP(0)), PG_GETARG_INT32(1), PG_GETARG_FLOAT8(2), InvalidOid);
}

/*
 * phasevec._prove_as(proof text, timeout_ms int, max_cost float8, author name, OUT ok boolean, OUT err text)
 * The proof runs as its author. The caller must already have the author's privileges (be the author, a member of
 * it that inherits, or a superuser): running as the author is then a step down, never a step up.
 */
Datum
phasevec_prove_as(PG_FUNCTION_ARGS)
{
	const char *author = NameStr(*PG_GETARG_NAME(3));
	Oid			role = get_role_oid(author, true);

	if (!OidIsValid(role))
		ereport(ERROR,
				(errcode(ERRCODE_UNDEFINED_OBJECT),
				 errmsg("phasevec: the author of this proof, role \"%s\", does not exist", author)));
	if (!has_privs_of_role(GetUserId(), role))
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("phasevec: role \"%s\" cannot run a proof as its author \"%s\"",
						GetUserNameFromId(GetUserId(), false), author),
				 errhint("Proofs run with their author's rights: verify as the author or as a role that has its privileges.")));
	return prove(fcinfo, text_to_cstring(PG_GETARG_TEXT_PP(0)), PG_GETARG_INT32(1), PG_GETARG_FLOAT8(2), role);
}

/*
 * phasevec.assert(watch text, key text, proof text, topic text, support jsonb, expires_at timestamptz)
 * Records the claim with its author: the current user of the CALLER (a SECURITY DEFINER function would only ever
 * see its owner). The row is written by phasevec._assert_set, which only the extension's owner may run: this
 * function steps into the owner of phasevec.assert for that one call, as PostgreSQL's own RI triggers do.
 */
Datum
phasevec_assert(PG_FUNCTION_ARGS)
{
	Oid			author = GetUserId();
	Oid			owner;
	Oid			save_userid;
	int			save_sec_context;
	HeapTuple	pt;
	Oid			types[7] = {TEXTOID, TEXTOID, TEXTOID, TEXTOID, JSONBOID, TIMESTAMPTZOID, OIDOID};
	Datum		values[7];
	char		nulls[8] = "       ";

	for (int i = 0; i < 6; i++)
	{
		if (PG_ARGISNULL(i))
		{
			values[i] = (Datum) 0;
			nulls[i] = 'n';
		}
		else
			values[i] = PG_GETARG_DATUM(i);
	}
	values[6] = ObjectIdGetDatum(author);

	pt = SearchSysCache1(PROCOID, ObjectIdGetDatum(fcinfo->flinfo->fn_oid));
	if (!HeapTupleIsValid(pt))
		elog(ERROR, "phasevec_assert: cache lookup failed for function %u", fcinfo->flinfo->fn_oid);
	owner = ((Form_pg_proc) GETSTRUCT(pt))->proowner;
	ReleaseSysCache(pt);

	GetUserIdAndSecContext(&save_userid, &save_sec_context);
	SetUserIdAndSecContext(owner, save_sec_context | SECURITY_LOCAL_USERID_CHANGE);
	if (SPI_connect() != SPI_OK_CONNECT)
		elog(ERROR, "phasevec_assert: SPI_connect failed");
	if (SPI_execute_with_args("SELECT phasevec._assert_set($1, $2, $3, $4, $5, $6, $7)",
							  7, types, values, nulls, false, 1) != SPI_OK_SELECT)
		elog(ERROR, "phasevec_assert: the claim was not recorded");
	SPI_finish();
	SetUserIdAndSecContext(save_userid, save_sec_context);
	PG_RETURN_VOID();
}
