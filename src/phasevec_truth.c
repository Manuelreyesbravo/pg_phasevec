/*
 * pg_phasevec 0.14.2: a proof with its own clock.
 *
 * statement_timeout is armed when a top-level statement starts, so a PL/pgSQL verify() could not cut one slow proof
 * among many. Here the proof runs inside an internal subtransaction (always rolled back), read-only, with a timer of
 * its own (a USER_TIMEOUT): when it fires, the proof is canceled, the subtransaction is undone and the proof is
 * refuted for its time. A cancel that is NOT ours (the caller statement_timeout, a user Ctrl-C) is thrown again, as
 * always. Before running, the planner estimates the proof (EXPLAIN): one above max_cost is refuted without running.
 * The proof runs with the caller rights and search_path: it is the caller code.
 */
#include "postgres.h"

#include <stdlib.h>
#include <string.h>

#include "access/htup_details.h"
#include "access/xact.h"
#include "executor/spi.h"
#include "fmgr.h"
#include "funcapi.h"
#include "miscadmin.h"
#include "storage/latch.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/memutils.h"
#include "utils/resowner.h"
#include "utils/timeout.h"

PG_FUNCTION_INFO_V1(phasevec_prove);

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

/* phasevec._prove_c(proof text, timeout_ms int, max_cost float8, OUT ok boolean, OUT err text) */
Datum
phasevec_prove(PG_FUNCTION_ARGS)
{
	char	   *proof = text_to_cstring(PG_GETARG_TEXT_PP(0));
	int			timeout_ms = PG_GETARG_INT32(1);
	double		max_cost = PG_GETARG_FLOAT8(2);
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

	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		elog(ERROR, "phasevec_prove: the result must be a row type");
	tupdesc = BlessTupleDesc(tupdesc);
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
		double		cost = -1;

		(void) set_config_option("transaction_read_only", "on", PGC_USERSET, PGC_S_SESSION,
								 GUC_ACTION_LOCAL, true, 0, false);
		if (SPI_connect() != SPI_OK_CONNECT)
			elog(ERROR, "phasevec_prove: SPI_connect failed");
		if (max_cost > 0)
			cost = estimated_cost(sql.data);
		if (max_cost > 0 && cost > max_cost)
		{
			char		buf[160];

			snprintf(buf, sizeof buf, "the proof is estimated at %.0f, above the limit of %.0f: not run", cost, max_cost);
			err = MemoryContextStrdup(oldcontext, buf);
			ok = false;
		}
		else
		{
			bool		isnull;
			Datum		d;

			if (my_timeout > 0)
				enable_timeout_after(prove_timeout, my_timeout);
			if (SPI_execute(sql.data, false, 1) != SPI_OK_SELECT || SPI_processed != 1)
				elog(ERROR, "the proof must return one row");
			if (my_timeout > 0)
				disable_timeout(prove_timeout, false);
			d = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &isnull);
			ok = !isnull && DatumGetBool(d);
			if (isnull)
				err = MemoryContextStrdup(oldcontext, "the proof returned NULL");
		}
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
		prove_in_progress = nested;
	}
	PG_END_TRY();

	values[0] = BoolGetDatum(ok);
	if (err)
		values[1] = CStringGetTextDatum(err);
	else
		nulls[1] = true;
	PG_RETURN_DATUM(HeapTupleGetDatum(heap_form_tuple(tupdesc, values, nulls)));
}
