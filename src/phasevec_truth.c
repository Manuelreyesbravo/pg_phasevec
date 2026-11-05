/*
 * pg_phasevec 0.14.2: a proof with its own clock.
 *
 * statement_timeout is armed when a top-level statement starts, so a PL/pgSQL verify() could not cut one slow proof
 * among many. Here the proof runs inside an internal subtransaction (always rolled back), read-only, with a timer of
 * its own (a USER_TIMEOUT). Before running, the planner estimates the proof (EXPLAIN): one above max_cost is refuted
 * without running.
 *
 * 0.20.0: a verdict is about one claim, judged in one state, by one author, under one clock.
 *
 * - A claim is (the row's text as its author read it, the proof, the author). assert() reads the text through the
 *   watch's recipe with the caller's rights and records its hash (truth.asserted_for) and the author's OID. A
 *   writer who edits the row afterwards changes the text, not the claim: the claim is not about the new text, and
 *   no verify() turns the new text into 'verified', whatever the proof reads.
 * - verify() and verify_one() are C, so they know who calls them, and they are the only door: the internals they use
 *   (_truth_due, _truth_of, _truth_set) carry no rights of their own and only the owner may run them. A verifier is
 *   granted verify() or verify_one() and nothing else.
 * - A proof runs as its author, in a security-restricted operation, only when the caller already holds the author's
 *   privileges. The author is an OID, resolved only while it still has the name it had: a dropped author, or a name
 *   that now belongs to another role, runs nothing.
 * - One stable state: inside the proof's subtransaction, as the author, the row is read before and after the proof
 *   (text hash and row version). The text must be the one asserted, and the version must not move while the proof
 *   runs; under READ COMMITTED each statement of the proof can see another snapshot, so a text that changed and
 *   changed back (same hash, new version) is caught and nothing is recorded.
 * - The clock bounds the verdict: a verdict counts only if our timer did not fire and the proof ended inside its
 *   limit. A proof that catches our cancel runs on, but it is refuted for its time. A proof cannot run another proof.
 *   A query_canceled that a proof raises itself (RAISE SQLSTATE '57014') is that proof's error; a real cancel
 *   (ProcessInterrupts: the caller's statement_timeout, a user's cancel) is thrown again.
 * - Session advisory locks a proof takes survive its rolled-back subtransaction: those it left are released.
 * - _note() is C too: it checks that its caller writes the watched table before it touches that watch's sources.
 */
#include "postgres.h"

#include <string.h>

#include "access/htup_details.h"
#include "access/xact.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_type.h"
#include "datatype/timestamp.h"
#include "executor/spi.h"
#include "fmgr.h"
#include "funcapi.h"
#include "miscadmin.h"
#include "nodes/parsenodes.h"
#include "parser/parser.h"
#include "storage/latch.h"
#include "storage/lock.h"
#include "utils/acl.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/memutils.h"
#include "utils/resowner.h"
#include "utils/syscache.h"
#include "utils/timeout.h"
#include "utils/timestamp.h"
#include "utils/tuplestore.h"

PG_FUNCTION_INFO_V1(phasevec_prove);
PG_FUNCTION_INFO_V1(phasevec_assert);
PG_FUNCTION_INFO_V1(phasevec_verify);
PG_FUNCTION_INFO_V1(phasevec_verify_one);
PG_FUNCTION_INFO_V1(phasevec_note);

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

/* Step into a role for one internal call, as PostgreSQL's own RI triggers do; an error puts the caller back. */
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

/* --------------------------------------------------------------------------------------- the watched row -- */

/*
 * The text of a watched row exactly as the watch trigger and brief() read it (the recipe over the row, as text,
 * NULL as ''), hashed as phasevec.sources hashes it, and the row version (xmin and ctid) it was read from.
 */
#define READ_SQL \
	"SELECT pg_catalog.sha256(pg_catalog.convert_to(COALESCE((%s)::pg_catalog.text, ''), 'UTF8')), " \
	"r.xmin::pg_catalog.text OPERATOR(pg_catalog.||) '/' OPERATOR(pg_catalog.||) r.ctid::pg_catalog.text " \
	"FROM %s r WHERE r.%s::pg_catalog.text OPERATOR(pg_catalog.=) $1 LIMIT 1"

typedef struct Target
{
	int32		watch;
	char	   *read_sql;
} Target;

/* The watch and how to read its rows. SPI connected, as the owner. */
static void
load_target(text *watch, Target *t, MemoryContext keep)
{
	Oid			at[1] = {TEXTOID};
	Datum		av[1] = {PointerGetDatum(watch)};
	HeapTuple	tup;
	TupleDesc	td;
	bool		isnull;
	char	   *src;
	char	   *key_col;
	char	   *recipe;

	if (SPI_execute_with_args("SELECT w.id, pg_catalog.format('%I.%I', n.nspname, c.relname), "
							  "w.key_col::pg_catalog.text, w.recipe FROM phasevec._watch($1) w "
							  "JOIN pg_catalog.pg_class c ON c.oid OPERATOR(pg_catalog.=) w.source "
							  "JOIN pg_catalog.pg_namespace n ON n.oid OPERATOR(pg_catalog.=) c.relnamespace",
							  1, at, av, NULL, true, 1) != SPI_OK_SELECT || SPI_processed != 1)
		elog(ERROR, "phasevec: the watch's table could not be found");
	tup = SPI_tuptable->vals[0];
	td = SPI_tuptable->tupdesc;
	t->watch = DatumGetInt32(SPI_getbinval(tup, td, 1, &isnull));
	src = SPI_getvalue(tup, td, 2);
	key_col = SPI_getvalue(tup, td, 3);
	recipe = SPI_getvalue(tup, td, 4);
	t->read_sql = MemoryContextStrdup(keep, psprintf(READ_SQL, recipe, src, quote_identifier(key_col)));
}

typedef struct Seen
{
	bool		found;
	bytea	   *hash;
	char	   *version;
} Seen;

/* Read one row with the current user's rights and a fresh snapshot. SPI connected. */
static void
read_row(const Target *t, const char *key, Seen *s, MemoryContext keep)
{
	Oid			at[1] = {TEXTOID};
	Datum		av[1] = {CStringGetTextDatum(key)};

	memset(s, 0, sizeof(Seen));
	if (SPI_execute_with_args(t->read_sql, 1, at, av, NULL, false, 1) != SPI_OK_SELECT)
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
}

static bool
same_bytes(const bytea *a, const bytea *b)
{
	if (a == NULL || b == NULL)
		return false;
	return VARSIZE_ANY_EXHDR(a) == VARSIZE_ANY_EXHDR(b) &&
		memcmp(VARDATA_ANY(a), VARDATA_ANY(b), VARSIZE_ANY_EXHDR(a)) == 0;
}

/*
 * read_row for assert(): the recipe is the table owner's SQL, run here with the asserting role's rights, so it runs
 * as a proof does: read-only, in a security-restricted operation, in a subtransaction rolled back afterwards (an
 * error is thrown again, after it). SPI connected.
 */
static void
read_row_guarded(const Target *t, const char *key, Seen *s, MemoryContext keep)
{
	MemoryContext oldcontext = CurrentMemoryContext;
	ResourceOwner oldowner = CurrentResourceOwner;
	Oid			save_userid;
	int			save_sec_context;

	GetUserIdAndSecContext(&save_userid, &save_sec_context);
	BeginInternalSubTransaction(NULL);
	MemoryContextSwitchTo(oldcontext);
	PG_TRY();
	{
		SetUserIdAndSecContext(save_userid, save_sec_context | SECURITY_RESTRICTED_OPERATION);
		(void) set_config_option("transaction_read_only", "on", PGC_USERSET, PGC_S_SESSION,
								 GUC_ACTION_LOCAL, true, 0, false);
		if (SPI_connect() != SPI_OK_CONNECT)
			elog(ERROR, "phasevec: SPI_connect failed");
		read_row(t, key, s, keep);
		SPI_finish();
		RollbackAndReleaseCurrentSubTransaction();
		MemoryContextSwitchTo(oldcontext);
		CurrentResourceOwner = oldowner;
		SetUserIdAndSecContext(save_userid, save_sec_context);
	}
	PG_CATCH();
	{
		ErrorData  *edata;

		MemoryContextSwitchTo(oldcontext);
		edata = CopyErrorData();
		FlushErrorState();
		RollbackAndReleaseCurrentSubTransaction();
		MemoryContextSwitchTo(oldcontext);
		CurrentResourceOwner = oldowner;
		SetUserIdAndSecContext(save_userid, save_sec_context);
		ReThrowError(edata);
	}
	PG_END_TRY();
}

/* -------------------------------------------------------------------------------- advisory locks left -- */

typedef struct Held
{
	int			n;
	LOCKTAG    *tag;
	LOCKMASK   *mask;
} Held;

/* The advisory locks this backend holds now, session or transaction level. */
static void
advisory_held(Held *h)
{
	LockData   *ld = GetLockStatusData();

	h->n = 0;
	h->tag = palloc(sizeof(LOCKTAG) * Max(ld->nelements, 1));
	h->mask = palloc(sizeof(LOCKMASK) * Max(ld->nelements, 1));
	for (int i = 0; i < ld->nelements; i++)
	{
		LockInstanceData *li = &ld->locks[i];

		if (li->pid == MyProcPid && li->locktag.locktag_type == LOCKTAG_ADVISORY && li->holdMask != 0)
		{
			h->tag[h->n] = li->locktag;
			h->mask[h->n] = li->holdMask;
			h->n++;
		}
	}
}

/*
 * After the proof's subtransaction is rolled back, every transaction-level lock it took is gone; a session-level
 * advisory lock is not. Release those on keys the caller did not hold before the proof. (A proof that stacks one
 * more hold on a key the caller already held keeps it: that cannot be told apart.)
 */
static void
advisory_release_new(const Held *before)
{
	Held		now;

	advisory_held(&now);
	for (int i = 0; i < now.n; i++)
	{
		bool		had = false;

		for (int j = 0; j < before->n && !had; j++)
			had = memcmp(&now.tag[i], &before->tag[j], sizeof(LOCKTAG)) == 0;
		if (had)
			continue;
		for (LOCKMODE m = 1; m <= MaxLockMode; m++)
			if (now.mask[i] & LOCKBIT_ON(m))
				while (LockHeldByMe(&now.tag[i], m, false))
					if (!LockRelease(&now.tag[i], m, true))
						break;
	}
}

/* ------------------------------------------------------------------------------------------- the judge -- */

typedef enum Outcome
{
	OUT_VERIFIED,
	OUT_REFUTED,
	OUT_UNPROVEN,				/* nothing judged: no row, not the asserted text, author gone */
	OUT_MOVED					/* the row changed while the proof ran: nothing recorded */
} Outcome;

static const char *const outcome_name[] = {"verified", "refuted", "unproven", NULL};

typedef struct Judgment
{
	Outcome		out;
	char	   *err;
} Judgment;

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

static void
require_clock(int timeout_ms)
{
	if (timeout_ms <= 0)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("phasevec: a proof runs under a clock: p_timeout_ms must be above 0")));
}

/*
 * Judge one proof: read-only, in a subtransaction always rolled back, under its own clock and cost cap. With a valid
 * as_role, as that role, in a security-restricted operation. With a target, the row is read before and after the
 * proof in the same subtransaction and the same identity: its text must be the one asserted, and it must not change
 * while the proof runs. The subtransaction's rollback puts the caller's identity back (and so does any error).
 */
static void
judge(const char *proof, int timeout_ms, double max_cost, Oid as_role,
	  const Target *target, const char *key, const bytea *asserted_for, Judgment *j)
{
	MemoryContext oldcontext = CurrentMemoryContext;
	ResourceOwner oldowner = CurrentResourceOwner;
	StringInfoData sql;
	Oid			save_userid;
	int			save_sec_context;
	Held		before;
	volatile Outcome out = OUT_REFUTED;
	const char *volatile err = NULL;
	volatile int phase = 1;		/* 0 reading the row, 1 proving, 2 reading it again */
	volatile TimestampTz started = 0;

	if (prove_in_progress)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("phasevec: a proof cannot run another proof")));
	if (prove_timeout == MAX_TIMEOUTS)
		prove_timeout = RegisterTimeout(USER_TIMEOUT, prove_timeout_handler);

	initStringInfo(&sql);
	appendStringInfo(&sql, "SELECT (%s)::boolean", proof);
	GetUserIdAndSecContext(&save_userid, &save_sec_context);
	advisory_held(&before);

	prove_fired = false;
	prove_in_progress = true;
	BeginInternalSubTransaction(NULL);
	MemoryContextSwitchTo(oldcontext);
	PG_TRY();
	{
		Seen		first = {0};
		Seen		last;
		bool		ready = true;

		if (OidIsValid(as_role))
			SetUserIdAndSecContext(as_role, save_sec_context | SECURITY_LOCAL_USERID_CHANGE |
								   SECURITY_RESTRICTED_OPERATION);
		(void) set_config_option("transaction_read_only", "on", PGC_USERSET, PGC_S_SESSION,
								 GUC_ACTION_LOCAL, true, 0, false);
		check_one_select(sql.data);
		if (SPI_connect() != SPI_OK_CONNECT)
			elog(ERROR, "phasevec: SPI_connect failed");
		started = GetCurrentTimestamp();
		if (timeout_ms > 0)
			enable_timeout_after(prove_timeout, timeout_ms);
		if (target)
		{
			phase = 0;
			read_row(target, key, &first, oldcontext);
			phase = 1;
			if (!first.found)
			{
				out = OUT_UNPROVEN;
				err = "the row is gone: there is nothing to judge";
				ready = false;
			}
			else if (!same_bytes(first.hash, asserted_for))
			{
				out = OUT_UNPROVEN;
				err = "the row does not say what was asserted (it changed, or it was not readable then): assert it again";
				ready = false;
			}
		}
		if (ready)
		{
			double		cost = -1;

			if (max_cost > 0)
			{
				cost = estimated_cost(sql.data);
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

				if (SPI_execute(sql.data, false, 1) != SPI_OK_SELECT || SPI_processed != 1)
					elog(ERROR, "the proof must return one row");
				d = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &isnull);
				out = (!isnull && DatumGetBool(d)) ? OUT_VERIFIED : OUT_REFUTED;
				if (isnull)
					err = "the proof returned NULL";
			}
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
		SetUserIdAndSecContext(save_userid, save_sec_context);
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
		MemoryContextSwitchTo(oldcontext);
		edata = CopyErrorData();
		FlushErrorState();
		RollbackAndReleaseCurrentSubTransaction();
		MemoryContextSwitchTo(oldcontext);
		CurrentResourceOwner = oldowner;
		SetUserIdAndSecContext(save_userid, save_sec_context);
		prove_in_progress = false;
		advisory_release_new(&before);

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
	advisory_release_new(&before);

	j->out = out;
	j->err = err ? pstrdup(err) : NULL;
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
	judge(text_to_cstring(PG_GETARG_TEXT_PP(0)), PG_GETARG_INT32(1), PG_GETARG_FLOAT8(2), InvalidOid,
		  NULL, NULL, NULL, &j);
	values[0] = BoolGetDatum(j.out == OUT_VERIFIED);
	if (j.err)
		values[1] = CStringGetTextDatum(j.err);
	else
		nulls[1] = true;
	PG_RETURN_DATUM(HeapTupleGetDatum(heap_form_tuple(tupdesc, values, nulls)));
}

/* ------------------------------------------------------------------------------------------- the claims -- */

typedef struct Claim
{
	char	   *key;
	char	   *proof;
	Oid			author;			/* InvalidOid: asserted before 0.20.0 */
	bool		author_known;	/* the OID is still a role, with the name it had */
	bytea	   *asserted_for;
} Claim;

#define CLAIM_COLUMNS "key, proof, author, author_known, asserted_for"

static void
claim_from(HeapTuple tup, TupleDesc td, Claim *c, MemoryContext keep)
{
	bool		isnull;
	Datum		d;
	MemoryContext o = MemoryContextSwitchTo(keep);

	c->key = TextDatumGetCString(SPI_getbinval(tup, td, 1, &isnull));
	d = SPI_getbinval(tup, td, 2, &isnull);
	c->proof = isnull ? NULL : TextDatumGetCString(d);
	d = SPI_getbinval(tup, td, 3, &isnull);
	c->author = isnull ? InvalidOid : DatumGetObjectId(d);
	d = SPI_getbinval(tup, td, 4, &isnull);
	c->author_known = !isnull && DatumGetBool(d);
	d = SPI_getbinval(tup, td, 5, &isnull);
	c->asserted_for = isnull ? NULL : DatumGetByteaPCopy(d);
	MemoryContextSwitchTo(o);
}

/* Record a judgment through phasevec._truth_set, as the owner; the verdict as it reads now. */
static char *
record(Oid owner, int32 watch, const Claim *c, const Judgment *j)
{
	Oid			at[7] = {INT4OID, TEXTOID, TEXTOID, TEXTOID, BYTEAOID, TEXTOID, OIDOID};
	Datum		av[7];
	char		nulls[8] = "       ";
	const char *name = outcome_name[j->out];
	MemoryContext keep = CurrentMemoryContext;
	char	   *v = NULL;
	Who			was;

	av[0] = Int32GetDatum(watch);
	av[1] = CStringGetTextDatum(c->key);
	av[2] = name ? CStringGetTextDatum(name) : (Datum) 0;
	nulls[2] = name ? ' ' : 'n';
	av[3] = j->err ? CStringGetTextDatum(j->err) : (Datum) 0;
	nulls[3] = j->err ? ' ' : 'n';
	av[4] = c->asserted_for ? PointerGetDatum(c->asserted_for) : (Datum) 0;
	nulls[4] = c->asserted_for ? ' ' : 'n';
	av[5] = c->proof ? CStringGetTextDatum(c->proof) : (Datum) 0;
	nulls[5] = c->proof ? ' ' : 'n';
	av[6] = ObjectIdGetDatum(c->author);
	nulls[6] = OidIsValid(c->author) ? ' ' : 'n';

	become(owner, &was);
	if (SPI_connect() != SPI_OK_CONNECT)
		elog(ERROR, "phasevec: SPI_connect failed");
	if (SPI_execute_with_args("SELECT phasevec._truth_set($1, $2, $3, $4, $5, $6, $7)",
							  7, at, av, nulls, false, 1) != SPI_OK_SELECT)
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

static void
judge_claim(const Claim *c, int timeout_ms, double max_cost, const Target *t, Judgment *j)
{
	if (!c->author_known)
	{
		j->out = OUT_UNPROVEN;
		j->err = pstrdup("the author of this proof is gone (dropped, or its name is another role's now): assert it again (adopt)");
	}
	else
		judge(c->proof, timeout_ms, max_cost, c->author, t, c->key, c->asserted_for, j);
}

static int64
interval_usec(const Interval *iv)
{
	if (INTERVAL_NOT_FINITE(iv))
		return INTERVAL_IS_NOBEGIN(iv) ? 0 : PG_INT64_MAX;
	return iv->time + (int64) iv->day * USECS_PER_DAY + (int64) iv->month * DAYS_PER_MONTH * USECS_PER_DAY;
}

/*
 * phasevec.verify(watch text, n int, every interval, budget interval, timeout_ms int, max_cost float8)
 *   RETURNS TABLE (key text, verdict text, error text)
 * The due proofs whose author the caller may act as (a gone author's claim is set unproven by anyone), oldest
 * first, while the budget lasts. The proof resolves names with the caller's search_path, as before 0.20.0: it runs
 * with its author's rights, which the caller already has, so the path lends nothing.
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

	for (int i = 0; i < 6; i++)
		if (PG_ARGISNULL(i))
			ereport(ERROR, (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED), errmsg("phasevec: verify() takes no NULL argument")));
	timeout_ms = PG_GETARG_INT32(4);
	max_cost = PG_GETARG_FLOAT8(5);
	require_clock(timeout_ms);
	budget_us = interval_usec(PG_GETARG_INTERVAL_P(3));
	InitMaterializedSRF(fcinfo, 0);

	become(owner, &was);
	if (SPI_connect() != SPI_OK_CONNECT)
		elog(ERROR, "phasevec: SPI_connect failed");
	load_target(PG_GETARG_TEXT_PP(0), &target, keep);
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
	for (uint64 i = 0; i < nclaims; i++)
	{
		const Claim *c = &claims[i];
		Judgment	j;
		char	   *v;
		Datum		values[3];
		bool		nulls[3] = {false, false, false};
		MemoryContext o;

		if (GetCurrentTimestamp() - t0 >= budget_us)
			break;
		/* _truth_due already left out the authors the caller may not act as; checked again where it matters */
		if (c->author_known && !has_privs_of_role(caller, c->author))
			continue;
		o = MemoryContextSwitchTo(per);
		judge_claim(c, timeout_ms, max_cost, &target, &j);
		v = record(owner, target.watch, c, &j);
		values[0] = CStringGetTextDatum(c->key);
		values[1] = v ? CStringGetTextDatum(v) : (Datum) 0;
		nulls[1] = v == NULL;
		values[2] = j.err ? CStringGetTextDatum(j.err) : (Datum) 0;
		nulls[2] = j.err == NULL;
		tuplestore_putvalues(rsinfo->setResult, rsinfo->setDesc, values, nulls);
		MemoryContextSwitchTo(o);
		MemoryContextReset(per);
	}
	MemoryContextDelete(per);
	return (Datum) 0;
}

/*
 * phasevec.verify_one(watch text, key text, timeout_ms int, max_cost float8) RETURNS text
 * One key, now or out of turn, as its author. NULL when the key has no proof or was replaced; an error when the proof
 * has no author or the caller may not act as it.
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

	for (int i = 0; i < 4; i++)
		if (PG_ARGISNULL(i))
			ereport(ERROR, (errcode(ERRCODE_NULL_VALUE_NOT_ALLOWED), errmsg("phasevec: verify_one() takes no NULL argument")));
	timeout_ms = PG_GETARG_INT32(2);
	require_clock(timeout_ms);

	become(owner, &was);
	if (SPI_connect() != SPI_OK_CONNECT)
		elog(ERROR, "phasevec: SPI_connect failed");
	load_target(PG_GETARG_TEXT_PP(0), &target, keep);
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
				 errhint("phasevec.adopt(watch) asserts again, as the caller, every proof of a watch whose author is unknown or gone.")));
	if (c.author_known && !has_privs_of_role(caller, c.author))
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("phasevec: role \"%s\" cannot run a proof as its author \"%s\"",
						GetUserNameFromId(caller, false), GetUserNameFromId(c.author, false)),
				 errhint("Proofs run with their author's rights: verify as the author or as a role that has its privileges.")));
	judge_claim(&c, timeout_ms, PG_GETARG_FLOAT8(3), &target, &j);
	v = record(owner, target.watch, &c, &j);
	if (v == NULL)
		PG_RETURN_NULL();
	PG_RETURN_TEXT_P(cstring_to_text(v));
}

/*
 * phasevec.assert(watch text, key text, proof text, topic text, support jsonb, expires_at timestamptz)
 * Records the claim with its author, the current user of the CALLER (a SECURITY DEFINER wrapper vouches with its
 * owner's rights, and that owner is the author), and what the author vouches for: the row's text as the author reads
 * it now, through the watch's recipe, with its own rights (read-only, in a security-restricted operation, as a proof
 * runs). A proof about a row its author cannot read is refused
 * (permission denied); a key with no row yet is bound to no text, and its proof never verifies until asserted again.
 */
Datum
phasevec_assert(PG_FUNCTION_ARGS)
{
	Oid			author = GetUserId();
	Oid			owner = function_owner(fcinfo);
	MemoryContext keep = CurrentMemoryContext;
	Oid			types[8] = {TEXTOID, TEXTOID, TEXTOID, TEXTOID, JSONBOID, TIMESTAMPTZOID, OIDOID, BYTEAOID};
	Datum		values[8];
	char		nulls[9] = "        ";
	bytea	   *seen = NULL;
	Who			was;

	for (int i = 0; i < 6; i++)
	{
		values[i] = PG_ARGISNULL(i) ? (Datum) 0 : PG_GETARG_DATUM(i);
		nulls[i] = PG_ARGISNULL(i) ? 'n' : ' ';
	}
	values[6] = ObjectIdGetDatum(author);

	if (SPI_connect() != SPI_OK_CONNECT)
		elog(ERROR, "phasevec_assert: SPI_connect failed");
	if (!PG_ARGISNULL(0) && !PG_ARGISNULL(1) && !PG_ARGISNULL(2))
	{
		Target		t;
		Seen		s;

		become(owner, &was);
		load_target(PG_GETARG_TEXT_PP(0), &t, keep);
		unbecome(&was);
		read_row_guarded(&t, text_to_cstring(PG_GETARG_TEXT_PP(1)), &s, keep);
		seen = s.found ? s.hash : NULL;
	}
	values[7] = seen ? PointerGetDatum(seen) : (Datum) 0;
	nulls[7] = seen ? ' ' : 'n';

	become(owner, &was);
	if (SPI_execute_with_args("SELECT phasevec._assert_set($1, $2, $3, $4, $5, $6, $7, $8)",
							  8, types, values, nulls, false, 1) != SPI_OK_SELECT)
		elog(ERROR, "phasevec_assert: the claim was not recorded");
	unbecome(&was);
	SPI_finish();
	PG_RETURN_VOID();
}

/*
 * phasevec._note(watch int, key text, hash bytea, body text): the watch trigger notes (or, with a NULL hash, forgets)
 * a row. It runs as whoever writes the table; it passes that role to _note_set, which refuses a role that does not
 * write the watch's own table: a writer of one watched table cannot touch another watch's sources.
 */
Datum
phasevec_note(PG_FUNCTION_ARGS)
{
	Oid			writer = GetUserId();
	Oid			owner = function_owner(fcinfo);
	Oid			types[5] = {INT4OID, TEXTOID, BYTEAOID, TEXTOID, OIDOID};
	Datum		values[5];
	char		nulls[6] = "     ";
	Who			was;

	for (int i = 0; i < 4; i++)
	{
		values[i] = PG_ARGISNULL(i) ? (Datum) 0 : PG_GETARG_DATUM(i);
		nulls[i] = PG_ARGISNULL(i) ? 'n' : ' ';
	}
	values[4] = ObjectIdGetDatum(writer);
	become(owner, &was);
	if (SPI_connect() != SPI_OK_CONNECT)
		elog(ERROR, "phasevec_note: SPI_connect failed");
	if (SPI_execute_with_args("SELECT phasevec._note_set($1, $2, $3, $4, $5)",
							  5, types, values, nulls, false, 1) != SPI_OK_SELECT)
		elog(ERROR, "phasevec_note: the row was not noted");
	SPI_finish();
	unbecome(&was);
	PG_RETURN_VOID();
}
