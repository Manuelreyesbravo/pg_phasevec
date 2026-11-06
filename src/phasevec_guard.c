/*
 * pg_phasevec 0.20.0: the one way phasevec runs code that is not its own (see phasevec_guard.h).
 *
 * What a guard is, and why each part:
 *
 * - One role, named by the caller of guard_enter: the table's owner for a recipe (as PostgreSQL runs an index
 *   expression in VACUUM, ANALYZE or REINDEX), the author for a proof, the reader for "which rows may I see". Code
 *   never runs with the rights of whoever happened to call phasevec (a superuser reading a brief made a table owner
 *   superuser through a cast the owner wrote).
 * - A security-restricted operation and transaction_read_only: no SET ROLE, no temporary objects, no PREPARE, LISTEN
 *   or DISCARD, no writes.
 * - A GUC nest level, rolled back as an abort rolls it back (AtEOXact_GUC(false)), with the settings that change how
 *   a value reads or prints pinned: a recipe renders the same text whoever calls it from whatever session (a writer
 *   in another TimeZone made a row print as the text its author had vouched for), and a proof means what it meant
 *   to its author (its settings are recorded with the claim). Nothing a proof sets survives it.
 * - The session's own state is out of reach. Its timeouts cannot be changed (a proof that set transaction_timeout
 *   ended the verifier's connection with a FATAL before any verdict was written, and every later verify() of the
 *   watch died the same way): each timeout setting's check hook refuses while a guard is open. Functions that change
 *   the session and are not undone by a rollback cannot be called (session-level advisory locks: a proof released
 *   the verifier's own; setseed: a proof chose the verifier's random(); pg_cancel_backend and pg_terminate_backend):
 *   the object access hook refuses them while a guard is open.
 */
#include "postgres.h"

#include "catalog/objectaccess.h"
#include "miscadmin.h"
#include "utils/fmgrtab.h"
#include "utils/guc.h"
#include "utils/guc_tables.h"
#include "utils/lsyscache.h"

#include "phasevec_guard.h"

const char *const phasevec_env_names[PHASEVEC_ENV_N] = {
	"DateStyle", "IntervalStyle", "TimeZone", "extra_float_digits", "bytea_output", "search_path",
	"lc_monetary", "lc_numeric", "lc_time", "standard_conforming_strings", "xmloption", "xmlbinary"
};
const char *const phasevec_env_canon[PHASEVEC_ENV_N] = {
	"ISO, MDY", "postgres", "UTC", "1", "hex", "pg_catalog, pg_temp",
	"C", "C", "C", "on", "content", "base64"
};

static int	guard_depth = 0;

bool
guard_active(void)
{
	return guard_depth > 0;
}

/* ------------------------------------------------------------------------------------------ the settings -- */

static void
apply_setting(const char *name, const char *value)
{
	const char *now = GetConfigOption(name, true, false);

	if (now != NULL && strcmp(now, value) == 0)
		return;
	(void) set_config_option(name, value, superuser() ? PGC_SUSET : PGC_USERSET, PGC_S_SESSION,
							 GUC_ACTION_SAVE, true, 0, false);
}

void
guard_enter(Guard *g, Oid role, const char *const *values)
{
	GetUserIdAndSecContext(&g->userid, &g->sec);
	g->depth = guard_depth;
	g->nest = NewGUCNestLevel();
	SetUserIdAndSecContext(role, g->sec | SECURITY_LOCAL_USERID_CHANGE | SECURITY_RESTRICTED_OPERATION);
	for (int i = 0; i < PHASEVEC_ENV_N; i++)
	{
		const char *v = values ? values[i] : phasevec_env_canon[i];

		if (v != NULL)
			apply_setting(phasevec_env_names[i], v);
	}
	/* LOCAL (it cannot be SAVEd): the abort-style rollback of the nest level takes it back all the same */
	(void) set_config_option("transaction_read_only", "on", PGC_USERSET, PGC_S_SESSION,
							 GUC_ACTION_LOCAL, true, 0, false);
	guard_depth = g->depth + 1;
}

void
guard_leave(Guard *g)
{
	guard_depth = g->depth;
	AtEOXact_GUC(false, g->nest);
	SetUserIdAndSecContext(g->userid, g->sec);
}

int
guard_mark(void)
{
	return guard_depth;
}

void
guard_unwind_to(int mark)
{
	guard_depth = mark;
}

int
guard_pin_settings(void)
{
	int			nest = NewGUCNestLevel();

	for (int i = 0; i < PHASEVEC_ENV_N; i++)
		apply_setting(phasevec_env_names[i], phasevec_env_canon[i]);
	return nest;
}

void
guard_unpin_settings(int nest)
{
	AtEOXact_GUC(false, nest);
}

char	  **
guard_env_now(void)
{
	char	  **env = palloc(sizeof(char *) * PHASEVEC_ENV_N);

	for (int i = 0; i < PHASEVEC_ENV_N; i++)
	{
		const char *v = GetConfigOption(phasevec_env_names[i], true, false);

		env[i] = psprintf("%s=%s", phasevec_env_names[i], v ? v : phasevec_env_canon[i]);
	}
	return env;
}

/* ------------------------------------------------------------------------------- the session's timeouts -- */

#define NTIMEOUTS 5
static const char *const timeout_names[NTIMEOUTS] = {
	"transaction_timeout", "statement_timeout", "lock_timeout",
	"idle_in_transaction_session_timeout", "idle_session_timeout"
};
static GucIntCheckHook timeout_prev[NTIMEOUTS];

static bool
timeout_check(int i, int *newval, void **extra, GucSource source)
{
	if (guard_depth > 0)
	{
		GUC_check_errcode(ERRCODE_INSUFFICIENT_PRIVILEGE);
		GUC_check_errmsg("phasevec: code that phasevec runs (a proof, a recipe) cannot change %s",
						 timeout_names[i]);
		GUC_check_errdetail("It would outlive the code: a timeout armed by a proof ends the session that runs it.");
		return false;
	}
	return timeout_prev[i] ? timeout_prev[i] (newval, extra, source) : true;
}

#define TIMEOUT_CHECK(i) \
	static bool timeout_check_##i(int *newval, void **extra, GucSource source) \
	{ return timeout_check(i, newval, extra, source); }
TIMEOUT_CHECK(0)
TIMEOUT_CHECK(1)
TIMEOUT_CHECK(2)
TIMEOUT_CHECK(3)
TIMEOUT_CHECK(4)
static const GucIntCheckHook timeout_hooks[NTIMEOUTS] = {
	timeout_check_0, timeout_check_1, timeout_check_2, timeout_check_3, timeout_check_4
};

#if PG_VERSION_NUM >= 190000
#define INT_CHECK_HOOK(g) ((g)->_int.check_hook)
#else
#define INT_CHECK_HOOK(g) (((struct config_int *) (g))->check_hook)
#endif

static void
freeze_timeouts(void)
{
	for (int i = 0; i < NTIMEOUTS; i++)
	{
		struct config_generic *g = find_option(timeout_names[i], false, true, 0);

		if (g == NULL || g->vartype != PGC_INT || INT_CHECK_HOOK(g) == timeout_hooks[i])
			continue;			/* not in this server, or already ours */
		timeout_prev[i] = INT_CHECK_HOOK(g);
		INT_CHECK_HOOK(g) = timeout_hooks[i];
	}
}

/* ----------------------------------------------------------------------- functions that change the session -- */

static const char *const session_functions[] = {
	"pg_advisory_lock_int8", "pg_advisory_lock_shared_int8", "pg_try_advisory_lock_int8",
	"pg_try_advisory_lock_shared_int8", "pg_advisory_unlock_int8", "pg_advisory_unlock_shared_int8",
	"pg_advisory_lock_int4", "pg_advisory_lock_shared_int4", "pg_try_advisory_lock_int4",
	"pg_try_advisory_lock_shared_int4", "pg_advisory_unlock_int4", "pg_advisory_unlock_shared_int4",
	"pg_advisory_unlock_all", "setseed", "pg_cancel_backend", "pg_terminate_backend"
};
#define NSESSION (sizeof(session_functions) / sizeof(session_functions[0]))
static Oid	session_oids[NSESSION * 2];
static int	nsession_oids = 0;
static object_access_hook_type prev_object_access = NULL;

static void
guard_object_access(ObjectAccessType access, Oid classId, Oid objectId, int subId, void *arg)
{
	if (prev_object_access)
		prev_object_access(access, classId, objectId, subId, arg);
	if (access != OAT_FUNCTION_EXECUTE || guard_depth == 0)
		return;
	for (int i = 0; i < nsession_oids; i++)
		if (session_oids[i] == objectId)
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("phasevec: code that phasevec runs (a proof, a recipe) cannot call %s()", get_func_name(objectId)),
					 errdetail("It changes the session it runs in, and a rollback does not undo that.")));
}

void
phasevec_guard_init(void)
{
	static bool done = false;

	if (done)
		return;
	done = true;
	for (int i = 0; i < fmgr_nbuiltins && nsession_oids < (int) lengthof(session_oids); i++)
		for (int j = 0; j < (int) NSESSION; j++)
			if (strcmp(fmgr_builtins[i].funcName, session_functions[j]) == 0)
			{
				session_oids[nsession_oids] = fmgr_builtins[i].foid;
				nsession_oids++;
			}
	freeze_timeouts();
	prev_object_access = object_access_hook;
	object_access_hook = guard_object_access;
}
