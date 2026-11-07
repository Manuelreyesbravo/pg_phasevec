/*
 * pg_phasevec 0.20.0: the one way phasevec runs code that is not its own (see phasevec_guard.h).
 *
 * The guard is a sealed room. What it is, and why each part:
 *
 * - Its own subtransaction, always rolled back: whatever the code queued, took or set (a NOTIFY, a lock, a setting, a
 *   cursor) ends with it. Until the third cut of 0.20.0 a recipe ran with no subtransaction, and a NOTIFY it queued
 *   went out with its caller's COMMIT.
 * - One role, named by the caller of guard_enter: the table's owner for a recipe (as PostgreSQL runs an index
 *   expression in VACUUM, ANALYZE or REINDEX, and with FORCE ROW LEVEL SECURITY not applied to it, as for a foreign-key
 *   check), the author for a proof, the reader for "which rows may I see". Code never runs with the rights of whoever
 *   happened to call phasevec (a superuser reading a brief made a table owner superuser through a cast the owner wrote).
 * - A security-restricted operation and transaction_read_only: no SET ROLE, no temporary objects, no writes.
 * - A whole settings state that is not the caller's. A recipe renders with every setting that can change what a value
 *   reads, prints or computes at its default, and DateStyle ISO, TimeZone UTC, search_path pg_catalog, ... pinned on top:
 *   the same text whoever calls it from whatever session. A proof does not run in its verifier's session at all
 *   (0.20.0, eighth review): it runs in a session of its own, a new session of its author (phasevec_truth.c), with
 *   what was in effect where it was asserted on top, as its author had it (guard_env_now). Until then it
 *   ran in the verifier's session, and each review found one more piece of that session that decided verdicts: its
 *   temporary objects, its settings' values, which custom placeholders it had, its uncommitted writes and DDL, its
 *   session_user, its application_name.
 * - Nothing that existed before it is in reach. The session's open cursors: those pg_cursors lists are frozen while it
 *   runs, a query begun before it cannot be run inside it, and FETCH, MOVE and CLOSE take only cursors opened inside
 *   it (a recipe read a superuser's open cursor over a table its owner could not read, and NOTIFYed the rows out). The
 *   session's timeouts and exit_on_error cannot be changed (a proof that set transaction_timeout ended the verifier's
 *   connection with a FATAL). Of the commands, only SET, SHOW, EXPLAIN, DECLARE, FETCH, MOVE, CLOSE, CALL and DO run:
 *   NOTIFY, LISTEN, PREPARE, DISCARD, LOAD and the rest are refused. Of the system's own functions, every one that
 *   only reads (stable or immutable) runs, and of the volatile ones only a reviewed few (the clock, sleep, random
 *   numbers, set_config): pg_notify, the advisory locks, setseed, currval, the large-object descriptors, signalling a
 *   backend, and every volatile system function no one reviewed are refused, as are pg_cursor and
 *   pg_prepared_statement, which read the session's own statements, EXPLAIN EXECUTE, which shows one, and
 *   txid_current and pg_current_xact_id, which give the session's transaction an id no rollback takes back.
 *   The session's temporary objects: pg_temp is searched last, and every temporary object a query uses is refused,
 *   by what the query depends on, however it is reached (named, found through search_path, inherited from, inside a
 *   SQL function, in a plan cached before the guard ran: guard_analyze, guard_plan). Until the fourth review a
 *   verifier's temporary table named like the author's took its place in the proof; until the fifth its temporary
 *   view, type, domain or operator did. (A proof's own session has none.)
 * - Nothing it keeps outlives what it was kept for: a guard and a pin (the settings and cursors a call reads once)
 *   end with their subtransaction and with their transaction, however they end (guard_subxact, guard_xact).
 */
#include "postgres.h"

#include "access/transam.h"
#include "access/xact.h"
#include "catalog/dependency.h"
#include "catalog/namespace.h"
#include "catalog/objectaddress.h"
#include "catalog/objectaccess.h"
#include "access/htup_details.h"
#include "catalog/pg_class.h"
#include "catalog/pg_collation.h"
#include "catalog/pg_language.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_operator.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_depend.h"
#include "catalog/pg_ts_config.h"
#include "catalog/pg_ts_dict.h"
#include "access/genam.h"
#include "access/table.h"
#include "utils/fmgroids.h"
#include "catalog/pg_type.h"
#include "executor/executor.h"
#include "executor/tuptable.h"
#include "funcapi.h"
#include "miscadmin.h"
#include "nodes/execnodes.h"
#include "nodes/nodeFuncs.h"
#include "nodes/parsenodes.h"
#include "optimizer/planner.h"
#include "parser/analyze.h"
#include "tcop/cmdtag.h"
#include "tcop/utility.h"
#include "utils/acl.h"
#include "utils/builtins.h"
#include "utils/fmgroids.h"
#include "utils/guc.h"
#include "utils/guc_tables.h"
#include "utils/hsearch.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/plancache.h"
#include "utils/portal.h"
#include "utils/resowner.h"
#include "utils/syscache.h"
#include "utils/tuplestore.h"
#include "utils/varlena.h"

#include "phasevec_guard.h"

/* ------------------------------------------------------------------------------------------- the pins -- */

#define NPINS 14
static const char *const pin_name[NPINS] = {
	"DateStyle", "IntervalStyle", "TimeZone", "extra_float_digits", "bytea_output", "search_path",
	"lc_monetary", "lc_numeric", "lc_time", "standard_conforming_strings", "xmloption", "xmlbinary",
	"timezone_abbreviations", "row_security"
};
static const char *const pin_value[NPINS] = {
	"ISO, MDY", "postgres", "UTC", "1", "hex", "pg_catalog, pg_temp",
	"C", "C", "C", "on", "content", "base64",
	"Default", "on"
};

/* ----------------------------------------------------------------------------------- the guard stack -- */

#define GUARD_MAX 32

typedef struct Level
{
	Oid			userid;			/* who was acting before */
	int			sec;
	MemoryContext cxt;			/* the caller's memory context and resource owner */
	ResourceOwner owner;
	SubTransactionId subid;		/* the guard's subtransaction */
	MemoryContext subcxt;		/* its CurTransactionContext */
	List	   *started;		/* the queries begun inside it */
	int			frozen_base;	/* its frozen cursors start here */
} Level;

static Level levels[GUARD_MAX];
static int	guard_depth = 0;

/*
 * This backend is a proof's own session (phasevec_truth.c): the only one where a proof runs. Nothing sets a setting
 * in it outside a guard, so the names off their default are those of its configuration, read once (a recipe's guard
 * resets them for every row it reads).
 */
static bool proof_session = false;
static List *baseline_nondefault = NIL;
static List *nondefault_names(void);

void
guard_proof_session(void)
{
	MemoryContext o = MemoryContextSwitchTo(TopMemoryContext);

	proof_session = true;
	baseline_nondefault = nondefault_names();
	MemoryContextSwitchTo(o);
}

static Portal *frozen = NULL;
static int	nfrozen = 0;
static int	frozen_cap = 0;

bool
guard_active(void)
{
	return guard_depth > 0;
}

int
guard_mark(void)
{
	return guard_depth;
}

/* ------------------------------------------------------------------------------------------- settings -- */

#if PG_VERSION_NUM >= 190000
#define G_BOOL(g) (&(g)->_bool)
#define G_INT(g) (&(g)->_int)
#define G_REAL(g) (&(g)->_real)
#define G_STR(g) (&(g)->_string)
#define G_ENUM(g) (&(g)->_enum)
#define ENUM_NAME(g, v) config_enum_lookup_by_value((g), (v))
#else
#define G_BOOL(g) ((struct config_bool *) (g))
#define G_INT(g) ((struct config_int *) (g))
#define G_REAL(g) ((struct config_real *) (g))
#define G_STR(g) ((struct config_string *) (g))
#define G_ENUM(g) ((struct config_enum *) (g))
#define ENUM_NAME(g, v) config_enum_lookup_by_value((struct config_enum *) (g), (v))
#endif

/*
 * Settings a claim records and a guard sets: every one a user can set (USERSET or SUSET, and RESET ALL resets) of the
 * groups that decide what a value reads, prints or computes (statement behavior, locale and formatting, compatibility,
 * other client defaults) and every custom one (a placeholder such as app.tenant, an extension's). Not resources,
 * planner, logging, statistics, replication or connections: they change how fast or where, not what. Of the kept
 * groups, not those below: the session's timeouts (a guard refuses them), how messages reach the client (and in which
 * language), and where libraries and extensions are found.
 */
static const char *const not_replayed[] = {
	"client_encoding", "client_min_messages", "lc_messages", "statement_timeout", "lock_timeout", "transaction_timeout",
	"idle_in_transaction_session_timeout", "idle_session_timeout", "dynamic_library_path", "extension_control_path"
};

static bool
replayable(const struct config_generic *g)
{
	if (g->context != PGC_USERSET && g->context != PGC_SUSET)
		return false;
	if (g->flags & (GUC_NO_RESET | GUC_NO_RESET_ALL | GUC_NOT_WHILE_SEC_REST))
		return false;
	switch (g->group)
	{
		case CLIENT_CONN_STATEMENT:
		case CLIENT_CONN_LOCALE:
		case CLIENT_CONN_OTHER:
		case COMPAT_OPTIONS_PREVIOUS:
		case COMPAT_OPTIONS_OTHER:
		case CUSTOM_OPTIONS:
			break;
		default:
			return false;
	}
	if (pg_strncasecmp(g->name, "phasevec.", 9) == 0)
		return false;
	for (int i = 0; i < (int) lengthof(not_replayed); i++)
		if (pg_strcasecmp(g->name, not_replayed[i]) == 0)
			return false;
	return true;
}

/*
 * A custom placeholder (app.tenant: a custom setting no loaded library defines) exists once anything in the session
 * named it in SET, set_config or RESET, or the configuration did, and nothing removes it: a rollback takes back its
 * value, not it. current_setting(name, true) reads NULL while it does not exist and its value ('' while it has none)
 * once it does, so whether it exists is part of what a proof (or a row-level security policy it runs under) reads.
 */
static bool
placeholder(const struct config_generic *g)
{
	return (g->flags & GUC_CUSTOM_PLACEHOLDER) != 0 && replayable(g);
}

/*
 * A setting's value as text, current or default; NULL for a string that is NULL (a placeholder's value until it is
 * given one, and its default). Until the seventh review a NULL placeholder read as '' here, as current_setting shows
 * it: one that existed read as at its default, and nothing told a placeholder that exists from one that does not.
 * buf: 64 bytes.
 */
static const char *
value_of(const struct config_generic *g, bool boot, char *buf)
{
	struct config_generic *gg = unconstify(struct config_generic *, g);

	switch (g->vartype)
	{
		case PGC_BOOL:
			return (boot ? G_BOOL(gg)->boot_val : *G_BOOL(gg)->variable) ? "on" : "off";
		case PGC_INT:
			snprintf(buf, 64, "%d", boot ? G_INT(gg)->boot_val : *G_INT(gg)->variable);
			return buf;
		case PGC_REAL:
			snprintf(buf, 64, "%.17g", boot ? G_REAL(gg)->boot_val : *G_REAL(gg)->variable);
			return buf;
		case PGC_STRING:
			return boot ? G_STR(gg)->boot_val : *G_STR(gg)->variable;
		case PGC_ENUM:
			return ENUM_NAME(gg, boot ? G_ENUM(gg)->boot_val : *G_ENUM(gg)->variable);
	}
	return NULL;
}

static bool
at_default(const struct config_generic *g)
{
	char		b1[64];
	char		b2[64];
	const char *now = value_of(g, false, b1);
	const char *dflt = value_of(g, true, b2);

	if (dflt == NULL || now == NULL)
		return dflt == now;
	return strcmp(now, dflt) == 0;
}

/* SAVE-set one setting in the current nest level, if it is not that already. */
static void
set_one(const char *name, const char *value)
{
	const char *now = GetConfigOption(name, true, false);

	if (now != NULL && strcmp(now, value) == 0)
		return;
	/*
	 * As SUSET: the value is one the author had (recorded by the extension, never passed by a caller) or a default,
	 * and the nest level it goes into ends with the guard.
	 */
	(void) set_config_option(name, value, PGC_SUSET, PGC_S_SESSION, GUC_ACTION_SAVE, true, 0, false);
}

/*
 * SAVE-set one setting the author's session had, with the author's own rights (seventeenth review): as if the author
 * set it (PGC_USERSET, the author as the role that set it), so PostgreSQL decides as it would in the author's own
 * session: a superuser-only setting (PGC_SUSET) only for a superuser, or a role granted SET on it (pg_parameter_acl),
 * and a placeholder whose library loads later in the proof's session by that library's definition (a superuser-only
 * one is then dropped, with a WARNING, as in the author's session). A setting the author may not set is not set (a
 * WARNING in the log). In the sixteenth cut every recorded setting was set as SUSET: an author that named a
 * superuser-only setting of a library its session had not loaded yet (SET plpgsql.variable_conflict) had it in the
 * proof's session, where it then took effect.
 */
/*
 * (twentieth review, RT20P-ENV-1) A recorded setting is set again exactly, or the proof is not judged. Until this cut
 * one PostgreSQL refused (the author lost the SET privilege it had through a role, by another role's REVOKE; the value
 * names an object its owner dropped since) was dropped with a WARNING, the proof ran with the author's default, and
 * its verdict was recorded for the claim's bind, which still names the setting: 'verified' for settings the proof
 * never ran under. Now the refusal is an ERROR here, the name is kept (guard_env_unreplayed), and the judge records
 * 'unproven' with the reason, never a verdict. "Exactly": the value it has after the SET reads as the one recorded.
 */
static const char *env_replaying = NULL;	/* the recorded setting being set again: an error now is its refusal */

#define ENV_MAX_LATE 64
static int	env_late_n = 0;		/* recorded settings that were placeholders when set again (a library that loads */
static const char *env_late_name[ENV_MAX_LATE];	/* later in the proof applies its own definition to them) */
static const char *env_late_value[ENV_MAX_LATE];

static bool
reads_as(const struct config_generic *g, const char *value)
{
	char		buf[64];
	const char *now = value_of(g, false, buf);

	return strcmp(now ? now : "", value) == 0;
}

static void
set_as_author(const char *name, const char *value, Oid author)
{
	const char *now = GetConfigOption(name, true, false);
	struct config_generic *g;

	env_replaying = name;
	if (now == NULL || strcmp(now, value) != 0)
		(void) set_config_option_ext(name, value, PGC_USERSET, PGC_S_SESSION, author, GUC_ACTION_SAVE, true, ERROR,
									 false);
	g = find_option(name, false, true, 0);
	if (g == NULL || !reads_as(g, value))
	{
		char		buf[64];
		const char *v = g ? value_of(g, false, buf) : NULL;

		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("set to \"%s\", it reads \"%s\"", value, v ? v : "")));
	}
	if ((g->flags & GUC_CUSTOM_PLACEHOLDER) != 0 && env_late_n < ENV_MAX_LATE)
	{
		env_late_name[env_late_n] = name;
		env_late_value[env_late_n] = value;
		env_late_n++;
	}
	env_replaying = NULL;
}

/*
 * A custom setting recorded as one that exists with no value ("app.x=": a placeholder named and never set, or set to
 * ''), whose library this session has loaded and which does not take '': the library's definition is in effect, at
 * its default, as in the author's own session once it loaded the library (a placeholder with no value is not applied
 * then). Nothing to set. One that takes '' is set to it.
 */
static bool
empty_placeholder_defined(const char *name, const char *value, Oid author)
{
	struct config_generic *g;

	if (value[0] != '\0' || strchr(name, '.') == NULL)
		return false;
	g = find_option(name, false, true, 0);
	if (g == NULL || (g->flags & GUC_CUSTOM_PLACEHOLDER) != 0)
		return false;
	/* only checked (changeVal false), and refused quietly */
	return set_config_option_ext(name, value, PGC_USERSET, PGC_S_SESSION, author, GUC_ACTION_SAVE, false, DEBUG5,
								 false) <= 0;
}

/* In a PG_CATCH of the code that entered a GUARD_AUTHOR guard: the recorded setting the error refused, or NULL. */
const char *
guard_env_unreplayed(void)
{
	const char *r = env_replaying;

	env_replaying = NULL;
	return r;
}

/*
 * After the proof ran: a recorded setting that was a placeholder when it was set again, and that a library the proof
 * loaded has defined since, still reads as recorded (the library applies its own definition: a superuser-only one is
 * dropped, with a WARNING, for an author that may not set it any more). NULL when every one does.
 */
const char *
guard_env_kept(void)
{
	for (int i = 0; i < env_late_n; i++)
	{
		struct config_generic *g = find_option(env_late_name[i], false, true, 0);

		if (g == NULL || ((g->flags & GUC_CUSTOM_PLACEHOLDER) == 0 && !reads_as(g, env_late_value[i])))
			return env_late_name[i];
	}
	return NULL;
}

static bool
named_in(const char *name, const char *const *names, int n)
{
	for (int i = 0; i < n; i++)
		if (pg_strcasecmp(name, names[i]) == 0)
			return true;
	return false;
}

/*
 * Every replayable setting at its default, but those named in keep (which the caller then sets): the state a recipe
 * or a proof starts from, whatever the session it runs in.
 */
static List *
nondefault_names(void)
{
	int			n;
	struct config_generic **vars = get_guc_variables(&n);
	List	   *names = NIL;

	for (int i = 0; i < n; i++)
		if (replayable(vars[i]) && !at_default(vars[i]))
			names = lappend(names, pstrdup(vars[i]->name));
	pfree(vars);
	return names;
}

static void
to_defaults(List *nondefault, const char *const *keep, int nkeep)
{
	ListCell   *lc;

	foreach(lc, nondefault)
	{
		const char *name = (const char *) lfirst(lc);
		struct config_generic *g;
		char		buf[64];
		const char *dflt;

		if (named_in(name, keep, nkeep))
			continue;
		g = find_option(name, false, true, 0);
		if (g == NULL || !replayable(g) || at_default(g))
			continue;
		dflt = value_of(g, true, buf);
		/* a placeholder cannot be made not to exist: '' reads as its NULL does (current_setting) */
		if (dflt == NULL && placeholder(g))
			dflt = "";
		if (dflt != NULL)
			set_one(g->name, dflt);
	}
}

static int
name_cmp(const void *a, const void *b)
{
	return strcmp(*(char *const *) a, *(char *const *) b);
}

/*
 * What a proof records of its author's session (0.20.0, eighth review): what that session changed over the
 * configuration every new session of it starts from (postgresql.conf, ALTER SYSTEM, ALTER DATABASE and ALTER ROLE
 * ... SET), which the proof's own session (a new session of its author) has anyway. A setting counts when the
 * session set it (SET, set_config, its startup options: a source from PGC_S_CLIENT up); a custom placeholder when the
 * session made it (no configuration gave it a value), with its value or none ("app.tenant="). application_name too:
 * the client named the session, and a proof or a row-level security policy may read it.
 */
static bool
session_made(const struct config_generic *g, GucSource source)
{
	if (source >= PGC_S_CLIENT)
		return true;
	return placeholder(g) && (source == PGC_S_DEFAULT || source == PGC_S_DYNAMIC_DEFAULT);
}

/*
 * May the author set this setting itself? (seventeenth review) A setting its session has that the author could not
 * set (a superuser's session SET it, and the author is the owner of a SECURITY DEFINER function it called) is not the
 * author's to have in its proof's session.
 */
static bool
author_may_set(const struct config_generic *g, Oid author)
{
	if (g->context == PGC_USERSET)
		return true;
	return superuser_arg(author) || pg_parameter_aclcheck(g->name, author, ACL_SET) == ACLCHECK_OK;
}

/*
 * Is the value a setting has now the author's? (nineteenth review, R19-PRIV-1) A value is the author's when the role
 * that set it (PostgreSQL keeps it: srole) is the author or a role with the author's privileges: the author's own
 * session, a SET clause of a function the author owns (PostgreSQL sets it as the function's owner, once the call is
 * the owner's), a SET inside such a function, or the session of a role that could have asserted as the author anyway
 * (yggdrasil's manu, a superuser, calling _afirmar of ygg_autor). A value a role WITHOUT the author's privileges set
 * (the session of the caller of the author's SECURITY DEFINER function, the startup options of that session, the SET
 * clause of that caller's own function) is not the author's, and is not recorded: the proof's session has the
 * author's own value for it. In the eighteenth cut the value recorded was the session's, read down PostgreSQL's
 * stack past every function's SET clause: a role that could call a wrapper hardened with SET search_path decided the
 * search_path its owner's proof ran with, and its own operator, found there, ran as the owner (a superuser: the
 * caller made itself one).
 */
static bool
authors_value(const struct config_generic *g, Oid author)
{
	Oid			by = g->srole;

	/*
	 * A placeholder that only exists (made by RESET, or named by the configuration: no value, and PostgreSQL records
	 * no setter for it) is the session's: the author's when the session's own role could act as the author.
	 */
	if (g->source == PGC_S_DEFAULT || g->source == PGC_S_DYNAMIC_DEFAULT)
		by = GetOuterUserId();
	return by == author || has_privs_of_role(by, author);
}

/*
 * (twentieth review, RT20M-2) A composite setting: one whose new value is made of the part a SET names and the rest of
 * the value it replaces (SET DateStyle = ISO keeps the field order, DMY or MDY, the session had). PostgreSQL stamps
 * the merged value with the role of the last SET alone, so authors_value() took a wrapper's SET DateStyle = ISO over
 * its caller's 'SQL, DMY' for the author's 'ISO, DMY': a role without the author's privileges chose how the author's
 * proof read '03/04/2026'. A composite value is the author's only when every value it was built on is: the one in
 * effect and each one under it in the session's stack, down to the session's own, was set by the author or a role
 * with its privileges, or by the configuration every session of the database starts from. Otherwise it is not
 * recorded, and the proof has its author's own value (the proof's session is a new session of the author): what any
 * caller does with its session decides nothing. Refusing the assert instead would let any caller of an author's
 * function make it fail (a trigger that asserts: every write) by setting its own DateStyle.
 */
static const char *const composite[] = {"DateStyle"};

static bool
set_by_authors(Oid by, GucSource source, Oid author)
{
	/* ALTER ROLE ... SET of the session's own role (PostgreSQL stamps it as set by a superuser): that role's */
	if (source == PGC_S_USER || source == PGC_S_DATABASE_USER)
		by = GetSessionUserId();
	return by == author || has_privs_of_role(by, author);
}

static bool
built_by_authors(const struct config_generic *g, Oid author)
{
	if (!named_in(g->name, composite, lengthof(composite)))
		return true;
	if (!set_by_authors(g->srole, g->source, author))
		return false;
	for (const GucStack *st = g->stack; st != NULL; st = st->prev)
	{
		if (!set_by_authors(st->srole, st->source, author))
			return false;
		if (st->state == GUC_SET_LOCAL && !set_by_authors(st->masked_srole, PGC_S_SESSION, author))
			return false;
	}
	return true;
}

static bool
recorded(const struct config_generic *g)
{
	return replayable(g) || pg_strcasecmp(g->name, "application_name") == 0;
}

ArrayType *
guard_env_now(Oid author)
{
	int			n;
	int			m = 0;
	struct config_generic **vars = get_guc_variables(&n);
	char	  **items = palloc(sizeof(char *) * Max(n, 1));
	Datum	   *d;

	for (int i = 0; i < n; i++)
	{
		char		buf[64];
		const char *v;
		GucSource	source;

		if (!recorded(vars[i]))
			continue;
		v = value_of(vars[i], false, buf);
		source = vars[i]->source;
		if (!session_made(vars[i], source) || !author_may_set(vars[i], author) || !authors_value(vars[i], author) ||
			!built_by_authors(vars[i], author))
			continue;
		items[m++] = psprintf("%s=%s", vars[i]->name, v ? v : "");
	}
	pfree(vars);
	qsort(items, m, sizeof(char *), name_cmp);
	d = palloc(sizeof(Datum) * Max(m, 1));
	for (int i = 0; i < m; i++)
		d[i] = CStringGetTextDatum(items[i]);
	return construct_array_builtin(d, m, TEXTOID);
}

GuardEnv *
guard_env_from(ArrayType *arr)
{
	GuardEnv   *e = palloc0(sizeof(GuardEnv));
	Datum	   *d;
	bool	   *nulls;
	int			n;

	if (arr == NULL)
		return e;
	deconstruct_array_builtin(arr, TEXTOID, &d, &nulls, &n);
	e->name = palloc(sizeof(char *) * Max(n, 1));
	e->value = palloc(sizeof(char *) * Max(n, 1));
	for (int k = 0; k < n; k++)
	{
		char	   *s;
		char	   *eq;

		if (nulls[k])
			continue;
		s = TextDatumGetCString(d[k]);
		eq = strchr(s, '=');
		if (eq == NULL)
			continue;
		*eq = '\0';
		e->name[e->n] = s;
		e->value[e->n] = eq + 1;
		e->n++;
	}
	return e;
}

static int
name_casecmp(const void *a, const void *b)
{
	return pg_strcasecmp(*(char *const *) a, *(char *const *) b);
}

/*
 * The custom placeholders this session has, sorted (*n of them). A placeholder, once a session has it, stays: no
 * rollback takes it away, and current_setting(name, true) then reads '' where it read NULL. The proof's own session
 * notes those it started with (they come from the configuration, which every new session of the author has) and
 * judges a claim only while it has no other one than those and the ones its author's session had
 * (guard_env_spent); a session that made one more (a proof's set_config, a recorded state that names one, a
 * recipe that set one) ends, and the next claim is judged in a new one.
 */
char	  **
guard_placeholders(int *n)
{
	int			nv;
	struct config_generic **vars = get_guc_variables(&nv);
	char	  **out = palloc(sizeof(char *) * Max(nv, 1));

	*n = 0;
	for (int i = 0; i < nv; i++)
		if (placeholder(vars[i]))
			out[(*n)++] = pstrdup(vars[i]->name);
	pfree(vars);
	qsort(out, *n, sizeof(char *), name_casecmp);
	return out;
}

const char *
guard_env_spent(char **base, int nbase, const GuardEnv *env)
{
	int			nv;
	struct config_generic **vars = get_guc_variables(&nv);
	const char *spent = NULL;

	for (int i = 0; i < nv && spent == NULL; i++)
	{
		const char *name = vars[i]->name;

		if (!placeholder(vars[i]))
			continue;
		if (bsearch(&name, base, nbase, sizeof(char *), name_casecmp) != NULL)
			continue;
		if (!named_in(name, env ? (const char *const *) env->name : NULL, env ? env->n : 0))
			spent = pstrdup(name);
	}
	pfree(vars);
	return spent;
}

static void
apply_pins(void)
{
	for (int i = 0; i < NPINS; i++)
		set_one(pin_name[i], pin_value[i]);
}

/*
 * A pinned call (verify, brief, _render, ...) opens many guards one after the other, and between them only
 * phasevec's own code runs: the settings off their default and the open cursors are the same at each. They are read
 * once, when the call pins its settings, and each guard opened directly in the call uses them.
 *
 * A pin has an owner and a lifetime: the subtransaction it was made in, in the transaction it was made in. Its lists
 * live in a memory context of its own under that transaction's, and it is taken off the stack when its call unpins
 * it, when its subtransaction is rolled back (its call ended in an error a savepoint or an exception block caught:
 * guard_subxact), and, all of them, when the transaction ends in any way (guard_xact). A subtransaction id is never
 * trusted alone: ids start over in every transaction, so a pin also names the transaction it belongs to. Until the
 * fourth review of 0.20.0 pins were cleared only when a transaction aborted: a pin left by a call whose error a
 * savepoint caught outlived a COMMIT, and the watch trigger of a later write inside a savepoint (the same
 * subtransaction id, in another transaction) took it, with its lists in freed memory: the server restarted.
 */
typedef struct Pin
{
	int			nest;
	uint64		xact;			/* the transaction it was made in (xact_count when it was made) */
	SubTransactionId subid;		/* the subtransaction it was made in */
	int			depth;			/* the guard depth it was made at */
	MemoryContext cxt;			/* its lists: a child of TopTransactionContext */
	List	   *nondefault;		/* names of the replayable settings off their default */
	List	   *portals;		/* names of the cursors pg_cursors listed */
} Pin;

static Pin	pins[GUARD_MAX];
static int	npins = 0;

/* Transactions ended in this session: a pin of an earlier one is never current. */
static uint64 xact_count = 0;

static List *nondefault_names(void);
static List *visible_portals(void);
static void reset_plans_if_dirty(void);

static void
pop_pin(void)
{
	Pin		   *p = &pins[--npins];

	/* a pin of an ended transaction went with its memory */
	if (p->cxt != NULL && p->xact == xact_count)
		MemoryContextDelete(p->cxt);
	p->cxt = NULL;
	p->nondefault = NIL;
	p->portals = NIL;
}

static Pin *
current_pin(void)
{
	while (npins > 0 &&
		   (pins[npins - 1].xact != xact_count || !SubTransactionIsActive(pins[npins - 1].subid)))
		pop_pin();
	if (npins > 0 && pins[npins - 1].depth == guard_depth)
		return &pins[npins - 1];
	return NULL;
}

int
guard_own_enter(void)
{
	int			nest = NewGUCNestLevel();

	apply_pins();
	set_one("transform_null_equals", "off");
	return nest;
}

void
guard_own_leave(int nest)
{
	AtEOXact_GUC(true, nest);
}

int
guard_pin_settings(void)
{
	int			nest = NewGUCNestLevel();
	Pin		   *p;

	while (npins > 0 && pins[npins - 1].nest >= nest)
		pop_pin();
	apply_pins();
	if (npins < GUARD_MAX)
	{
		MemoryContext o;

		p = &pins[npins];
		p->cxt = AllocSetContextCreate(TopTransactionContext, "phasevec pin", ALLOCSET_SMALL_SIZES);
		p->nest = nest;
		p->xact = xact_count;
		p->subid = GetCurrentSubTransactionId();
		p->depth = guard_depth;
		o = MemoryContextSwitchTo(p->cxt);
		p->nondefault = nondefault_names();
		p->portals = visible_portals();
		MemoryContextSwitchTo(o);
		npins++;
	}
	return nest;
}

void
guard_unpin_settings(int nest)
{
	while (npins > 0 && pins[npins - 1].nest >= nest)
		pop_pin();
	AtEOXact_GUC(false, nest);
}

/*
 * The session's temporary schema is searched first unless search_path names it: a temporary table of whoever runs
 * the code would take the place of the table it names. Inside a guard pg_temp is searched last (as PostgreSQL
 * advises for SECURITY DEFINER functions), and a temporary relation is refused anyway (guard_start).
 */
static void
temp_last(void)
{
	const char *sp = GetConfigOption("search_path", false, false);
	char	   *copy = pstrdup(sp ? sp : "");
	List	   *names;
	ListCell   *lc;
	bool		named = false;

	if (!SplitIdentifierString(copy, ',', &names))
		named = true;			/* a value no one could set: leave it to PostgreSQL */
	foreach(lc, names)
		if (strcmp((const char *) lfirst(lc), "pg_temp") == 0)
			named = true;
	if (!named)
		set_one("search_path", names == NIL ? "pg_temp" : psprintf("%s, pg_temp", sp));
	list_free(names);
	pfree(copy);
}

/* ----------------------------------------------------------------------------- the session's cursors -- */

/* The names of the cursors pg_cursors lists (every one but the protocol's). */
static List *
visible_portals(void)
{
	LOCAL_FCINFO(fcinfo, 0);
	FmgrInfo	flinfo;
	ReturnSetInfo rsinfo;
	ExprContext econtext;
	TupleTableSlot *slot;
	List	   *names = NIL;

	memset(&rsinfo, 0, sizeof(rsinfo));
	memset(&econtext, 0, sizeof(econtext));
	econtext.type = T_ExprContext;
	econtext.ecxt_per_query_memory = CurrentMemoryContext;
	rsinfo.type = T_ReturnSetInfo;
	rsinfo.econtext = &econtext;
	rsinfo.allowedModes = SFRM_Materialize;
	fmgr_info(F_PG_CURSOR, &flinfo);
	InitFunctionCallInfoData(*fcinfo, &flinfo, 0, InvalidOid, NULL, (Node *) &rsinfo);
	(void) FunctionCallInvoke(fcinfo);
	if (rsinfo.setResult == NULL)
		return NIL;
	slot = MakeSingleTupleTableSlot(rsinfo.setDesc, &TTSOpsMinimalTuple);
	while (tuplestore_gettupleslot(rsinfo.setResult, true, false, slot))
	{
		bool		isnull;
		Datum		v = slot_getattr(slot, 1, &isnull);

		if (!isnull)
			names = lappend(names, TextDatumGetCString(v));
	}
	ExecDropSingleTupleTableSlot(slot);
	tuplestore_end(rsinfo.setResult);
	return names;
}

/*
 * Freeze the session's ready cursors: marked active, PostgreSQL itself refuses to run or drop them (a PL/pgSQL FETCH
 * or CLOSE through a refcursor, SPI, a utility FETCH). Thawed when the guard ends.
 */
static void
freeze_portals(List *names)
{
	ListCell   *lc;

	foreach(lc, names)
	{
		Portal		p = GetPortalByName((const char *) lfirst(lc));

		if (p == NULL || p->status != PORTAL_READY)
			continue;
		if (nfrozen == frozen_cap)
		{
			frozen_cap = Max(16, frozen_cap * 2);
			frozen = frozen ? repalloc(frozen, sizeof(Portal) * frozen_cap)
				: MemoryContextAlloc(TopMemoryContext, sizeof(Portal) * frozen_cap);
		}
		frozen[nfrozen++] = p;
		p->status = PORTAL_ACTIVE;
	}
}

static void
thaw_to(int base)
{
	while (nfrozen > base)
	{
		Portal		p = frozen[--nfrozen];

		if (p->status == PORTAL_ACTIVE)
			p->status = PORTAL_READY;
	}
}

/* ----------------------------------------------------------------------------------- entering, leaving -- */

void
guard_enter(Guard *g, Oid role, GuardMode mode, const GuardEnv *env)
{
	MemoryContext cxt = CurrentMemoryContext;
	ResourceOwner owner = CurrentResourceOwner;
	Level	   *L;
	int			sec;
	Pin		   *pin = current_pin();
	List	   *nondefault;
	List	   *portals;

	if (guard_depth >= GUARD_MAX)
		ereport(ERROR,
				(errcode(ERRCODE_PROGRAM_LIMIT_EXCEEDED),
				 errmsg("phasevec: code that phasevec runs is nested more than %d deep", GUARD_MAX)));
	if (guard_depth == 0)
		reset_plans_if_dirty();
	BeginInternalSubTransaction(NULL);
	L = &levels[guard_depth];
	GetUserIdAndSecContext(&L->userid, &L->sec);
	L->cxt = cxt;
	L->owner = owner;
	L->subid = GetCurrentSubTransactionId();
	L->subcxt = CurTransactionContext;
	L->started = NIL;
	L->frozen_base = nfrozen;
	g->level = guard_depth;
	guard_depth++;
	MemoryContextSwitchTo(cxt);
	if (mode == GUARD_AUTHOR && !proof_session)
		elog(ERROR, "phasevec: a proof runs only in a session of its own");
	nondefault = pin ? pin->nondefault : mode != GUARD_RENDER ? NIL :
		proof_session && guard_depth == 1 ? baseline_nondefault : nondefault_names();
	portals = pin ? pin->portals : visible_portals();

	sec = L->sec | SECURITY_LOCAL_USERID_CHANGE | SECURITY_RESTRICTED_OPERATION;
	if (mode == GUARD_RENDER)
		sec |= SECURITY_NOFORCE_RLS;
	SetUserIdAndSecContext(role, sec);
	switch (mode)
	{
		case GUARD_RENDER:
			to_defaults(nondefault, pin_name, NPINS);
			apply_pins();
			break;
		case GUARD_AUTHOR:
			/*
			 * A new session of the author (the proof's own: phasevec_truth.c) with what its author's session changed
			 * on top. Only what a claim records: a hand-edited row cannot set anything else.
			 */
			env_late_n = 0;
			env_replaying = NULL;
			for (int i = 0; env && i < env->n; i++)
			{
				struct config_generic *rec = find_option(env->name[i], false, true, 0);

				if (rec == NULL ? strchr(env->name[i], '.') != NULL : recorded(rec))
				{
					if (!empty_placeholder_defined(env->name[i], env->value[i], role))
						set_as_author(env->name[i], env->value[i], role);
				}
				else
				{
					/* (twentieth review) not a setting phasevec sets again here (gone from this server): no verdict */
					env_replaying = env->name[i];
					ereport(ERROR,
							(errcode(ERRCODE_UNDEFINED_OBJECT),
							 errmsg("this server has no setting \"%s\" that phasevec sets", env->name[i])));
				}
			}
			break;
		case GUARD_READER:
			apply_pins();
			break;
		case GUARD_ASIS:
			break;
	}
	/* a recipe and a reader run with the pins, which name pg_temp last */
	if (mode == GUARD_AUTHOR || mode == GUARD_ASIS)
		temp_last();
	/* LOCAL (it cannot be SAVEd): the rollback of the subtransaction takes it back all the same */
	(void) set_config_option("transaction_read_only", "on", PGC_USERSET, PGC_S_SESSION,
							 GUC_ACTION_LOCAL, true, 0, false);
	freeze_portals(portals);
}

/* Roll back the innermost guard: its subtransaction (and any left inside it), its cursors thawed. */
static void
unwind_one(void)
{
	Level	   *L = &levels[--guard_depth];

	thaw_to(L->frozen_base);
	/* off the stack first: guard_subxact sees the rollback of a guard no longer open */
	while (IsSubTransaction() && GetCurrentSubTransactionId() >= L->subid)
		RollbackAndReleaseCurrentSubTransaction();
	SetUserIdAndSecContext(L->userid, L->sec);
	MemoryContextSwitchTo(L->cxt);
	CurrentResourceOwner = L->owner;
}

void
guard_leave(Guard *g)
{
	if (g->level != guard_depth - 1 || GetCurrentSubTransactionId() != levels[g->level].subid)
		elog(ERROR, "phasevec: a guard left out of order");
	unwind_one();
}

ErrorData *
guard_catch(int mark, MemoryContext cxt)
{
	ErrorData  *e;

	MemoryContextSwitchTo(cxt);
	e = CopyErrorData();
	FlushErrorState();
	while (guard_depth > mark)
		unwind_one();
	MemoryContextSwitchTo(cxt);
	return e;
}

/*
 * The end of a transaction ends everything phasevec keeps for it, however it ends: guards (an error no one caught),
 * frozen cursors and pins. A transaction cannot commit or prepare inside a guard (only an error leaves one open).
 */
static void
guard_xact(XactEvent event, void *arg)
{
	switch (event)
	{
		case XACT_EVENT_PRE_COMMIT:
		case XACT_EVENT_PARALLEL_PRE_COMMIT:
		case XACT_EVENT_PRE_PREPARE:
			if (guard_depth > 0)
				elog(ERROR, "phasevec: a transaction cannot end inside code phasevec runs");
			break;
		case XACT_EVENT_COMMIT:
		case XACT_EVENT_PARALLEL_COMMIT:
		case XACT_EVENT_PREPARE:
		case XACT_EVENT_ABORT:
		case XACT_EVENT_PARALLEL_ABORT:
			thaw_to(0);
			guard_depth = 0;
			npins = 0;			/* their memory goes with TopTransactionContext */
			xact_count++;
			break;
	}
}

/*
 * A subtransaction rolled back takes with it every pin made in it or in one under it (their ids are greater), and
 * every guard opened there that phasevec did not close itself.
 */
static void
guard_subxact(SubXactEvent event, SubTransactionId mySubid, SubTransactionId parentSubid, void *arg)
{
	if (event != SUBXACT_EVENT_ABORT_SUB)
		return;
	while (npins > 0 && pins[npins - 1].subid >= mySubid)
		pop_pin();
	while (guard_depth > 0 && levels[guard_depth - 1].subid >= mySubid)
	{
		thaw_to(levels[guard_depth - 1].frozen_base);
		guard_depth--;
	}
}

/* ------------------------------------------------------------------------------------ queries and commands -- */

static ExecutorStart_hook_type prev_start = NULL;
static ExecutorRun_hook_type prev_run = NULL;
static ExecutorEnd_hook_type prev_end = NULL;
static ProcessUtility_hook_type prev_utility = NULL;

/*
 * The session's temporary objects are the session's, as its cursors are: whoever runs the code made them, not the
 * code's author or owner. None can be made inside a guard (it is a security-restricted operation), and none may be
 * used there. Until the fifth review only temporary tables and functions were refused, by the kind of range-table
 * entry they came in: a temporary view (a subquery entry since PostgreSQL 16), a temporary type, domain, operator or
 * collation went through, and the verifier's own objects decided a proof.
 *
 * So the refusal goes by what a query depends on, not by how it names it: every query parsed inside a guard
 * (guard_analyze) is walked for the objects it uses, as PostgreSQL walks a view's query to decide whether the view is
 * temporary (relations, views, types, domains, functions, operators, collations, and the objects regclass-like
 * constants name), and one in a temporary schema is refused. That walk sees the query before the planner folds it:
 * 'b'::pg_temp.e < 'a'::pg_temp.e is a constant true once planned.
 */
static void
refuse_temp_object(Oid classId, Oid objectId)
{
	const char *kind = "object";
	char	   *name = NULL;

	switch (classId)
	{
		case RelationRelationId:
			switch (get_rel_relkind(objectId))
			{
				case RELKIND_VIEW:
					kind = "view";
					break;
				case RELKIND_SEQUENCE:
					kind = "sequence";
					break;
				default:
					kind = "table";
					break;
			}
			name = get_rel_name(objectId);
			break;
		case TypeRelationId:
			kind = "type";
			name = format_type_be(objectId);
			break;
		case ProcedureRelationId:
			kind = "function";
			name = get_func_name(objectId);
			break;
		case OperatorRelationId:
			{
				HeapTuple	tp = SearchSysCache1(OPEROID, ObjectIdGetDatum(objectId));

				kind = "operator";
				if (HeapTupleIsValid(tp))
				{
					name = pstrdup(NameStr(((Form_pg_operator) GETSTRUCT(tp))->oprname));
					ReleaseSysCache(tp);
				}
			}
			break;
		case CollationRelationId:
			kind = "collation";
			name = get_collation_name(objectId);
			break;
		default:
			{
				ObjectAddress a;

				a.classId = classId;
				a.objectId = objectId;
				a.objectSubId = 0;
				name = getObjectDescription(&a, true);
			}
			break;
	}
	ereport(ERROR,
			(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
			 errmsg("phasevec: code that phasevec runs (a proof, a recipe) cannot %s temporary %s \"%s\"",
					classId == RelationRelationId ? "read" : "use", kind, name ? name : "?"),
			 errdetail("A temporary object is the session's that runs the code, not the code's author's.")));
}

static bool
in_temp_schema(Oid classId, Oid objectId)
{
	ObjectAddress a;
	Oid			nsp;

	if (objectId < FirstNormalObjectId)
		return false;
	a.classId = classId;
	a.objectId = objectId;
	a.objectSubId = 0;
	nsp = get_object_namespace(&a);
	return OidIsValid(nsp) && isAnyTempNamespace(nsp);
}

/* PostgreSQL 18's walk below either refuses (inside a guard) or only notes that it met one (probing, outside). */
static bool probing = false;
static bool probed = false;

static void
refuse_if_temp(Oid classId, Oid objectId)
{
	if (OidIsValid(objectId) && in_temp_schema(classId, objectId))
	{
		if (probing)
			probed = true;
		else
			refuse_temp_object(classId, objectId);
	}
}

/*
 * The walk over what a query can name. PostgreSQL 18 has no collectDependenciesOfExpr(), and PostgreSQL 19's does not
 * record every type a query uses (in the sixth review the RETURNING type of JSON_VALUE and JSON_QUERY went past it, as
 * past this walk, which had no case for them): on 19 both run. A type is followed to its domain's base type and its
 * array's element type.
 */
static void
refuse_temp_type(Oid typid)
{
	for (int depth = 0; OidIsValid(typid) && typid >= FirstNormalObjectId && depth < 16; depth++)
	{
		Oid			next;
		Oid			elem = get_element_type(typid);

		/* an array of a temporary type is named by its element, as PostgreSQL 19 names it */
		refuse_if_temp(TypeRelationId, OidIsValid(elem) ? elem : typid);
		refuse_if_temp(TypeRelationId, typid);
		next = getBaseType(typid);
		if (next == typid)
			next = get_element_type(typid);
		typid = next;
	}
}

static void
refuse_temp_oper(Oid opno)
{
	refuse_if_temp(OperatorRelationId, opno);
	if (OidIsValid(opno))
		refuse_if_temp(ProcedureRelationId, get_opcode(opno));
}

static bool
temp_walker(Node *node, void *context)
{
	if (node == NULL)
		return false;
	if (IsA(node, Query))
	{
		Query	   *q = (Query *) node;
		ListCell   *lc;
		List	   *clauses[3] = {q->sortClause, q->groupClause, q->distinctClause};

		foreach(lc, q->rtable)
		{
			RangeTblEntry *rte = (RangeTblEntry *) lfirst(lc);
			ListCell   *c;

			refuse_if_temp(RelationRelationId, rte->relid);
			foreach(c, rte->coltypes)
				refuse_temp_type(lfirst_oid(c));
			foreach(c, rte->colcollations)
				refuse_if_temp(CollationRelationId, lfirst_oid(c));
			if (rte->rtekind == RTE_FUNCTION)
				foreach(c, rte->functions)
				{
					RangeTblFunction *f = (RangeTblFunction *) lfirst(c);
					ListCell   *t;

					foreach(t, f->funccoltypes)
						refuse_temp_type(lfirst_oid(t));
				}
		}
		for (int i = 0; i < 3; i++)
			foreach(lc, clauses[i])
				if (IsA(lfirst(lc), SortGroupClause))
				{
					refuse_temp_oper(((SortGroupClause *) lfirst(lc))->eqop);
					refuse_temp_oper(((SortGroupClause *) lfirst(lc))->sortop);
				}
		return query_tree_walker(q, temp_walker, context, 0);
	}
	switch (nodeTag(node))
	{
		case T_Var:
			refuse_temp_type(((Var *) node)->vartype);
			refuse_if_temp(CollationRelationId, ((Var *) node)->varcollid);
			break;
		case T_Const:
			{
				Const	   *c = (Const *) node;

				refuse_temp_type(c->consttype);
				refuse_if_temp(CollationRelationId, c->constcollid);
				if (!c->constisnull)
					switch (c->consttype)
					{
						case REGCLASSOID:
							refuse_if_temp(RelationRelationId, DatumGetObjectId(c->constvalue));
							break;
						case REGTYPEOID:
							refuse_temp_type(DatumGetObjectId(c->constvalue));
							break;
						case REGPROCOID:
						case REGPROCEDUREOID:
							refuse_if_temp(ProcedureRelationId, DatumGetObjectId(c->constvalue));
							break;
						case REGOPEROID:
						case REGOPERATOROID:
							refuse_temp_oper(DatumGetObjectId(c->constvalue));
							break;
						case REGCOLLATIONOID:
							refuse_if_temp(CollationRelationId, DatumGetObjectId(c->constvalue));
							break;
						case REGCONFIGOID:
							refuse_if_temp(TSConfigRelationId, DatumGetObjectId(c->constvalue));
							break;
						case REGDICTIONARYOID:
							refuse_if_temp(TSDictionaryRelationId, DatumGetObjectId(c->constvalue));
							break;
						case REGNAMESPACEOID:
							if (isAnyTempNamespace(DatumGetObjectId(c->constvalue)))
							{
								if (probing)
									probed = true;
								else
									refuse_temp_object(NamespaceRelationId, DatumGetObjectId(c->constvalue));
							}
							break;
					}
			}
			break;
		case T_Param:
			refuse_temp_type(((Param *) node)->paramtype);
			refuse_if_temp(CollationRelationId, ((Param *) node)->paramcollid);
			break;
		case T_FuncExpr:
			refuse_if_temp(ProcedureRelationId, ((FuncExpr *) node)->funcid);
			refuse_temp_type(((FuncExpr *) node)->funcresulttype);
			refuse_if_temp(CollationRelationId, ((FuncExpr *) node)->inputcollid);
			break;
		case T_OpExpr:
		case T_DistinctExpr:
		case T_NullIfExpr:
			refuse_temp_oper(((OpExpr *) node)->opno);
			refuse_temp_type(((OpExpr *) node)->opresulttype);
			refuse_if_temp(CollationRelationId, ((OpExpr *) node)->inputcollid);
			break;
		case T_ScalarArrayOpExpr:
			refuse_temp_oper(((ScalarArrayOpExpr *) node)->opno);
			refuse_if_temp(CollationRelationId, ((ScalarArrayOpExpr *) node)->inputcollid);
			break;
		case T_RowCompareExpr:
			{
				ListCell   *lc;

				foreach(lc, ((RowCompareExpr *) node)->opnos)
					refuse_temp_oper(lfirst_oid(lc));
				foreach(lc, ((RowCompareExpr *) node)->inputcollids)
					refuse_if_temp(CollationRelationId, lfirst_oid(lc));
			}
			break;
		case T_Aggref:
			refuse_if_temp(ProcedureRelationId, ((Aggref *) node)->aggfnoid);
			refuse_temp_type(((Aggref *) node)->aggtype);
			break;
		case T_WindowFunc:
			refuse_if_temp(ProcedureRelationId, ((WindowFunc *) node)->winfnoid);
			refuse_temp_type(((WindowFunc *) node)->wintype);
			break;
		case T_SubscriptingRef:
			refuse_temp_type(((SubscriptingRef *) node)->refcontainertype);
			refuse_temp_type(((SubscriptingRef *) node)->refrestype);
			break;
		case T_FieldSelect:
			refuse_temp_type(((FieldSelect *) node)->resulttype);
			break;
		case T_FieldStore:
			refuse_temp_type(((FieldStore *) node)->resulttype);
			break;
		case T_RelabelType:
			refuse_temp_type(((RelabelType *) node)->resulttype);
			break;
		case T_CoerceViaIO:
			refuse_temp_type(((CoerceViaIO *) node)->resulttype);
			break;
		case T_ArrayCoerceExpr:
			refuse_temp_type(((ArrayCoerceExpr *) node)->resulttype);
			break;
		case T_ConvertRowtypeExpr:
			refuse_temp_type(((ConvertRowtypeExpr *) node)->resulttype);
			break;
		case T_CollateExpr:
			refuse_if_temp(CollationRelationId, ((CollateExpr *) node)->collOid);
			break;
		case T_CaseExpr:
			refuse_temp_type(((CaseExpr *) node)->casetype);
			break;
		case T_CaseTestExpr:
			refuse_temp_type(((CaseTestExpr *) node)->typeId);
			break;
		case T_ArrayExpr:
			refuse_temp_type(((ArrayExpr *) node)->array_typeid);
			break;
		case T_RowExpr:
			refuse_temp_type(((RowExpr *) node)->row_typeid);
			break;
		case T_CoalesceExpr:
			refuse_temp_type(((CoalesceExpr *) node)->coalescetype);
			break;
		case T_MinMaxExpr:
			refuse_temp_type(((MinMaxExpr *) node)->minmaxtype);
			break;
		case T_CoerceToDomain:
			refuse_temp_type(((CoerceToDomain *) node)->resulttype);
			break;
		case T_CoerceToDomainValue:
			refuse_temp_type(((CoerceToDomainValue *) node)->typeId);
			break;
		case T_SetToDefault:
			refuse_temp_type(((SetToDefault *) node)->typeId);
			break;
		case T_NextValueExpr:
			refuse_if_temp(RelationRelationId, ((NextValueExpr *) node)->seqid);
			break;
		case T_JsonExpr:
			/* JSON_VALUE, JSON_QUERY, JSON_EXISTS ... RETURNING t: with NULL ON ERROR, t is in no other node */
			if (((JsonExpr *) node)->returning)
				refuse_temp_type(((JsonExpr *) node)->returning->typid);
			refuse_if_temp(CollationRelationId, ((JsonExpr *) node)->collation);
			break;
		case T_JsonConstructorExpr:
			if (((JsonConstructorExpr *) node)->returning)
				refuse_temp_type(((JsonConstructorExpr *) node)->returning->typid);
			break;
		case T_XmlExpr:
			refuse_temp_type(((XmlExpr *) node)->type);
			break;
		default:
			break;
	}
	return expression_tree_walker(node, temp_walker, context);
}

/* Does a query (or an expression with no range table) use a temporary object? Inside a guard: refused if so. */
static bool
temp_in(Node *node, bool refuse)
{
#if PG_VERSION_NUM >= 190000
	ObjectAddresses *addrs = new_object_addresses();
	ObjectAddress obj;
	bool		found;

	collectDependenciesOfExpr(addrs, node, NIL);
	found = find_temp_object(addrs, false, &obj);
	free_object_addresses(addrs);
	if (found && refuse)
		refuse_temp_object(obj.classId, obj.objectId);
	if (found)
		return true;
#endif
	probing = !refuse;
	probed = false;
	PG_TRY();
	{
		(void) temp_walker(node, NULL);
	}
	PG_FINALLY();
	{
		probing = false;
	}
	PG_END_TRY();
	return probed;
}

static void
refuse_temp_in(Node *node)
{
	(void) temp_in(node, true);
}

/*
 * Out of a guard: may a plan made for this query keep something of the session's temporary objects that a guard
 * would not see again? It may if it uses one, or if it calls a SQL function that is not phasevec's: the planner
 * inlines such a body with no hook and folds it (see guard_needs_fmgr).
 */
static Oid	own_schema = InvalidOid;
static bool sql_function(Oid fn);

static bool
calls_sql_walker(Node *node, void *context)
{
	Oid			fn = InvalidOid;

	if (node == NULL)
		return false;
	if (IsA(node, Query))
		return query_tree_walker((Query *) node, calls_sql_walker, context, 0);
	if (IsA(node, FuncExpr))
		fn = ((FuncExpr *) node)->funcid;
	else if (IsA(node, OpExpr) || IsA(node, DistinctExpr) || IsA(node, NullIfExpr))
		fn = get_opcode(((OpExpr *) node)->opno);
	else if (IsA(node, ScalarArrayOpExpr))
		fn = get_opcode(((ScalarArrayOpExpr *) node)->opno);
	if (OidIsValid(fn) && sql_function(fn))
	{
		if (!OidIsValid(own_schema))
			own_schema = get_namespace_oid("phasevec", true);
		if (get_func_namespace(fn) != own_schema)
			return true;
	}
	return expression_tree_walker(node, calls_sql_walker, context);
}

/*
 * A plan the session made out of a guard is used inside one without being parsed again when nothing it depends on
 * changed and the search_path matches (a function with its own SET search_path: the same inside and out): a
 * PL/pgSQL statement or a SQL function body the verifier ran first, with its temporary objects folded in. Such a
 * plan marks the session (plans_dirty), and before a guard runs code every cached plan is parsed again (inside it,
 * where guard_analyze sees it). A session with no temporary object never marks itself, nor one whose plans could
 * not keep one.
 */
static bool plans_dirty = false;

static void
note_plan_outside(Query *query, const char *source)
{
	Oid			nsp;
	Oid			toast;

	if (plans_dirty)
		return;
	/*
	 * A statement the client sent (its text is the one the server is running: debug_query_string, also for a
	 * protocol-level prepared statement it binds) is planned for that statement alone, and no code in a guard can run
	 * its plan: only a statement of a function's body (PL/pgSQL, SQL), kept in the plan cache, can be used again
	 * there. Until the sixth review every statement marked the session, and a session that wrote to its temporary
	 * table in each transaction threw away every cached plan (the watch trigger's, its own prepared statements) at
	 * the next write to a watched table: 5.5 times the latency of a single-row write.
	 */
	if (source != NULL && source == debug_query_string)
		return;
	GetTempNamespaceState(&nsp, &toast);
	if (!OidIsValid(nsp))
		return;					/* no temporary object: nothing to keep */
	if (temp_in((Node *) query, false) || calls_sql_walker((Node *) query, NULL))
		plans_dirty = true;
}

static void
reset_plans_if_dirty(void)
{
	if (plans_dirty)
	{
		ResetPlanCache();
		plans_dirty = false;
	}
}

static post_parse_analyze_hook_type prev_analyze = NULL;
static planner_hook_type prev_planner = NULL;

#if PG_VERSION_NUM >= 190000
#define JUMBLE const JumbleState
#else
#define JUMBLE JumbleState
#endif
static void
guard_analyze(ParseState *pstate, Query *query, JUMBLE *jstate)
{
	if (prev_analyze)
		prev_analyze(pstate, query, jstate);
	if (guard_depth == 0)
	{
		note_plan_outside(query, pstate ? pstate->p_sourcetext : NULL);
		return;
	}
	refuse_temp_in((Node *) query);
	if (query->commandType == CMD_UTILITY && query->utilityStmt != NULL && IsA(query->utilityStmt, CallStmt))
		refuse_temp_in((Node *) ((CallStmt *) query->utilityStmt)->funcexpr);
}

/*
 * And every query planned, before the planner folds it: a SQL function body written BEGIN ATOMIC is kept parsed and
 * is planned with no parse (it names its objects by OID).
 */
#if PG_VERSION_NUM >= 190000
static PlannedStmt *
guard_plan(Query *parse, const char *query_string, int cursorOptions, ParamListInfo boundParams, ExplainState *es)
#else
static PlannedStmt *
guard_plan(Query *parse, const char *query_string, int cursorOptions, ParamListInfo boundParams)
#endif
{
	if (guard_depth > 0)
		refuse_temp_in((Node *) parse);
	else
		note_plan_outside(parse, query_string);
#if PG_VERSION_NUM >= 190000
	if (prev_planner)
		return prev_planner(parse, query_string, cursorOptions, boundParams, es);
	return standard_planner(parse, query_string, cursorOptions, boundParams, es);
#else
	if (prev_planner)
		return prev_planner(parse, query_string, cursorOptions, boundParams);
	return standard_planner(parse, query_string, cursorOptions, boundParams);
#endif
}

/*
 * And at the executor, what the planner added: a temporary child of a permanent table it inherits from, and any
 * relation the plan depends on (a view is a subquery entry that keeps its relation's OID).
 */
static void
refuse_temp(const PlannedStmt *ps)
{
	ListCell   *lc;

	foreach(lc, ps->rtable)
		refuse_if_temp(RelationRelationId, ((RangeTblEntry *) lfirst(lc))->relid);
	foreach(lc, ps->relationOids)
		refuse_if_temp(RelationRelationId, lfirst_oid(lc));
}


static void
guard_start(QueryDesc *qd, int eflags)
{
	if (guard_depth > 0)
		refuse_temp(qd->plannedstmt);
	if (prev_start)
		prev_start(qd, eflags);
	else
		standard_ExecutorStart(qd, eflags);
	if (guard_depth > 0)
	{
		Level	   *L = &levels[guard_depth - 1];
		MemoryContext o = MemoryContextSwitchTo(L->subcxt);

		L->started = lappend(L->started, qd);
		MemoryContextSwitchTo(o);
	}
}

static void
guard_run(QueryDesc *qd, ScanDirection direction, uint64 count)
{
	if (guard_depth > 0 && !list_member_ptr(levels[guard_depth - 1].started, qd))
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("phasevec: code that phasevec runs (a proof, a recipe) cannot read a cursor opened before it ran"),
				 errdetail("The session's cursors are its caller's, read with its caller's rights.")));
	if (prev_run)
		prev_run(qd, direction, count);
	else
		standard_ExecutorRun(qd, direction, count);
}

static void
guard_end(QueryDesc *qd)
{
	if (guard_depth > 0)
		levels[guard_depth - 1].started = list_delete_ptr(levels[guard_depth - 1].started, qd);
	if (prev_end)
		prev_end(qd);
	else
		standard_ExecutorEnd(qd);
}

/* A cursor named in FETCH, MOVE or CLOSE must have been opened inside the guard. */
static void
own_cursor(const char *name, const char *what)
{
	Portal		p;

	if (name == NULL || name[0] == '\0')
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("phasevec: code that phasevec runs (a proof, a recipe) cannot run %s on every cursor", what)));
	p = GetPortalByName(name);
	if (p == NULL)
		return;					/* PostgreSQL says it does not exist */
	if (p->createSubid == InvalidSubTransactionId || p->createSubid < levels[guard_depth - 1].subid)
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("phasevec: code that phasevec runs (a proof, a recipe) cannot %s cursor \"%s\", opened before it ran",
						what, name),
				 errdetail("The session's cursors are its caller's, read with its caller's rights.")));
}

static void
guard_utility(PlannedStmt *pstmt, const char *queryString, bool readOnlyTree, ProcessUtilityContext context,
			  ParamListInfo params, QueryEnvironment *queryEnv, DestReceiver *dest, QueryCompletion *qc)
{
	if (guard_depth > 0)
	{
		Node	   *stmt = pstmt->utilityStmt;

		switch (nodeTag(stmt))
		{
			case T_ExplainStmt:
				{
					Node	   *q = ((ExplainStmt *) stmt)->query;

					/* EXPLAIN EXECUTE shows (and with ANALYZE runs) a statement the session prepared */
					if (IsA(q, Query) && ((Query *) q)->commandType == CMD_UTILITY &&
						IsA(((Query *) q)->utilityStmt, ExecuteStmt))
						ereport(ERROR,
								(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
								 errmsg("phasevec: code that phasevec runs (a proof, a recipe) cannot explain a prepared statement"),
								 errdetail("The session's prepared statements are its caller's.")));
				}
				break;
			case T_VariableSetStmt:
			case T_VariableShowStmt:
			case T_DeclareCursorStmt:
			case T_CallStmt:
			case T_DoStmt:
				break;
			case T_FetchStmt:
				own_cursor(((FetchStmt *) stmt)->portalname, ((FetchStmt *) stmt)->ismove ? "MOVE" : "FETCH");
				break;
			case T_ClosePortalStmt:
				own_cursor(((ClosePortalStmt *) stmt)->portalname, "CLOSE");
				break;
			default:
				ereport(ERROR,
						(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
						 errmsg("phasevec: code that phasevec runs (a proof, a recipe) cannot run %s",
								GetCommandTagName(CreateCommandTag(stmt))),
						 errdetail("It reads; of the commands only SET, SHOW, EXPLAIN, DECLARE, FETCH, MOVE, CLOSE, CALL and DO run.")));
		}
	}
	if (prev_utility)
		prev_utility(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
	else
		standard_ProcessUtility(pstmt, queryString, readOnlyTree, context, params, queryEnv, dest, qc);
}

/* -------------------------------------------------------------------------------- the system's functions -- */

/*
 * Volatile system functions reviewed as safe in a guard: they leave nothing past its rollback (a setting goes back
 * with it, a transaction-level advisory lock is released with it) and read nothing of the session but the clock.
 * set_config of a custom name the session does not have leaves the placeholder behind (no rollback removes one): in
 * a proof's own session, the next claim is judged in a new one (guard_env_spent).
 * (random() draws from the session's generator, which a guard cannot seed: setseed is refused.)
 */
static const char *const volatile_allowed[] = {
	"clock_timestamp", "timeofday", "pg_sleep", "pg_sleep_for", "pg_sleep_until",
	"random", "random_normal", "gen_random_uuid", "uuidv4", "uuidv7", "set_config",
	"pg_advisory_xact_lock", "pg_advisory_xact_lock_shared", "pg_try_advisory_xact_lock",
	"pg_try_advisory_xact_lock_shared"
};

/*
 * Functions that read the session's own statements and channels, or its transaction's id, whatever their volatility:
 * txid_current() and pg_current_xact_id() are stable, yet they give the caller's transaction an id, which no
 * rollback of the guard takes back.
 */
static const char *const session_readers[] = {
	"pg_cursor", "pg_prepared_statement", "pg_listening_channels", "pg_notification_queue_usage",
	"txid_current", "pg_current_xact_id", "txid_current_if_assigned", "pg_current_xact_id_if_assigned"
};

typedef struct FnVerdict
{
	Oid			fn;
	bool		refused;
} FnVerdict;

static HTAB *fn_verdicts = NULL;

static bool
refused_function(Oid fn)
{
	FnVerdict  *v;
	bool		found;

	if (fn >= FirstNormalObjectId)
		return false;			/* not the system's: its body runs in the guard too */
	if (fn_verdicts == NULL)
	{
		HASHCTL		ctl;

		ctl.keysize = sizeof(Oid);
		ctl.entrysize = sizeof(FnVerdict);
		fn_verdicts = hash_create("phasevec guard functions", 256, &ctl, HASH_ELEM | HASH_BLOBS);
	}
	v = hash_search(fn_verdicts, &fn, HASH_FIND, NULL);
	if (v == NULL)
	{
		HeapTuple	tp = SearchSysCache1(PROCOID, ObjectIdGetDatum(fn));
		bool		refused = false;

		if (HeapTupleIsValid(tp))
		{
			Form_pg_proc p = (Form_pg_proc) GETSTRUCT(tp);
			const char *name = NameStr(p->proname);

			refused = named_in(name, session_readers, lengthof(session_readers)) ||
				(p->provolatile == PROVOLATILE_VOLATILE &&
				 !named_in(name, volatile_allowed, lengthof(volatile_allowed)));
			ReleaseSysCache(tp);
		}
		v = hash_search(fn_verdicts, &fn, HASH_ENTER, &found);
		v->refused = refused;
	}
	return v->refused;
}

static object_access_hook_type prev_object_access = NULL;
static needs_fmgr_hook_type prev_needs_fmgr = NULL;

static bool
temp_function(Oid fn)
{
	return fn >= FirstNormalObjectId && isAnyTempNamespace(get_func_namespace(fn));
}

/*
 * Inside a guard no function that is not the system's is inlined: PostgreSQL does not inline a function a plugin
 * hooks. A temporary function is then set up as a call, and refused there (guard_object_access): inlined, a SQL
 * function's body ran as if the proof had written it. A SQL function's body is then parsed as its own query, where
 * guard_analyze sees what it uses: inlined, it was parsed with no hook, and 'b'::pg_temp.e < 'a'::pg_temp.e in its
 * body was folded to a constant before anything could see the temporary type.
 */
static bool
sql_function(Oid fn)
{
	HeapTuple	tp;
	bool		sql = false;

	if (fn < FirstNormalObjectId)
		return false;
	tp = SearchSysCache1(PROCOID, ObjectIdGetDatum(fn));
	if (HeapTupleIsValid(tp))
	{
		sql = ((Form_pg_proc) GETSTRUCT(tp))->prolang == SQLlanguageId;
		ReleaseSysCache(tp);
	}
	return sql;
}

static bool
guard_needs_fmgr(Oid fn)
{
	if (prev_needs_fmgr && prev_needs_fmgr(fn))
		return true;
	return guard_depth > 0 && (temp_function(fn) || sql_function(fn));
}

static void
guard_object_access(ObjectAccessType access, Oid classId, Oid objectId, int subId, void *arg)
{
	if (prev_object_access)
		prev_object_access(access, classId, objectId, subId, arg);
	if (guard_depth == 0)
		return;
	if (access == OAT_NAMESPACE_SEARCH && objectId >= FirstNormalObjectId && isAnyTempNamespace(objectId))
	{
		ObjectAccessNamespaceSearch *ns = (ObjectAccessNamespaceSearch *) arg;
		Oid			mine;
		Oid			toast;

		/*
		 * A temporary schema named by its own name (pg_temp_3.v), the session's or another's: refused. In a
		 * search_path, another session's is left out (the session's own is put first if it is left out: it stays
		 * where pg_temp puts it, last).
		 */
		GetTempNamespaceState(&mine, &toast);
		if (ns->ereport_on_violation)
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("phasevec: code that phasevec runs (a proof, a recipe) cannot use temporary schema \"%s\"",
							get_namespace_name(objectId)),
					 errdetail("A temporary schema is a session's, not the code's author's.")));
		if (objectId != mine && objectId != toast)
			ns->result = false;
		return;
	}
	if (access != OAT_FUNCTION_EXECUTE)
		return;
	/* a temporary function is the session's, as a temporary table is (refuse_temp) */
	if (temp_function(objectId))
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("phasevec: code that phasevec runs (a proof, a recipe) cannot call temporary function %s()",
						get_func_name(objectId)),
				 errdetail("A temporary function is the session's that runs the code, not the code's author's.")));
	if (refused_function(objectId))
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("phasevec: code that phasevec runs (a proof, a recipe) cannot call %s()", get_func_name(objectId)),
				 errdetail("Of the system's volatile functions only a reviewed few run there: this one may change or read "
						   "the session it runs in past a rollback.")));
}

/* ------------------------------------------------------------------------------- the session's settings -- */

#define NFROZEN_INT 5
static const char *const frozen_int_names[NFROZEN_INT] = {
	"transaction_timeout", "statement_timeout", "lock_timeout",
	"idle_in_transaction_session_timeout", "idle_session_timeout"
};
static GucIntCheckHook int_prev[NFROZEN_INT];
static GucBoolCheckHook exit_prev = NULL;

static bool
int_check(int i, int *newval, void **extra, GucSource source)
{
	if (guard_depth > 0)
	{
		GUC_check_errcode(ERRCODE_INSUFFICIENT_PRIVILEGE);
		GUC_check_errmsg("phasevec: code that phasevec runs (a proof, a recipe) cannot change %s",
						 frozen_int_names[i]);
		GUC_check_errdetail("It would outlive the code: a timeout armed by a proof ends the session that runs it.");
		return false;
	}
	return int_prev[i] ? int_prev[i] (newval, extra, source) : true;
}

#define INT_CHECK(i) \
	static bool int_check_##i(int *newval, void **extra, GucSource source) \
	{ return int_check(i, newval, extra, source); }
INT_CHECK(0)
INT_CHECK(1)
INT_CHECK(2)
INT_CHECK(3)
INT_CHECK(4)
static const GucIntCheckHook int_hooks[NFROZEN_INT] = {
	int_check_0, int_check_1, int_check_2, int_check_3, int_check_4
};

static bool
exit_check(bool *newval, void **extra, GucSource source)
{
	if (guard_depth > 0 && *newval)
	{
		GUC_check_errcode(ERRCODE_INSUFFICIENT_PRIVILEGE);
		GUC_check_errmsg("phasevec: code that phasevec runs (a proof, a recipe) cannot change exit_on_error");
		GUC_check_errdetail("Its next error would end the session that runs it.");
		return false;
	}
	return exit_prev ? exit_prev(newval, extra, source) : true;
}

static void
freeze_settings(void)
{
	struct config_generic *g;

	for (int i = 0; i < NFROZEN_INT; i++)
	{
		g = find_option(frozen_int_names[i], false, true, 0);
		if (g == NULL || g->vartype != PGC_INT || G_INT(g)->check_hook == int_hooks[i])
			continue;			/* not in this server, or already ours */
		int_prev[i] = G_INT(g)->check_hook;
		G_INT(g)->check_hook = int_hooks[i];
	}
	g = find_option("exit_on_error", false, true, 0);
	if (g != NULL && g->vartype == PGC_BOOL && G_BOOL(g)->check_hook != exit_check)
	{
		exit_prev = G_BOOL(g)->check_hook;
		G_BOOL(g)->check_hook = exit_check;
	}
}

void
phasevec_guard_init(void)
{
	static bool done = false;

	if (done)
		return;
	done = true;
	freeze_settings();
	prev_object_access = object_access_hook;
	object_access_hook = guard_object_access;
	prev_needs_fmgr = needs_fmgr_hook;
	needs_fmgr_hook = guard_needs_fmgr;
	prev_analyze = post_parse_analyze_hook;
	post_parse_analyze_hook = guard_analyze;
	prev_planner = planner_hook;
	planner_hook = guard_plan;
	prev_start = ExecutorStart_hook;
	ExecutorStart_hook = guard_start;
	prev_run = ExecutorRun_hook;
	ExecutorRun_hook = guard_run;
	prev_end = ExecutorEnd_hook;
	ExecutorEnd_hook = guard_end;
	prev_utility = ProcessUtility_hook;
	ProcessUtility_hook = guard_utility;
	RegisterXactCallback(guard_xact, NULL);
	RegisterSubXactCallback(guard_subxact, NULL);
}
