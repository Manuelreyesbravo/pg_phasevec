/*
 * pg_phasevec 0.20.0: the one way phasevec runs code that is not its own.
 *
 * A watch's recipe is the table owner's SQL (and through casts, functions and operators, code the table owner
 * controls); a proof is its author's. Everything phasevec runs of either goes through guard_enter()/guard_leave():
 * a sealed room. It is a subtransaction of its own, always rolled back; inside it the code runs as one named role,
 * in a security-restricted operation, read-only, with a whole settings state that is not the caller's (the author's
 * recorded one for a proof, the canonical one for a recipe), and nothing that existed before it is in reach: not the
 * session's open cursors, not its notifications, not its timeouts, locks or random seed, not the system's functions
 * that change or read the session. See phasevec_guard.c.
 */
#ifndef PHASEVEC_GUARD_H
#define PHASEVEC_GUARD_H

#include "utils/array.h"
#include "utils/elog.h"

typedef struct Guard
{
	int			level;			/* the depth it opened (its entry in the guard stack) */
} Guard;

/* Which settings the code runs with. */
typedef enum GuardMode
{
	GUARD_RENDER,				/* a recipe, as the table's owner: every setting at its default, the pins on top,
								 * FORCE ROW LEVEL SECURITY not applied to the owner (as for a foreign-key check) */
	GUARD_AUTHOR,				/* a proof, or what its author sees, in the proof's own session (a new session of
								 * its author): the author's recorded settings on top */
	GUARD_READER,				/* what a reader sees of a table: the reader's own settings, the pins on top */
	GUARD_ASIS					/* the settings as they are (the SQL of 0.14.2 to 0.19.0 proving as the caller) */
} GuardMode;

/* A recorded settings state: "name=value" pairs. */
typedef struct GuardEnv
{
	int			n;
	char	  **name;
	char	  **value;
} GuardEnv;

extern void phasevec_guard_init(void);
extern void guard_enter(Guard *g, Oid role, GuardMode mode, const GuardEnv *env);
extern void guard_leave(Guard *g);

/*
 * In a PG_CATCH: guard_mark() taken before the PG_TRY. Copies the error (into cxt), rolls back every guard opened
 * since the mark and returns the error; the caller rethrows it (ReThrowError) or handles it.
 */
extern int	guard_mark(void);
extern ErrorData *guard_catch(int mark, MemoryContext cxt);

/* Settings only (no identity, no read-only): the pinned ones for a whole call, in a nest level of their own. */
extern int	guard_pin_settings(void);
extern void guard_unpin_settings(int nest);
extern bool guard_active(void);

/*
 * The proof's own session (phasevec_truth.c): this backend is one, the only kind where GUARD_AUTHOR runs. The custom
 * placeholders a session has (sorted), and the first one it has that is neither among base nor named by env (NULL:
 * none): one a proof, a recorded state or a recipe made, which the next claim's author may not have had.
 */
extern void guard_proof_session(void);
extern char **guard_placeholders(int *n);
extern const char *guard_env_spent(char **base, int nbase, const GuardEnv *env);

/*
 * The settings state a proof records: what this session changed over the configuration a new session of it starts
 * from (every replayable setting it set, every custom placeholder it made, its application_name).
 */
extern ArrayType *guard_env_now(void);
/* A recorded state, from its text[] (NULL: none recorded, every setting at its default). */
extern GuardEnv *guard_env_from(ArrayType *arr);

#endif
