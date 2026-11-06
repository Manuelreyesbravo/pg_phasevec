/*
 * pg_phasevec 0.20.0: the one way phasevec runs code that is not its own.
 *
 * A watch's recipe is the table owner's SQL (and through casts, functions and operators, code the table owner
 * controls); a proof is its author's. Everything phasevec runs of either goes through guard_enter()/guard_leave():
 * as one named role, in a security-restricted operation, read-only, inside a GUC nest level with the settings that
 * change how values read and print pinned, and with the session's own state out of reach (its timeouts, its
 * session-level advisory locks, its random() seed, its backend). See phasevec_guard.c.
 */
#ifndef PHASEVEC_GUARD_H
#define PHASEVEC_GUARD_H

typedef struct Guard
{
	Oid			userid;			/* who was acting before */
	int			sec;
	int			nest;			/* the GUC nest level the guard opened */
	int			depth;			/* guard depth before */
} Guard;

/* The settings a render pins and a claim records, and their pinned (canonical) values. */
#define PHASEVEC_ENV_N 12
extern const char *const phasevec_env_names[PHASEVEC_ENV_N];
extern const char *const phasevec_env_canon[PHASEVEC_ENV_N];

extern void phasevec_guard_init(void);
/* values: PHASEVEC_ENV_N strings (NULL: leave that one as it is) or NULL for the canonical ones */
extern void guard_enter(Guard *g, Oid role, const char *const *values);
extern void guard_leave(Guard *g);
/*
 * In a PG_CATCH, before the error goes on: the guard depth back to what guard_mark() said before the PG_TRY. The
 * abort that follows (of the subtransaction or the statement) puts the identity and the settings back.
 */
extern int	guard_mark(void);
extern void guard_unwind_to(int mark);
/* Settings only (no identity, no read-only): the pinned ones for a whole call, in a nest level of their own. */
extern int	guard_pin_settings(void);
extern void guard_unpin_settings(int nest);
extern bool guard_active(void);
/* The current values of the recorded settings, "name=value" each, in phasevec_env_names order. */
extern char **guard_env_now(void);

#endif
