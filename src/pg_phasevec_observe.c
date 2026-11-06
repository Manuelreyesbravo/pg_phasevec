/*
 * pg_phasevec 0.20.0: the watch trigger's entry point, a library of its own.
 *
 * From 0.20.0 the watch trigger phasevec._observe() is C (src/phasevec_truth.c, phasevec_observe). A session that
 * loaded pg_phasevec's library before ALTER EXTENSION pg_phasevec UPDATE keeps that older library, which has no
 * phasevec_observe: every write to a watched table from it failed with "could not find function". The trigger is
 * declared in this library instead, which no older session has loaded. It finds phasevec_observe in the session's
 * pg_phasevec library (by the name the extension's functions use, its module_pathname) and runs it; when the
 * session's library is an older one it refuses the write and says why (the write is not let through unrecorded):
 * reconnect, or restart the server, after updating the extension.
 */
#include "postgres.h"

#include "fmgr.h"

PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(phasevec_observe_entry);

Datum
phasevec_observe_entry(PG_FUNCTION_ARGS)
{
	static PGFunction observe = NULL;

	if (observe == NULL)
	{
		observe = load_external_function("pg_phasevec", "phasevec_observe", false, NULL);
		if (observe == NULL)
			ereport(ERROR,
					(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
					 errmsg("phasevec: this session loaded the library of an older pg_phasevec, before the extension was updated"),
					 errdetail("The watch trigger of this version is not in it: the write is refused, not let through unrecorded."),
					 errhint("Reconnect (or restart the server) after ALTER EXTENSION pg_phasevec UPDATE.")));
	}
	return observe(fcinfo);
}
