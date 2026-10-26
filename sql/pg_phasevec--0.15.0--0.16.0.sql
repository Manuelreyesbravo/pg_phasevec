-- pg_phasevec 0.16.0: security hardening. No behaviour changes for a caller that has the rights.
--
-- Threat model, said here and not discovered later:
--   A watch's recipe and a proof are SQL written by the user and run with the user's own rights;
--   phasevec is not a sandbox for third-party code. Maintenance functions (ivf_build/maintain/absorb,
--   counts_compact) are owner/admin operations, revoked from PUBLIC in 0.16.0.
--
-- The library of 0.16.0 adds upper bounds and size/bounds checks on the C paths (defense in depth): an
-- index shape or a search parameter far outside what a real index uses is refused rather than trusted
-- to fit in memory. None of it changes a legitimate build or search.
--
-- The SQL contract is the same as 0.15.0; only the C hardening and these grants differ.
\echo Use "ALTER EXTENSION pg_phasevec UPDATE TO '0.16.0'" to load this file. \quit

-- Maintenance is owner/admin work: take it away from PUBLIC. A role that needs it is granted it back
-- explicitly by the owner; the search path (find, find_ivf, search, recall) is untouched.
REVOKE EXECUTE ON FUNCTION phasevec.ivf_build(text, int, int, int, boolean) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION phasevec.ivf_maintain(text, double precision, int) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION phasevec.ivf_maintain_all(double precision, int) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION phasevec.ivf_absorb(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION phasevec.counts_compact(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION phasevec._ivf_dirty() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION phasevec.ivf_sweep(int, bit, smallint[], int, int, int) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION phasevec.ivf_delta(int, int, bit, smallint[], int) FROM PUBLIC;
