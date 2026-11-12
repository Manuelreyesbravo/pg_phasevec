-- pg_phasevec 0.19.0: the extension's data goes into pg_dump.
--
-- Until 0.18.0 every table of the extension was a plain member: pg_dump left out its rows and
-- its sequences, so a dump of a database with watches restored the watches' triggers on the
-- watched tables but not the watches, the readings, the sources or the truth they refer to.
-- (Found on 2026-11-05: the daily dump of the author's own deployment had no phasevec data at all; it
-- was being covered by a separate \copy of all 19 tables.)
--
-- Marked: the tables that hold what users and maintenance functions wrote (readers, watches,
-- readings, sources, truth, usefulness, recall_baseline, audits, the built coarse index ivf_*,
-- npu_snaps, lexstats/lexdocs) and their sequences, or ids would start again from 1 after a
-- restore and collide.
-- NOT marked, on purpose: the five tables the extension's own triggers derive from those
-- (counts, count_deltas, kstate via _recount/_refresh; ivf_dirty, npu_dirty via _ivf_dirty).
-- During a restore, loading watches/readings/sources fires those triggers and rebuilds them;
-- dumping them too made the restore fail with a duplicate key in counts (seen while testing).
-- After a restore every key is in ivf_dirty: the coarse index is treated as stale until the next
-- ivf_maintain, which is the conservative reading.
-- No table is filled by an install or upgrade script (every INSERT lives inside a function), so
-- no WHERE filter is needed: a fresh CREATE EXTENSION leaves them empty.
-- pg_dump orders the config tables' data by their foreign keys (processExtensionTables).

-- One statement per object: each call updates the same pg_extension row, and two calls inside
-- ONE statement fail with "tuple already updated by self" (seen while testing this script).
SELECT pg_catalog.pg_extension_config_dump('phasevec.readers', '');
SELECT pg_catalog.pg_extension_config_dump('phasevec.watches', '');
SELECT pg_catalog.pg_extension_config_dump('phasevec.readings', '');
SELECT pg_catalog.pg_extension_config_dump('phasevec.sources', '');
SELECT pg_catalog.pg_extension_config_dump('phasevec.truth', '');
SELECT pg_catalog.pg_extension_config_dump('phasevec.usefulness', '');
SELECT pg_catalog.pg_extension_config_dump('phasevec.recall_baseline', '');
SELECT pg_catalog.pg_extension_config_dump('phasevec.audits', '');
SELECT pg_catalog.pg_extension_config_dump('phasevec.lexstats', '');
SELECT pg_catalog.pg_extension_config_dump('phasevec.lexdocs', '');
SELECT pg_catalog.pg_extension_config_dump('phasevec.ivf_cents', '');
SELECT pg_catalog.pg_extension_config_dump('phasevec.ivf_lists', '');
SELECT pg_catalog.pg_extension_config_dump('phasevec.ivf_added', '');
SELECT pg_catalog.pg_extension_config_dump('phasevec.npu_snaps', '');
SELECT pg_catalog.pg_extension_config_dump('phasevec.readers_id_seq', '');
SELECT pg_catalog.pg_extension_config_dump('phasevec.watches_id_seq', '');
SELECT pg_catalog.pg_extension_config_dump('phasevec.audits_id_seq', '');
SELECT pg_catalog.pg_extension_config_dump('phasevec.ivf_added_seq_seq', '');
SELECT pg_catalog.pg_extension_config_dump('phasevec.ivf_gen', '');
