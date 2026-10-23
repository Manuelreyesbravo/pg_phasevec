-- pg_phasevec 0.11.0: the coarse index's delta is kept between questions.
--
-- Every question of find_ivf read the delta (ivf_dirty joined to readings) again; with the ~50 rows a
-- burst of writes leaves there that was 0.108 ms of a 0.62 ms question (b_100k). Each backend now keeps
-- the rows it read and reads them again only after a write to readings or ivf_dirty has committed
-- (phasevec.delta_cache, on by default). The two statement triggers below are what tells it: they mark the
-- writing transaction, which bumps a counter shared by the cluster once its commit is visible. They fire
-- ALWAYS (also under session_replication_role = replica, e.g. a logical replication apply); a backend
-- that finds either of them missing or disabled does not keep the delta.

CREATE FUNCTION phasevec._delta_touch() RETURNS trigger LANGUAGE C AS 'MODULE_PATHNAME', 'phasevec_delta_touch';
REVOKE ALL ON FUNCTION phasevec._delta_touch() FROM PUBLIC;
COMMENT ON FUNCTION phasevec._delta_touch() IS
    'Statement trigger on readings and ivf_dirty: marks the transaction so that, once committed, every backend reads the coarse index''s delta again (0.11.0).';

CREATE TRIGGER delta_touch AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON phasevec.readings
    FOR EACH STATEMENT EXECUTE FUNCTION phasevec._delta_touch();
CREATE TRIGGER delta_touch AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON phasevec.ivf_dirty
    FOR EACH STATEMENT EXECUTE FUNCTION phasevec._delta_touch();
ALTER TABLE phasevec.readings ENABLE ALWAYS TRIGGER delta_touch;
ALTER TABLE phasevec.ivf_dirty ENABLE ALWAYS TRIGGER delta_touch;
