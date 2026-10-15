EXTENSION    = pg_muninn
DATA         = sql/pg_muninn--0.1.0.sql sql/pg_muninn--0.1.0--0.2.0.sql
REGRESS      = core upgrade
REGRESS_OPTS = --inputdir=test --outputdir=test
PG_CONFIG   ?= pg_config

PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
