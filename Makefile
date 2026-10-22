MODULE_big   = pg_phasevec
OBJS         = src/phasevec_ivf.o src/phasevec_ask.o
PG_CFLAGS    = -O3 -march=native
EXTENSION    = pg_phasevec
DATA         = sql/pg_phasevec--0.1.0.sql sql/pg_phasevec--0.1.0--0.2.0.sql sql/pg_phasevec--0.2.0--0.3.0.sql sql/pg_phasevec--0.3.0--0.4.0.sql sql/pg_phasevec--0.4.0--0.5.0.sql sql/pg_phasevec--0.5.0--0.6.0.sql sql/pg_phasevec--0.6.0--0.7.0.sql sql/pg_phasevec--0.7.0--0.8.0.sql sql/pg_phasevec--0.8.0--0.9.0.sql sql/pg_phasevec--0.9.0--0.10.0.sql
REGRESS      = core upgrade compute truncated lexical pooled bulk ivf search maintain upgrade_ivf
REGRESS_OPTS = --inputdir=test --outputdir=test
PG_CONFIG   ?= pg_config

PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
