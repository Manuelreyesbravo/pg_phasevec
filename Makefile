MODULE_big   = pg_phasevec
OBJS         = src/phasevec_ivf.o src/phasevec_ask.o src/phasevec_truth.o src/phasevec_guard.o
# The watch trigger's entry point (src/pg_phasevec_observe.c): a library no session that loaded an older
# pg_phasevec has loaded, so after ALTER EXTENSION UPDATE such a session is told to reconnect.
MODULES      = src/pg_phasevec_observe
# Portable by default: the server's CFLAGS plus -O3. A build tuned to THIS machine's CPU (it may not run on
# another one: SIGILL) is opt-in:  make PHASEVEC_NATIVE=1
PG_CFLAGS    = -O3
ifeq ($(PHASEVEC_NATIVE),1)
PG_CFLAGS   += -march=native
endif
EXTENSION    = pg_phasevec
DATA         = sql/pg_phasevec--0.1.0.sql sql/pg_phasevec--0.1.0--0.2.0.sql sql/pg_phasevec--0.2.0--0.3.0.sql sql/pg_phasevec--0.3.0--0.4.0.sql sql/pg_phasevec--0.4.0--0.5.0.sql sql/pg_phasevec--0.5.0--0.6.0.sql sql/pg_phasevec--0.6.0--0.7.0.sql sql/pg_phasevec--0.7.0--0.8.0.sql sql/pg_phasevec--0.8.0--0.9.0.sql sql/pg_phasevec--0.9.0--0.10.0.sql sql/pg_phasevec--0.10.0--0.11.0.sql sql/pg_phasevec--0.11.0--0.12.0.sql sql/pg_phasevec--0.12.0--0.13.0.sql sql/pg_phasevec--0.13.0--0.14.0.sql sql/pg_phasevec--0.14.0--0.14.1.sql sql/pg_phasevec--0.14.1--0.14.2.sql sql/pg_phasevec--0.14.2--0.15.0.sql sql/pg_phasevec--0.15.0--0.16.0.sql sql/pg_phasevec--0.16.0--0.17.0.sql sql/pg_phasevec--0.17.0--0.18.0.sql sql/pg_phasevec--0.18.0--0.19.0.sql sql/pg_phasevec--0.19.0--0.20.0.sql
REGRESS      = core upgrade compute truncated lexical pooled bulk ivf search maintain upgrade_ivf delta_cache npu npu_reader truth truth_limits truth_clock truth_replacement security ivf_reinstall ivf_shared_cache recall brief dump_config truth_binding truth_author truth_cost privileges ivf_blobs upgrade_020 truth_claim truth_deadline truth_door truth_guard truth_sealed
REGRESS_OPTS = --inputdir=test --outputdir=test
PG_CONFIG   ?= pg_config

PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
