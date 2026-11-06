#!/usr/bin/env bash
# Captures what the real phasevec.search() answers for section (6) of test/sql/truth_sealed.sql, which replays it:
# the real reader (reader/phasevec-reader, built with reader/build.sh) reads the five rows of that section and answers
# the question recall() asks there. Run it again when the reader, its model or find() changes, and paste the rows it
# prints into the stub of that section (read_at in UTC). A throwaway cluster in a temporary directory; nothing is
# installed into the PostgreSQL tree.
#   MODEL=.modelos/Qwen3-Embedding-0.6B-Q8_0.gguf PG=~/pg19/bin test/search_capture.sh
set -uo pipefail
cd "$(dirname "$0")/.."
PG=${PG:-$HOME/pg19/bin}
PORT=${PV_PORT:-5493}
MODEL=${MODEL:?MODEL names the gguf model of the reader}
READER=${READER:-reader/phasevec-reader}
T=$(mktemp -d)
S=$T/s
mkdir -p "$S" "$T/sock"
trap '[ -n "${RP:-}" ] && kill "$RP" 2>/dev/null; "$PG/pg_ctl" -D "$T/data" -w stop >/dev/null 2>&1; rm -rf "$T"' EXIT
"$PG/initdb" -D "$T/data" -A trust -U "$(id -un)" >/dev/null || exit 1
mkdir -p "$T/data/ext/extension" "$T/data/ext/lib"
make -s PG_CONFIG="$PG/pg_config" >/dev/null
for f in pg_phasevec.control sql/*.sql; do ln -sfn "$PWD/$f" "$T/data/ext/extension/$(basename "$f")"; done
ln -sfn "$PWD/pg_phasevec.so" "$T/data/ext/lib/pg_phasevec.so"
ln -sfn "$PWD/src/pg_phasevec_observe.so" "$T/data/ext/lib/pg_phasevec_observe.so"
printf "dynamic_library_path = '%s:\$libdir'\nextension_control_path = '%s:\$system'\n" \
    "$T/data/ext/lib" "$T/data/ext" >> "$T/data/postgresql.conf"
"$PG/pg_ctl" -D "$T/data" -o "-p $PORT -k $S" -l "$T/server.log" -w start >/dev/null || exit 1
DSN="host=$S port=$PORT dbname=postgres user=$(id -un)"
P=("$PG/psql" -X -q -h "$S" -p "$PORT" -d postgres -v ON_ERROR_STOP=1)
"${P[@]}" <<'SQL' || exit 1
CREATE EXTENSION pg_phasevec;
CREATE TABLE hr (id int PRIMARY KEY, owner_name text, body text);
INSERT INTO hr VALUES (1, $o$pv_s_alice$o$, $t$alice: the salary review is done$t$),
                      (2, $o$pv_s_bobby$o$, $t$bob: the salary review is not done$t$),
                      (3, $o$pv_s_alice$o$, $t$alice: plan v1$t$),
                      (4, $o$pv_s_bobby$o$, $t$bob: plan v2, layoffs$t$),
                      (5, $o$pv_s_alice$o$, $t$alice: plan v3$t$);
SQL
RO=(--model "$MODEL" --backend cpu --threads "${THREADS:-8}" --ctx 1024 --pooling last --dsn "$DSN")
"$READER" --register --reader qwen3-0.6b-q8@cpu "${RO[@]}" || exit 1
"${P[@]}" -c "SELECT phasevec.watch('hr', 'hr'::regclass, 'id', 'r.body', 'qwen3-0.6b-q8@cpu') > 0" >/dev/null || exit 1
"$READER" --watch hr --once "${RO[@]}" || exit 1
"$READER" --watch hr --serve-dir "$T/sock" "${RO[@]}" > "$T/reader.log" 2>&1 &
RP=$!
for _ in $(seq 150); do [ -S "$T/sock/hr.sock" ] && break; sleep 0.2; done
"${P[@]}" -At -F '|' <<SQL
SET phasevec.socket_dir = '$T/sock';
SET TimeZone = 'UTC';
SELECT key, score::text, hamming, state, familiarity, read_at, truncated
  FROM phasevec.search('hr', 'salary', 30, false);
SQL
