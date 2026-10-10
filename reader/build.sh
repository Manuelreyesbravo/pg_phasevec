#!/usr/bin/env bash
# Builds muninn-reader against a llama.cpp build tree and a PostgreSQL install.
#   LLAMA_DIR=~/src/llama.cpp LLAMA_BUILD=build-cuda PG_CONFIG=pg_config reader/build.sh
set -euo pipefail
cd "$(dirname "$0")"
LLAMA_DIR=${LLAMA_DIR:-$HOME/src/llama.cpp}
LLAMA_BUILD=${LLAMA_BUILD:-build-cuda}
PG_CONFIG=${PG_CONFIG:-pg_config}
LIB="$LLAMA_DIR/$LLAMA_BUILD/bin"
g++ -O2 -std=c++17 -Wall -Wextra -o muninn-reader muninn_reader.cpp \
    -I"$LLAMA_DIR/include" -I"$LLAMA_DIR/ggml/include" -I"$("$PG_CONFIG" --includedir)" \
    -L"$LIB" -lllama -lggml -lggml-base -L"$("$PG_CONFIG" --libdir)" -lpq \
    -Wl,-rpath,"$LIB" -Wl,-rpath,"$("$PG_CONFIG" --libdir)"
echo "built reader/muninn-reader"
