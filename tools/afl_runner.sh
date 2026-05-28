#!/bin/bash
set -euo pipefail

SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPTS_DIR")"
FUZZ_DIR="$PROJECT_DIR/fuzz"
CORPUS_DIR="$FUZZ_DIR/corpus"
OUTPUT_DIR="$FUZZ_DIR/afl_output"
BUILD_DIR="$FUZZ_DIR/build_afl"

echo "=== AFL++ Fuzzing Runner for ngx_http_script.c ==="
echo ""

if ! command -v afl-clang-fast &>/dev/null; then
    echo "AFL++ not found. Install with:"
    echo "  git clone https://github.com/AFLplusplus/AFLplusplus.git"
    echo "  cd AFLplusplus && make && sudo make install"
    exit 1
fi

mkdir -p "$BUILD_DIR" "$OUTPUT_DIR"

echo "[1/2] Building with AFL++..."
afl-clang-fast -fsanitize=address -g -O1 \
    -I. \
    "$FUZZ_DIR/ngx_http_script_fuzz.c" \
    -o "$BUILD_DIR/ngx_script_afl"

echo "[2/2] Starting AFL++ fuzzer..."
echo "  Corpus: $CORPUS_DIR"
echo "  Output: $OUTPUT_DIR"
echo ""

AFL_SKIP_CPUFREQ=1 afl-fuzz \
    -i "$CORPUS_DIR" \
    -o "$OUTPUT_DIR" \
    -m none \
    -t 500 \
    -- "$BUILD_DIR/ngx_script_afl" @@

echo "Fuzzing complete. Results in $OUTPUT_DIR"
