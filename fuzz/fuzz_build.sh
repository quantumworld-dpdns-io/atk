#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/fuzz/build"

echo "Building libFuzzer harness for ngx_http_script engine..."

mkdir -p "$BUILD_DIR"

clang -fsanitize=fuzzer,address \
    -g -O1 \
    -I. \
    "$SCRIPT_DIR/ngx_http_script_fuzz.c" \
    -o "$BUILD_DIR/ngx_script_fuzz"

echo "Fuzzer built: $BUILD_DIR/ngx_script_fuzz"
echo ""
echo "To run:"
echo "  mkdir -p $PROJECT_DIR/fuzz/corpus"
echo "  $BUILD_DIR/ngx_script_fuzz $PROJECT_DIR/fuzz/corpus"
echo ""
echo "To reproduce a crash:"
echo "  $BUILD_DIR/ngx_script_fuzz $PROJECT_DIR/fuzz/crashes/<crash_file>"
