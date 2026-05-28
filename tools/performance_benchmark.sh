#!/bin/bash
# performance_benchmark.sh — Benchmark nginx throughput before/after fix
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RESULTS="$ROOT/results/benchmark"
mkdir -p "$RESULTS"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

HOST="http://127.0.0.1:19321"
REQUESTS=10000
CONCURRENCY=10

echo "=== Performance Benchmark ==="
echo "Host: $HOST"
echo "Requests: $REQUESTS"
echo "Concurrency: $CONCURRENCY"
echo ""

bench() {
    local label="$1"
    local url="$2"
    local out="$RESULTS/${label}_${TIMESTAMP}.txt"

    echo -n "  $label ... "

    if command -v wrk &>/dev/null; then
        wrk -t2 -c$CONCURRENCY -d10s "$url" > "$out" 2>&1
    elif command -v ab &>/dev/null; then
        ab -n $REQUESTS -c $CONCURRENCY "$url" > "$out" 2>&1
    elif command -v hey &>/dev/null; then
        hey -n $REQUESTS -c $CONCURRESSION "$url" > "$out" 2>&1
    elif command -v siege &>/dev/null; then
        siege -b -r 100 -c $CONCURRENCY "$url" > "$out" 2>&1
    else
        echo "SKIP (no benchmark tool)"
        return
    fi

    # Extract throughput
    if grep -q "Requests/sec" "$out" 2>/dev/null; then
        grep "Requests/sec" "$out"
    elif grep -q "Transfer rate" "$out" 2>/dev/null; then
        grep "Transfer rate" "$out"
    elif grep -q "Throughput" "$out" 2>/dev/null; then
        grep "Throughput" "$out"
    else
        echo "done (see $out)"
    fi
}

echo "--- Static file ---"
bench "static_root" "${HOST}/"

echo "--- Simple rewrite (no capture) ---"
bench "simple_rewrite" "${HOST}/api/hello"

echo "--- Normal location ---"
bench "normal_location" "${HOST}/api/test"

echo ""
echo "Benchmark results: $RESULTS"
