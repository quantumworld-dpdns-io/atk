#!/bin/bash
# memory_analysis.sh — Analyze nginx memory usage
set -euo pipefail

RESULTS_DIR="${1:-./results/memory}"
mkdir -p "$RESULTS_DIR"

echo "=== Memory Analysis ==="
echo ""

analyze_pid() {
    local pid="$1"
    local label="$2"
    local out="$RESULTS_DIR/${label}_${pid}.txt"

    echo "--- $label (PID $pid) ---"
    echo "  PID: $pid" > "$out"

    if [ -f "/proc/$pid/status" ]; then
        echo "  VmPeak: $(grep VmPeak /proc/$pid/status 2>/dev/null || echo N/A)"
        echo "  VmRSS:  $(grep VmRSS /proc/$pid/status 2>/dev/null || echo N/A)"
        echo "  VmSize: $(grep VmSize /proc/$pid/status 2>/dev/null || echo N/A)"
        echo "  Threads: $(grep Threads /proc/$pid/status 2>/dev/null || echo N/A)"
    fi

    if command -v pmap &>/dev/null; then
        pmap -x "$pid" > "${out%.txt}_pmap.txt" 2>/dev/null && \
            echo "  pmap: $(wc -l < "${out%.txt}_pmap.txt") regions" || \
            echo "  pmap: N/A"
    fi

    echo ""
}

for pid in $(pgrep -x nginx 2>/dev/null); do
    # Determine master vs worker
    ppid=$(ps -o ppid= -p $pid 2>/dev/null | tr -d ' ')
    if [ "$ppid" = "1" ] || [ "$ppid" = "0" ]; then
        analyze_pid "$pid" "master"
    else
        analyze_pid "$pid" "worker"
    fi
done

echo "--- Summary ---"
if command -v valgrind &>/dev/null; then
    echo "  valgrind available (run manually for massif/heap analysis)"
else
    echo "  valgrind not installed"
fi

echo "  Results: $RESULTS_DIR"
