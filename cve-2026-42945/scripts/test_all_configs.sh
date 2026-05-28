#!/bin/bash
# test_all_configs.sh — Run all config patterns against nginx
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RESULTS="$ROOT/results/config_matrix"
rm -rf "$RESULTS"
mkdir -p "$RESULTS"

HOST="127.0.0.1"
PORT="19321"
PASS=0
FAIL=0

run_config() {
    local config="$1"
    local label="$2"
    local expected_crash="${3:-yes}"

    echo "Testing: $label ($config)"

    # Write config
    cp "$config" "$ROOT/env/nginx.conf"

    # Restart nginx
    cd "$ROOT/env" && docker compose restart nginx -t 10 > /dev/null 2>&1 || {
        docker compose up -d > /dev/null 2>&1 || true
    }
    sleep 3

    # Health check
    if ! python3 "$ROOT/scripts/trigger.py" --host "$HOST" --port "$PORT" --check-alive > /dev/null 2>&1; then
        echo "  [SKIP] nginx not responding"
        return
    fi

    # Run trigger
    local out="$RESULTS/${label}.txt"
    set +e
    python3 "$ROOT/scripts/trigger.py" --host "$HOST" --port "$PORT" --plus-count 969 > "$out" 2>&1
    local rc=$?
    set -e

    # Check crash
    sleep 2
    if python3 "$ROOT/scripts/trigger.py" --host "$HOST" --port "$PORT" --check-alive > /dev/null 2>&1; then
        alive=true
    else
        alive=false
    fi

    if [ "$expected_crash" = "yes" ] && [ "$alive" = false ]; then
        echo "  [PASS] Crashed as expected"
        PASS=$((PASS+1))
    elif [ "$expected_crash" = "yes" ] && [ "$alive" = true ]; then
        echo "  [FAIL] Expected crash but server alive"
        FAIL=$((FAIL+1))
    elif [ "$expected_crash" = "no" ] && [ "$alive" = true ]; then
        echo "  [PASS] No crash (expected)"
        PASS=$((PASS+1))
    else
        echo "  [FAIL] Unexpected behavior"
        FAIL=$((FAIL+1))
    fi
}

echo "=== Config Matrix Test ==="
echo ""

# Vulnerable configs (expected to crash)
run_config "$ROOT/configs/vulnerable.conf" "basic_vuln" "yes"
run_config "$ROOT/configs/advanced/vulnerable_advanced.conf" "advanced_vuln" "yes"
run_config "$ROOT/configs/advanced/vulnerable_ingress.conf" "ingress_vuln" "yes"
run_config "$ROOT/configs/advanced/vulnerable_gateway.conf" "gateway_vuln" "yes"

# Safe configs (expected NOT to crash)
run_config "$ROOT/configs/safe.conf" "basic_safe" "no"
run_config "$ROOT/configs/named_capture.conf" "named_capture_safe" "no"

echo ""
echo "=== Results ==="
echo "Pass: $PASS  Fail: $FAIL"
echo "Details in: $RESULTS"
