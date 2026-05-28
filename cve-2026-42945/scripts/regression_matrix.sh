#!/bin/bash
# regression_matrix.sh — Run tests across nginx versions and configs
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RESULTS="$ROOT/results/regression"
mkdir -p "$RESULTS"
rm -f "$RESULTS"/*.txt

DOCKER_DIR="$ROOT/env"
PASS=0
FAIL=0
SKIP=0

test_version_config() {
    local version="$1"
    local config="$2"
    local label="$3"
    local expected="$4"  # crash or no-crash
    local out="$RESULTS/${label}_v${version}.txt"

    echo -n "  $version / $label ... "

    # Build nginx image for this version
    if ! docker build -t nginx-test:"$version" \
        --build-arg NGINX_VERSION="$version" \
        -f "$ROOT/Dockerfile.patched" . > /dev/null 2>&1; then
        echo "SKIP (build failed)"
        SKIP=$((SKIP+1))
        return
    fi

    # Write config
    cp "$config" "$DOCKER_DIR/nginx.conf"

    # Start container
    if ! docker run -d --rm \
        --name "nginx-test-${version}" \
        -p 19321:19321 \
        nginx-test:"$version" > /dev/null 2>&1; then
        echo "SKIP (run failed)"
        SKIP=$((SKIP+1))
        return
    fi
    sleep 5

    # Test
    set +e
    python3 "$ROOT/scripts/trigger.py" --plus-count 969 > "$out" 2>&1
    local trigger_rc=$?
    sleep 2
    python3 "$ROOT/scripts/trigger.py" --check-alive >> "$out" 2>&1
    local alive_rc=$?
    set -e

    # Cleanup
    docker kill "nginx-test-${version}" > /dev/null 2>&1 || true

    # Evaluate
    if [ "$expected" = "crash" ]; then
        if [ $alive_rc -ne 0 ]; then
            echo "PASS (crashed)"
            PASS=$((PASS+1))
        else
            echo "FAIL (expected crash, got alive)"
            FAIL=$((FAIL+1))
        fi
    else
        if [ $alive_rc -eq 0 ]; then
            echo "PASS (alive)"
            PASS=$((PASS+1))
        else
            echo "FAIL (expected alive, got crash)"
            FAIL=$((FAIL+1))
        fi
    fi
}

echo "=== Regression Test Matrix ==="
echo ""

# Test matrix
test_version_config "1.22.0" "$ROOT/configs/vulnerable.conf" "vuln" "crash"
test_version_config "1.24.0" "$ROOT/configs/vulnerable.conf" "vuln" "crash"
test_version_config "1.26.0" "$ROOT/configs/vulnerable.conf" "vuln" "crash"
test_version_config "1.30.0" "$ROOT/configs/vulnerable.conf" "vuln" "crash"
test_version_config "1.30.1" "$ROOT/configs/vulnerable.conf" "vuln" "no-crash"
test_version_config "1.30.1" "$ROOT/configs/safe.conf" "safe" "no-crash"

echo ""
echo "=== Summary ==="
echo "Pass: $PASS  Fail: $FAIL  Skip: $SKIP"
echo "Results: $RESULTS"
