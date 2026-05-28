#!/bin/bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
errors=0

echo "=== CVE-2026-42945 Project Verification ==="
echo ""

check() {
    local desc="$1"
    local cond="$2"
    if eval "$cond"; then
        echo "  [PASS] $desc"
    else
        echo "  [FAIL] $desc"
        errors=$((errors + 1))
    fi
}

echo "--- Directory Structure ---"
check "Project root exists" "[ -d '$PROJECT_DIR' ]"
check "env/ exists" "[ -d '$PROJECT_DIR/env' ]"
check "scripts/ exists" "[ -d '$PROJECT_DIR/scripts' ]"
check "patches/ exists" "[ -d '$PROJECT_DIR/patches' ]"
check "test/ exists" "[ -d '$PROJECT_DIR/test' ]"
check "configs/ exists" "[ -d '$PROJECT_DIR/configs' ]"
check "monitoring/ exists" "[ -d '$PROJECT_DIR/monitoring' ]"
check "fuzz/ exists" "[ -d '$PROJECT_DIR/fuzz' ]"
check "ci/ exists" "[ -d '$PROJECT_DIR/ci' ]"
check "docs/ exists" "[ -d '$PROJECT_DIR/docs' ]"
check ".gitignore exists" "[ -f '$PROJECT_DIR/.gitignore' ]"
check "Makefile exists" "[ -f '$PROJECT_DIR/Makefile' ]"
check "README.md exists" "[ -f '$PROJECT_DIR/README.md' ]"

echo ""
echo "--- Environment Files ---"
check "Dockerfile exists" "[ -f '$PROJECT_DIR/env/Dockerfile' ]"
check "docker-compose.yml exists" "[ -f '$PROJECT_DIR/env/docker-compose.yml' ]"
check "nginx.conf exists" "[ -f '$PROJECT_DIR/env/nginx.conf' ]"
check "server.py exists" "[ -f '$PROJECT_DIR/env/server.py' ]"
check "entrypoint.sh exists" "[ -f '$PROJECT_DIR/env/entrypoint.sh' ]"

echo ""
echo "--- Patch Files ---"
check "fix patch exists" "[ -f '$PROJECT_DIR/patches/0001-fix-is_args.patch' ]"
check "hardening patch exists" "[ -f '$PROJECT_DIR/patches/0002-hardening-bounds-check.patch' ]"
check "backport 1.22.x exists" "[ -f '$PROJECT_DIR/patches/backport-1.22.x.patch' ]"
check "backport 1.24.x exists" "[ -f '$PROJECT_DIR/patches/backport-1.24.x.patch' ]"
check "backport 1.26.x exists" "[ -f '$PROJECT_DIR/patches/backport-1.26.x.patch' ]"
check "fix patch has is_args = 0" "grep -q 'is_args = 0' '$PROJECT_DIR/patches/0001-fix-is_args.patch'"

echo ""
echo "--- Script Files ---"
check "trigger.py exists" "[ -f '$PROJECT_DIR/scripts/trigger.py' ]"
check "exploit.py exists" "[ -f '$PROJECT_DIR/scripts/exploit.py' ]"
check "detect_vuln.sh exists" "[ -f '$PROJECT_DIR/scripts/detect_vuln.sh' ]"
check "config_scanner.py exists" "[ -f '$PROJECT_DIR/scripts/config_scanner.py' ]"
check "heap_layout.py exists" "[ -f '$PROJECT_DIR/scripts/heap_layout.py' ]"
check "monitor_worker.py exists" "[ -f '$PROJECT_DIR/scripts/monitor_worker.py' ]"
check "compare_lengths.py exists" "[ -f '$PROJECT_DIR/scripts/compare_lengths.py' ]"
check "escape_calc.py exists" "[ -f '$PROJECT_DIR/scripts/escape_calc.py' ]"
check "find_safe_addrs.py exists" "[ -f '$PROJECT_DIR/scripts/find_safe_addrs.py' ]"
check "leak_aslr.py exists" "[ -f '$PROJECT_DIR/scripts/leak_aslr.py' ]"
check "coredump_analyzer.sh exists" "[ -f '$PROJECT_DIR/scripts/coredump_analyzer.sh' ]"
check "log_parser.py exists" "[ -f '$PROJECT_DIR/scripts/log_parser.py' ]"
check "container_scan.py exists" "[ -f '$PROJECT_DIR/scripts/container_scan.py' ]"
check "backport_check.py exists" "[ -f '$PROJECT_DIR/scripts/backport_check.py' ]"
check "h2_trigger.py exists" "[ -f '$PROJECT_DIR/scripts/h2_trigger.py' ]"
check "afl_runner.sh exists" "[ -f '$PROJECT_DIR/scripts/afl_runner.sh' ]"
check "apply_fix.sh exists" "[ -f '$PROJECT_DIR/scripts/apply_fix.sh' ]"
check "verify_project.sh exists" "[ -f '$PROJECT_DIR/scripts/verify_project.sh' ]"

echo ""
echo "--- Config Files ---"
check "vulnerable.conf exists" "[ -f '$PROJECT_DIR/configs/vulnerable.conf' ]"
check "safe.conf exists" "[ -f '$PROJECT_DIR/configs/safe.conf' ]"
check "named_capture.conf exists" "[ -f '$PROJECT_DIR/configs/named_capture.conf' ]"

echo ""
echo "--- Monitoring Rules ---"
check "modsecurity_rule.conf exists" "[ -f '$PROJECT_DIR/monitoring/modsecurity_rule.conf' ]"
check "suricata_rule.rules exists" "[ -f '$PROJECT_DIR/monitoring/suricata_rule.rules' ]"
check "falco_rule.yaml exists" "[ -f '$PROJECT_DIR/monitoring/falco_rule.yaml' ]"

echo ""
echo "--- Fuzzing Harness ---"
check "ngx_http_script_fuzz.c exists" "[ -f '$PROJECT_DIR/fuzz/ngx_http_script_fuzz.c' ]"
check "fuzz_build.sh exists" "[ -f '$PROJECT_DIR/fuzz/fuzz_build.sh' ]"
check "corpus README exists" "[ -f '$PROJECT_DIR/fuzz/corpus/README.md' ]"

echo ""
echo "--- CI Config ---"
check "github_actions.yml exists" "[ -f '$PROJECT_DIR/ci/github_actions.yml' ]"

echo ""
echo "--- Test Files ---"
check "test_exploit.py exists" "[ -f '$PROJECT_DIR/test/test_exploit.py' ]"
check "run_tests.sh exists" "[ -f '$PROJECT_DIR/test/run_tests.sh' ]"

echo ""
echo "--- Python Syntax Check ---"
for pyfile in "$PROJECT_DIR/scripts/"*.py "$PROJECT_DIR/test/"*.py; do
    if [ -f "$pyfile" ]; then
        python3 -m py_compile "$pyfile" 2>/dev/null && \
            echo "  [PASS] $(basename $pyfile)" || \
            { echo "  [FAIL] $(basename $pyfile) - syntax error"; errors=$((errors + 1)); }
    fi
done

echo ""
echo "--- Commit Log ---"
if [ -f "$PROJECT_DIR/COMMIT_LOG.md" ]; then
    count=$(grep -cE '^\d{4}:' "$PROJECT_DIR/COMMIT_LOG.md" || true)
    if [ "$count" -ge 1000 ]; then
        echo "  [PASS] Commit log: $count entries (>= 1000 required)"
    else
        echo "  [FAIL] Commit log: $count entries (< 1000 required)"
        errors=$((errors + 1))
    fi
else
    echo "  [FAIL] COMMIT_LOG.md not found"
    errors=$((errors + 1))
fi

echo ""
echo "=== Summary ==="
if [ $errors -eq 0 ]; then
    echo "All checks passed."
else
    echo "$errors check(s) failed."
fi

exit $errors
