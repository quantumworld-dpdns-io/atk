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
check "docker/ exists" "[ -d '$PROJECT_DIR/docker' ]"
check "exploit/ exists" "[ -d '$PROJECT_DIR/exploit' ]"
check "shell/ exists" "[ -d '$PROJECT_DIR/shell' ]"
check "patches/ exists" "[ -d '$PROJECT_DIR/patches' ]"
check "test/ exists" "[ -d '$PROJECT_DIR/test' ]"
check "configs/ exists" "[ -d '$PROJECT_DIR/configs' ]"
check "detection/ exists" "[ -d '$PROJECT_DIR/detection' ]"
check "fuzz/ exists" "[ -d '$PROJECT_DIR/fuzz' ]"
check "docs/ exists" "[ -d '$PROJECT_DIR/docs' ]"
check "tools/ exists" "[ -d '$PROJECT_DIR/tools' ]"
check "pipelines/ exists" "[ -d '$PROJECT_DIR/pipelines' ]"
check ".github/workflows/ exists" "[ -d '$PROJECT_DIR/.github/workflows' ]"
check ".gitignore exists" "[ -f '$PROJECT_DIR/.gitignore' ]"
check "Makefile exists" "[ -f '$PROJECT_DIR/Makefile' ]"
check "README.md exists" "[ -f '$PROJECT_DIR/README.md' ]"

echo ""
echo "--- Docker Environment ---"
check "Dockerfile exists" "[ -f '$PROJECT_DIR/docker/Dockerfile' ]"
check "docker-compose.yml exists" "[ -f '$PROJECT_DIR/docker/docker-compose.yml' ]"
check "nginx.conf exists" "[ -f '$PROJECT_DIR/docker/nginx.conf' ]"
check "server.py exists" "[ -f '$PROJECT_DIR/docker/server.py' ]"
check "entrypoint.sh exists" "[ -f '$PROJECT_DIR/docker/entrypoint.sh' ]"
check "Dockerfile.patched exists" "[ -f '$PROJECT_DIR/docker/Dockerfile.patched' ]"
check "Dockerfile.asan exists" "[ -f '$PROJECT_DIR/docker/Dockerfile.asan' ]"

echo ""
echo "--- Patch Files ---"
check "fix patch exists" "[ -f '$PROJECT_DIR/patches/0001-fix-is_args.patch' ]"
check "hardening patch exists" "[ -f '$PROJECT_DIR/patches/0002-hardening-bounds-check.patch' ]"
check "backport 1.22.x exists" "[ -f '$PROJECT_DIR/patches/backport-1.22.x.patch' ]"
check "backport 1.24.x exists" "[ -f '$PROJECT_DIR/patches/backport-1.24.x.patch' ]"
check "backport 1.26.x exists" "[ -f '$PROJECT_DIR/patches/backport-1.26.x.patch' ]"
check "fix patch has is_args = 0" "grep -q 'is_args = 0' '$PROJECT_DIR/patches/0001-fix-is_args.patch'"

echo ""
echo "--- Exploit Scripts ---"
check "trigger.py exists" "[ -f '$PROJECT_DIR/exploit/trigger.py' ]"
check "exploit.py exists" "[ -f '$PROJECT_DIR/exploit/exploit.py' ]"
check "config_scanner.py exists" "[ -f '$PROJECT_DIR/exploit/config_scanner.py' ]"
check "heap_layout.py exists" "[ -f '$PROJECT_DIR/exploit/heap_layout.py' ]"
check "monitor_worker.py exists" "[ -f '$PROJECT_DIR/exploit/monitor_worker.py' ]"
check "compare_lengths.py exists" "[ -f '$PROJECT_DIR/exploit/compare_lengths.py' ]"
check "escape_calc.py exists" "[ -f '$PROJECT_DIR/exploit/escape_calc.py' ]"
check "find_safe_addrs.py exists" "[ -f '$PROJECT_DIR/exploit/find_safe_addrs.py' ]"
check "leak_aslr.py exists" "[ -f '$PROJECT_DIR/exploit/leak_aslr.py' ]"
check "log_parser.py exists" "[ -f '$PROJECT_DIR/exploit/log_parser.py' ]"
check "h2_trigger.py exists" "[ -f '$PROJECT_DIR/exploit/h2_trigger.py' ]"

echo ""
echo "--- Detection Scripts ---"
check "detect_vuln.sh exists" "[ -f '$PROJECT_DIR/detection/detect_vuln.sh' ]"
check "check_aslr.sh exists" "[ -f '$PROJECT_DIR/detection/check_aslr.sh' ]"
check "container_scan.py exists" "[ -f '$PROJECT_DIR/detection/container_scan.py' ]"
check "harden_nginx.sh exists" "[ -f '$PROJECT_DIR/detection/harden_nginx.sh' ]"

echo ""
echo "--- WAF Rules ---"
check "modsecurity_rule.conf exists" "[ -f '$PROJECT_DIR/detection/modsecurity_rule.conf' ]"
check "suricata_rule.rules exists" "[ -f '$PROJECT_DIR/detection/suricata_rule.rules' ]"
check "falco_rule.yaml exists" "[ -f '$PROJECT_DIR/detection/falco_rule.yaml' ]"

echo ""
echo "--- Tool Scripts ---"
check "apply_fix.sh exists" "[ -f '$PROJECT_DIR/tools/apply_fix.sh' ]"
check "backport_check.py exists" "[ -f '$PROJECT_DIR/tools/backport_check.py' ]"
check "coredump_analyzer.sh exists" "[ -f '$PROJECT_DIR/tools/coredump_analyzer.sh' ]"
check "verify_project.sh exists" "[ -f '$PROJECT_DIR/tools/verify_project.sh' ]"
check "afl_runner.sh exists" "[ -f '$PROJECT_DIR/tools/afl_runner.sh' ]"

echo ""
echo "--- Config Files ---"
check "vulnerable.conf exists" "[ -f '$PROJECT_DIR/configs/vulnerable.conf' ]"
check "safe.conf exists" "[ -f '$PROJECT_DIR/configs/safe.conf' ]"
check "named_capture.conf exists" "[ -f '$PROJECT_DIR/configs/named_capture.conf' ]"
check "advanced/ exists" "[ -d '$PROJECT_DIR/configs/advanced' ]"

echo ""
echo "--- Fuzzing Harness ---"
check "ngx_http_script_fuzz.c exists" "[ -f '$PROJECT_DIR/fuzz/ngx_http_script_fuzz.c' ]"
check "fuzz_build.sh exists" "[ -f '$PROJECT_DIR/fuzz/fuzz_build.sh' ]"
check "corpus README exists" "[ -f '$PROJECT_DIR/fuzz/corpus/README.md' ]"

echo ""
echo "--- Test Files ---"
check "test_exploit.py exists" "[ -f '$PROJECT_DIR/test/test_exploit.py' ]"
check "run_tests.sh exists" "[ -f '$PROJECT_DIR/test/run_tests.sh' ]"

echo ""
echo "--- Shell Verification ---"
check "shell_listener.py exists" "[ -f '$PROJECT_DIR/shell/shell_listener.py' ]"
check "shell_payloads.py exists" "[ -f '$PROJECT_DIR/shell/shell_payloads.py' ]"
check "shell_verify.py exists" "[ -f '$PROJECT_DIR/shell/shell_verify.py' ]"
check "shell_manager.py exists" "[ -f '$PROJECT_DIR/shell/shell_manager.py' ]"
check "shell_test_runner.sh exists" "[ -f '$PROJECT_DIR/shell/shell_test_runner.sh' ]"

echo ""
echo "--- Documentation ---"
check "root-cause-analysis.md exists" "[ -f '$PROJECT_DIR/docs/root-cause-analysis.md' ]"
check "exploitation-guide.md exists" "[ -f '$PROJECT_DIR/docs/exploitation-guide.md' ]"
check "detection-guide.md exists" "[ -f '$PROJECT_DIR/docs/detection-guide.md' ]"
check "mitigation-guide.md exists" "[ -f '$PROJECT_DIR/docs/mitigation-guide.md' ]"
check "FAQ.md exists" "[ -f '$PROJECT_DIR/docs/FAQ.md' ]"

echo ""
echo "--- Pipeline Scripts ---"
check "run_all.sh exists" "[ -f '$PROJECT_DIR/pipelines/run_all.sh' ]"
check "run_all.ps1 exists" "[ -f '$PROJECT_DIR/pipelines/run_all.ps1' ]"

echo ""
echo "--- Python Syntax Check ---"
for pyfile in "$PROJECT_DIR/exploit/"*.py "$PROJECT_DIR/detection/"*.py \
              "$PROJECT_DIR/tools/"*.py "$PROJECT_DIR/shell/"*.py \
              "$PROJECT_DIR/test/"*.py; do
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
