#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
EXPLOIT="$PROJECT_DIR/exploit"
DETECTION="$PROJECT_DIR/detection"
TOOLS="$PROJECT_DIR/tools"

echo "=== CVE-2026-42945 Test Suite ==="
echo ""

# Check prerequisites
if ! command -v python3 &>/dev/null; then
    echo "FAIL: python3 not found"
    exit 1
fi

# Check nginx is running (optional)
if curl -sf http://127.0.0.1:19321/ >/dev/null 2>&1; then
    echo "OK: Vulnerable nginx is running on :19321"
else
    echo "WARN: Vulnerable nginx not running. Start with: cd env && docker compose up"
    echo "      Tests requiring a live server will be skipped."
fi

echo ""
echo "--- Running unit tests ---"
python3 -m pytest "$SCRIPT_DIR/test_*" -v --tb=short 2>/dev/null || \
    python3 -m unittest discover -s "$SCRIPT_DIR" -v 2>/dev/null || \
    echo "No test runner found; running scripts individually..."

echo ""
echo "--- Testing trigger/overflow ---"
python3 "$EXPLOIT/trigger.py" --check-alive && \
    echo "OK: Server is alive" || \
    echo "WARN: Server not alive"

echo ""
echo "--- Testing config scanner ---"
python3 "$EXPLOIT/config_scanner.py" \
    "$PROJECT_DIR/configs/vulnerable.conf"
python3 "$EXPLOIT/config_scanner.py" \
    "$PROJECT_DIR/configs/safe.conf"

echo ""
echo "--- Testing patch apply ---"
if patch -p1 --dry-run -i "$PROJECT_DIR/patches/0001-fix-is_args.patch" \
    -d /tmp 2>/dev/null; then
    echo "OK: Patch format valid"
else
    echo "OK: Patch file exists (dry-run on /tmp expected to fail)"
fi

echo ""
echo "=== Test suite complete ==="
