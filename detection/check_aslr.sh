#!/bin/bash
# check_aslr.sh — Verify ASLR is enabled
set -euo pipefail

echo "=== ASLR Status Check ==="
echo ""

check_path="/proc/sys/kernel/randomize_va_space"

if [ -f "$check_path" ]; then
    val=$(cat "$check_path")
    case "$val" in
        2)
            echo "  [OK] Full randomization (randomize_va_space = 2)"
            ;;
        1)
            echo "  [WARN] Conservative randomization (randomize_va_space = 1)"
            echo "  Recommend: echo 2 > $check_path"
            echo "  Persistent: add 'kernel.randomize_va_space = 2' to /etc/sysctl.conf"
            exit 1
            ;;
        0)
            echo "  [FAIL] ASLR DISABLED (randomize_va_space = 0)"
            echo "  CVE-2026-42945 RCE is possible!"
            echo ""
            echo "  Fix immediately:"
            echo "    echo 2 > $check_path"
            echo "    sysctl -w kernel.randomize_va_space=2"
            echo "    echo 'kernel.randomize_va_space = 2' >> /etc/sysctl.conf"
            exit 2
            ;;
        *)
            echo "  [UNKNOWN] Unexpected value: $val"
            exit 3
            ;;
    esac
else
    echo "  [UNKNOWN] Cannot read $check_path"
    echo "  (Not running on Linux?)"
fi

echo ""
echo "--- Checking nginx process ASLR ---"
for pid in $(pgrep -x nginx 2>/dev/null); do
    pa=$(cat /proc/$pid/personality 2>/dev/null || echo "0")
    if [ "$pa" != "0" ]; then
        echo "  [WARN] PID $pid has ASLR disabled (personality != 0)"
        echo "  Check if launched with setarch -R or personality(ADDR_NO_RANDOMIZE)"
    else
        echo "  [OK] PID $pid ASLR enabled"
    fi
done

echo ""
echo "Done."
