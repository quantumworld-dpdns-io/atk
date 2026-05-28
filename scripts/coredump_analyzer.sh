#!/bin/bash
set -euo pipefail

analyze_core() {
    local core_file="$1"
    local nginx_binary="$2"

    if [ ! -f "$core_file" ]; then
        echo "Core file not found: $core_file"
        return 1
    fi
    if [ ! -f "$nginx_binary" ]; then
        echo "NGINX binary not found: $nginx_binary"
        return 1
    fi

    echo "=== Core Dump Analysis ==="
    echo "Core: $core_file"
    echo "Binary: $nginx_binary"
    echo ""

    gdb -batch -ex "bt" -ex "info registers" -ex "x/20gx \$rsp" \
        -ex "info threads" -ex "quit" \
        "$nginx_binary" "$core_file" 2>/dev/null || {
        echo "GDB analysis failed. Try:"
        echo "  gdb $nginx_binary $core_file"
        return 1
    }
}

enable_core_dumps() {
    local dir="$1"

    mkdir -p "$dir"
    echo "$dir/core.%e.%p" > /proc/sys/kernel/core_pattern 2>/dev/null || \
        echo "WARN: Cannot set core_pattern (run as root)"

    ulimit -c unlimited
    echo "Core dumps enabled in $dir"
}

case "${1:-analyze}" in
    analyze)
        if [ $# -lt 3 ]; then
            echo "Usage: $0 analyze <core_file> <nginx_binary>"
            exit 1
        fi
        analyze_core "$2" "$3"
        ;;
    enable)
        enable_core_dumps "${2:-/tmp/cores}"
        ;;
    *)
        echo "Usage: $0 {analyze|enable}"
        exit 1
        ;;
esac
