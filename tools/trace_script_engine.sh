#!/bin/bash
# trace_script_engine.sh — GDB script to trace the two-pass engine
set -euo pipefail

GDB_SCRIPT="/tmp/gdb_trace_script.txt"
PID="${1:-}"

if [ -z "$PID" ]; then
    echo "Usage: $0 <nginx_worker_pid>"
    echo ""
    echo "Find PIDs: pgrep -x nginx"
    exit 1
fi

cat > "$GDB_SCRIPT" << 'GDB'
set pagination off
set confirm off

break ngx_http_script_start_args_code
commands
    printf "START_ARGS: is_args=%d\n", e->is_args
    continue
end

break ngx_http_script_complex_value_code
commands
    printf "COMPLEX_VALUE: is_args=%d\n", e->is_args
    continue
end

break ngx_http_script_copy_capture_len_code
commands
    printf "COPY_CAPTURE_LEN: is_args=%d\n", e->is_args
    continue
end

break ngx_http_script_copy_capture_code
commands
    printf "COPY_CAPTURE: is_args=%d, pos=%p\n", e->is_args, e->pos
    continue
end

break ngx_http_script_regex_end_code
commands
    printf "REGEX_END: is_args=%d\n", e->is_args
    continue
end

break ngx_http_script_regex_start_code
commands
    printf "REGEX_START\n"
    continue
end

continue
GDB

echo "Attaching to PID $PID with GDB trace..."
echo "Script: $GDB_SCRIPT"
echo ""
echo "When a request hits the vulnerable pattern, you'll see:"
echo "  START_ARGS: is_args=1"
echo "  COMPLEX_VALUE: is_args=1"
echo "  COPY_CAPTURE_LEN: is_args=0  ← MISMATCH!"
echo "  COPY_CAPTURE: is_args=1      ← OVERFLOW HERE"
echo "  REGEX_END: is_args=1         ← SHOULD BE 0 AFTER FIX"
echo ""
echo "Starting GDB..."
gdb -batch -x "$GDB_SCRIPT" -p "$PID"
