#!/bin/bash
# harden_nginx.sh — Security hardening for nginx (CVE-2026-42945 context)
set -euo pipefail

CONFIG="${1:-/etc/nginx/nginx.conf}"

echo "=== NGINX Security Hardening ==="
echo "Config: $CONFIG"
echo ""

apply() {
    local desc="$1"
    local file="$2"
    local search="$3"
    local replace="$4"

    if grep -q "$search" "$file" 2>/dev/null; then
        echo "  [OK] $desc"
    else
        echo "  [APPLY] $desc"
        echo "$replace" >> "$file"
    fi
}

# ASLR
echo "--- ASLR Check ---"
aslr=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo "0")
if [ "$aslr" -eq 2 ]; then
    echo "  [OK] ASLR enabled (randomize_va_space=2)"
elif [ "$aslr" -eq 1 ]; then
    echo "  [WARN] ASLR partial (randomize_va_space=1, recommend 2)"
else
    echo "  [WARN] ASLR DISABLED (randomize_va_space=0)"
    echo "    Fix: echo 2 > /proc/sys/kernel/randomize_va_space"
    echo "    Persistent: add 'kernel.randomize_va_space=2' to /etc/sysctl.conf"
fi

echo ""
echo "--- Config Hardening ---"

# Disable server tokens
apply "server_tokens off" "$CONFIG" \
    "server_tokens off" \
    "server_tokens off;"

# Security headers
for header in \
    "add_header X-Content-Type-Options nosniff" \
    "add_header X-Frame-Options SAMEORIGIN" \
    "add_header X-XSS-Protection '1; mode=block'" \
    "add_header Referrer-Policy strict-origin-when-cross-origin"; do
    name=$(echo "$header" | awk '{print $3}')
    apply "$header" "$CONFIG" "$name" "$header;"
done

# Rate limiting
apply "limit_req_zone for rewrite" "$CONFIG" \
    "limit_req_zone" \
    "limit_req_zone \$binary_remote_addr zone=rewrite:10m rate=5r/s;"

apply "limit_req on rewrite locations" "$CONFIG" \
    "limit_req zone=rewrite" \
    "limit_req zone=rewrite burst=10 nodelay;"

# Client body size
apply "client_max_body_size 1m" "$CONFIG" \
    "client_max_body_size" \
    "client_max_body_size 1m;"

# SSL hardening
apply "ssl_protocols TLSv1.2 TLSv1.3" "$CONFIG" \
    "ssl_protocols" \
    "ssl_protocols TLSv1.2 TLSv1.3;"
apply "ssl_ciphers HIGH:!aNULL:!MD5" "$CONFIG" \
    "ssl_ciphers" \
    "ssl_ciphers HIGH:!aNULL:!MD5;"

echo ""
echo "--- Core dump check ---"
ulimit -c 2>/dev/null || echo "  [OK] Core dumps disabled"
echo ""
echo "Done. Reload nginx: nginx -s reload"
