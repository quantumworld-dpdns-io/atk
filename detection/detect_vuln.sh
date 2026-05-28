#!/bin/bash
set -euo pipefail

check_version() {
    local ver="$1"
    echo "$ver" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$' || return 1

    IFS='.' read -r major minor patch <<< "$ver"

    # Vulnerable: 0.6.27 through 1.30.0
    if [ "$major" -eq 0 ]; then
        [ "$minor" -eq 6 ] && [ "$patch" -ge 27 ] && return 0
        return 1
    fi

    if [ "$major" -eq 1 ]; then
        if [ "$minor" -lt 30 ]; then
            return 0
        fi
        if [ "$minor" -eq 30 ] && [ "$patch" -le 0 ]; then
            return 0
        fi
    fi

    return 1
}

check_config() {
    local config="$1"
    local found_vuln=0

    while IFS= read -r line; do
        if echo "$line" | grep -qE 'rewrite\s+\S+\s+\S*\?'; then
            local rewrite_line="$line"
            local has_capture=0
            local has_followup=0

            echo "$rewrite_line" | grep -qE '\$\d' && has_capture=1

            echo "$rewrite_line" | grep -qE '\?' && has_capture=1

            read -r next_line
            if echo "$next_line" | grep -qE '^\s*(rewrite|set|if)\s'; then
                has_followup=1
            fi

            if [ "$has_capture" -eq 1 ] && [ "$has_followup" -eq 1 ]; then
                echo "VULNERABLE: $line"
                found_vuln=1
            fi
        fi
    done < <(grep -n 'rewrite\|set\|if' "$config" 2>/dev/null)

    return $found_vuln
}

echo "=== CVE-2026-42945 Detection ==="

if command -v nginx &>/dev/null; then
    NGINX_VER=$(nginx -v 2>&1 | grep -oP 'nginx/\K[0-9]+\.[0-9]+\.[0-9]+' || echo "unknown")
    echo "NGINX version: $NGINX_VER"
    if check_version "$NGINX_VER"; then
        echo ">>> VERSION IS VULNERABLE (affects 0.6.27 - 1.30.0)"
    else
        echo ">>> Version is not in vulnerable range"
    fi
else
    echo "NGINX not found in PATH"
fi

if [ -d /etc/nginx ]; then
    echo ""
    echo "--- Checking /etc/nginx configs ---"
    find /etc/nginx -name '*.conf' 2>/dev/null | while read -r f; do
        check_config "$f"
    done
fi

echo ""
echo "Done."
