#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

apply_patch() {
    local nginx_src="$1"
    local patch_file="$2"

    if [ ! -d "$nginx_src/src" ]; then
        echo "Not a valid nginx source: $nginx_src"
        return 1
    fi
    if [ ! -f "$patch_file" ]; then
        echo "Patch file not found: $patch_file"
        return 1
    fi

    echo "Applying $(basename $patch_file) to $nginx_src"

    if patch -p1 --dry-run -i "$patch_file" -d "$nginx_src" >/dev/null 2>&1; then
        echo "  Dry run: OK"
    else
        echo "  Patch does not apply cleanly"
        return 1
    fi

    pushd "$nginx_src" >/dev/null
    cp src/http/ngx_http_script.c src/http/ngx_http_script.c.bak
    patch -p1 -i "$patch_file"
    popd >/dev/null

    echo "  Applied successfully (backup: ngx_http_script.c.bak)"
    return 0
}

rebuild_nginx() {
    local nginx_src="$1"
    echo "Rebuilding nginx..."
    cd "$nginx_src"
    make -j$(nproc) 2>&1 | tail -5 || {
        echo "Build failed"
        return 1
    }
    echo "  Build successful"
}

restart_nginx() {
    local nginx_bin="$1"
    local config="$2"

    if [ -f "${nginx_bin%/*}/nginx.pid" ]; then
        echo "Reloading nginx..."
        kill -HUP "$(cat ${nginx_bin%/*}/nginx.pid)" 2>/dev/null || true
    fi

    "$nginx_bin" -t -c "$config" 2>&1 | head -3
    echo "  Config test: OK"
}

case "${1:-}" in
    apply)
        if [ $# -lt 2 ]; then
            echo "Usage: $0 apply <nginx_src> [patch_file]"
            exit 1
        fi
        nginx_src="$2"
        patch_file="${3:-$PROJECT_DIR/patches/0001-fix-is_args.patch}"
        apply_patch "$nginx_src" "$patch_file"
        ;;
    rebuild)
        if [ $# -lt 2 ]; then
            echo "Usage: $0 rebuild <nginx_src>"
            exit 1
        fi
        rebuild_nginx "$2"
        ;;
    restart)
        if [ $# -lt 2 ]; then
            echo "Usage: $0 restart <nginx_binary> [config_path]"
            exit 1
        fi
        restart_nginx "$2" "${3:-/etc/nginx/nginx.conf}"
        ;;
    verify)
        if [ $# -lt 2 ]; then
            echo "Usage: $0 verify <nginx_binary>"
            exit 1
        fi
        binary="$2"
        if strings "$binary" | grep -q "nginx"; then
            $binary -V 2>&1 | head -1
            echo "  Binary exists and runs"
        fi
        ;;
    rollback)
        if [ $# -lt 2 ]; then
            echo "Usage: $0 rollback <nginx_src>"
            exit 1
        fi
        if [ -f "$2/src/http/ngx_http_script.c.bak" ]; then
            cp "$2/src/http/ngx_http_script.c.bak" \
               "$2/src/http/ngx_http_script.c"
            echo "Rolled back ngx_http_script.c"
        else
            echo "No backup found"
        fi
        ;;
    *)
        echo "Usage: $0 {apply|rebuild|restart|verify|rollback}"
        exit 1
        ;;
esac
