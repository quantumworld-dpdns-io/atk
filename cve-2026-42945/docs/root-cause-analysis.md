# CVE-2026-42945 — Root Cause Analysis

## The Bug

A heap buffer overflow in `ngx_http_rewrite_module` caused by a state mismatch
between the two-pass script engine.

### Two-Pass Design

NGINX's script engine evaluates directives like `rewrite` and `set` in two passes:

1. **Length pass** — computes total buffer size needed for the result
2. **Copy pass** — writes the actual data into the allocated buffer

These passes use separate engine instances. The length pass uses a freshly
zeroed sub-engine (`le`), while the copy pass uses the main engine (`e`).

### The Mismatch

When a `rewrite` directive has a `?` in its replacement string:

```nginx
rewrite ^/api/(.*)$ /internal?migrated=true;
```

`ngx_http_script_start_args_code()` sets `e->is_args = 1` on the main engine.
This flag is **never cleared** after the rewrite completes.

When a subsequent `set`, `if`, or `rewrite` directive references the capture:

```nginx
set $original_endpoint $1;
```

The length pass (`ngx_http_script_complex_value_code`) creates a zeroed
sub-engine via `ngx_memzero(&le, sizeof(le))`, so `le.is_args = 0`.
`ngx_http_script_copy_capture_len_code` sees `is_args = 0` and returns
the **raw** capture length.

The copy pass runs on the main engine where `e->is_args = 1`.
`ngx_http_script_copy_capture_code` sees `is_args = 1` and calls
`ngx_escape_uri(pos, ..., NGX_ESCAPE_ARGS)`, which expands each
escapable character (`+`, `%`, `&`) from 1 byte to 3 bytes.

### Result

The destination buffer was allocated for `raw_length` bytes, but the
copy phase writes `raw_length + 2*N` bytes (where N is escapable chars).
This overflows the heap buffer with attacker-controlled data.

## The Fix

One line in `src/http/ngx_http_script.c`:

```c
void
ngx_http_script_regex_end_code(ngx_http_script_engine_t *e)
{
    ...
    r = e->request;

    e->is_args = 0;   // <-- ADD THIS LINE
    e->quote = 0;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http script regex end");
    ...
}
```

Resetting `is_args` at the end of regex evaluation ensures the flag
doesn't leak into subsequent directive evaluations.

## Timeline

| Date | Event |
|------|-------|
| 2008 | Bug introduced (nginx 0.6.27) |
| Apr 18, 2026 | depthfirst system autonomously discovers the bug |
| Apr 21, 2026 | Reported to NGINX via GitHub security advisory |
| Apr 24, 2026 | NGINX confirms the vulnerability |
| May 5, 2026 | RCE PoC shared with NGINX |
| May 13, 2026 | F5 releases advisory and patches (1.30.1, 1.31.0) |
| May 13, 2026 | Public disclosure |

## Affected Code Path

```
ngx_http_script_start_args_code()
  └─ e->is_args = 1;          ← SET (never cleared)

ngx_http_script_complex_value_code()
  ├─ ngx_memzero(&le, ...)    ← sub-engine, is_args=0
  ├─ le.ip = code->lengths
  └─ ngx_http_script_copy_capture_len_code()
       └─ is_args=0 → raw length  ← PASS 1: LENGTH

ngx_http_script_copy_capture_code()
  └─ is_args=1 → escaped      ← PASS 2: COPY (OVERFLOW!)
```
