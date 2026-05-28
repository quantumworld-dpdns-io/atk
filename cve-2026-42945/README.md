# CVE-2026-42945 — NGINX Rift

**Heap Buffer Overflow in NGINX ngx_http_rewrite_module**

CVSS v4.0: 9.2 (Critical) | CWE-122
Introduced: 2008 (v0.6.27) | Fixed: 2026-05-13 (v1.30.1, v1.31.0)

## Vulnerability Summary

An unauthenticated, remote attacker can trigger a deterministic heap buffer
overflow in NGINX worker processes by sending a crafted HTTP request to a
server with a specific `rewrite` + `set` configuration pattern.

**Trigger pattern:**
```nginx
location ~ ^/api/(.*)$ {
    rewrite ^/api/(.*)$ /internal?migrated=true;
    set $original_endpoint $1;
}
```

## Root Cause

In `src/http/ngx_http_script.c`, the script engine uses a two-pass process:
1. **Length pass** — compute required buffer size
2. **Copy pass** — write data into allocated buffer

When a `rewrite` replacement contains `?`, `ngx_http_script_start_args_code`
sets `e->is_args = 1`. This flag is **never cleared**. When a subsequent
`set`/`if`/`rewrite` directive references an unnamed PCRE capture (`$1`),
the length pass runs on a freshly-zeroed sub-engine (`le.is_args = 0`), so
it returns the raw capture length. The copy pass runs on the main engine
(`e->is_args = 1`), which calls `ngx_escape_uri` with `NGX_ESCAPE_ARGS`,
expanding `+`, `%`, `&` from 1 byte to 3 bytes — overflowing the heap
buffer sized for the raw length.

## Project Structure

```
env/               — Docker environment (Dockerfile, nginx.conf, entrypoint, backend)
scripts/           — Trigger, exploit, detection, utility scripts
patches/           — Fix patches and backports
test/              — Test suite (regression, unit, integration)
configs/           — Vulnerable and safe nginx config examples
monitoring/        — WAF rules, SIEM detections, Falco/Suricata rules
fuzz/              — Fuzzing harness and corpus
ci/                — CI configuration for various platforms
docs/              — Technical writeup and analysis
exploit/           — Standalone exploit modules
```

## Build & Run (Vulnerable)

```bash
# Build and start vulnerable nginx
cd env && docker compose up

# Verify worker is alive
curl http://localhost:19321/

# Trigger the overflow
python3 ../scripts/trigger.py --host localhost --port 19321 --plus-count 969

# Run full RCE exploit (ASLR disabled)
python3 ../scripts/exploit.py --host localhost --port 19321 --cmd "whoami > /tmp/pwned"
```

## Fix

A one-line fix in `src/http/ngx_http_script.c`:
```c
e->is_args = 0;  // reset is_args flag after regex evaluation
```

## Affected Versions

| Product | Affected | Fixed |
|---------|----------|-------|
| NGINX OSS | 0.6.27 – 1.30.0 | 1.30.1, 1.31.0 |
| NGINX Plus | R32 – R36 | R36 P4, R32 P6 |

## References

- https://nvd.nist.gov/vuln/detail/CVE-2026-42945
- https://depthfirst.com/research/nginx-rift-achieving-nginx-rce-via-an-18-year-old-vulnerability
- https://github.com/DepthFirstDisclosures/Nginx-Rift
- https://github.com/nginx/nginx/commit/524977e7c534e87e5b55739fa74601c9f1102686
- https://my.f5.com/manage/s/article/K000161019
