# CVE-2026-42945 — Presentation Slides (Markdown)

## Slide 1: Title
**NGINX Rift: CVE-2026-42945**
An 18-Year-Old Heap Buffer Overflow in NGINX
CVSS 9.2 (Critical) | depthfirst

## Slide 2: TL;DR
- Heap overflow in ngx_http_rewrite_module
- Unauthenticated RCE
- 18 years undetected (2008–2026)
- Affects 0.6.27 through 1.30.0
- One-line fix

## Slide 3: The Vulnerable Pattern
```
rewrite ^/api/(.*)$ /internal?migrated=true;
set $original_endpoint $1;
```

## Slide 4: Root Cause
```
Pass 1 (length):  sub-engine (is_args=0) → raw length
Pass 2 (copy):    main engine (is_args=1) → escaped length
                  → allocating raw, writing escaped → OVERFLOW
```

## Slide 5: Exploitation
- Cross-request heap Feng Shui
- Spray fake pool_cleanup via POST bodies
- Overflow cleanup pointer → system() call
- Worker crash → respawn with identical layout → retry

## Slide 6: Impact
- **DoS**: Single request crashes worker
- **RCE**: With ASLR disabled or bypassed
- **Scope**: 18 years of all nginx versions

## Slide 7: Fix
One line of code:
```c
// In ngx_http_script_regex_end_code():
e->is_args = 0;
```

## Slide 8: Mitigation
1. Upgrade to 1.30.1+
2. Use named captures
3. Enable ASLR
4. Deploy WAF rules

## Slide 9: Detection
- Log: worker SIGSEGV
- Network: URIs with 100+ `+` signs
- Config: rewrite + ? + unnamed capture

## Slide 10: Lessons
- "Stable" code can hide critical bugs for decades
- Config patterns matter for exploitability
- Autonomous discovery is the future
