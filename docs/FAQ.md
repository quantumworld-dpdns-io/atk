# CVE-2026-42945 — FAQ

## General

### What is CVE-2026-42945?
A critical (CVSS 9.2) heap buffer overflow in NGINX's `ngx_http_rewrite_module`
that allows unauthenticated remote code execution.

### What versions are affected?
NGINX Open Source 0.6.27 through 1.30.0 (introduced in 2008).

### What versions are fixed?
NGINX Open Source 1.30.1 and 1.31.0.

### Is this being exploited in the wild?
Yes. VulnCheck reported active exploitation starting May 16, 2026.

## Technical

### Do I need ASLR disabled to be exploited?
For RCE, yes — or the attacker must bypass ASLR. For DoS (worker crash),
no — a single request crashes the worker regardless of ASLR.

### What configuration is required?
A `rewrite` directive with `?` in the replacement, followed by `set`,
`if`, or `rewrite` that references an unnamed PCRE capture (`$1`, `$2`).

### Can I just use named captures to fix it?
Yes. Named captures (e.g., `(?<name>...)`) are not affected because they
are not processed through the `ngx_http_script_copy_capture_code` path.

### Is HTTP/2 affected?
Yes. The vulnerability is in the HTTP processing layer, not specific to
HTTP version.

### Is HTTPS required?
No. The bug works over both HTTP and HTTPS.

## Mitigation

### Can I fix it without upgrading?
Yes. Replace unnamed captures with named captures, or reorder directives
to avoid the vulnerable pattern. See `docs/mitigation-guide.md`.

### Does the fix affect performance?
No measurable impact.

### How do I verify the fix?
```bash
python3 scripts/trigger.py --plus-count 969
python3 scripts/trigger.py --check-alive
```

### What about Ingress NGINX Controller?
Affected versions: 3.5.0–3.7.2, 4.0.0–4.0.1, 5.0.0–5.4.1.
Upgrade to a patched version or use the config workaround.

## Detection

### How do I know if I'm vulnerable?
1. Check nginx version
2. Scan configs for vulnerable patterns
3. Use `scripts/detect_vuln.sh`

### What should I look for in logs?
- Worker process exited on signal 11 (SIGSEGV)
- URIs with excessive `+` characters
- Rapid worker restarts

## Disclosure

### Who discovered this?
The depthfirst platform autonomously discovered the vulnerability in April
2026 during automated source code analysis of NGINX.

### Was this responsibly disclosed?
Yes. Reported to NGINX on April 21, 2026. Patches released May 13, 2026.

### Are there related CVEs?
Yes. CVE-2026-42946, CVE-2026-40701, and CVE-2026-42934 were disclosed
at the same time.
