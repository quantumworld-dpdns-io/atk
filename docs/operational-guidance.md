# CVE-2026-42945 — Operational Guidance

## Incident Response Checklist

### Triage (First 15 Minutes)

- [ ] Confirm nginx version: `nginx -v`
- [ ] Check configs: `python3 scripts/config_scanner.py /etc/nginx/`
- [ ] Check logs for crashes: `python3 scripts/log_parser.py /var/log/nginx/error.log`
- [ ] Check ASLR status: `cat /proc/sys/kernel/randomize_va_space`

### Containment (First Hour)

- [ ] Deploy WAF rules: `cp monitoring/* /etc/modsecurity/rules/`
- [ ] Apply config workaround (named captures)
- [ ] Rate-limit rewrite-heavy endpoints
- [ ] Block URIs with 100+ consecutive `+` characters

### Remediation (First 4 Hours)

- [ ] Upgrade nginx to 1.30.1+
- [ ] Or apply patch: `./scripts/apply_fix.sh apply /path/to/nginx-src`
- [ ] Test fix: `python3 scripts/trigger.py --plus-count 969`
- [ ] Verify all instances are patched
- [ ] Scan container images: `python3 scripts/container_scan.py`

### Recovery (First 24 Hours)

- [ ] Monitor for worker crashes
- [ ] Rotate credentials on potentially compromised systems
- [ ] Review access logs for exploit attempts
- [ ] Update incident documentation

## Communication Template

```
Subject: CVE-2026-42945 (NGINX Rift) — [STATUS]

Affected systems: [list]
Patched systems: [list]
Vulnerable configs found: [yes/no]
Exploitation detected: [yes/no]
Containment status: [in progress / complete]

Next steps:
1. [action]
2. [action]

Next update: [time]
```

## Post-Incident Review Template

- What was the initial detection method?
- How many systems were affected?
- How quickly was containment achieved?
- Were there any signs of pre-existing exploitation?
- What would improve detection next time?
- What would improve response speed?
- Are there compensating controls to add?
