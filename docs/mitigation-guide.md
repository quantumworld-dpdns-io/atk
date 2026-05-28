# CVE-2026-42945 — Mitigation Guide

## Priority Actions (in order)

### 1. Upgrade nginx (RECOMMENDED)

Upgrade to the fixed version:

| Product | Fixed Version |
|---------|---------------|
| NGINX Open Source | 1.30.1 or 1.31.0 |
| NGINX Plus R36 | R36 P4 |
| NGINX Plus R32 | R32 P6 |

```bash
# Debian/Ubuntu
apt-get update && apt-get install --only-upgrade nginx

# RHEL/CentOS
yum update nginx

# Alpine
apk upgrade nginx

# From source
# Apply patch and rebuild
./scripts/apply_fix.sh apply /path/to/nginx-src
./scripts/apply_fix.sh rebuild /path/to/nginx-src
./scripts/apply_fix.sh restart /usr/local/sbin/nginx
```

### 2. Config Workaround (if upgrade is not possible)

Replace unnamed captures with named captures:

**Vulnerable:**
```nginx
rewrite ^/users/([0-9]+)/profile/(.*)$ /profile.php?id=$1&tab=$2 last;
```

**Fixed (named captures):**
```nginx
rewrite ^/users/(?<user_id>[0-9]+)/profile/(?<section>.*)$ /profile.php?id=$user_id&tab=$section last;
```

**Alternative: reorder directives to avoid the vulnerable sequence:**
```nginx
set $original_endpoint "";
location ~ ^/api/(.*)$ {
    set $original_endpoint $1;
    rewrite ^/api/(.*)$ /internal?migrated=true;
}
```

### 3. Verify ASLR is Enabled

```bash
cat /proc/sys/kernel/randomize_va_space
# Should return 2 (full randomization)

# Check for nginx processes launched with ASLR disabled
./scripts/check_aslr.sh
```

### 4. Deploy WAF Rules

```bash
# ModSecurity
cp monitoring/modsecurity_rule.conf /etc/modsecurity/rules/

# Suricata
cp monitoring/suricata_rule.rules /etc/suricata/rules/

# Falco
cp monitoring/falco_rule.yaml /etc/falco/rules.yaml
```

### 5. Monitor for Exploitation

```bash
# Real-time log monitoring
python3 scripts/log_parser.py /var/log/nginx/error.log --watch

# Worker crash monitoring
python3 scripts/monitor_worker.py

# Config scanning
python3 scripts/config_scanner.py /etc/nginx/
```

## Verification

### After mitigation, confirm the fix works:

```bash
# 1. Check nginx version
nginx -v

# 2. Test config syntax
nginx -t

# 3. Send exploit URI — should NOT crash
python3 scripts/trigger.py --plus-count 969

# 4. Verify server is still alive
python3 scripts/trigger.py --check-alive
```

## Emergency Response

If active exploitation is suspected:

1. **Immediate**: Block URIs with 100+ `+` characters at the edge WAF/load balancer
2. **Immediate**: Enable rate limiting on all rewrite-heavy endpoints
3. **Within 1 hour**: Upgrade nginx or apply config workaround
4. **Within 4 hours**: Scan all instances for vulnerable configs
5. **Within 24 hours**: Rotate any credentials that may have been exposed
6. **Ongoing**: Monitor logs for worker crashes and exploit attempts

## FAQ

**Q: Does the fix affect performance?**
A: No measurable impact. The one-line fix only resets a flag that should
have been reset already.

**Q: Can the vulnerability be triggered over HTTPS?**
A: Yes. The bug is in HTTP request processing, regardless of TLS.

**Q: What about HTTP/2?**
A: Both h2 and h2c are affected.

**Q: Is Ingress NGINX Controller affected?**
A: Yes, versions 3.5.0–3.7.2, 4.0.0–4.0.1, 5.0.0–5.4.1.
