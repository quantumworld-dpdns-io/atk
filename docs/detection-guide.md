# CVE-2026-42945 — Detection Guide

## Version Detection

### Check installed version

```bash
nginx -v 2>&1
# nginx version: nginx/1.26.0
```

### Vulnerable versions

| Product | Affected | Fixed |
|---------|----------|-------|
| NGINX OSS | 0.6.27–1.30.0 | 1.30.1, 1.31.0 |

### Automated detection

```bash
./scripts/detect_vuln.sh
```

## Config Scanning

### Vulnerable pattern

```nginx
rewrite ^/api/(.*)$ /internal?migrated=true;
set $original_endpoint $1;       # ← must reference unnamed capture
```

### What to look for

1. `rewrite` with `?` in replacement string
2. `rewrite`, `set`, or `if` on the following line
3. Unnamed capture reference (`$1`, `$2`, etc.) in the follow-up

### Automated scan

```bash
# Scan single config file
python3 scripts/config_scanner.py /etc/nginx/nginx.conf

# Scan directory recursively
python3 scripts/config_scanner.py /etc/nginx/

# Show fix suggestions
python3 scripts/config_scanner.py --fix /etc/nginx/nginx.conf
```

## Log Monitoring

### Crash indicators

```
2026/05/28 12:00:01 [alert] 1#0: worker process 42 exited on signal 11 (SIGSEGV)
```

### Exploit attempt indicators

```
GET /api/AAAAA++++++++++++++++++++++++++++++... HTTP/1.1
POST /spray HTTP/1.1 ... X-Delay: 60 ... Content-Length: 4000
```

### Automated log analysis

```bash
python3 scripts/log_parser.py /var/log/nginx/error.log
python3 scripts/log_parser.py /var/log/nginx/error.log --watch
```

## WAF Detection

### ModSecurity

```apache
SecRule REQUEST_URI "@rx \+{100,}" ...
```

Deploy: `cp monitoring/modsecurity_rule.conf /etc/modsecurity/rules/`

### Suricata/Snort

```text
alert http any any -> $HOME_NET $HTTP_PORTS \
    (msg:"CVE-2026-42945"; pcre:"/\+{100,}/U"; sid:10000001;)
```

Deploy: `cp monitoring/suricata_rule.rules /etc/suricata/rules/`

### Falco

```yaml
- rule: NGINX Worker Crash Detected
  condition: proc.name = "nginx" and evt.arg.sig = 11
```

Deploy: `cp monitoring/falco_rule.yaml /etc/falco/rules.yaml`

## Container Scanning

```bash
python3 scripts/container_scan.py
python3 scripts/container_scan.py nginx:latest nginx:1.26-alpine
```

## Network Detection

### What to monitor

1. URIs with 100+ consecutive `+` characters
2. URIs with 50+ encoded escapable characters (`%26`, `%2B`, `%25`)
3. POST to `/spray` with body size ~4000 and `X-Delay: 60`
4. Rapid connection cycling (crash-loop DoS indicator)

### Tools

- WAF (ModSecurity, NAXSI)
- IDS/IPS (Suricata, Snort)
- Runtime security (Falco, Tracee)
- SIEM (Splunk, ELK, Sentinel)
- Network observability (Zeek, Tshark)
