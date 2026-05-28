# CVE-2026-42945 — Disclosure Timeline

## Discovery & Disclosure

| Date | Event |
|------|-------|
| 2008 | Bug introduced in NGINX 0.6.27 |
| Apr 18, 2026 | depthfirst platform autonomously detects 5 memory corruption issues in NGINX source code during automated scan |
| Apr 21, 2026 | depthfirst reports all 5 issues to NGINX via GitHub Security Advisory |
| Apr 24, 2026 | NGINX confirms 4 of the 5 reported issues |
| Apr 28, 2026 | depthfirst informs NGINX that working RCE PoC has been developed |
| May 5, 2026 | depthfirst shares RCE PoC and demo video with NGINX |
| May 13, 2026 | F5 releases security advisory K000161019 and NGINX patches (1.30.1, 1.31.0) |
| May 13, 2026 | depthfirst publishes technical writeup and PoC |
| May 14, 2026 | CVE-2026-42945 published in NVD |
| May 16, 2026 | VulnCheck reports active in-the-wild exploitation |
| May 17, 2026 | The Hacker News publishes coverage |
| May 18, 2026 | Akamai publishes mitigation guidance |
| May 21, 2026 | F5 updates advisory with expanded affected product list |
| May 28, 2026 | This repository published |

## NVD Timeline

| Date | Event |
|------|-------|
| May 13, 2026 | CVE received from F5 Networks |
| May 13, 2026 | CVSS v4.0 scored 9.2 (Critical) by F5 |
| May 13, 2026 | CVSS v3.1 scored 8.1 (High) by F5 |
| May 13, 2026 | CWE-122 (Heap-based Buffer Overflow) assigned |
| May 14, 2026 | GitHub PoC repository linked |
| May 21, 2026 | Description updated to mention ASLR bypass |

## Patch Release Timeline

| Date | Product | Version |
|------|---------|---------|
| May 13, 2026 | NGINX Open Source | 1.30.1 |
| May 13, 2026 | NGINX Open Source | 1.31.0 |
| May 13, 2026 | NGINX Plus R36 | R36 P4 |
| May 13, 2026 | NGINX Plus R35 | R35 P2 |
| May 13, 2026 | NGINX Plus R32 | R32 P6 |
| May 14, 2026 | Debian Bullseye | 1.18.0-6.1+deb11u6 |
| May 14, 2026 | Debian Bookworm | 1.22.1-9+deb12u7 |
| May 14, 2026 | Debian Trixie | 1.26.3-3+deb13u5 |
| May 14, 2026 | Debian Sid | 1.30.1-2 |
