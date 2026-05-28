#!/usr/bin/env python3
import argparse
import re
import sys


CRASH_PATTERNS = [
    re.compile(r'signal\s+\d+\s+\(SIGSEGV\)', re.I),
    re.compile(r'worker process \d+ exited on signal', re.I),
    re.compile(r'heap-buffer-overflow', re.I),
    re.compile(r'AddressSanitizer', re.I),
    re.compile(r'memcpy.*overflow', re.I),
    re.compile(r'stack smashing detected', re.I),
    re.compile(r'corrupted double-linked list', re.I),
    re.compile(r'free\(\): invalid pointer', re.I),
    re.compile(r'malloc\(\): corrupted', re.I),
]

EXPLOIT_PATTERNS = [
    re.compile(r'GET /api/[A-Za-z0-9/%]*\+{50,}', re.I),
    re.compile(r'POST /spray.*X-Delay.*60', re.I),
    re.compile(r'(?:%26|%2B|%25){50,}'),
    re.compile(r'Content-Length: 4000'),
]


def parse_log(filepath):
    crashes = []
    exploit_attempts = []
    entries = []

    with open(filepath, 'r') as f:
        for line in f:
            for p in CRASH_PATTERNS:
                if p.search(line):
                    crashes.append(line.strip())
                    break

            for p in EXPLOIT_PATTERNS:
                if p.search(line):
                    exploit_attempts.append(line.strip())
                    break

            entries.append(line.rstrip())

    return {
        'total_lines': len(entries),
        'crashes': crashes,
        'exploit_attempts': exploit_attempts,
    }


def main():
    parser = argparse.ArgumentParser(description="Parse NGINX error logs for CVE-2026-42945")
    parser.add_argument('logfile', help='NGINX error log path')
    parser.add_argument('--watch', action='store_true',
                        help='Watch file for new entries')
    args = parser.parse_args()

    result = parse_log(args.logfile)
    print(f"Total log entries: {result['total_lines']}")
    print(f"Crashes detected: {len(result['crashes'])}")
    print(f"Exploit attempts detected: {len(result['exploit_attempts'])}")

    if result['crashes']:
        print("\n--- Crashes ---")
        for c in result['crashes'][:20]:
            print(f"  {c}")

    if result['exploit_attempts']:
        print("\n--- Exploit Attempts ---")
        for e in result['exploit_attempts'][:20]:
            print(f"  {e}")

    if args.watch:
        import time
        last_size = len(open(args.logfile).read())
        try:
            while True:
                time.sleep(1)
                current = parse_log(args.logfile)
                if len(current['crashes']) > len(result['crashes']):
                    new = current['crashes'][len(result['crashes']):]
                    for c in new:
                        print(f"[NEW CRASH] {c}")
                result = current
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    sys.exit(main())
