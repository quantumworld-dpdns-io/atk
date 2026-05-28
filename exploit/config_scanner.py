#!/usr/bin/env python3
import argparse
import fnmatch
import os
import re
import sys


VULN_PATTERN = re.compile(
    r'(rewrite\s+\S+\s+\S*\?\S*.*?;)'
    r'\s*\n\s*(rewrite|set|if)\s',
    re.MULTILINE
)

UNNAMED_CAPTURE = re.compile(r'(?<!\?P<\w+>)\(\??:')


def scan_config(filepath):
    with open(filepath, 'r') as f:
        content = f.read()

    findings = []

    for m in VULN_PATTERN.finditer(content):
        line_num = content[:m.start()].count('\n') + 1
        rewrite_part = m.group(1)
        followup = m.group(2)

        findings.append({
            'file': filepath,
            'line': line_num,
            'rewrite': rewrite_part.strip(),
            'followup_type': followup,
            'has_named': bool(re.search(r'\?P<\w+>', rewrite_part)),
        })

    return findings


def scan_directory(root):
    findings = []
    for dirpath, dirnames, filenames in os.walk(root):
        for f in filenames:
            if fnmatch.fnmatch(f, '*.conf') or f == 'nginx.conf':
                fp = os.path.join(dirpath, f)
                findings.extend(scan_config(fp))
    return findings


def suggest_fix(finding):
    rewrite = finding['rewrite']
    has_named = finding['has_named']

    if has_named:
        return "Already using named captures. Check if is_args leak still applies."

    return (
        "Replace unnamed captures with named captures:\n"
        "  Vulnerable: rewrite ^/users/([0-9]+)/profile/(.*)$ /profile.php?id=$1&tab=$2 last;\n"
        "  Fixed:      rewrite ^/users/(?<user_id>[0-9]+)/profile/(?<section>.*)$ /profile.php?id=$user_id&tab=$section last;\n"
        "Or reorder directives to avoid rewrite+? followed by set/if/rewrite."
    )


def main():
    parser = argparse.ArgumentParser(description="Scan nginx configs for CVE-2026-42945")
    parser.add_argument('paths', nargs='+', help='Config files or directories to scan')
    parser.add_argument('--fix', action='store_true', help='Show fix suggestions')
    args = parser.parse_args()

    findings = []
    for path in args.paths:
        if os.path.isfile(path):
            findings.extend(scan_config(path))
        elif os.path.isdir(path):
            findings.extend(scan_directory(path))

    if not findings:
        print("No vulnerable patterns found.")
        return 0

    print(f"Found {len(findings)} vulnerable pattern(s):\n")
    for f in findings:
        print(f"  File: {f['file']}:{f['line']}")
        print(f"  Rewrite: {f['rewrite']}")
        print(f"  Followed-by: {f['followup_type']}")
        if args.fix:
            print(f"  Suggestion: {suggest_fix(f)}")
        print()
    return 1


if __name__ == "__main__":
    sys.exit(main())
