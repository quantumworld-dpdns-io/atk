#!/usr/bin/env python3
import argparse
import os
import subprocess
import sys


NGINX_TAGS = [
    "release-0.6.27",
    "release-1.0.0",
    "release-1.10.0",
    "release-1.20.0",
    "release-1.22.0",
    "release-1.24.0",
    "release-1.26.0",
    "release-1.30.0",
]

FIX_COMMIT = "524977e7c534e87e5b55739fa74601c9f1102686"


def check_vulnerable(nginx_src, tag):
    try:
        subprocess.run(
            ["git", "-C", nginx_src, "checkout", tag],
            check=True, capture_output=True
        )
    except subprocess.CalledProcessError:
        print(f"  Could not checkout {tag}")
        return None

    result = subprocess.run(
        ["git", "-C", nginx_src, "merge-base", "--is-ancestor", FIX_COMMIT, "HEAD"],
        capture_output=True
    )
    fixed = result.returncode == 0

    script_path = os.path.join(nginx_src, "src/http/ngx_http_script.c")
    if not os.path.exists(script_path):
        print(f"  {script_path} not found")
        return None

    with open(script_path, 'r') as f:
        content = f.read()

    has_bug_pattern = (
        'ngx_http_script_start_args_code' in content and
        'is_args = 1' in content and
        'ngx_http_script_regex_end_code' in content
    )

    has_fix = 'e->is_args = 0' in content

    return {
        'tag': tag,
        'fixed': fixed,
        'has_bug_pattern': has_bug_pattern,
        'has_fix': has_fix,
        'vulnerable': has_bug_pattern and not has_fix,
    }


def main():
    parser = argparse.ArgumentParser(description="Check nginx tags for CVE-2026-42945")
    parser.add_argument("--nginx-src", required=True,
                        help="Path to nginx source checkout")
    parser.add_argument("--all", action="store_true",
                        help="Check all tags, not just major releases")
    args = parser.parse_args()

    nginx_src = os.path.abspath(args.nginx_src)
    if not os.path.exists(os.path.join(nginx_src, "src")):
        print(f"Not a valid nginx source: {nginx_src}")
        return 1

    tags_to_check = NGINX_TAGS
    if args.all:
        result = subprocess.run(
            ["git", "-C", nginx_src, "tag", "--sort=version:refname"],
            capture_output=True, text=True
        )
        tags_to_check = result.stdout.strip().splitlines()

    print(f"Checking {len(tags_to_check)} tags for CVE-2026-42945...\n")

    for tag in tags_to_check:
        info = check_vulnerable(nginx_src, tag)
        if info is None:
            continue

        status = "VULNERABLE" if info['vulnerable'] else "SAFE"
        print(f"  {tag:25s} {status}")

    print("\nDone.")


if __name__ == "__main__":
    sys.exit(main())
