#!/usr/bin/env python3
import argparse
import re
import subprocess
import sys


def parse_maps(pid):
    out = subprocess.check_output(['cat', f'/proc/{pid}/maps']).decode()
    regions = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        addr_range, perms = parts[0], parts[1]
        start, end = addr_range.split('-')
        start, end = int(start, 16), int(end, 16)
        regions.append({
            'start': start,
            'end': end,
            'size': end - start,
            'perms': perms,
            'path': ' '.join(parts[2:]) if len(parts) > 5 else '',
        })
    return regions


def find_nginx_pids():
    out = subprocess.check_output(['pgrep', '-x', 'nginx']).decode().strip()
    if not out:
        return []
    return [int(p) for p in out.splitlines()]


def main():
    parser = argparse.ArgumentParser(description="Analyze NGINX heap layout")
    parser.add_argument('--pid', type=int, help='Worker PID (auto-detect if omitted)')
    parser.add_argument('--heap-base', action='store_true', help='Show likely heap base')
    args = parser.parse_args()

    pids = find_nginx_pids() if not args.pid else [args.pid]
    if not pids:
        print("No nginx processes found")
        return 1

    pid = pids[-1]
    regions = parse_maps(pid)

    print(f"=== Memory Map for PID {pid} ===\n")

    heap_regions = [r for r in regions if '[heap]' in r['path']]
    libc_regions = [r for r in regions if 'libc' in r['path'] and 'r-xp' in r['perms']]
    stack_regions = [r for r in regions if '[stack]' in r['path']]

    print("--- Heap ---")
    for r in heap_regions:
        print(f"  {r['start']:#018x} - {r['end']:#018x}  ({r['size']:#x} bytes)")

    print("\n--- libc (text) ---")
    for r in libc_regions:
        print(f"  {r['start']:#018x} - {r['end']:#018x}  ({r['size']:#x} bytes)")
        print(f"    system offset (approx): {r['start'] + 0x50d70:#x}")

    print("\n--- Stack ---")
    for r in stack_regions:
        print(f"  {r['start']:#018x} - {r['end']:#018x}")

    if heap_regions:
        hb = heap_regions[0]['start']
        print(f"\nHeap base candidates for HEAP_BASE constant:")
        print(f"  HEAP_BASE = 0x{hb:x}")
        for i in range(0, 8 * 1024 * 1024, 4096):
            if hb + i != heap_regions[0]['start']:
                pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
