#!/usr/bin/env python3
import argparse
import sys


def calc_overflow(prefix_len, plus_count, suffix_bytes=0):
    raw_len = prefix_len + plus_count + suffix_bytes
    escaped_len = prefix_len + (plus_count * 3) + suffix_bytes
    overflow = escaped_len - raw_len
    return {
        'prefix_len': prefix_len,
        'plus_count': plus_count,
        'suffix_bytes': suffix_bytes,
        'raw_length': raw_len,
        'escaped_length': escaped_len,
        'overflow_bytes': overflow,
        'expansion_ratio': escaped_len / raw_len if raw_len else 0,
    }


def find_min_overflow(target_overflow=64, prefix=349):
    for n in range(1, 2000):
        r = calc_overflow(prefix, n)
        if r['overflow_bytes'] >= target_overflow:
            return r
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Calculate overflow sizes for CVE-2026-42945"
    )
    parser.add_argument("--prefix", type=int, default=349)
    parser.add_argument("--plus", type=int, default=969)
    parser.add_argument("--find-min", type=int,
                        help="Find minimum plus count for target overflow")
    args = parser.parse_args()

    if args.find_min:
        r = find_min_overflow(args.find_min, args.prefix)
        if r:
            print(f"To overflow by {args.find_min} bytes:")
            print(f"  Prefix: {r['prefix_len']}")
            print(f"  Plus:   {r['plus_count']}")
            print(f"  Raw:    {r['raw_length']}")
            print(f"  Escaped: {r['escaped_length']}")
            print(f"  Overflow: {r['overflow_bytes']}")
        else:
            print("Not achievable in range")
        return

    r = calc_overflow(args.prefix, args.plus)
    print(f"Overflow calculation:")
    print(f"  Prefix:  {r['prefix_len']}")
    print(f"  Plus:    {r['plus_count']}")
    print(f"  Raw:     {r['raw_length']}")
    print(f"  Escaped: {r['escaped_length']}")
    print(f"  Overflow: {r['overflow_bytes']}")
    print(f"  Ratio:   {r['expansion_ratio']:.2f}x")


if __name__ == "__main__":
    sys.exit(main())
