#!/usr/bin/env python3
import argparse


NGX_ESCAPE_ARGS = 1


def ngx_escape_uri(src, size):
    """
    Simulate the NGX_ESCAPE_ARGS logic.
    Returns the number of bytes the escaped string will occupy.
    """
    dst_len = 0
    for i in range(size):
        ch = src[i]
        if ch == ord('%'):
            dst_len += 3  # % -> %25
        elif ch == ord('+'):
            dst_len += 3  # + -> %2B
        elif ch == ord('&'):
            dst_len += 3  # & -> %26
        elif ch == ord('?'):
            dst_len += 3  # ? -> %3F
        elif ch == ord('#'):
            dst_len += 3  # # -> %23
        elif ch < 32 or ch > 126:
            dst_len += 3  # non-printable -> %XX
        else:
            dst_len += 1  # safe character, no escaping
    return dst_len


def main():
    parser = argparse.ArgumentParser(
        description="Compare raw vs escaped capture lengths"
    )
    parser.add_argument("--string", help="Input string to analyze")
    parser.add_argument("--input-file", help="File containing input string")
    args = parser.parse_args()

    if args.input_file:
        with open(args.input_file, 'rb') as f:
            data = f.read().strip()
    elif args.string:
        data = args.string.encode('latin-1')
    else:
        data = b""
        print("No input provided, using example:")
        print("  Captured: /api/users/123+admin?page=1&filter=test")
        print()
        data = b"/api/users/123+admin?page=1&filter=test"

    raw_len = len(data)
    escaped_len = ngx_escape_uri(data, raw_len)
    diff = escaped_len - raw_len

    print(f"Raw bytes:     {data}")
    print(f"Raw length:    {raw_len}")
    print(f"Escaped length: {escaped_len}")
    print(f"Difference:    {diff}")
    print()

    escapable = sum(1 for b in data if b in (ord('+'), ord('%'), ord('&'), ord('?'), ord('#')))
    print(f"Escapable chars: {escapable}")
    print(f"Expected overhead: {escapable * 2} "
          f"(each escapable char goes from 1 to 3 bytes = +2)")

    if diff > 0:
        print(f"\n*** POTENTIAL OVERFLOW: buffer sized for {raw_len} but "
              f"writes {escaped_len} bytes (overflow by {diff}) ***")
    else:
        print("\nNo overflow risk (no escapable characters)")


if __name__ == "__main__":
    sys.exit(main())
