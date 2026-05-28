#!/usr/bin/env python3
import argparse
import os
import signal
import subprocess
import sys
import time


def find_worker_pids():
    out = subprocess.check_output(['pgrep', '-x', 'nginx']).decode().strip()
    if not out:
        return []
    return [int(p) for p in out.splitlines() if p != str(os.getpid())]


def monitor_workers(host, port, interval=1):
    initial = find_worker_pids()
    if not initial:
        print("No nginx workers found")
        return

    print(f"Monitoring {len(initial)} worker(s): {initial}")
    print(f"Sending healthcheck to {host}:{port} every {interval}s\n")

    import socket

    baseline = set(initial)
    crash_count = 0

    try:
        while True:
            current = set(find_worker_pids())
            new_workers = current - baseline
            dead_workers = baseline - current

            if dead_workers:
                crash_count += len(dead_workers)
                ts = time.strftime("%H:%M:%S")
                print(f"[{ts}] WORKERS CRASHED: {dead_workers}")
                print(f"[{ts}] New workers spawned: {new_workers}")
                print(f"[{ts}] Total crashes: {crash_count}")
                baseline = current

            alive = False
            try:
                s = socket.create_connection((host, port), timeout=2)
                s.sendall(b"GET / HTTP/1.1\r\nHost: l\r\nConnection:close\r\n\r\n")
                s.recv(50)
                s.close()
                alive = True
            except Exception:
                pass

            status = "ALIVE" if alive else "DEAD"
            print(f"  [{time.strftime('%H:%M:%S')}] Workers: {len(baseline)} "
                  f"Crash count: {crash_count} Status: {status}")

            time.sleep(interval)

    except KeyboardInterrupt:
        print(f"\nMonitoring stopped. Total crashes observed: {crash_count}")


def main():
    parser = argparse.ArgumentParser(description="Monitor NGINX worker health")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=19321)
    parser.add_argument("--interval", type=float, default=1.0,
                        help="check interval in seconds")
    args = parser.parse_args()

    monitor_workers(args.host, args.port, args.interval)


if __name__ == "__main__":
    sys.exit(main())
