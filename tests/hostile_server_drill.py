#!/usr/bin/env python3
"""
Point the real firmware at a deliberately misbehaving server and check that it
refuses to proceed.

The rejection tests in server/test_client.py cover a hostile client against the
real server. This covers the other direction, which is the one that matters in
the field: a device that believes whatever answers on port 8443 will complete a
handshake with an attacker and then encrypt its data to them. It fails silently
and looks healthy while doing it.

For each mode this script starts server/rogue_server.py on the Pi in place of the
real server, resets the board so the firmware runs again, captures the serial
output, and requires that the session did NOT complete.

    python3 tests/hostile_server_drill.py --pi volker@192.168.188.53

Requires pyserial; run it with the ESP-IDF Python environment.
"""

from __future__ import annotations

import argparse
import glob
import subprocess
import sys
import time
from pathlib import Path

import serial

MODES = [
    ("wrong-mac", "ServerHello with one MAC bit flipped"),
    ("impostor", "man in the middle with an unpinned ML-KEM key"),
    ("replay", "ServerHello recorded from an earlier session"),
    ("bad-type", "unknown frame type instead of ServerHello"),
    ("bad-length", "ServerHello one byte short"),
    ("truncate", "announced 72 bytes, sent 30, closed"),
    ("silence", "accepted the connection and never answered"),
]

REMOTE_DIR = "~/pqc-server"


def ssh(host: str, key: Path, command: str, timeout: int = 30) -> str:
    result = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-i", str(key), host, command],
        capture_output=True, text=True, timeout=timeout,
    )
    return result.stdout


def stop_servers(host: str, key: Path) -> None:
    # The bracket keeps the pattern from matching this very ssh command line,
    # which otherwise kills the shell running it and produces no output at all.
    ssh(host, key, 'pkill -f "[p]qc_server.py"; pkill -f "[r]ogue_server.py"; sleep 1')


def start_rogue(host: str, key: Path, mode: str) -> None:
    cmd = (f"cd {REMOTE_DIR} && setsid python3 -u rogue_server.py --mode {mode} "
           f"--connections 1 </dev/null >rogue.log 2>&1 &")
    try:
        subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-i", str(key), host, cmd],
            capture_output=True, text=True, timeout=8,
        )
    except subprocess.TimeoutExpired:
        # ssh keeps the channel open for the detached child; the server is up.
        pass
    time.sleep(2)


def start_real(host: str, key: Path) -> None:
    cmd = (f"cd {REMOTE_DIR} && setsid python3 -u pqc_server.py --host 0.0.0.0 "
           f"--port 8443 </dev/null >live.log 2>&1 &")
    try:
        subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-i", str(key), host, cmd],
            capture_output=True, text=True, timeout=8,
        )
    except subprocess.TimeoutExpired:
        pass
    time.sleep(2)


def reset_and_capture(port: str, seconds: float) -> str:
    """Reset the board over DTR/RTS and collect its output."""
    with serial.Serial(port, 115200, timeout=0.2) as ser:
        ser.setDTR(False)
        ser.setRTS(True)
        time.sleep(0.1)
        ser.setRTS(False)
        time.sleep(0.05)
        ser.reset_input_buffer()

        end = time.time() + seconds
        buf = b""
        while time.time() < end:
            buf += ser.read(4096)
            if b"session completed" in buf or b"session failed" in buf:
                break
    return buf.decode("utf-8", "replace")


def evaluate(output: str) -> tuple[bool, str]:
    """A pass means the firmware refused. Silence is not a pass."""
    if "session completed" in output:
        return False, "firmware COMPLETED the session"
    if "session failed" not in output:
        return False, "no verdict on the serial line (hang or crash?)"

    for line in output.splitlines():
        if "pqc:" in line and any(
            w in line for w in ("mismatch", "unexpected", "no ServerHello",
                                "failed", "not the pinned")
        ):
            return True, line.split("pqc:", 1)[1].strip()
    return True, "rejected"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pi", required=True, help="user@host of the Pi")
    ap.add_argument("--key", type=Path, default=Path.home() / ".ssh/id_ed25519")
    ap.add_argument("--serial", default=None, help="serial port of the board")
    ap.add_argument("--capture-seconds", type=float, default=30.0)
    args = ap.parse_args()

    port = args.serial
    if port is None:
        candidates = glob.glob("/dev/cu.usbserial*")
        if not candidates:
            sys.exit("no /dev/cu.usbserial* found - is the board plugged in?")
        port = candidates[0]

    print(f"board on {port}, rogue server on {args.pi}\n")

    results = []
    for mode, description in MODES:
        if mode == "replay":
            # The replay mode needs a ServerHello to replay. Its first
            # connection serves correctly and records one; only the second
            # actually replays. Priming here rather than counting the recording
            # round as a result - that round is supposed to succeed.
            ssh(args.pi, args.key, f"rm -f {REMOTE_DIR}/.replay_capture.bin")
            stop_servers(args.pi, args.key)
            start_rogue(args.pi, args.key, mode)
            reset_and_capture(port, args.capture_seconds)

        stop_servers(args.pi, args.key)
        start_rogue(args.pi, args.key, mode)

        output = reset_and_capture(port, args.capture_seconds)
        ok, detail = evaluate(output)
        results.append((mode, ok))

        mark = "ok  " if ok else "FAIL"
        print(f"  {mark}  {mode:<11} {description}")
        print(f"        firmware: {detail}")

    stop_servers(args.pi, args.key)
    start_real(args.pi, args.key)
    print("\nreal server restarted")

    passed = sum(1 for _, ok in results if ok)
    print(f"\n{passed}/{len(results)} rejection paths hold")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
