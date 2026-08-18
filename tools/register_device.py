#!/usr/bin/env python3
"""
Register this device's PSK with the reference server.

Reads device_id and PSK out of the gitignored device_config.h and writes them
into the server's device table over SSH.

The PSK is never printed, never passed on a command line (where it would land in
the shell history and in `ps`), and never written to a temporary file. It goes to
the Pi on stdin of a single ssh invocation. Only a short fingerprint is shown, so
both ends can be compared without exposing the value.

    python3 tools/register_device.py --host volker@192.168.188.53
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import re
import subprocess
import sys
from pathlib import Path

# Resolved from this file's location rather than the working directory, so the
# tool works from anywhere instead of only from the repository root.
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = REPO_ROOT / "firmware/esp32s3-dut/main/device_config.h"
REMOTE_TABLE = "~/pqc-server/devices.json"


def extract_bytes(source: str, macro: str, expected: int) -> bytes:
    """Pull a { 0x.., 0x.. } initialiser out of a #define, continuations and all."""
    match = re.search(rf"#define\s+{macro}\s*((?:[^\n\\]*\\\s*\n)*[^\n]*)", source)
    if not match:
        sys.exit(f"{macro} not found in the config header")

    body = match.group(1).replace("\\", " ")
    inner = re.search(r"\{(.*?)\}", body, re.S)
    if not inner:
        sys.exit(f"{macro} has no {{ ... }} initialiser")

    values = [v.strip() for v in inner.group(1).split(",") if v.strip()]
    try:
        raw = bytes(int(v, 0) for v in values)
    except ValueError as exc:
        sys.exit(f"{macro} contains a value that is not a byte literal: {exc}")

    if len(raw) != expected:
        sys.exit(f"{macro} has {len(raw)} bytes, expected {expected}")
    return raw


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True, help="user@host of the Pi")
    ap.add_argument("--key", type=Path, default=Path.home() / ".ssh/id_ed25519")
    ap.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    args = ap.parse_args()

    if not args.config.exists():
        sys.exit(
            f"{args.config} not found. Copy device_config.h.example to "
            "device_config.h and fill it in - see docs/provisioning.md"
        )

    source = args.config.read_text()
    device_id = extract_bytes(source, "DEVICE_ID", 8)
    psk = extract_bytes(source, "DEVICE_PSK", 32)

    if psk == bytes(32):
        sys.exit("DEVICE_PSK is still all zeros - generate a real one first")
    if device_id == bytes(8):
        sys.exit("DEVICE_ID is still all zeros - generate a real one first")

    fingerprint = hashlib.sha256(psk).hexdigest()[:16]

    # The remote program is carried inside the command (base64, so no quoting
    # hazards), which leaves stdin free for the secret. The PSK therefore never
    # appears in argv, in `ps`, or in a shell history on either machine.
    remote_program = f"""
import json, os, sys
from pathlib import Path
path = Path(os.path.expanduser({REMOTE_TABLE!r}))
table = json.loads(path.read_text()) if path.exists() else {{}}
device_id = sys.stdin.readline().strip()
psk = sys.stdin.readline().strip()
action = "updated" if device_id in table else "added"
table[device_id] = psk
path.write_text(json.dumps(table, indent=2) + "\\n")
path.chmod(0o600)
print(f"{{action}} {{device_id}}; table now holds {{len(table)}} device(s)")
"""
    encoded = base64.b64encode(remote_program.encode()).decode()
    remote_cmd = (
        "umask 077; mkdir -p ~/pqc-server; "
        f"python3 -c \"import base64;exec(base64.b64decode('{encoded}'))\""
    )

    proc = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-i", str(args.key), args.host, remote_cmd],
        input=f"{device_id.hex()}\n{psk.hex()}\n",
        capture_output=True, text=True, timeout=60,
    )
    if proc.returncode != 0:
        sys.exit(f"ssh failed:\n{proc.stderr.strip()}")

    print(proc.stdout.strip())
    print(f"  device_id      : {device_id.hex()}")
    print(f"  psk fingerprint: sha256:{fingerprint} (first 8 bytes)")
    print("  the PSK itself was not printed and is not in your shell history")
    return 0


if __name__ == "__main__":
    sys.exit(main())
