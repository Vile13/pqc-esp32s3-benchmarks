#!/usr/bin/env python3
"""
Pin the server's ML-KEM public key into the firmware.

Creates the server's long-term key pair on the Raspberry Pi if it does not exist
yet, fetches the *public* half, and writes it as a C header for the client.

The private key is generated on the Pi and never leaves it. This script only
ever reads the public key.

Usage:
    python3 tools/pin_server_key.py --host volker@192.168.188.53
    python3 tools/pin_server_key.py --host ... --level 512
"""

import argparse
import base64
import hashlib
import subprocess
import sys
from pathlib import Path

RAW_PUBKEY_BYTES = {512: 800, 768: 1184, 1024: 1568}

REMOTE_DIR = "~/pqc-server"


def ssh(host: str, script: str, key: Path | None) -> str:
    cmd = ["ssh", "-o", "BatchMode=yes"]
    if key:
        cmd += ["-i", str(key)]
    cmd += [host, "bash -s"]
    result = subprocess.run(
        cmd, input=script, capture_output=True, text=True, timeout=120
    )
    if result.returncode != 0:
        sys.exit(f"ssh failed:\n{result.stderr.strip()}")
    return result.stdout


def parse_spki(der: bytes, expected_len: int) -> bytes:
    """
    Pull the raw public key out of a SubjectPublicKeyInfo structure.

    SPKI is SEQUENCE { AlgorithmIdentifier, BIT STRING }. Rather than assuming a
    fixed header length, walk the DER: the raw key is the BIT STRING contents
    after its leading 'unused bits' byte. The expected length is then asserted,
    so a wrong parameter set fails here instead of producing a firmware that
    silently encapsulates to garbage.
    """

    def read_len(buf: bytes, i: int) -> tuple[int, int]:
        n = buf[i]
        i += 1
        if n < 0x80:
            return n, i
        count = n & 0x7F
        return int.from_bytes(buf[i : i + count], "big"), i + count

    i = 0
    if der[i] != 0x30:
        sys.exit("not a DER SEQUENCE - unexpected public key format")
    _, i = read_len(der, i + 1)

    # Skip the AlgorithmIdentifier SEQUENCE.
    if der[i] != 0x30:
        sys.exit("expected AlgorithmIdentifier SEQUENCE")
    alg_len, i = read_len(der, i + 1)
    i += alg_len

    if der[i] != 0x03:
        sys.exit("expected BIT STRING holding the public key")
    bits_len, i = read_len(der, i + 1)
    unused = der[i]
    if unused != 0:
        sys.exit(f"BIT STRING has {unused} unused bits, expected 0")

    raw = der[i + 1 : i + bits_len]
    if len(raw) != expected_len:
        sys.exit(
            f"public key is {len(raw)} bytes, expected {expected_len} - "
            "wrong ML-KEM parameter set?"
        )
    return raw


def c_array(raw: bytes) -> str:
    lines = []
    for i in range(0, len(raw), 12):
        lines.append("    " + " ".join(f"0x{b:02x}," for b in raw[i : i + 12]))
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True, help="user@host of the Pi")
    ap.add_argument("--key", type=Path, default=Path.home() / ".ssh/id_ed25519")
    ap.add_argument("--level", type=int, default=768, choices=(512, 768, 1024))
    ap.add_argument(
        "--out",
        type=Path,
        default=Path("firmware/esp32s3-dut/main/server_key.h"),
    )
    args = ap.parse_args()

    expected = RAW_PUBKEY_BYTES[args.level]

    remote = f"""
set -e
umask 077
mkdir -p {REMOTE_DIR}
cd {REMOTE_DIR}
if [ ! -f server_dk.pem ]; then
    openssl genpkey -algorithm ML-KEM-{args.level} -out server_dk.pem 2>/dev/null
    chmod 600 server_dk.pem
    echo "GENERATED" >&2
else
    echo "EXISTING" >&2
fi
openssl pkey -in server_dk.pem -pubout -outform DER | base64 -w0
"""
    der = base64.b64decode(ssh(args.host, remote, args.key).strip())
    raw = parse_spki(der, expected)

    key_id = hashlib.sha256(raw).digest()[:4]
    fingerprint = hashlib.sha256(raw).hexdigest()

    header = f"""/*
 * Pinned ML-KEM-{args.level} public key of the reference server.
 *
 * GENERATED FILE - do not edit. Regenerate with:
 *   python3 tools/pin_server_key.py --host {args.host} --level {args.level}
 *
 * This key is public, not secret. It is gitignored anyway because it binds the
 * firmware to one specific server instance, which is deployment state rather
 * than source.
 *
 * Pinning is what authenticates the server: there is no certificate chain and
 * none is needed. The consequence is that replacing the server's key pair means
 * reflashing every client, which is why server_key_id exists - see
 * docs/protocol.md.
 *
 * SHA-256 of the raw public key:
 *   {fingerprint}
 */

#ifndef SERVER_KEY_H
#define SERVER_KEY_H

#include <stdint.h>

#define SERVER_KEY_LEVEL {args.level}
#define SERVER_KEY_BYTES {expected}

static const uint8_t SERVER_KEY_ID[4] = {{
    {" ".join(f"0x{b:02x}," for b in key_id)}
}};

static const uint8_t SERVER_PUBLIC_KEY[SERVER_KEY_BYTES] = {{
{c_array(raw)}
}};

#endif /* SERVER_KEY_H */
"""

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(header)

    print(f"wrote {args.out}")
    print(f"  ML-KEM-{args.level}, {expected} bytes")
    print(f"  server_key_id : {key_id.hex()}")
    print(f"  sha256(ek_S)  : {fingerprint}")
    print(f"  private key stays on the Pi at {REMOTE_DIR}/server_dk.pem")
    return 0


if __name__ == "__main__":
    sys.exit(main())
