#!/usr/bin/env python3
"""
PQC-IoT-1 reference server.

Terminates the handshake from docs/protocol.md (mode A) and prints the decrypted
sensor records. Intended to run on the Raspberry Pi.

ML-KEM decapsulation is delegated to OpenSSL 3.5, which implements FIPS 203
natively. That is deliberate: OpenSSL's implementation shares no code with the
firmware's mlkem-native, so when the two interoperate it is evidence rather than
a mirror of one implementation against itself.

Everything else - HKDF, HMAC, AES-256-GCM - comes from Python's stdlib and
`cryptography`.

    python3 pqc_server.py --key ~/pqc-server/server_dk.pem \
                          --devices ~/pqc-server/devices.json
"""

from __future__ import annotations

import argparse
import hmac
import json
import logging
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import protocol as p

log = logging.getLogger("pqc-server")


class DeviceTable:
    """device_id -> PSK, loaded from a 0600 JSON file."""

    def __init__(self, path: Path):
        self.path = path
        if not path.exists():
            raise SystemExit(
                f"device table {path} not found - register a device first "
                "(tools/register_device.py)"
            )
        mode = path.stat().st_mode & 0o777
        if mode & 0o077:
            raise SystemExit(
                f"device table {path} has mode {mode:o}; it holds PSKs and must "
                "be 0600"
            )
        raw = json.loads(path.read_text())
        self._psks = {
            bytes.fromhex(k): bytes.fromhex(v) for k, v in raw.items()
        }
        for did, psk in self._psks.items():
            if len(did) != p.DEVICE_ID_LEN or len(psk) != p.PSK_LEN:
                raise SystemExit(f"malformed entry for device {did.hex()}")
        log.info("loaded %d device(s)", len(self._psks))

    def psk_for(self, device_id: bytes) -> bytes | None:
        return self._psks.get(device_id)


class MlKemPrivateKey:
    """ML-KEM decapsulation via the OpenSSL command line."""

    def __init__(self, pem_path: Path):
        self.pem = pem_path
        if not pem_path.exists():
            raise SystemExit(f"server key {pem_path} not found")

        out = subprocess.run(
            ["openssl", "pkey", "-in", str(pem_path), "-noout", "-text"],
            capture_output=True, text=True,
        )
        if out.returncode != 0:
            raise SystemExit(f"cannot read {pem_path}: {out.stderr.strip()}")
        self.description = out.stdout.splitlines()[0] if out.stdout else "ML-KEM"

        # Cache the raw public key so server_key_id can be checked against what
        # the client says it encapsulated to.
        der = subprocess.run(
            ["openssl", "pkey", "-in", str(pem_path), "-pubout", "-outform", "DER"],
            capture_output=True, check=True,
        ).stdout
        import hashlib
        # The raw key is the tail of the SPKI structure; length depends on level.
        for raw_len in (800, 1184, 1568):
            if len(der) == raw_len + 22:
                self.raw_public = der[-raw_len:]
                break
        else:
            raise SystemExit(f"unexpected public key DER length {len(der)}")
        self.key_id = hashlib.sha256(self.raw_public).digest()[:4]

    def decapsulate(self, ciphertext: bytes) -> bytes:
        with tempfile.TemporaryDirectory() as tmp:
            ct_path = Path(tmp) / "ct.bin"
            ss_path = Path(tmp) / "ss.bin"
            ct_path.write_bytes(ciphertext)
            result = subprocess.run(
                ["openssl", "pkeyutl", "-decap", "-inkey", str(self.pem),
                 "-in", str(ct_path), "-secret", str(ss_path)],
                capture_output=True,
            )
            if result.returncode != 0 or not ss_path.exists():
                raise p.ProtocolError("decapsulation failed")
            ss = ss_path.read_bytes()
        if len(ss) != 32:
            raise p.ProtocolError(f"shared secret is {len(ss)} bytes, expected 32")
        return ss


def handle_connection(conn: socket.socket, peer, key: MlKemPrivateKey,
                      devices: DeviceTable) -> None:
    conn.settimeout(20)
    t_start = time.monotonic()

    ftype, payload = p.read_frame(conn)
    if ftype != p.FRAME_CLIENT_HELLO:
        raise p.ProtocolError(f"expected ClientHello, got frame type {ftype:#04x}")

    hello = p.ClientHello.parse(payload)
    log.info("%s: ClientHello device=%s suite=%#04x (%d bytes)",
             peer, hello.device_id.hex(), hello.suite, len(payload))

    if not hmac.compare_digest(hello.server_key_id, key.key_id):
        raise p.ProtocolError(
            f"client pinned key {hello.server_key_id.hex()}, we hold "
            f"{key.key_id.hex()}"
        )

    psk = devices.psk_for(hello.device_id)
    if psk is None:
        raise p.ProtocolError(f"unknown device {hello.device_id.hex()}")

    # Verified BEFORE decapsulating: the MAC is a hash, decapsulation is not.
    # Without this an unprovisioned peer could make us do unlimited ML-KEM work.
    expected_mac = p.hello_mac(psk, hello.signed_part)
    if not hmac.compare_digest(expected_mac, hello.psk_mac):
        raise p.ProtocolError("PSK MAC mismatch")

    t_decap = time.monotonic()
    ss = key.decapsulate(hello.kem_ct)
    decap_ms = (time.monotonic() - t_decap) * 1000

    server_nonce = secrets.token_bytes(p.NONCE_LEN)
    session_id = secrets.token_bytes(p.SESSION_ID_LEN)
    th2 = p.transcript_2(hello.raw, server_nonce, session_id)
    keys = p.derive_keys(ss, psk, hello.client_nonce, server_nonce, th2)

    server_mac = hmac.new(keys.srv_confirm, th2, "sha256").digest()
    p.write_frame(conn, p.FRAME_SERVER_HELLO,
                  p.build_server_hello(server_nonce, session_id, server_mac))

    ftype, payload = p.read_frame(conn)
    if ftype != p.FRAME_CLIENT_FINISHED:
        raise p.ProtocolError(f"expected ClientFinished, got {ftype:#04x}")
    if len(payload) != p.MAC_LEN:
        raise p.ProtocolError("ClientFinished has wrong length")

    expected = hmac.new(keys.cli_confirm, th2 + server_mac, "sha256").digest()
    if not hmac.compare_digest(expected, payload):
        raise p.ProtocolError("ClientFinished MAC mismatch")

    handshake_ms = (time.monotonic() - t_start) * 1000
    log.info("%s: handshake complete session=%s (%.1f ms total, %.1f ms decap)",
             peer, session_id.hex(), handshake_ms, decap_ms)

    inbound = p.RecordStream(keys.c2s, session_id)
    records = 0
    payload_bytes = 0
    while True:
        try:
            ftype, payload = p.read_frame(conn)
        except p.ProtocolError:
            break
        if ftype == p.FRAME_CLOSE:
            break
        if ftype != p.FRAME_DATA:
            raise p.ProtocolError(f"unexpected frame {ftype:#04x} after handshake")

        plaintext = inbound.open(payload)
        records += 1
        payload_bytes += len(plaintext)
        log.info("%s: record %d (%d B payload): %s",
                 peer, records, len(plaintext),
                 plaintext.decode("utf-8", "replace").strip())

    log.info("%s: session closed after %d record(s), %d payload bytes",
             peer, records, payload_bytes)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--key", type=Path,
                    default=Path.home() / "pqc-server/server_dk.pem")
    ap.add_argument("--devices", type=Path,
                    default=Path.home() / "pqc-server/devices.json")
    ap.add_argument("--once", action="store_true",
                    help="serve a single connection and exit (for tests)")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-5s %(message)s",
        datefmt="%H:%M:%S",
    )

    key = MlKemPrivateKey(args.key)
    devices = DeviceTable(args.devices)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(4)

    log.info("PQC-IoT-1 reference server on %s:%d", args.host, args.port)
    log.info("server key %s, key_id %s", key.description, key.key_id.hex())

    while True:
        conn, peer = srv.accept()
        peer_str = f"{peer[0]}:{peer[1]}"
        try:
            handle_connection(conn, peer_str, key, devices)
        except p.ProtocolError as exc:
            # Logged here, never sent to the peer: telling a caller which check
            # failed turns the server into an oracle (docs/protocol.md).
            log.warning("%s: rejected - %s", peer_str, exc)
        except (socket.timeout, OSError) as exc:
            log.warning("%s: transport error - %s", peer_str, exc)
        finally:
            conn.close()
        if args.once:
            return 0


if __name__ == "__main__":
    sys.exit(main())
