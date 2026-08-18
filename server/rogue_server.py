#!/usr/bin/env python3
"""
Deliberately misbehaving server, for testing the firmware's rejection paths.

The rejection tests in test_client.py point a hostile *client* at the real
server. This is the other half: a hostile *server* pointed at the real firmware.
Both halves are needed. A client that accepts anything a server says fails only
in the field, and it fails silently - it completes a handshake, encrypts, and
sends data to whoever answered.

Runs on the Pi in place of pqc_server.py, on the same port, so the firmware
reaches it without being reflashed.

    python3 rogue_server.py --mode wrong-mac

Modes:
    wrong-mac    structurally valid ServerHello, corrupted MAC
    impostor     a different ML-KEM key pair - the classic man-in-the-middle
    bad-type     answers with an unknown frame type
    bad-length   ServerHello one byte short
    truncate     announces 72 bytes, sends 30, closes
    silence      accepts the connection and never answers
    replay       replays a ServerHello recorded from an earlier session
    bad-ek       mode B: a correctly MACed ServerHello carrying a MALFORMED
                 ephemeral public key (coefficients outside [0,q-1]). The MAC is
                 valid, so only the FIPS 203 section 7.2 input check can catch
                 it. This is the attack mode B introduces and mode A does not
                 have: ek_E is the first key material that arrives over the wire.
    swap-ek      mode B: valid ek_E in the transcript, a different one on the
                 wire - the substitution the server MAC exists to prevent

Every one of these must end with the firmware refusing to send data.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import logging
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import protocol as p

log = logging.getLogger("rogue")

REPLAY_STORE = Path.home() / "pqc-server/.replay_capture.bin"

# These modes only make sense against a mode B handshake. The firmware runs mode
# A first, so those connections are served correctly and only the mode B one is
# attacked.
FS_ONLY_MODES = {"bad-ek", "swap-ek"}


def decapsulate(pem: Path, ciphertext: bytes) -> bytes | None:
    with tempfile.TemporaryDirectory() as tmp:
        ct = Path(tmp) / "ct.bin"
        ss = Path(tmp) / "ss.bin"
        ct.write_bytes(ciphertext)
        r = subprocess.run(
            ["openssl", "pkeyutl", "-decap", "-inkey", str(pem), "-in", str(ct),
             "-secret", str(ss)],
            capture_output=True,
        )
        if r.returncode != 0 or not ss.exists():
            return None
        return ss.read_bytes()


def make_impostor_key() -> Path:
    """A key pair the client has not pinned. This is the man-in-the-middle."""
    path = Path(tempfile.mkdtemp()) / "impostor.pem"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ML-KEM-768", "-out", str(path)],
        capture_output=True, check=True,
    )
    return path


def make_ephemeral() -> tuple[bytes, Path]:
    d = Path(tempfile.mkdtemp())
    pem = d / "eph.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "ML-KEM-768",
                    "-out", str(pem)], capture_output=True, check=True)
    der = subprocess.run(["openssl", "pkey", "-in", str(pem), "-pubout",
                          "-outform", "DER"],
                         capture_output=True, check=True).stdout
    return der[-1184:], pem


def build_valid_server_hello(hello_raw: bytes, ss: bytes, psk: bytes,
                             ek_eph: bytes = b"", ek_on_wire: bytes | None = None):
    """
    Builds a ServerHello whose MAC is computed over `ek_eph` but which carries
    `ek_on_wire` (defaulting to the same). Passing a different one produces the
    substitution attack the MAC is supposed to make impossible.
    """
    server_nonce = secrets.token_bytes(p.NONCE_LEN)
    session_id = secrets.token_bytes(p.SESSION_ID_LEN)
    hello = p.ClientHello.parse(hello_raw)
    th2 = p.transcript_2(hello_raw, server_nonce, session_id, ek_eph)

    if p.SUITE_PARAMS[hello.suite]["fs"]:
        srv_confirm = p.derive_stage1(ss, psk, hello.client_nonce, server_nonce,
                                      th2)
    else:
        srv_confirm = p.derive_keys(ss, psk, hello.client_nonce, server_nonce,
                                    th2).srv_confirm

    mac = hmac.new(srv_confirm, th2, "sha256").digest()
    carried = ek_eph if ek_on_wire is None else ek_on_wire
    return server_nonce + session_id + carried + mac


def handle(conn: socket.socket, mode: str, key: Path, psk: bytes) -> str:
    """Return a short description of what was sent, for the log."""
    ftype, payload = p.read_frame(conn)
    if ftype != p.FRAME_CLIENT_HELLO:
        return f"client sent frame {ftype:#04x}, not ClientHello"
    hello = p.ClientHello.parse(payload)
    log.info("ClientHello from device %s (%d bytes)", hello.device_id.hex(),
             len(payload))

    fs = p.SUITE_PARAMS[hello.suite]["fs"]

    if mode in FS_ONLY_MODES and not fs:
        # Serve the mode A handshake honestly; the attack targets mode B.
        ss = decapsulate(key, hello.kem_ct)
        p.write_frame(conn, p.FRAME_SERVER_HELLO,
                      build_valid_server_hello(payload, ss, psk))
        # Let the client finish so its mode B attempt follows.
        try:
            p.read_frame(conn)
        except Exception:
            pass
        return "served the mode A handshake correctly (attack targets mode B)"

    if mode == "bad-ek":
        ss = decapsulate(key, hello.kem_ct)
        ek_eph, _ = make_ephemeral()
        # Push coefficients out of range. ML-KEM packs 12-bit coefficients, so
        # all-ones bytes give values well above q-1 = 3328.
        malformed = b"\xff" * 8 + ek_eph[8:]
        p.write_frame(conn, p.FRAME_SERVER_HELLO,
                      build_valid_server_hello(payload, ss, psk, malformed))
        return "sent a correctly MACed ServerHello with a malformed ek_E"

    if mode == "swap-ek":
        ss = decapsulate(key, hello.kem_ct)
        signed_ek, _ = make_ephemeral()
        other_ek, _ = make_ephemeral()
        p.write_frame(conn, p.FRAME_SERVER_HELLO,
                      build_valid_server_hello(payload, ss, psk, signed_ek,
                                               ek_on_wire=other_ek))
        return "MACed one ek_E and sent a different one"

    if mode == "silence":
        time.sleep(30)
        return "sent nothing at all"

    if mode == "bad-type":
        p.write_frame(conn, 0x42, secrets.token_bytes(p.SERVER_HELLO_LEN))
        return "answered with frame type 0x42"

    if mode == "bad-length":
        p.write_frame(conn, p.FRAME_SERVER_HELLO, secrets.token_bytes(71))
        return "sent a 71-byte ServerHello (72 expected)"

    if mode == "truncate":
        conn.sendall(bytes([p.FRAME_SERVER_HELLO, 0x00, 0x48]))  # claims 72
        conn.sendall(secrets.token_bytes(30))
        conn.close()
        return "announced 72 bytes, sent 30, closed"

    if mode == "impostor":
        # A man in the middle holding its own key pair. It cannot decapsulate a
        # ciphertext addressed to the pinned key, so whatever shared secret it
        # derives is not the client's.
        impostor = make_impostor_key()
        ss = decapsulate(impostor, hello.kem_ct) or secrets.token_bytes(32)
        p.write_frame(conn, p.FRAME_SERVER_HELLO,
                      build_valid_server_hello(payload, ss, psk))
        return "answered with a ServerHello derived from an unpinned key"

    ss = decapsulate(key, hello.kem_ct)
    if ss is None:
        return "could not decapsulate"

    if mode == "wrong-mac":
        sh = bytearray(build_valid_server_hello(payload, ss, psk))
        sh[-1] ^= 0x01
        p.write_frame(conn, p.FRAME_SERVER_HELLO, bytes(sh))
        return "sent a ServerHello with one MAC bit flipped"

    if mode == "replay":
        if REPLAY_STORE.exists():
            recorded = REPLAY_STORE.read_bytes()
            p.write_frame(conn, p.FRAME_SERVER_HELLO, recorded)
            return "replayed a ServerHello recorded from an earlier session"
        sh = build_valid_server_hello(payload, ss, psk)
        REPLAY_STORE.write_bytes(sh)
        p.write_frame(conn, p.FRAME_SERVER_HELLO, sh)
        return "served correctly and recorded the ServerHello for replay"

    raise SystemExit(f"unknown mode {mode}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True,
                    choices=["wrong-mac", "impostor", "bad-type", "bad-length",
                             "truncate", "silence", "replay", "bad-ek",
                             "swap-ek"])
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--key", type=Path,
                    default=Path.home() / "pqc-server/server_dk.pem")
    ap.add_argument("--devices", type=Path,
                    default=Path.home() / "pqc-server/devices.json")
    ap.add_argument("--connections", type=int, default=1)
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s ROGUE %(message)s",
                        datefmt="%H:%M:%S")

    table = json.loads(args.devices.read_text())
    psk = bytes.fromhex(next(iter(table.values())))

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(4)
    log.info("mode=%s listening on %s:%d", args.mode, args.host, args.port)

    served = 0
    while served < args.connections:
        conn, peer = srv.accept()
        conn.settimeout(30)
        try:
            what = handle(conn, args.mode, args.key, psk)
            log.info("%s: %s", peer[0], what)
        except Exception as exc:
            log.info("%s: connection ended (%s)", peer[0], exc)
        finally:
            conn.close()
        served += 1

    log.info("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
