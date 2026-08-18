#!/usr/bin/env python3
"""
Test client for the PQC-IoT-1 reference server.

Exercises the server end to end before the firmware exists, and stays useful
afterwards as the thing that isolates blame: if the firmware fails but this
client succeeds, the fault is on the device.

    python3 test_client.py --host 127.0.0.1 --port 8443 \
        --server-pubkey ~/pqc-server/server_pk.pem \
        --devices ~/pqc-server/devices.json

It also runs negative tests (--negative), which matter more than the happy path.
A server that accepts a forged MAC still passes a successful handshake.

Note on independence: this client uses OpenSSL for encapsulation, as the server
does for decapsulation. It therefore does NOT establish cross-implementation
interoperability - that claim belongs to the firmware, which uses mlkem-native.
This is a test of the server, not of ML-KEM.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import secrets
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

import protocol as p


def encapsulate(pubkey_pem: Path) -> tuple[bytes, bytes]:
    with tempfile.TemporaryDirectory() as tmp:
        ct = Path(tmp) / "ct.bin"
        ss = Path(tmp) / "ss.bin"
        result = subprocess.run(
            ["openssl", "pkeyutl", "-encap", "-inkey", str(pubkey_pem), "-pubin",
             "-secret", str(ss), "-out", str(ct)],
            capture_output=True,
        )
        if result.returncode != 0:
            raise SystemExit(f"encapsulation failed: {result.stderr.decode().strip()}")
        return ct.read_bytes(), ss.read_bytes()


def server_key_id(pubkey_pem: Path) -> bytes:
    der = subprocess.run(
        ["openssl", "pkey", "-in", str(pubkey_pem), "-pubin", "-outform", "DER"],
        capture_output=True, check=True,
    ).stdout
    for raw_len in (800, 1184, 1568):
        if len(der) == raw_len + 22:
            return hashlib.sha256(der[-raw_len:]).digest()[:4]
    raise SystemExit(f"unexpected public key DER length {len(der)}")


def first_device(devices_path: Path) -> tuple[bytes, bytes]:
    raw = json.loads(devices_path.read_text())
    if not raw:
        raise SystemExit("device table is empty")
    did, psk = next(iter(raw.items()))
    return bytes.fromhex(did), bytes.fromhex(psk)


def handshake(host: str, port: int, pubkey: Path, device_id: bytes, psk: bytes,
              *, corrupt_psk_mac: bool = False,
              corrupt_client_mac: bool = False) -> tuple[socket.socket, p.RecordStream, int]:
    kem_ct, ss = encapsulate(pubkey)
    client_nonce = secrets.token_bytes(p.NONCE_LEN)

    hello = p.ClientHello.build(p.SUITE_MLKEM768, device_id,
                                server_key_id(pubkey), client_nonce, kem_ct, psk)
    if corrupt_psk_mac:
        hello = hello[:-1] + bytes([hello[-1] ^ 0x01])

    sock = socket.create_connection((host, port), timeout=20)
    p.write_frame(sock, p.FRAME_CLIENT_HELLO, hello)
    handshake_bytes = 3 + len(hello)

    ftype, payload = p.read_frame(sock)
    if ftype != p.FRAME_SERVER_HELLO:
        raise p.ProtocolError(f"expected ServerHello, got {ftype:#04x}")
    handshake_bytes += 3 + len(payload)

    server_nonce, session_id, server_mac = p.parse_server_hello(payload)
    th2 = p.transcript_2(hello, server_nonce, session_id)
    keys = p.derive_keys(ss, psk, client_nonce, server_nonce, th2)

    expected = hmac.new(keys.srv_confirm, th2, "sha256").digest()
    if not hmac.compare_digest(expected, server_mac):
        raise p.ProtocolError("server MAC mismatch - not the pinned server")

    client_mac = hmac.new(keys.cli_confirm, th2 + server_mac, "sha256").digest()
    if corrupt_client_mac:
        client_mac = client_mac[:-1] + bytes([client_mac[-1] ^ 0x01])
    p.write_frame(sock, p.FRAME_CLIENT_FINISHED, client_mac)
    handshake_bytes += 3 + len(client_mac)

    return sock, p.RecordStream(keys.c2s, session_id), handshake_bytes


def run_happy_path(args) -> bool:
    device_id, psk = first_device(args.devices)
    sock, stream, hs_bytes = handshake(args.host, args.port, args.server_pubkey,
                                       device_id, psk)
    print(f"  handshake ok, {hs_bytes} bytes on the wire "
          f"(spec predicts 1279)")

    payloads = [b'{"co2":812,"t":22.4,"rh":47}',
                b'{"co2":815,"t":22.4,"rh":47}',
                b'{"co2":809,"t":22.5,"rh":46}']
    total = 0
    for pt in payloads:
        frame = stream.seal(pt)
        p.write_frame(sock, p.FRAME_DATA, frame)
        total += 3 + len(frame)
    print(f"  {len(payloads)} records sent, {total} bytes for "
          f"{sum(len(x) for x in payloads)} bytes of payload")

    p.write_frame(sock, p.FRAME_CLOSE, b"")
    sock.close()
    return True


def expect_rejection(label: str, fn) -> bool:
    try:
        fn()
    except (p.ProtocolError, ConnectionError, socket.timeout, OSError):
        print(f"  ok    {label}: rejected")
        return True
    print(f"  FAIL  {label}: accepted, should have been rejected")
    return False


def run_negative(args) -> bool:
    device_id, psk = first_device(args.devices)
    ok = True

    def forged_psk_mac():
        sock, _, _ = handshake(args.host, args.port, args.server_pubkey,
                               device_id, psk, corrupt_psk_mac=True)
        sock.close()

    def unknown_device():
        sock, _, _ = handshake(args.host, args.port, args.server_pubkey,
                               secrets.token_bytes(8), psk)
        sock.close()

    def wrong_psk():
        sock, _, _ = handshake(args.host, args.port, args.server_pubkey,
                               device_id, secrets.token_bytes(32))
        sock.close()

    def forged_client_mac():
        sock, stream, _ = handshake(args.host, args.port, args.server_pubkey,
                                    device_id, psk, corrupt_client_mac=True)
        # The server must refuse data after a bad ClientFinished.
        p.write_frame(sock, p.FRAME_DATA, stream.seal(b"should not be accepted"))
        sock.settimeout(5)
        sock.recv(1)  # expect the connection to be gone
        raise p.ProtocolError("connection still open")

    def replayed_record():
        sock, stream, _ = handshake(args.host, args.port, args.server_pubkey,
                                    device_id, psk)
        frame = stream.seal(b'{"co2":800}')
        p.write_frame(sock, p.FRAME_DATA, frame)
        p.write_frame(sock, p.FRAME_DATA, frame)  # byte-identical replay
        sock.settimeout(5)
        if sock.recv(1) == b"":
            raise p.ProtocolError("server closed on replay")
        raise p.ProtocolError("connection still open")

    def tampered_ciphertext():
        sock, stream, _ = handshake(args.host, args.port, args.server_pubkey,
                                    device_id, psk)
        frame = bytearray(stream.seal(b'{"co2":800}'))
        frame[12] ^= 0x01
        p.write_frame(sock, p.FRAME_DATA, bytes(frame))
        sock.settimeout(5)
        if sock.recv(1) == b"":
            raise p.ProtocolError("server closed on tampered record")
        raise p.ProtocolError("connection still open")

    ok &= expect_rejection("forged PSK MAC", forged_psk_mac)
    ok &= expect_rejection("unknown device_id", unknown_device)
    ok &= expect_rejection("wrong PSK", wrong_psk)
    ok &= expect_rejection("forged ClientFinished", forged_client_mac)
    ok &= expect_rejection("replayed data record", replayed_record)
    ok &= expect_rejection("tampered ciphertext", tampered_ciphertext)
    return ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--server-pubkey", type=Path,
                    default=Path.home() / "pqc-server/server_pk.pem")
    ap.add_argument("--devices", type=Path,
                    default=Path.home() / "pqc-server/devices.json")
    ap.add_argument("--negative", action="store_true",
                    help="run the rejection tests instead of the happy path")
    args = ap.parse_args()

    if args.negative:
        print("negative tests:")
        ok = run_negative(args)
    else:
        print("happy path:")
        ok = run_happy_path(args)

    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
