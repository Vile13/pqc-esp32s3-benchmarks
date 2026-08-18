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


SUITES = {"A": p.SUITE_MLKEM768, "B": p.SUITE_MLKEM768_FS}


def wrap_raw_pubkey(template_pem: Path, raw: bytes) -> Path:
    """
    Re-encode a raw ML-KEM public key as SubjectPublicKeyInfo so OpenSSL accepts
    it. The ephemeral key arrives over the wire as 1184 bare bytes; the pinned
    server key supplies the 22-byte AlgorithmIdentifier prefix, which is
    identical for the same parameter set.
    """
    der = subprocess.run(
        ["openssl", "pkey", "-in", str(template_pem), "-pubin", "-outform", "DER"],
        capture_output=True, check=True,
    ).stdout
    prefix = der[:len(der) - len(raw)]
    if len(prefix) != 22:
        raise SystemExit(f"unexpected SPKI prefix of {len(prefix)} bytes")

    out = Path(tempfile.mkdtemp()) / "eph_pub.der"
    out.write_bytes(prefix + raw)
    return out


def encapsulate_der(pubkey_der: Path) -> tuple[bytes, bytes]:
    with tempfile.TemporaryDirectory() as tmp:
        ct = Path(tmp) / "ct.bin"
        ss = Path(tmp) / "ss.bin"
        result = subprocess.run(
            ["openssl", "pkeyutl", "-encap", "-inkey", str(pubkey_der),
             "-pubin", "-keyform", "DER", "-secret", str(ss), "-out", str(ct)],
            capture_output=True,
        )
        if result.returncode != 0:
            raise SystemExit(
                f"ephemeral encapsulation failed: {result.stderr.decode().strip()}"
            )
        return ct.read_bytes(), ss.read_bytes()


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
              *, suite: int = p.SUITE_MLKEM768, corrupt_psk_mac: bool = False,
              corrupt_client_mac: bool = False) -> tuple[socket.socket, p.RecordStream, int]:
    params = p.SUITE_PARAMS[suite]
    forward_secrecy = params["fs"]

    kem_ct, ss_static = encapsulate(pubkey)
    client_nonce = secrets.token_bytes(p.NONCE_LEN)

    hello = p.ClientHello.build(suite, device_id, server_key_id(pubkey),
                                client_nonce, kem_ct, psk)
    if corrupt_psk_mac:
        hello = hello[:-1] + bytes([hello[-1] ^ 0x01])

    sock = socket.create_connection((host, port), timeout=20)
    p.write_frame(sock, p.FRAME_CLIENT_HELLO, hello)
    handshake_bytes = 3 + len(hello)

    ftype, payload = p.read_frame(sock)
    if ftype != p.FRAME_SERVER_HELLO:
        raise p.ProtocolError(f"expected ServerHello, got {ftype:#04x}")
    handshake_bytes += 3 + len(payload)

    if len(payload) != p.server_hello_len(suite):
        raise p.ProtocolError(
            f"ServerHello is {len(payload)} bytes, expected "
            f"{p.server_hello_len(suite)}"
        )

    server_nonce = payload[:p.NONCE_LEN]
    session_id = payload[p.NONCE_LEN:p.NONCE_LEN + p.SESSION_ID_LEN]
    rest = payload[p.NONCE_LEN + p.SESSION_ID_LEN:]
    ek_eph = rest[:params["ek"]] if forward_secrecy else b""
    server_mac = rest[len(ek_eph):]

    th2 = p.transcript_2(hello, server_nonce, session_id, ek_eph)

    if forward_secrecy:
        srv_confirm = p.derive_stage1(ss_static, psk, client_nonce,
                                      server_nonce, th2)
    else:
        keys = p.derive_keys(ss_static, psk, client_nonce, server_nonce, th2)
        srv_confirm = keys.srv_confirm

    expected = hmac.new(srv_confirm, th2, "sha256").digest()
    if not hmac.compare_digest(expected, server_mac):
        raise p.ProtocolError("server MAC mismatch - not the pinned server")

    if forward_secrecy:
        # The MAC above authenticated ek_eph, so encapsulating to it is safe.
        eph_der = wrap_raw_pubkey(pubkey, ek_eph)
        ct_eph, ss_eph = encapsulate_der(eph_der)
        th3 = p.transcript_3(th2, ct_eph)
        keys = p.derive_stage2(ss_static, ss_eph, psk, client_nonce,
                               server_nonce, th3)
        transcript_for_mac = th3
        tail = ct_eph
    else:
        transcript_for_mac = th2
        tail = b""

    client_mac = hmac.new(keys.cli_confirm, transcript_for_mac + server_mac,
                          "sha256").digest()
    if corrupt_client_mac:
        client_mac = client_mac[:-1] + bytes([client_mac[-1] ^ 0x01])

    p.write_frame(sock, p.FRAME_CLIENT_FINISHED, tail + client_mac)
    handshake_bytes += 3 + len(tail) + len(client_mac)

    return sock, p.RecordStream(keys.c2s, session_id), handshake_bytes


def run_happy_path(args) -> bool:
    device_id, psk = first_device(args.devices)
    suite = SUITES[args.suite]
    predicted = 3551 if p.SUITE_PARAMS[suite]["fs"] else 1279

    sock, stream, hs_bytes = handshake(args.host, args.port, args.server_pubkey,
                                       device_id, psk, suite=suite)
    match = "matches" if hs_bytes == predicted else "DIFFERS FROM"
    print(f"  mode {args.suite}: handshake ok, {hs_bytes} bytes on the wire "
          f"({match} the specification's {predicted})")

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
    suite = SUITES[args.suite]
    ok = True

    def forged_psk_mac():
        sock, _, _ = handshake(args.host, args.port, args.server_pubkey,
                               device_id, psk, suite=suite,
                               corrupt_psk_mac=True)
        sock.close()

    def unknown_device():
        sock, _, _ = handshake(args.host, args.port, args.server_pubkey,
                               secrets.token_bytes(8), psk, suite=suite)
        sock.close()

    def wrong_psk():
        sock, _, _ = handshake(args.host, args.port, args.server_pubkey,
                               device_id, secrets.token_bytes(32), suite=suite)
        sock.close()

    def forged_client_mac():
        sock, stream, _ = handshake(args.host, args.port, args.server_pubkey,
                                    device_id, psk, suite=suite,
                                    corrupt_client_mac=True)
        # The server must refuse data after a bad ClientFinished.
        p.write_frame(sock, p.FRAME_DATA, stream.seal(b"should not be accepted"))
        sock.settimeout(5)
        sock.recv(1)  # expect the connection to be gone
        raise p.ProtocolError("connection still open")

    def replayed_record():
        sock, stream, _ = handshake(args.host, args.port, args.server_pubkey,
                                    device_id, psk, suite=suite)
        frame = stream.seal(b'{"co2":800}')
        p.write_frame(sock, p.FRAME_DATA, frame)
        p.write_frame(sock, p.FRAME_DATA, frame)  # byte-identical replay
        sock.settimeout(5)
        if sock.recv(1) == b"":
            raise p.ProtocolError("server closed on replay")
        raise p.ProtocolError("connection still open")

    def tampered_ciphertext():
        sock, stream, _ = handshake(args.host, args.port, args.server_pubkey,
                                    device_id, psk, suite=suite)
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
    ap.add_argument("--suite", choices=sorted(SUITES), default="A",
                    help="A = pinned static key, B = forward secrecy")
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
