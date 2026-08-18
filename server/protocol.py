"""
PQC-IoT-1 wire format and key schedule.

Shared by the reference server and the test client so that both derive keys from
the same code path. The firmware implements the same specification independently
in C - that independence is the point, and it is what the interoperability test
actually tests.

Specification: docs/protocol.md
"""

from __future__ import annotations

import hashlib
import hmac
import socket
import struct
from dataclasses import dataclass

VERSION = 0x01

SUITE_MLKEM768 = 0x01
SUITE_MLKEM512 = 0x02

SUITE_PARAMS = {
    SUITE_MLKEM768: {"level": 768, "ct": 1088, "ek": 1184},
    SUITE_MLKEM512: {"level": 512, "ct": 768, "ek": 800},
}

FRAME_CLIENT_HELLO = 0x01
FRAME_SERVER_HELLO = 0x02
FRAME_CLIENT_FINISHED = 0x03
FRAME_DATA = 0x10
FRAME_CLOSE = 0x7F

MAX_FRAME = 4096

NONCE_LEN = 32
SESSION_ID_LEN = 8
DEVICE_ID_LEN = 8
KEY_ID_LEN = 4
MAC_LEN = 32
PSK_LEN = 32
TAG_LEN = 16

LABEL_HELLO = b"PQC-IoT-1 hello"
LABEL_SRV_CONFIRM = b"PQC-IoT-1 server confirm"
LABEL_CLI_CONFIRM = b"PQC-IoT-1 client confirm"
LABEL_C2S = b"PQC-IoT-1 c2s"
LABEL_S2C = b"PQC-IoT-1 s2c"


class ProtocolError(Exception):
    """Any deviation from the specification. Always fatal to the connection.

    Callers must not report the reason to the peer: distinguishing 'unknown
    device' from 'bad MAC' hands an attacker an oracle for enumerating
    provisioned devices (docs/protocol.md, failure handling).
    """


# --------------------------------------------------------------------- framing


def read_exactly(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ProtocolError("peer closed mid-frame")
        buf += chunk
    return bytes(buf)


def read_frame(sock: socket.socket) -> tuple[int, bytes]:
    head = read_exactly(sock, 3)
    ftype, length = struct.unpack("!BH", head)
    if length > MAX_FRAME:
        raise ProtocolError(f"frame length {length} exceeds maximum")
    return ftype, read_exactly(sock, length)


def write_frame(sock: socket.socket, ftype: int, payload: bytes) -> None:
    if len(payload) > MAX_FRAME:
        raise ProtocolError("frame too large to send")
    sock.sendall(struct.pack("!BH", ftype, len(payload)) + payload)


# ---------------------------------------------------------------- key schedule


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


@dataclass
class SessionKeys:
    srv_confirm: bytes
    cli_confirm: bytes
    c2s: bytes
    s2c: bytes


def derive_keys(ss: bytes, psk: bytes, client_nonce: bytes, server_nonce: bytes,
                th2: bytes) -> SessionKeys:
    """
    IKM is the KEM shared secret concatenated with the PSK, so the two are
    independent lines of defence rather than one. Breaking ML-KEM leaves an
    attacker facing 256 bits of symmetric secret; stealing one device's PSK
    leaves them facing ML-KEM, and tells them nothing about any other device.
    """
    if len(psk) != PSK_LEN:
        raise ProtocolError("PSK must be 32 bytes")

    prk = hkdf_extract(client_nonce + server_nonce, ss + psk)
    return SessionKeys(
        srv_confirm=hkdf_expand(prk, LABEL_SRV_CONFIRM + th2, 32),
        cli_confirm=hkdf_expand(prk, LABEL_CLI_CONFIRM + th2, 32),
        c2s=hkdf_expand(prk, LABEL_C2S + th2, 32),
        s2c=hkdf_expand(prk, LABEL_S2C + th2, 32),
    )


def transcript_2(client_hello: bytes, server_nonce: bytes, session_id: bytes) -> bytes:
    return hashlib.sha256(client_hello + server_nonce + session_id).digest()


def hello_mac(psk: bytes, hello_without_mac: bytes) -> bytes:
    return hmac.new(psk, LABEL_HELLO + hello_without_mac, hashlib.sha256).digest()


# ------------------------------------------------------------------- messages


@dataclass
class ClientHello:
    version: int
    suite: int
    device_id: bytes
    server_key_id: bytes
    client_nonce: bytes
    kem_ct: bytes
    psk_mac: bytes
    raw: bytes

    @property
    def signed_part(self) -> bytes:
        """Everything the psk_mac covers - the payload minus the MAC itself."""
        return self.raw[:-MAC_LEN]

    @classmethod
    def parse(cls, payload: bytes) -> "ClientHello":
        if len(payload) < 2:
            raise ProtocolError("ClientHello truncated")
        version, suite = payload[0], payload[1]
        if version != VERSION:
            raise ProtocolError(f"unsupported version {version:#04x}")
        params = SUITE_PARAMS.get(suite)
        if params is None:
            raise ProtocolError(f"unsupported suite {suite:#04x}")

        expected = (2 + DEVICE_ID_LEN + KEY_ID_LEN + NONCE_LEN
                    + params["ct"] + MAC_LEN)
        if len(payload) != expected:
            raise ProtocolError(
                f"ClientHello is {len(payload)} bytes, expected {expected}"
            )

        i = 2
        device_id = payload[i:i + DEVICE_ID_LEN]; i += DEVICE_ID_LEN
        key_id = payload[i:i + KEY_ID_LEN]; i += KEY_ID_LEN
        nonce = payload[i:i + NONCE_LEN]; i += NONCE_LEN
        kem_ct = payload[i:i + params["ct"]]; i += params["ct"]
        psk_mac = payload[i:i + MAC_LEN]

        return cls(version, suite, device_id, key_id, nonce, kem_ct, psk_mac,
                   payload)

    @classmethod
    def build(cls, suite: int, device_id: bytes, server_key_id: bytes,
              client_nonce: bytes, kem_ct: bytes, psk: bytes) -> bytes:
        body = (bytes([VERSION, suite]) + device_id + server_key_id
                + client_nonce + kem_ct)
        return body + hello_mac(psk, body)


def build_server_hello(server_nonce: bytes, session_id: bytes, mac: bytes) -> bytes:
    return server_nonce + session_id + mac


def parse_server_hello(payload: bytes) -> tuple[bytes, bytes, bytes]:
    expected = NONCE_LEN + SESSION_ID_LEN + MAC_LEN
    if len(payload) != expected:
        raise ProtocolError(f"ServerHello is {len(payload)} bytes, expected {expected}")
    return (payload[:NONCE_LEN],
            payload[NONCE_LEN:NONCE_LEN + SESSION_ID_LEN],
            payload[NONCE_LEN + SESSION_ID_LEN:])


# -------------------------------------------------------------- data records


class RecordStream:
    """
    One direction of the encrypted channel.

    Sequence numbers are per direction and strictly increasing. Because each
    direction has its own key, a record can never be reflected back at its
    sender and accepted, and the GCM nonce cannot repeat under a given key.
    """

    def __init__(self, key: bytes, session_id: bytes):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        self._aead = AESGCM(key)
        self._session_id = session_id
        self._send_seq = 0
        self._last_recv_seq = -1

    @staticmethod
    def _nonce(seq: int) -> bytes:
        return b"\x00\x00\x00\x00" + struct.pack("!Q", seq)

    def _aad(self, seq: int, ct_len: int) -> bytes:
        return self._session_id + struct.pack("!QH", seq, ct_len)

    def seal(self, plaintext: bytes) -> bytes:
        seq = self._send_seq
        # AES-GCM is length-preserving, so ct_len equals the plaintext length
        # and the AAD can be computed before encrypting.
        sealed = self._aead.encrypt(self._nonce(seq), plaintext,
                                    self._aad(seq, len(plaintext)))
        ciphertext, tag = sealed[:-TAG_LEN], sealed[-TAG_LEN:]
        self._send_seq += 1
        return struct.pack("!QH", seq, len(ciphertext)) + ciphertext + tag

    def open(self, payload: bytes) -> bytes:
        if len(payload) < 10 + TAG_LEN:
            raise ProtocolError("data record truncated")
        seq, ct_len = struct.unpack("!QH", payload[:10])
        if len(payload) != 10 + ct_len + TAG_LEN:
            raise ProtocolError("data record length mismatch")
        if seq <= self._last_recv_seq:
            raise ProtocolError(f"replayed or reordered record (seq {seq})")

        ciphertext = payload[10:10 + ct_len]
        tag = payload[10 + ct_len:]
        try:
            plaintext = self._aead.decrypt(self._nonce(seq), ciphertext + tag,
                                           self._aad(seq, ct_len))
        except Exception as exc:
            raise ProtocolError("AEAD tag verification failed") from exc

        self._last_recv_seq = seq
        return plaintext
