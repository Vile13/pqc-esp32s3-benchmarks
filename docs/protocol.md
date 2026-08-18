# PQC-IoT-1 — protocol specification

Version 1. Draft, written before the implementation exists.

> **Educational and experimental protocol. Not a replacement for TLS.**
> It has not been reviewed, standardised or formally analysed. Do not deploy it.
> It exists so that every byte on the wire and every derived key can be
> explained and measured, which a TLS stack does not let you do without a lot of
> ceremony.

## Purpose

Establish a shared session key between a constrained device (ESP32-S3) and a
server (Raspberry Pi) using ML-KEM (FIPS 203), then carry authenticated,
encrypted sensor data over it.

The protocol is deliberately small. Its job is to make the cost of post-quantum
key establishment measurable in an honest end-to-end setting — see the research
question in the [README](../README.md).

## Roles and notation

| Role | Party |
|---|---|
| Client | ESP32-S3, initiator, constrained |
| Server | Raspberry Pi, responder |

- `||` is concatenation. All integers are **big-endian**.
- `u8`, `u16`, `u64` are unsigned integers of that width in bits.
- `H(x)` is SHA-256.
- `MAC(k, m)` is HMAC-SHA-256.
- Byte counts in this document are for ML-KEM-768 (suite `0x01`).

## Threat model

**Assumed capabilities of the adversary**

- Full control of the network: read, drop, reorder, modify, replay, inject.
- Ability to record traffic today and attack it later with a quantum computer
  ("harvest now, decrypt later") — the reason this protocol exists.
- Ability to run their own client hardware and connect to the server.

**Assumed *not* available to the adversary**

- The server's ML-KEM private key.
- Any device's provisioned PSK.
- Physical access to the device: no side-channel, fault-injection or flash
  readout. See non-goals.

**Security goals**

1. Confidentiality of payload data against a passive quantum adversary.
2. Integrity and authenticity of every payload byte.
3. Mutual authentication: the client learns it is talking to the pinned server,
   the server learns which provisioned device it is talking to.
4. Replay resistance, both of whole sessions and of individual records.

**Explicit non-goals** are listed at the end of this document. They are part of
the specification, not an afterthought.

## Provisioning

Before first use, both parties hold:

| Item | Client | Server | Size |
|---|---|---|---|
| Server ML-KEM public key `ek_S` | pinned in firmware | — | 1184 B |
| Server ML-KEM private key `dk_S` | — | on disk, `0600` | 2400 B |
| `server_key_id` | pinned | known | 4 B |
| `device_id` | pinned | in device table | 8 B |
| `PSK` | pinned | in device table, per device | 32 B |

`server_key_id` is the first 4 bytes of `H(ek_S)`. It lets the server hold
several key pairs at once and lets a client say which one it encapsulated to,
so server keys can be rotated without a flag day: deploy the new key, let
clients migrate, retire the old one.

The PSK must come from a cryptographically secure generator and be at least 256
bits. Its length is what makes the PSK path quantum-resistant on its own.

## Suites

| Id | KEM | KDF | AEAD | Forward secrecy |
|---|---|---|---|---|
| `0x01` | ML-KEM-768 | HKDF-SHA-256 | AES-256-GCM | no (mode A) |
| `0x02` | ML-KEM-512 | HKDF-SHA-256 | AES-256-GCM | no (mode A) |
| `0x11` | ML-KEM-768 | HKDF-SHA-256 | AES-256-GCM | yes (mode B) |
| `0x12` | ML-KEM-512 | HKDF-SHA-256 | AES-256-GCM | yes (mode B) |

Suites `0x01`/`0x02` are implemented in v1.1. Suites `0x11`/`0x12` are specified
here and implemented in v2 — the difference between them is precisely the cost
of forward secrecy, which is the number this project exists to produce.

## Framing

The protocol runs over TCP, which already provides ordering and retransmission.
Every message is framed:

```
frame := type:u8 || length:u16 || payload[length]
```

| type | Message | Direction |
|---|---|---|
| `0x01` | ClientHello | C → S |
| `0x02` | ServerHello | S → C |
| `0x03` | ClientFinished | C → S |
| `0x10` | Data | both |
| `0x7f` | Close | both |

`length` never exceeds 4096. A frame with an unknown type, or a length outside
the range valid for that type, terminates the connection.

## Handshake, mode A (suites 0x01, 0x02)

```
Client                                                    Server
  |                                                          |
  |-- ClientHello ------------------------------------------>|
  |   device_id, client_nonce, ct = Encaps(ek_S), psk_mac     |
  |                                                          |
  |                        verify psk_mac, then ss = Decaps(ct, dk_S)
  |                                                          |
  |<------------------------------------------ ServerHello --|
  |                     server_nonce, session_id, server_mac  |
  |                                                          |
  |-- ClientFinished --------------------------------------->|
  |   client_mac                                              |
  |                                                          |
  |<================= Data, AES-256-GCM ====================>|
```

One round trip before the first data record.

### ClientHello (`0x01`), 1166 bytes

| Field | Type | Bytes |
|---|---|---|
| `version` | u8 = 0x01 | 1 |
| `suite` | u8 | 1 |
| `device_id` | u8[8] | 8 |
| `server_key_id` | u8[4] | 4 |
| `client_nonce` | u8[32] | 32 |
| `kem_ct` | u8[1088] | 1088 |
| `psk_mac` | u8[32] | 32 |

`kem_ct, ss = ML-KEM.Encaps(ek_S)`.

`client_nonce` must come from a CSPRNG. On the ESP32 that means the radio must
be up — see [hardware.md](hardware.md); a build without Wi-Fi has no guaranteed
entropy source and must not run this protocol.

```
psk_mac = MAC(PSK, "PQC-IoT-1 hello" || version || suite || device_id
                   || server_key_id || client_nonce || kem_ct)
```

**Why the PSK MAC sits in the first message.** The server looks up the PSK by
`device_id` and verifies this MAC *before* it decapsulates. Decapsulation is the
expensive operation; the MAC check is a hash. Without it, any host on the network
could make the server perform unlimited ML-KEM decapsulations by sending random
bytes. With it, an attacker must first hold a valid PSK.

This is the only place a MAC is keyed directly by the PSK. Everything after it is
keyed by material derived from both the PSK and the KEM shared secret.

### Key schedule

Both parties compute, after the server has decapsulated:

```
TH1 = H(ClientHello payload)
TH2 = H(ClientHello payload || server_nonce || session_id)

salt = client_nonce || server_nonce                     (64 bytes)
IKM  = ss || PSK                                        (64 bytes)
PRK  = HKDF-Extract(salt, IKM)

k_srv_confirm = HKDF-Expand(PRK, "PQC-IoT-1 server confirm" || TH2, 32)
k_cli_confirm = HKDF-Expand(PRK, "PQC-IoT-1 client confirm" || TH2, 32)
k_c2s         = HKDF-Expand(PRK, "PQC-IoT-1 c2s" || TH2, 32)
k_s2c         = HKDF-Expand(PRK, "PQC-IoT-1 s2c" || TH2, 32)
```

**Why the PSK is mixed into the IKM rather than used only for authentication.**
It makes the two secrets independent lines of defence. An adversary who breaks
ML-KEM still faces a 256-bit symmetric secret. An adversary who extracts a PSK
from one device still has to break ML-KEM to read that device's traffic — and
learns nothing about any other device, since PSKs are per-device.

Separate keys per direction mean a record can never be reflected back at its
sender and accepted.

### ServerHello (`0x02`), 72 bytes

| Field | Type | Bytes |
|---|---|---|
| `server_nonce` | u8[32] | 32 |
| `session_id` | u8[8] | 8 |
| `server_mac` | u8[32] | 32 |

```
server_mac = MAC(k_srv_confirm, TH2)
```

Producing this MAC proves the server decapsulated `kem_ct`, which only the holder
of `dk_S` can do, and that it holds the PSK. That is the server's authentication:
there is no certificate and none is needed, because the client pinned `ek_S`.

`session_id` is freshly random per session and used in record AAD.

### ClientFinished (`0x03`), 32 bytes

| Field | Type | Bytes |
|---|---|---|
| `client_mac` | u8[32] | 32 |

```
client_mac = MAC(k_cli_confirm, TH2 || server_mac)
```

The server must not accept any Data record before verifying this.

## Handshake, mode B — forward secrecy (suites 0x11, 0x12)

Mode A has a property worth stating plainly: **it provides no forward secrecy.**
The server's ML-KEM key is long-lived and pinned. An adversary who records
sessions today and later obtains `dk_S` can decapsulate every recorded session
and decrypt all of it. The PSK mixed into the key schedule limits this to
adversaries who also hold the PSK, but within that assumption the exposure is
total and retroactive.

Mode B fixes this by adding an ephemeral KEM key pair per session:

```
Client                                                    Server
  |-- ClientHello ------------------------------------------>|
  |   (as mode A: ct_static to the pinned key)                |
  |                                                          |
  |                         generate ephemeral (ek_E, dk_E)   |
  |<------------------------------------------ ServerHello --|
  |             server_nonce, session_id, ek_E, server_mac    |
  |                                                          |
  |-- ClientKeyExchange ------------------------------------>|
  |   ct_eph = Encaps(ek_E), client_mac                       |
```

ServerHello gains `ek_E` (1184 B), and ClientFinished becomes ClientKeyExchange
carrying `ct_eph` (1088 B) ahead of `client_mac`. The key schedule changes in one
place:

```
IKM = ss_static || ss_eph || PSK                        (96 bytes)
```

`dk_E` is destroyed as soon as `ss_eph` is derived. Recovering `dk_S` afterwards
no longer helps: `ss_eph` is unrecoverable, and it is part of every session key.

The cost, which v2 measures: one extra encapsulation on the device, one extra
key generation on the server, and 2272 extra bytes on the wire per handshake.

## Data records (`0x10`)

| Field | Type | Bytes |
|---|---|---|
| `seq` | u64 | 8 |
| `ct_len` | u16 | 2 |
| `ciphertext` | u8[ct_len] | ct_len |
| `tag` | u8[16] | 16 |

```
key   = k_c2s for client → server, k_s2c for server → client
nonce = 0x00000000 || seq                               (12 bytes)
aad   = session_id || seq || ct_len
ciphertext, tag = AES-256-GCM(key, nonce, aad, plaintext)
```

`seq` starts at 0 and increments by one per record, per direction. Because the
directions use different keys, the nonce cannot repeat under a given key as long
as `seq` never repeats.

**Replay and reordering.** A receiver keeps `last_seq` per direction and accepts
a record only if `seq > last_seq`. TCP already guarantees ordering, so a strict
increase is sufficient and no window is needed. A replayed record is rejected by
this check; a replayed *session* is rejected because `server_nonce` is fresh and
the client will not produce a matching `client_mac`.

**Rekeying.** A session ends and the handshake is repeated when `seq` reaches
2^32, or when the rekey interval configured for the device elapses. That interval
is the tunable that the whole project is about: every rekey costs a full
handshake, which for a sensor node dwarfs the data it protects.

## Failure handling

Any of the following terminates the connection immediately:

- unknown `version` or `suite`
- unknown `device_id`, or `server_key_id` that does not match a held key
- `psk_mac`, `server_mac` or `client_mac` mismatch
- ML-KEM key or ciphertext rejected by the FIPS 203 §7.2 input checks
- AEAD tag failure
- `seq` not strictly greater than `last_seq`
- malformed framing

**No error detail is sent.** The peer sees a closed connection and nothing else.
Distinguishing "unknown device" from "bad MAC" would hand an attacker an oracle
for enumerating provisioned devices. Failures are logged locally on the server,
never signalled on the wire.

Comparisons on secrets — MAC verification in particular — must be constant-time.

## Wire cost

This table is the reason the protocol is specified before it is built.

| | Mode A | Mode B (forward secrecy) |
|---|---|---|
| ClientHello | 1166 | 1166 |
| ServerHello | 72 | 1256 |
| ClientFinished / KeyExchange | 32 | 1120 |
| Framing (3 × 3 B) | 9 | 9 |
| **Handshake total** | **1279 B** | **3551 B** |
| Per data record overhead | 29 B | 29 B |

A SCD41 reading — CO₂, temperature, humidity — is about 10 bytes. Encrypted and
framed it costs 39 bytes on the wire.

So one mode A handshake costs as much as **roughly 33 sensor readings**, and one
mode B handshake as much as **91**.

For a node reporting every five minutes, the share of transmitted bytes spent on
key establishment rather than on data:

| Rekey interval | Readings per session | Mode A | Mode B |
|---|---|---|---|
| every reading (5 min) | 1 | 97 % | 99 % |
| hourly | 12 | 73 % | 88 % |
| daily | 288 | 10 % | 24 % |
| weekly | 2016 | 1.6 % | 4.3 % |

This is the trade-off the project is about, and it is steeper than it looks from
the outside. Rekeying hourly means the majority of what the node transmits is key
establishment, not measurements. Forward secrecy roughly triples the handshake
and therefore bites hardest exactly where rekeying is most frequent — which is
where forward secrecy is worth the most.

Those ratios are arithmetic from this specification, and bytes are only a proxy.
The figure that decides the question is energy, because a radio's cost per byte
is not linear in the byte count — the wake-up and the tail dominate for short
transmissions. Measuring that, in millijoules, is v2.

## Non-goals

- **Not TLS.** No certificates, no negotiation, no extensions, no
  interoperability with anything.
- **No side-channel resistance claims.** Constant-time MAC comparison is
  required above, but the implementation is not hardened against power or
  electromagnetic analysis, and no such testing is planned.
- **No protection against a compromised device.** A device that has been opened
  and had its flash read gives up its PSK and the pinned server key. Secure Boot
  and flash encryption are out of scope for v1.
- **No denial-of-service resistance beyond the PSK check.** An attacker holding a
  valid PSK can still exhaust the server.
- **No formal analysis.** The key schedule follows familiar patterns, but it has
  not been machine-checked, and it should not be trusted as if it had.
