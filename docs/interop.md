# Vertical slice: ESP32-S3 to Raspberry Pi

First end-to-end post-quantum session, 2026-08-18.

## What happened

An ESP32-S3 established an ML-KEM-768 session key with a Raspberry Pi 3 and sent
AES-256-GCM encrypted sensor records over it, using the handshake specified in
[protocol.md](protocol.md), mode A.

Device side:

```
=== protocol client ===
wifi: connected, ip 192.168.188.54
pqc : connecting to 192.168.188.53:8443
pqc : handshake ok in 105 ms (encapsulation 7 ms), 1279 bytes
pqc : 3 record(s) sent, 108 bytes of payload
session completed
```

Server side:

```
ClientHello device=65782c503bf33f00 suite=0x01 (1166 bytes)
handshake complete session=5d1bab68d994a2ba (107.2 ms total, 53.1 ms decap)
record 1 (36 B payload): {"seq":0,"co2":810,"t":22.4,"rh":47}
record 2 (36 B payload): {"seq":1,"co2":811,"t":22.4,"rh":47}
record 3 (36 B payload): {"seq":2,"co2":812,"t":22.4,"rh":47}
session closed after 3 record(s), 108 payload bytes
```

## Why this is evidence and not a mirror

The two ends share no cryptographic code:

| | Device | Server |
|---|---|---|
| ML-KEM | mlkem-native v2.0.0, portable C | OpenSSL 3.5.6 |
| HKDF / HMAC | mbedtls | Python stdlib |
| AES-256-GCM | mbedtls, hardware accelerated | `cryptography` |
| Protocol | C, written from the specification | Python, written from the specification |

Had both ends run the same implementation, a successful handshake would show only
that the implementation agrees with itself — a broken one would interoperate just
as happily. Two independent implementations arriving at the same shared secret,
the same four derived keys and the same three MACs is a different kind of claim.

It sits alongside the ACVP vectors rather than replacing them
([conformance.md](conformance.md)): the vectors establish that the ML-KEM
implementation matches FIPS 203; interoperability establishes that the protocol
layer built on top of it is not mis-wired. Neither alone would be enough.

## Numbers

Indicative, not benchmarks. They were taken with the radio up, the network in the
loop and a Python server on the other end — exactly the conditions v2's
measurements are designed to exclude.

| | |
|---|---|
| Handshake, device wall clock | 105 ms |
| of which ML-KEM-768 encapsulation | 7 ms |
| Handshake, server wall clock | 107.2 ms |
| of which ML-KEM-768 decapsulation | 53.1 ms |
| Handshake, bytes on the wire | 1279 — the specification's arithmetic, exactly |
| Data record | 65 bytes for a 36-byte payload |

Two observations worth keeping.

**The constrained device is the fast half.** Encapsulation on a 240 MHz Xtensa
took 7 ms; decapsulation on a 1.2 GHz Cortex-A53 took 53 ms. That inversion is an
artefact, not a finding: the server shells out to the OpenSSL command line per
handshake, so its figure is mostly process startup. It is recorded because it is
what was measured, and it is a good illustration of why v2 measures the device on
a radio-free build rather than trusting numbers taken through a protocol stack.

**The wire cost predicted on paper held exactly.** 1279 bytes was computed in the
specification before any code existed, and both the Python test client and the
firmware produced precisely that. The ratio arguments in
[protocol.md](protocol.md) therefore rest on measured framing, not on estimates.

## What this does not show

- **No forward secrecy.** This is mode A: the server's ML-KEM key is long-lived
  and pinned. An adversary who records these sessions and later obtains the
  server's private key can decrypt all of them retroactively. Mode B is specified
  and not yet implemented.
- **Nothing about energy.** The question this project exists to answer is what a
  rekey costs in millijoules, and that needs the INA219 harness from v2.
- **No side-channel claims**, here or anywhere else in this project.

## Rejection paths, both directions

A channel is only as good as what it refuses. Two harnesses cover the two
directions, and both are needed: a server that accepts a forged MAC and a client
that believes whatever answers on port 8443 both pass a happy-path demo
perfectly.

**Hostile client against the real server** — `server/test_client.py --negative`:
forged PSK MAC, unknown device_id, wrong PSK, forged ClientFinished, replayed
data record, tampered ciphertext. All six rejected, with the reason logged
locally and nothing revealed on the wire.

**Hostile server against the real firmware** — `tests/hostile_server_drill.py`
starts `server/rogue_server.py` on the Pi in place of the real server, resets the
board for each case, and reads the verdict off the serial line:

```
  ok    wrong-mac   server MAC mismatch - this is not the pinned server
  ok    impostor    server MAC mismatch - this is not the pinned server
  ok    replay      server MAC mismatch - this is not the pinned server
  ok    bad-type    unexpected frame 0x42 of 72 bytes
  ok    bad-length  unexpected frame 0x02 of 71 bytes
  ok    truncate    no ServerHello - no answer or connection closed
  ok    silence     no ServerHello - no answer or connection closed

7/7 rejection paths hold
```

The `impostor` case is the one that matters most: a man in the middle holding its
own ML-KEM key pair, answering in the pinned server's place. It cannot
decapsulate a ciphertext addressed to the pinned key, so the shared secret it
derives is not the device's, and the confirmation MAC does not verify. That is
pinning doing its job.

`replay` needs two rounds — the rogue server records a valid ServerHello on the
first connection and replays it on the second. The first version of the drill ran
each mode once and therefore graded the recording round, which legitimately
succeeds. Worth stating, because a test harness that scores its own setup phase
is a way to get a green result that means nothing.

### A bug this found

The server cached the device table at startup. Registering a device while the
server was running had no effect: the server reported `unknown device` for an id
that was plainly present in `devices.json`. It now re-reads the file whenever its
modification time changes.
