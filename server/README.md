# Reference server

Terminates the PQC-IoT-1 handshake ([spec](../docs/protocol.md), mode A) and
prints the decrypted records. Runs on the Raspberry Pi.

| File | Role |
|---|---|
| `protocol.py` | wire format and key schedule, shared by server and test client |
| `pqc_server.py` | the server |
| `test_client.py` | happy-path and rejection tests |

## Dependencies

Python 3.11+, `cryptography` (for AES-256-GCM), and **OpenSSL 3.5 or newer** for
ML-KEM. Raspberry Pi OS on Debian 13 ships OpenSSL 3.5.6, which supports ML-KEM
natively — no third-party PQC library is needed.

HKDF and HMAC come from the standard library.

## Why OpenSSL rather than a port of the firmware's library

The firmware uses mlkem-native. The server uses OpenSSL. The two share no code.

If both ends ran the same implementation, a successful handshake would prove only
that the implementation agrees with itself — a broken one would interoperate just
as happily. Two independent implementations reaching the same shared secret is
evidence. It sits alongside, not instead of, the ACVP vectors in
[conformance.md](../docs/conformance.md): the vectors prove agreement with
FIPS 203, interoperability proves the protocol layer on top is not mis-wired.

## Running

```bash
python3 pqc_server.py --host 0.0.0.0 --port 8443
```

Defaults: key at `~/pqc-server/server_dk.pem`, device table at
`~/pqc-server/devices.json`. The server refuses to start if the device table is
group- or world-readable, since it holds PSKs.

## Testing

```bash
python3 test_client.py --host 127.0.0.1 --port 8443
python3 test_client.py --host 127.0.0.1 --port 8443 --negative
```

The negative tests are the ones that matter. A server that accepts a forged MAC
passes the happy path perfectly.

```
  ok    forged PSK MAC: rejected
  ok    unknown device_id: rejected
  ok    wrong PSK: rejected
  ok    forged ClientFinished: rejected
  ok    replayed data record: rejected
  ok    tampered ciphertext: rejected
```

The test client uses OpenSSL for encapsulation, exactly as the server does for
decapsulation. It therefore tests the *server*, not ML-KEM, and establishes no
cross-implementation claim. That claim belongs to the firmware.

## Measured on a Raspberry Pi 3 Model B

From the first end-to-end run:

| | |
|---|---|
| Handshake, wire | 1279 bytes — matching the specification's arithmetic exactly |
| Handshake, server wall clock | 41.2 ms |
| of which ML-KEM decapsulation | 29.7 ms |
| Data record | 57 bytes for a 28-byte payload |

The decapsulation figure includes process startup for the OpenSSL command line,
so it says more about shelling out than about ML-KEM. It is recorded because it
is real, not because it is a benchmark — the numbers this project is about are
measured on the device, not here.

## Not a production server

Single-threaded, one connection at a time, no TLS around it, no rate limiting
beyond the PSK check, no supervision. It exists to be read and to be correct, not
to be deployed.
