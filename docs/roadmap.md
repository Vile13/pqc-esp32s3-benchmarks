# Roadmap

Two rules shape the order of work:

1. **Correctness before communication.** An implementation that is wrong will
   still appear to work end to end, so it is verified against reference vectors
   first.
2. **A measurement is only published once it is trustworthy.** Benchmarking
   comes after the system works, on builds stripped of everything that would
   contaminate the numbers.

## v1 — the vertical slice

Goal: an ESP32-S3 establishes a post-quantum session key with a Raspberry Pi and
sends authenticated, encrypted data over it.

### v1.0 — ML-KEM, verified ✅ done (2026-08-17)

- mlkem-native integrated as an ESP-IDF component, ML-KEM-512 and ML-KEM-768
- Working buffers pinned to internal SRAM, enforced at build time and asserted at
  runtime (verified in [bringup.md](bringup.md))
- **Verified against the NIST Known Answer Tests before anything talks to
  anything**

Why the KATs come first, and not after the demo: if both ends run the same
faulty implementation, they still agree on a shared secret. AES-GCM decrypts,
the sensor data arrives, and the system looks correct from the outside. A broken
RNG, a mis-wired parameter set or a swapped byte encoding all survive that test
unnoticed. Interoperability proves two implementations agree; only KATs prove
they agree with FIPS 203.

**Done when:** KATs pass for both parameter sets on the board itself.

Result: 160 of 160 ACVP vectors pass on the device, covering every group
defined for these two parameter sets — including the FIPS 203 §7.2 key validity
checks that decide whether a malformed key arriving over the network is rejected
or quietly processed. See [conformance.md](conformance.md).

### v1.1 — the handshake ✅ done (2026-08-18)

- Protocol specified before implementation: [protocol.md](protocol.md)
- Transport is plain TCP, not MQTT. A handshake is request/response, MQTT is
  publish/subscribe, and the broker would sit in the middle of the later
  measurement path. Mosquitto, Node-RED and MariaDB are already running on the
  Pi and get used in v3, where the finished session layer is embedded into that
  stack.
- The Pi's ML-KEM comes from **OpenSSL 3.5.6**, which supports it natively — an
  implementation sharing no code with mlkem-native, so interoperability is real
  evidence rather than a mirror.
- Minimal documented protocol, ESP32-S3 to Raspberry Pi over Wi-Fi
- HKDF-SHA-256 for key derivation, AES-256-GCM for the payload
- Replay protection: session ID plus a monotonic sequence counter
- Authentication: pinned server key plus a per-device PSK. A deliberate interim
  choice — quantum-resistant given a long, properly provisioned PSK, and it
  keeps ML-DSA out of the picture until the channel itself is trustworthy.
- Python reference server on the Pi

The Pi runs an independent implementation of ML-KEM, not a port of the firmware's.
When two different implementations interoperate, that is genuine evidence rather
than a mirror — a useful second signal alongside the KATs.

**Done when:** the S3 sends encrypted, authenticated data the Pi can decrypt,
and a tampered ciphertext or a replayed frame is rejected.

Result: done, see [interop.md](interop.md). Rejection paths are covered in both
directions — six against the server via `server/test_client.py --negative`, seven
against the firmware via `tests/hostile_server_drill.py`.

## v2 — measurement

Only now do numbers get produced, and the harness is built to earn them.

Benchmarks of the crypto core run on a **radio-free build**: no Wi-Fi, no I2C, no
display. Retransmissions, power management and sensor timing would all land
inside the measurement window and make a fluctuating number impossible to
attribute. The protocol figures are measured separately, with the radio on, and
reported as such.

- Per operation: cycles for key generation, encapsulation, decapsulation; peak
  stack via high-water marks; flash footprint
- Classical baseline (X25519) and hybrid (X25519 + ML-KEM-768) on the same harness
- Repeated runs with reported spread, never single best-case figures
- Energy per handshake, measured by the NodeMCU + INA219 in the supply line —
  the device under test never measures itself (see [hardware.md](hardware.md))
- Bytes on the wire per handshake versus bytes of payload — **the central ratio
  of this project**

**Done when:** the re-keying question from the README can be answered in
millijoules across the classical, post-quantum and hybrid configurations.

## v3 — payload and presentation

- SCD41 as the real payload; GY-21P supplying ambient pressure for CO₂ compensation
- SSD1306 showing live handshake timings, for the README demo
- Malformed-ciphertext, replay and fuzzing tests
- Plots generated from the committed result files, not drawn by hand
- Documented limitations: what was measured, what was not, and what the numbers
  do not support

## Later, explicitly not now

- **ML-DSA (FIPS 204)** as an authentication alternative to the PSK. It shifts
  flash, RAM and message volume all at once, so it belongs after a stable baseline.
- **SLH-DSA (FIPS 205)** as a contrast case — large signatures show where the
  embedded limit actually sits.
- **TLS 1.3 / DTLS** via wolfSSL, as a realistic-protocol comparison against the
  custom handshake.
- **Secure Boot and OTA verification** with PQC signatures.
- **TSL2561** as a payload-size scaling knob, to test whether the overhead ratio
  behaves as predicted when the payload grows.

## Non-goals

This project makes no side-channel resistance claims. Timing and power traces are
collected for performance analysis; using them for a leakage assessment would
require a threat model, methodology and equipment that are not in place here.
Saying so is more useful than implying protection that was never tested.
