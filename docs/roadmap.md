# Roadmap

The guiding constraint: **a measurement is only published once it is
trustworthy.** Each phase adds one source of variance at a time, so that when a
number moves it is clear what moved it. Sensors, radio and energy are therefore
deliberately kept out of the early phases — not because they are hard, but
because they would contaminate the baseline.

## v1 — the crypto core, no sensors, no radio

The device under test does nothing but cryptography. No Wi-Fi, no I2C, no
display.

- ML-KEM-512 and ML-KEM-768 (FIPS 203) building and running on the ESP32-S3
- Verified against the NIST Known Answer Tests — a benchmark of a wrong
  implementation is worthless
- Working buffers pinned to internal SRAM, enforced in the linker script and
  asserted at runtime (see [hardware.md](hardware.md))
- Measured per operation: cycles for key generation, encapsulation,
  decapsulation; peak stack via high-water marks; flash footprint
- Classical baseline: X25519 on the same board, same harness
- Repeated runs with reported spread, not single best-case numbers

**Done when:** KATs pass and repeated runs of the same build agree within a
stated tolerance.

## v2 — the secure channel with real payload

Now the handshake becomes a protocol and carries actual sensor data.

- Minimal documented handshake, ESP32-S3 to Raspberry Pi over Wi-Fi
- HKDF-SHA-256 for key derivation, AES-256-GCM for the data, replay protection
  via session ID and a monotonic sequence counter
- Authentication for v2: pinned server key plus a per-device PSK. This is a
  deliberate interim choice — it is quantum-resistant when the PSK is long and
  properly provisioned, and it avoids pulling ML-DSA into the measurement before
  the channel itself is trustworthy.
- SCD41 as payload; GY-21P supplying ambient pressure for CO₂ compensation
- Energy per handshake, measured by the NodeMCU + INA219 on the supply line
- Bytes on the wire per handshake versus bytes of payload — **the central ratio
  of this project**
- Hybrid mode: X25519 + ML-KEM-768, for comparison against both baselines

**Done when:** the re-keying question from the README can be answered with
measured millijoules across the classical, post-quantum and hybrid configurations.

## v3 — presentation and hardening

- SSD1306 showing live handshake timings, for the README demo
- Malformed-ciphertext and replay tests
- Plots generated from the committed result files, not hand-drawn
- Documented limitations: what was measured, what was not, what the numbers do
  not support

## Later, explicitly not now

- **ML-DSA (FIPS 204)** as an authentication alternative to the PSK. Interesting,
  but it changes flash, RAM and message volume all at once and belongs after the
  baseline is solid.
- **SLH-DSA (FIPS 205)** as a contrast case — large signatures, useful for
  showing where the embedded limit actually is.
- **TLS 1.3 / DTLS** via wolfSSL, as a realistic-protocol comparison against the
  custom handshake.
- **Secure Boot and OTA verification** with PQC signatures.
- **TSL2561** as a payload-size scaling knob, to test whether the handshake
  overhead ratio behaves as predicted when the payload grows.

## Non-goals

This project does not make side-channel resistance claims. Timing and power
traces are collected for performance analysis, and using them for a leakage
assessment would require a threat model, methodology and equipment that are not
in place here. Saying so is more useful than implying protection that was never
tested.
