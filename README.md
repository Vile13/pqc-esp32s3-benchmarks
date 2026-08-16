# pqc-esp32s3-benchmarks

Reproducible benchmarks for NIST post-quantum cryptography on the ESP32-S3,
measured on real hardware with an external power monitor.

> **Status: work in progress.** No results yet. Every number in this repository
> is measured on the hardware described in [docs/hardware.md](docs/hardware.md)
> or it is not published. Placeholders are marked `_pending_`.

## The research question

That ML-KEM runs on an ESP32 is already known. The open engineering question is
what it *costs* on a device that spends its life asleep.

A SCD41 sensor reading is roughly 10 bytes. An ML-KEM-768 ciphertext is 1088
bytes and the encapsulation key is 1184 bytes. On a battery-powered sensor node,
**the key exchange outweighs the data it protects by two orders of magnitude.**

That turns re-keying into a budget decision rather than a security preference:

> How often can a constrained IoT node afford to re-key, and what does forward
> secrecy cost there in millijoules?

Everything in this repository exists to answer that with measured numbers:
runtime, stack, flash, bytes on the wire, and energy per handshake.

## Scope

**In scope**

- ML-KEM-512 / ML-KEM-768 (FIPS 203) key establishment on ESP32-S3
- Classical baseline (X25519) and hybrid (X25519 + ML-KEM-768) for comparison
- Runtime, peak stack, heap, flash footprint, network volume, energy per handshake
- A minimal documented handshake protocol, carrying real sensor data
- NIST Known Answer Tests against the reference implementation

**Explicitly out of scope (for now)**

- ML-DSA / SLH-DSA signatures — planned for v2, see [docs/roadmap.md](docs/roadmap.md)
- TLS 1.3 / DTLS integration
- Secure Boot, OTA update verification
- Side-channel resistance claims of any kind

## Not a TLS replacement

The handshake in this repository is an **educational and experimental protocol**,
built so that each field is measurable and explainable. It is not reviewed, not
standardised, and not a substitute for TLS. Do not deploy it.

## Hardware

Measured device under test, verified by `esptool`:
ESP32-S3-DevKitC-1-N8R8, 8 MB flash, 8 MB PSRAM, dual core at 240 MHz.
Energy is measured by a **separate** board (NodeMCU/ESP8266 + INA219) in the
supply line, so the device under test never measures itself.

Full wiring, addresses and rationale: [docs/hardware.md](docs/hardware.md)

## Results

_pending_ — no measurement runs have been made yet.

Hardware bring-up passed on 2026-08-16: the toolchain builds and runs, buffer
placement in internal SRAM is verified on the board rather than assumed, and the
cycle counter agrees with the configured 240 MHz clock. Details and raw output
in [docs/bringup.md](docs/bringup.md).

## Repository layout

```
firmware/    ESP-IDF project for the ESP32-S3 (device under test)
server/      Python reference server (counterpart of the handshake)
benchmarks/  measurement harness, raw results, plots
tests/       NIST KATs, malformed-input and replay tests
docs/        hardware, protocol, threat model, limitations
```

## License

_pending_
