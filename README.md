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
- Forward secrecy via a per-session ephemeral ML-KEM key pair (protocol mode B),
  measured against the static-key mode on the same board
- Classical baseline (X25519) and hybrid (X25519 + ML-KEM-768) for comparison
- Runtime, peak stack, heap, flash footprint, network volume, energy per handshake
- A minimal documented handshake protocol ([spec](docs/protocol.md)), carrying
  real sensor data
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

**Benchmarks:** measured on a radio-free build — ML-KEM-768 keygen 5.5 ms,
encapsulation 6.5 ms, decapsulation 8.0 ms at 240 MHz, 14.4 KB of flash for both
parameter sets, 18.6 KB peak stack. Full table, method and the important caveat
about the X25519 baseline in [docs/benchmarks.md](docs/benchmarks.md).

The headline finding is not the one expected: on an ESP32-S3 using the
cryptography ESP-IDF actually ships, ML-KEM-768 key establishment is *cheaper in
CPU time* than classical X25519. The post-quantum cost on this platform is
bandwidth and memory, not computation — which sharpens the research question
above rather than answering it.

**Energy:** _pending_ — cycles are not joules, and the INA219 harness is the next
piece of work.

**Correctness:** ML-KEM-512 and ML-KEM-768 pass all 160 NIST ACVP vectors on the
device — every group defined for these parameter sets, including the FIPS 203
§7.2 key validity checks. The vectors come from
NIST's ACVP-Server, not from the library under test, so passing them is evidence
rather than a tautology. Details, scope and provenance in
[docs/conformance.md](docs/conformance.md).

**Vertical slice:** an ESP32-S3 establishes an ML-KEM-768 session with a
Raspberry Pi and sends AES-256-GCM encrypted records over it. The two ends share
no cryptographic code — mlkem-native on the device, OpenSSL on the server — so
interoperating is evidence rather than a mirror. Handshake 105 ms on the device,
1279 bytes on the wire, exactly the figure the specification predicted before any
code existed. See [docs/interop.md](docs/interop.md).

**Bring-up:** toolchain builds and runs, buffer placement in internal SRAM is
verified on the board rather than assumed, and the cycle counter agrees with the
configured 240 MHz clock — [docs/bringup.md](docs/bringup.md).

## Setting it up

Provisioning — server key pair, device identity, PSK, Wi-Fi — is described in
[docs/provisioning.md](docs/provisioning.md). Credentials live in gitignored
files and are never committed.

## Repository layout

```
firmware/    ESP-IDF project for the ESP32-S3 (device under test)
server/      Python reference server (counterpart of the handshake)
benchmarks/  measurement harness, raw results, plots
tests/       NIST ACVP vectors, malformed-input and replay tests
tools/       provisioning helpers
docs/        hardware, protocol, provisioning, conformance, limitations
```

## License

_pending_
