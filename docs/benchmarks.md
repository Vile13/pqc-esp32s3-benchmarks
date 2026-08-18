# Benchmarks

Measured 2026-08-18 on the board described in [hardware.md](hardware.md).

## How these were taken

`firmware/esp32s3-bench/` is a **separate project that never initialises the
radio**. No Wi-Fi, no lwIP, no I2C, no display: retransmissions, power-management
transitions and sensor timing would all land inside a measurement window and make
a fluctuating figure impossible to attribute.

The consequence is deliberate. Without the radio the hardware RNG has no
guaranteed entropy source, so `randombytes()` refuses to serve and every
operation runs through the `*_derand` API with fixed inputs. Fixed inputs are
what a benchmark wants anyway.

| | |
|---|---|
| Chip | ESP32-S3 rev v0.2, 2 cores, 240 MHz |
| Toolchain | ESP-IDF v5.5.5, portable C, no native backend |
| ML-KEM | mlkem-native v2.0.0 |
| Iterations | 50 per operation, after two warm-up calls |
| Buffer placement | verified internal SRAM before every run |
| FreeRTOS tick | 100 Hz |

**Why min, median and max rather than an average.** The spread is not noise to
average away: it is the 100 Hz tick landing inside some measurement windows.
`min` is the cleanest estimate of pure computation, `max` shows what the
interference costs, and the standard deviation shows how often it happens.
Reporting only a mean would hide both.

## Results

Cycles at 240 MHz. Divide by 240,000 for milliseconds.

| Operation | min | median | max | stddev | peak stack |
|---|---|---|---|---|---|
| ML-KEM-512 keygen | 826,946 | 827,032 | 828,557 | 735 | 9,960 B |
| ML-KEM-512 encaps | 977,622 | 977,717 | 981,832 | 887 | 12,600 B |
| ML-KEM-512 decaps | 1,249,586 | 1,251,037 | 1,251,209 | 744 | 13,416 B |
| ML-KEM-768 keygen | 1,320,311 | 1,321,788 | 1,323,448 | 808 | 14,312 B |
| ML-KEM-768 encaps | 1,549,938 | 1,551,438 | 1,552,184 | 724 | 17,464 B |
| ML-KEM-768 decaps | 1,916,997 | 1,919,235 | 1,921,981 | 1,462 | 18,600 B |
| X25519 keygen (ecp API) | 21,321,656 | 21,488,532 | 21,493,142 | 71,653 | 1,336 B |
| X25519 derive (ecp API) | 22,053,998 | 22,249,858 | 22,426,078 | 104,047 | 1,400 B |
| X25519 full exchange (ecdh API) | 87,223,913 | 87,277,197 | 87,770,346 | 239,225 | 1,848 B |

In milliseconds, ML-KEM-768: keygen 5.5 ms, encapsulation 6.5 ms, decapsulation
8.0 ms. The relative spread is under 0.2 % throughout.

### Flash

From `idf.py size-components`:

| Archive | Flash code | Flash data | Total |
|---|---|---|---|
| `libmlkem.a` (ML-KEM-512 + 768) | 13,915 B | 448 B | **14,363 B** |
| `libmbedcrypto.a` (for comparison) | 20,247 B | 2,573 B | 22,966 B |

14.4 KB of flash covers both parameter sets including the shared Keccak code.

## The X25519 comparison needs a caveat, and it is a big one

Taken at face value the table says ML-KEM-768 beats X25519 by a factor of
roughly eighteen: 4.79 M cycles for keygen + encaps + decaps against 87.2 M for a
full X25519 exchange. **Do not read that as "ML-KEM is faster than elliptic
curves on embedded hardware."** It is not what was measured.

What was measured is X25519 *as ESP-IDF ships it*, which is mbedtls's generic
bignum ECP path. mbedtls can route Curve25519 to the Everest implementation,
which is dramatically faster — but ESP-IDF does not compile it. In this build
`libeverest.a` contains **zero defined functions**, verified with `nm`. There is
no fast path available to call.

To rule out the obvious objection that the wrong entry point was measured, both
mbedtls APIs were timed: the raw ECP functions and the `mbedtls_ecdh_context`
API, which is the one that would dispatch to Everest if it existed. The full
exchange through the context API costs 87.2 M cycles, which is within 1 % of
2 × keygen + 2 × derive measured through the ECP path. Both agree, because both
end up in the same code.

For context, published Curve25519 implementations on comparable 32-bit
microcontrollers run in the low millions of cycles. A dedicated X25519 on this
chip would plausibly land in the same range as ML-KEM-768 rather than an order of
magnitude above it.

**So the honest statement is narrower and more useful:** on an ESP32-S3 using the
cryptography ESP-IDF actually provides, post-quantum key establishment with
ML-KEM-768 is *cheaper* than classical X25519 key establishment. The
post-quantum migration cost on this platform is not a slowdown in computation. It
is 1184 and 1088 bytes per key and ciphertext against 32 — a bandwidth and memory
cost, not a CPU one.

That reframes the project's research question rather than answering it: the
handshake is expensive because of what it *transmits*, not what it *computes*.

## Stack is where the real asymmetry is

| | ML-KEM-768 | X25519 |
|---|---|---|
| Peak stack, worst operation | 18,600 B | 1,848 B |
| Public key | 1,184 B | 32 B |
| Ciphertext / ephemeral public | 1,088 B | 32 B |
| Private key | 2,400 B | 32 B |

Ten times the stack and thirty times the key material. On a device with 512 KB of
SRAM that is affordable; the point of measuring it is that it is the figure that
would stop being affordable first, and it is why the default 3,584-byte ESP-IDF
main task stack silently overflows (see [conformance.md](conformance.md)).

## Not measured here

- **Energy.** Nothing in this document is a power measurement, and cycles are not
  a proxy: the 200 ms difference between protocol modes A and B
  ([interop.md](interop.md)) is dominated by radio and by the peer, both of which
  draw very different current from a busy CPU. The INA219 harness described in
  [hardware.md](hardware.md) is the next piece of work.
- **Hybrid X25519 + ML-KEM-768.** Both halves are measured; the combination is
  not yet wired into the protocol.
- **Side channels.** Timing figures here are performance data. Using them for a
  leakage assessment would need a threat model and equipment this project does
  not have, and it is listed as a non-goal in [protocol.md](protocol.md).

## Reproducing

```bash
. ~/esp/esp-idf/export.sh
cd firmware/esp32s3-bench
idf.py set-target esp32s3
idf.py -p <port> flash monitor
```

No provisioning is needed: this build has no credentials, no server and no
network.
