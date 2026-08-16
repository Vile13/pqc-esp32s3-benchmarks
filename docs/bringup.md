# Bring-up

Verified on 2026-08-16 with ESP-IDF v5.5.5 on the board described in
[hardware.md](hardware.md). This is not a benchmark — it is the precondition
for one.

## What is checked, and why

| Check | Fails if | Consequence if unnoticed |
|---|---|---|
| Toolchain builds and runs | Binary does not boot | Nothing else is possible |
| `malloc()` returns internal SRAM | A buffer lands in PSRAM | Benchmarks measure SPI latency, not ML-KEM |
| PSRAM reachable on request | `MALLOC_CAP_SPIRAM` returns NULL | Board is not configured as documented |
| Cycle counter matches the clock | Counter drifts from `esp_timer` | Cycle figures cannot be converted to time |

The buffer-placement check is the one that matters. ML-KEM is dominated by
temporary polynomial buffers, and PSRAM is reached over a serial bus. A single
stray allocation would quietly turn a cryptographic benchmark into a memory-bus
benchmark, and the resulting numbers would look entirely plausible.

## Result

```
=== device under test ===
cores          : 2
silicon rev    : v0.2
cpu frequency  : 240 MHz
flash          : 8 MB
features       : wifi ble psram
psram          : 8 MB

=== memory ===
internal free  : 382560 bytes
psram free     : 8386156 bytes

=== buffer placement ===
ok    plain malloc -> internal SRAM (0x3fce9a54)
ok    explicit SPIRAM request -> PSRAM (0x3c030998)

=== cycle counter ===
elapsed        : 200000 us
cycles         : 47999949
implied clock  : 240.00 MHz (configured 240 MHz)
ok    deviation 0.00 MHz (tolerance 2.00 MHz)

=== bring-up result ===
buffer placement : PASS
cycle counter    : PASS
overall          : PASS
```

Two observations worth keeping:

- The cycle counter and `esp_timer` agree to within measurement resolution
  (47,999,949 cycles over 200,000 µs = 240.00 MHz). Benchmarks can therefore be
  reported in cycles and converted to time with confidence.
- `esp_chip_info()` does **not** set `CHIP_FEATURE_EMB_PSRAM` on this board even
  though 8 MB of octal PSRAM is present and initialised. PSRAM presence is
  derived from `heap_caps_get_total_size(MALLOC_CAP_SPIRAM)` instead. A feature
  bit that reports the opposite of reality is exactly the kind of detail that
  ends up in a README as a false claim.

## Reproducing

```bash
. ~/esp/esp-idf/export.sh
cd firmware/esp32s3-dut
idf.py set-target esp32s3
idf.py -p /dev/cu.usbserial-1410 flash monitor
```

## Toolchain note

ESP-IDF's `install.sh` does not install `cmake` or `ninja` on macOS — it assumes
they are present system-wide. Installing them through ESP-IDF's own tool manager
keeps the whole toolchain self-contained under `~/.espressif`:

```bash
python3 $IDF_PATH/tools/idf_tools.py install cmake ninja
```
