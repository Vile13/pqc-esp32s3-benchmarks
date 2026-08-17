/*
 * Bring-up check for the device under test.
 *
 * This firmware contains no cryptography on purpose. Before any ML-KEM number
 * is worth reporting, three things have to be established on the real board:
 *
 *   1. the toolchain produces a binary that runs,
 *   2. memory placement is controllable - crypto buffers land in internal SRAM
 *      and stay there (see docs/hardware.md),
 *   3. the cycle counter agrees with the configured clock, so that later
 *      measurements can be reported in cycles rather than guessed.
 *
 * If any of these fails, every subsequent benchmark is meaningless.
 */

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "esp_chip_info.h"
#include "esp_cpu.h"
#include "esp_flash.h"
#include "esp_heap_caps.h"
#include "esp_memory_utils.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "mlkem_selftest.h"

/* Roughly the largest working buffer an ML-KEM-768 operation is expected to
 * need. Used here only to prove the allocation lands where we claim it does. */
#define CRYPTO_SCRATCH_BYTES 8192

static void report_chip(void)
{
    esp_chip_info_t info;
    esp_chip_info(&info);

    uint32_t flash_bytes = 0;
    if (esp_flash_get_size(NULL, &flash_bytes) != ESP_OK) {
        flash_bytes = 0;
    }

    printf("\n=== device under test ===\n");
    printf("cores          : %d\n", info.cores);
    printf("silicon rev    : v%d.%d\n", info.revision / 100, info.revision % 100);
    printf("cpu frequency  : %d MHz\n", CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ);
    printf("flash          : %" PRIu32 " MB\n", flash_bytes / (1024 * 1024));
    /* CHIP_FEATURE_EMB_PSRAM is not set on this ESP32-S3 even though 8 MB of
     * octal PSRAM is present and initialised, so the heap is asked instead of
     * the feature bit. */
    size_t psram_bytes = heap_caps_get_total_size(MALLOC_CAP_SPIRAM);
    printf("features       : %s%s%s\n",
           (info.features & CHIP_FEATURE_WIFI_BGN) ? "wifi " : "",
           (info.features & CHIP_FEATURE_BLE) ? "ble " : "",
           (psram_bytes > 0) ? "psram " : "");
    printf("psram          : %u MB\n", (unsigned)(psram_bytes / (1024 * 1024)));
}

static void report_memory(void)
{
    printf("\n=== memory ===\n");
    printf("internal free  : %u bytes\n",
           (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
    printf("psram free     : %u bytes\n",
           (unsigned)heap_caps_get_free_size(MALLOC_CAP_SPIRAM));
}

/*
 * The invariant this whole project rests on: a buffer meant for cryptography
 * must not end up in PSRAM, where access is serial and timing is far less
 * predictable. Measuring SPI latency and calling it ML-KEM would be the easiest
 * way to publish a wrong number.
 *
 * Verified rather than assumed: SPIRAM_USE_CAPS_ALLOC keeps plain malloc() in
 * internal SRAM, and this checks that the compiled configuration actually
 * behaves that way on this board.
 */
static bool verify_buffer_placement(void)
{
    bool ok = true;

    printf("\n=== buffer placement ===\n");

    void *scratch = malloc(CRYPTO_SCRATCH_BYTES);
    if (scratch == NULL) {
        printf("FAIL  plain malloc(%d) returned NULL\n", CRYPTO_SCRATCH_BYTES);
        return false;
    }
    bool scratch_internal = esp_ptr_internal(scratch);
    printf("%s  plain malloc -> %s (%p)\n",
           scratch_internal ? "ok  " : "FAIL",
           scratch_internal ? "internal SRAM" : "PSRAM",
           scratch);
    ok &= scratch_internal;
    free(scratch);

    /* The counter-check: PSRAM must still be reachable on request, otherwise
     * the board is not configured the way docs/hardware.md describes. */
    void *external = heap_caps_malloc(CRYPTO_SCRATCH_BYTES, MALLOC_CAP_SPIRAM);
    if (external == NULL) {
        printf("FAIL  MALLOC_CAP_SPIRAM returned NULL - PSRAM not usable\n");
        return false;
    }
    bool external_is_psram = esp_ptr_external_ram(external);
    printf("%s  explicit SPIRAM request -> %s (%p)\n",
           external_is_psram ? "ok  " : "FAIL",
           external_is_psram ? "PSRAM" : "internal SRAM",
           external);
    ok &= external_is_psram;
    heap_caps_free(external);

    return ok;
}

/*
 * Cross-checks the CPU cycle counter against esp_timer, which is driven by a
 * separate clock source. Later benchmarks report cycles; if the counter does
 * not tick at the configured frequency, those cycle figures cannot be converted
 * to time and comparisons against other platforms fall apart.
 */
static bool verify_cycle_counter(void)
{
    const int64_t window_us = 200000; /* 200 ms */

    printf("\n=== cycle counter ===\n");

    int64_t t0 = esp_timer_get_time();
    uint32_t c0 = esp_cpu_get_cycle_count();
    while ((esp_timer_get_time() - t0) < window_us) {
        /* busy wait: no sleeping, the core must stay clocked */
    }
    uint32_t c1 = esp_cpu_get_cycle_count();
    int64_t t1 = esp_timer_get_time();

    uint32_t cycles = c1 - c0; /* unsigned wrap is intentional and correct */
    int64_t elapsed_us = t1 - t0;
    double measured_mhz = (double)cycles / (double)elapsed_us;

    printf("elapsed        : %" PRId64 " us\n", elapsed_us);
    printf("cycles         : %" PRIu32 "\n", cycles);
    printf("implied clock  : %.2f MHz (configured %d MHz)\n",
           measured_mhz, CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ);

    double deviation = measured_mhz - (double)CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ;
    if (deviation < 0) {
        deviation = -deviation;
    }
    bool ok = deviation < 2.0;
    printf("%s  deviation %.2f MHz (tolerance 2.00 MHz)\n",
           ok ? "ok  " : "FAIL", deviation);

    return ok;
}

void app_main(void)
{
    /* Let the console settle so the first lines are not cut off. */
    vTaskDelay(pdMS_TO_TICKS(200));

    report_chip();
    report_memory();

    bool placement_ok = verify_buffer_placement();
    bool counter_ok = verify_cycle_counter();
    bool selftest_ok = mlkem_selftest_run();

    printf("\n=== bring-up result ===\n");
    printf("buffer placement : %s\n", placement_ok ? "PASS" : "FAIL");
    printf("cycle counter    : %s\n", counter_ok ? "PASS" : "FAIL");
    printf("mlkem self-test  : %s\n", selftest_ok ? "PASS" : "FAIL");
    printf("overall          : %s\n",
           (placement_ok && counter_ok && selftest_ok) ? "PASS" : "FAIL");
    printf("\nconsistency only - ACVP conformance vectors still outstanding\n");
}
