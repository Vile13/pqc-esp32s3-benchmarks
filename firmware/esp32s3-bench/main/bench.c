/*
 * Measurement harness.
 *
 * Two things it deliberately does not do:
 *
 *   - It does not disable interrupts around an operation. ML-KEM-768 key
 *     generation takes several milliseconds; suppressing the tick for that long
 *     would trade one distortion for a worse one. Instead the tick's effect is
 *     made visible in the spread.
 *   - It does not report a single number. A mean alone would hide both the
 *     clean-run cost and the cost of interference.
 */

#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_cpu.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "bench.h"

#define MAX_ITERATIONS 200

/*
 * Probe stack size in BYTES.
 *
 * Both FreeRTOS calls used below depart from vanilla FreeRTOS on ESP-IDF, and in
 * the same direction:
 *   - xTaskCreate's usStackDepth is bytes, not words
 *   - uxTaskGetStackHighWaterMark returns bytes, not words
 *
 * Getting either wrong is quiet: the first attempt here asked for 12288 bytes
 * believing it was 48 KB, and scaled the result by sizeof(StackType_t) on top.
 * The smaller operations still produced plausible-looking figures - four times
 * too large - before a larger one overflowed the task and made the mistake
 * visible. Plausible wrong numbers are the failure mode this project exists to
 * avoid, so the units are asserted rather than assumed.
 */
#define STACK_PROBE_BYTES (64 * 1024)
#define STACK_PROBE_MIN_HEADROOM 2048

static uint32_t s_samples[MAX_ITERATIONS];

static int compare_u32(const void *a, const void *b)
{
    uint32_t x = *(const uint32_t *)a;
    uint32_t y = *(const uint32_t *)b;
    return (x > y) - (x < y);
}

bool bench_measure(const char *name, bench_op_t op, int iterations,
                   bench_result_t *out)
{
    if (iterations < 3 || iterations > MAX_ITERATIONS) {
        return false;
    }

    /* Warm up: first call pays for cold caches and lazy initialisation, and that
     * is not what we are trying to report. */
    op();
    op();

    for (int i = 0; i < iterations; i++) {
        uint32_t start = esp_cpu_get_cycle_count();
        op();
        uint32_t end = esp_cpu_get_cycle_count();
        s_samples[i] = end - start; /* unsigned wrap is correct here */
    }

    double sum = 0.0;
    for (int i = 0; i < iterations; i++) {
        sum += (double)s_samples[i];
    }
    double mean = sum / iterations;

    double var = 0.0;
    for (int i = 0; i < iterations; i++) {
        double d = (double)s_samples[i] - mean;
        var += d * d;
    }

    qsort(s_samples, iterations, sizeof(s_samples[0]), compare_u32);

    out->name = name;
    out->iterations = iterations;
    out->min = s_samples[0];
    out->max = s_samples[iterations - 1];
    out->median = s_samples[iterations / 2];
    out->mean = mean;
    out->stddev = sqrt(var / iterations);
    out->stack_bytes = 0;
    return true;
}

/* ------------------------------------------------------------ stack usage -- */

static bench_op_t s_probe_op;
static volatile size_t s_probe_result;
static TaskHandle_t s_probe_caller;

static void stack_probe_task(void *arg)
{
    (void)arg;
    s_probe_op();
    /* Smallest free stack ever seen, in bytes on ESP-IDF. */
    size_t remaining = (size_t)uxTaskGetStackHighWaterMark(NULL);
    if (remaining < STACK_PROBE_MIN_HEADROOM) {
        /* Too close to the edge to trust: the true peak may have been clipped. */
        s_probe_result = 0;
    } else {
        s_probe_result = STACK_PROBE_BYTES - remaining;
    }
    xTaskNotifyGive(s_probe_caller);
    vTaskDelete(NULL);
}

size_t bench_stack_usage(bench_op_t op)
{
    s_probe_op = op;
    s_probe_result = 0;
    s_probe_caller = xTaskGetCurrentTaskHandle();

    TaskHandle_t task = NULL;
    /* Pinned to a core so the measurement is not split across two stacks. */
    BaseType_t ok = xTaskCreatePinnedToCore(stack_probe_task, "stackprobe",
                                            STACK_PROBE_BYTES, NULL, 5, &task, 1);
    if (ok != pdPASS) {
        return 0;
    }

    ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(20000));
    return s_probe_result;
}

/* ---------------------------------------------------------------- printing -- */

void bench_print_header(void)
{
    printf("\n%-26s %5s %10s %10s %10s %9s %8s\n", "operation", "runs",
           "min", "median", "max", "stddev", "stack");
    printf("%-26s %5s %10s %10s %10s %9s %8s\n", "", "", "cycles", "cycles",
           "cycles", "cycles", "bytes");
    printf("--------------------------------------------------------"
           "--------------------------\n");
}

void bench_print(const bench_result_t *r)
{
    printf("%-26s %5d %10" PRIu32 " %10" PRIu32 " %10" PRIu32 " %9.0f",
           r->name, r->iterations, r->min, r->median, r->max, r->stddev);
    if (r->stack_bytes) {
        printf(" %8u\n", (unsigned)r->stack_bytes);
    } else {
        printf(" %8s\n", "-");
    }
}
