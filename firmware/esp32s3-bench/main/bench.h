#ifndef BENCH_H
#define BENCH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* One measured operation. */
typedef void (*bench_op_t)(void);

typedef struct
{
    const char *name;
    int iterations;
    uint32_t min;
    uint32_t median;
    uint32_t max;
    double mean;
    double stddev;
    size_t stack_bytes; /* peak stack of a single call, 0 if not measured */
} bench_result_t;

/*
 * Time `op` over `iterations` runs and report the distribution in CPU cycles.
 *
 * The spread is not noise to be averaged away: the FreeRTOS tick runs at 100 Hz
 * and an operation that straddles a tick pays for it. `min` is therefore the
 * cleanest estimate of pure computation, while `max` shows what interference
 * costs. Reporting only a mean would hide both.
 */
bool bench_measure(const char *name, bench_op_t op, int iterations,
                   bench_result_t *out);

/*
 * Peak stack consumed by a single call, measured by running `op` in a dedicated
 * task and reading its high-water mark. Returns 0 on failure.
 */
size_t bench_stack_usage(bench_op_t op);

void bench_print_header(void);
void bench_print(const bench_result_t *r);

#endif /* BENCH_H */
