#ifndef MLKEM_SELFTEST_H
#define MLKEM_SELFTEST_H

#include <stdbool.h>

/* Round-trip and implicit-rejection checks for ML-KEM-512 and ML-KEM-768.
 * Consistency only - conformance is decided by the ACVP vectors. */
bool mlkem_selftest_run(void);

#endif /* MLKEM_SELFTEST_H */
