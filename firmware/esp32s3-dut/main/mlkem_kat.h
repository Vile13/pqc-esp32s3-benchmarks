#ifndef MLKEM_KAT_H
#define MLKEM_KAT_H

#include <stdbool.h>

/* Run the NIST ACVP conformance vectors for ML-KEM-512 and ML-KEM-768 on the
 * device. Returns true only if every vector matches. */
bool mlkem_kat_run(void);

#endif /* MLKEM_KAT_H */
