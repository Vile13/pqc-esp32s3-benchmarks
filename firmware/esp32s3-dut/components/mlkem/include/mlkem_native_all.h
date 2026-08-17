/*
 * Multi-level ML-KEM API: ML-KEM-512 and ML-KEM-768 in one binary.
 *
 * Follows the pattern from mlkem-native's monolithic_build_multilevel example.
 * ML-KEM-1024 is deliberately left out - the project's scope is 512 and 768
 * (see docs/roadmap.md). Adding it is two lines here and two in
 * mlkem_native_all.c.
 *
 * Exposed symbols: mlkem512_* and mlkem768_*.
 */

#if !defined(MLKEM_NATIVE_ALL_H)
#define MLKEM_NATIVE_ALL_H

/* API for ML-KEM-512 */
#define MLK_CONFIG_PARAMETER_SET 512
#include <mlkem_native.h>
#undef MLK_CONFIG_PARAMETER_SET
#undef MLK_H

/* API for ML-KEM-768 */
#define MLK_CONFIG_PARAMETER_SET 768
#include <mlkem_native.h>
#undef MLK_CONFIG_PARAMETER_SET
#undef MLK_H

#endif /* !MLKEM_NATIVE_ALL_H */
