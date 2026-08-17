/*
 * Single compilation unit holding ML-KEM-512 and ML-KEM-768.
 *
 * mlkem-native's own multi-level Makefile compiles the whole source tree once
 * per parameter set. ESP-IDF's build system compiles a component's sources
 * exactly once, so that approach does not transfer. The monolithic pattern
 * below does: mlkem_native.c is included repeatedly with a different parameter
 * set each time, and level-independent code (Keccak, shared helpers) is emitted
 * only for the first inclusion.
 *
 * The ordering of the MLK_CONFIG_* defines matters and mirrors upstream's
 * monolithic_build_multilevel example. MLK_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS
 * is dropped before the final inclusion so shared headers are cleaned up once
 * at the end.
 */

/* Include the public API first, so MLK_CHECK_APIS can verify the individual
 * level builds below stay consistent with it. */
#include "mlkem_native_all.h"

#define MLK_CHECK_APIS

/* --- ML-KEM-512: emits the level-independent code as well --- */
#define MLK_CONFIG_MULTILEVEL_WITH_SHARED
#define MLK_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS
#define MLK_CONFIG_PARAMETER_SET 512
#include "mlkem_native.c"
#undef MLK_CONFIG_PARAMETER_SET
#undef MLK_CONFIG_MULTILEVEL_WITH_SHARED

/* --- ML-KEM-768: reuses the shared code emitted above --- */
#define MLK_CONFIG_MULTILEVEL_NO_SHARED
#undef MLK_CONFIG_MONOBUILD_KEEP_SHARED_HEADERS
#define MLK_CONFIG_PARAMETER_SET 768
#include "mlkem_native.c"
#undef MLK_CONFIG_PARAMETER_SET
