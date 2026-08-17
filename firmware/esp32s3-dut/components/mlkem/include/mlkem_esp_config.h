/*
 * mlkem-native configuration for this project.
 *
 * Selected through -DMLK_CONFIG_FILE so that the upstream submodule stays
 * untouched and can be re-pinned to a new release without merging local edits.
 */

#ifndef MLKEM_ESP_CONFIG_H
#define MLKEM_ESP_CONFIG_H

/* Default level when a translation unit does not set one explicitly.
 * mlkem_native_all.c overrides this per inclusion. */
#ifndef MLK_CONFIG_PARAMETER_SET
#define MLK_CONFIG_PARAMETER_SET 768
#endif

/* Exported symbols become mlkem512_*, mlkem768_*, ... */
#define MLK_CONFIG_NAMESPACE_PREFIX mlkem

/* Several parameter sets live in one binary; shared code is emitted once. */
#define MLK_CONFIG_MULTILEVEL_BUILD

/*
 * No native backend.
 *
 * ML-KEM leans on Keccak/SHAKE, and the ESP32-S3's SHA accelerator covers
 * SHA-1 and SHA-2 only - it does not touch Keccak. There is no Xtensa LX7
 * backend in mlkem-native either, so this build is portable C throughout.
 * That is the honest baseline to measure first; hand-optimising Keccak or the
 * NTT for Xtensa is a later work package, and it only means something when
 * compared against a number measured here.
 */

#endif /* MLKEM_ESP_CONFIG_H */
