# ML-KEM (FIPS 203) via mlkem-native, pinned to release v2.0.0 as a submodule.
#
# Only two files are compiled: the monolithic wrapper that pulls in the upstream
# sources once per parameter set, and this project's random source. The submodule
# itself is never edited - configuration is injected through MLK_CONFIG_FILE.

idf_component_register(
    SRCS
        "mlkem_native_all.c"
        "esp_randombytes.c"
    INCLUDE_DIRS
        "include"
        "mlkem-native/mlkem"
    REQUIRES
        esp_hw_support
        log
)

# Point mlkem-native at this project's configuration instead of its default.
# PUBLIC, because mlkem_native.h resolves the config on the consumer side too.
target_compile_definitions(${COMPONENT_LIB}
    PUBLIC "MLK_CONFIG_FILE=\"mlkem_esp_config.h\""
)
