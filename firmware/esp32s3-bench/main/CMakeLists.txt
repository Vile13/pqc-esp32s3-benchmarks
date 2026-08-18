idf_component_register(
    SRCS
        "main.c"
        "bench.c"
    INCLUDE_DIRS "."
    REQUIRES
        mlkem
    PRIV_REQUIRES
        esp_hw_support  # esp_cpu.h - cycle counter
        esp_timer
        heap
        mbedtls         # X25519 baseline
)
