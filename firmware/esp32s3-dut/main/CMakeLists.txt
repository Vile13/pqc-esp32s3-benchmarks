idf_component_register(
    SRCS
        "main.c"
        "mlkem_selftest.c"
        "mlkem_kat.c"
    INCLUDE_DIRS "."
    REQUIRES
        mlkem
    PRIV_REQUIRES
        # Naming REQUIRES above drops the implicit component set, so everything
        # main.c pulls in has to be listed explicitly.
        spi_flash      # esp_flash.h  - flash size
        esp_timer      # esp_timer.h  - cross-check for the cycle counter
        esp_hw_support # esp_cpu.h, esp_memory_utils.h
        heap           # esp_heap_caps.h
)
