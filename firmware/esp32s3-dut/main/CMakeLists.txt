idf_component_register(
    SRCS
        "main.c"
        "mlkem_selftest.c"
        "mlkem_kat.c"
        "wifi_sta.c"
        "pqc_session.c"
    INCLUDE_DIRS "."
    REQUIRES
        mlkem
    PRIV_REQUIRES
        # Naming REQUIRES above drops the implicit component set, so everything
        # this component pulls in has to be listed explicitly.
        spi_flash      # esp_flash.h  - flash size
        esp_timer      # esp_timer.h  - cycle counter cross-check, timings
        esp_hw_support # esp_cpu.h, esp_memory_utils.h, esp_random.h
        heap           # esp_heap_caps.h
        esp_wifi       # station bring-up
        esp_netif      # IP stack glue
        esp_event      # Wi-Fi and IP events
        nvs_flash      # Wi-Fi calibration data
        lwip           # sockets
        mbedtls        # HKDF, HMAC-SHA256, AES-256-GCM
)

# The protocol client needs credentials and the pinned server key. Both are
# gitignored, so a fresh clone must be provisioned before it can build.
foreach(required device_config.h server_key.h)
    if(NOT EXISTS "${CMAKE_CURRENT_LIST_DIR}/${required}")
        message(FATAL_ERROR
            "\n  main/${required} is missing.\n"
            "  This file holds deployment state and is not in git.\n"
            "  See docs/provisioning.md.\n")
    endif()
endforeach()
