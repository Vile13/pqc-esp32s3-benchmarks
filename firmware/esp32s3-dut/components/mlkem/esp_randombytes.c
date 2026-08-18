/*
 * Random source for mlkem-native on ESP32.
 *
 * mlkem-native deliberately ships no RNG: randombytes() is the consumer's
 * responsibility. On this platform that is esp_fill_random().
 *
 * IMPORTANT - read docs/hardware.md before relying on this.
 *
 * The ESP32 hardware RNG is only guaranteed to produce true random numbers
 * while Wi-Fi or Bluetooth is enabled. The radio-free build used for
 * benchmarking is therefore exactly the configuration in which this function
 * must NOT be used to generate keys that matter. Weak randomness in ML-KEM key
 * generation is not a degradation, it is a total loss of security, and it
 * leaves no trace in the output.
 *
 * Consequently:
 *   - benchmarks call the *_derand() API with fixed coins and never reach here,
 *   - the protocol build calls the randomized API with the radio up, which is
 *     the supported configuration.
 *
 * The runtime guard below makes a violation of that split loud instead of
 * silent.
 */

#include <stddef.h>
#include <stdint.h>

#include "esp_log.h"
#include "esp_random.h"
#include "sdkconfig.h"

#if defined(CONFIG_ESP_WIFI_ENABLED)
#include "esp_wifi.h"
#endif

static const char *TAG = "mlkem_rng";

/*
 * The condition is that the radio is RUNNING, not that it is compiled in.
 * CONFIG_ESP_WIFI_ENABLED is set by default on every chip that has Wi-Fi, so a
 * compile-time check alone would pass in a build that never calls
 * esp_wifi_start() - exactly the case this is supposed to catch.
 */
static bool rf_entropy_available(void)
{
#if defined(CONFIG_ESP_WIFI_ENABLED)
    wifi_mode_t mode;
    /* Returns ESP_ERR_WIFI_NOT_INIT until esp_wifi_init() has run, and reports
     * WIFI_MODE_NULL while the radio is initialised but idle. */
    if (esp_wifi_get_mode(&mode) == ESP_OK && mode != WIFI_MODE_NULL) {
        return true;
    }
#endif
#if defined(CONFIG_BT_ENABLED)
    return true; /* Bluetooth controller state is not queried here. */
#else
    return false;
#endif
}

int randombytes(uint8_t *out, size_t outlen)
{
    if (out == NULL) {
        return -1;
    }

    if (!rf_entropy_available()) {
        /* Refuse rather than hand back key material that looks perfectly
         * random and is not. Benchmarks must use the _derand API. */
        ESP_LOGE(TAG,
                 "randombytes() called while the radio is not running - the "
                 "hardware RNG has no guaranteed entropy source. Use the "
                 "_derand API for benchmarks. Refusing.");
        return -1;
    }

    esp_fill_random(out, outlen);
    return 0;
}
