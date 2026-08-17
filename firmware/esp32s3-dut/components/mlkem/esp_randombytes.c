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

static const char *TAG = "mlkem_rng";

#if !defined(CONFIG_ESP_WIFI_ENABLED) && !defined(CONFIG_BT_ENABLED)
#define MLKEM_RNG_NO_RF_ENTROPY 1
#endif

int randombytes(uint8_t *out, size_t outlen)
{
    if (out == NULL) {
        return -1;
    }

#if defined(MLKEM_RNG_NO_RF_ENTROPY)
    /* Neither Wi-Fi nor Bluetooth is compiled in, so the hardware RNG has no
     * guaranteed entropy source. Refuse rather than hand back key material that
     * looks perfectly random and is not. Benchmarks must use the _derand API. */
    ESP_LOGE(TAG,
             "randombytes() called in a build without Wi-Fi or Bluetooth - "
             "hardware RNG has no guaranteed entropy source. Use the _derand "
             "API for benchmarks. Refusing.");
    (void)outlen;
    return -1;
#else
    esp_fill_random(out, outlen);
    return 0;
#endif
}
