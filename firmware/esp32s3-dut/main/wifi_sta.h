#ifndef WIFI_STA_H
#define WIFI_STA_H

#include <stdbool.h>

#include "esp_err.h"

/* Bring up the station and block until an IP address is assigned.
 *
 * Must succeed before any nonce or ML-KEM key is generated: the hardware RNG
 * has no guaranteed entropy source until the radio runs (docs/hardware.md). */
esp_err_t wifi_sta_start(void);

bool wifi_sta_is_connected(void);

#endif /* WIFI_STA_H */
