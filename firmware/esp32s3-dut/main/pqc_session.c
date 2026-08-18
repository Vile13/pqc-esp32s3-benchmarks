/*
 * PQC-IoT-1 client, mode A. See docs/protocol.md.
 *
 * Independent C implementation of the same specification the Python server
 * implements. Nothing is shared between them: ML-KEM comes from mlkem-native
 * here and from OpenSSL there, and the two key schedules were written from the
 * document rather than from each other. That is what makes a successful
 * handshake evidence instead of a mirror.
 *
 * Timings printed here are indicative, not benchmarks. They run with the radio
 * up and the network in the loop, which is exactly what v2's measurements
 * exclude.
 */

#include <string.h>

#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"
#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"

#include "device_config.h"
#include "mlkem_native_all.h"
#include "pqc_session.h"
#include "server_key.h"

static const char *TAG = "pqc";

#define PROTOCOL_VERSION 0x01
#define SUITE_MLKEM768 0x01

#define FRAME_CLIENT_HELLO 0x01
#define FRAME_SERVER_HELLO 0x02
#define FRAME_CLIENT_FINISHED 0x03
#define FRAME_DATA 0x10
#define FRAME_CLOSE 0x7F

#define NONCE_LEN 32
#define SESSION_ID_LEN 8
#define DEVICE_ID_LEN 8
#define KEY_ID_LEN 4
#define MAC_LEN 32
#define PSK_LEN 32
#define TAG_LEN 16
#define SS_LEN 32

#define CLIENT_HELLO_LEN                                                       \
    (2 + DEVICE_ID_LEN + KEY_ID_LEN + NONCE_LEN + MLKEM768_CIPHERTEXTBYTES     \
     + MAC_LEN)
#define SERVER_HELLO_LEN (NONCE_LEN + SESSION_ID_LEN + MAC_LEN)

static const char LABEL_HELLO[] = "PQC-IoT-1 hello";
static const char LABEL_SRV_CONFIRM[] = "PQC-IoT-1 server confirm";
static const char LABEL_CLI_CONFIRM[] = "PQC-IoT-1 client confirm";
static const char LABEL_C2S[] = "PQC-IoT-1 c2s";
static const char LABEL_S2C[] = "PQC-IoT-1 s2c";

static const uint8_t DEVICE_ID_BYTES[DEVICE_ID_LEN] = DEVICE_ID;
static const uint8_t DEVICE_PSK_BYTES[PSK_LEN] = DEVICE_PSK;

typedef struct
{
    uint8_t srv_confirm[32];
    uint8_t cli_confirm[32];
    uint8_t c2s[32];
    uint8_t s2c[32];
} session_keys_t;

/* ------------------------------------------------------------- primitives -- */

/* Comparisons on secrets must not leak where the first difference is. */
static bool ct_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}

static void hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg,
                        size_t msg_len, uint8_t out[32])
{
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_hmac(info, key, key_len, msg, msg_len, out);
}

/* HMAC over two pieces without allocating a joined buffer. */
static void hmac_sha256_2(const uint8_t *key, size_t key_len, const uint8_t *a,
                          size_t a_len, const uint8_t *b, size_t b_len,
                          uint8_t out[32])
{
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, info, 1);
    mbedtls_md_hmac_starts(&ctx, key, key_len);
    mbedtls_md_hmac_update(&ctx, a, a_len);
    if (b_len) {
        mbedtls_md_hmac_update(&ctx, b, b_len);
    }
    mbedtls_md_hmac_finish(&ctx, out);
    mbedtls_md_free(&ctx);
}

static void derive_key(const uint8_t prk[32], const char *label,
                       const uint8_t th2[32], uint8_t out[32])
{
    uint8_t info[40 + 32];
    size_t label_len = strlen(label);
    memcpy(info, label, label_len);
    memcpy(info + label_len, th2, 32);

    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_hkdf_expand(md, prk, 32, info, label_len + 32, out, 32);
}

/* ------------------------------------------------------------------ frames -- */

static bool send_all(int sock, const uint8_t *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        int n = send(sock, buf + sent, len - sent, 0);
        if (n <= 0) {
            return false;
        }
        sent += (size_t)n;
    }
    return true;
}

static bool recv_all(int sock, uint8_t *buf, size_t len)
{
    size_t got = 0;
    while (got < len) {
        int n = recv(sock, buf + got, len - got, 0);
        if (n <= 0) {
            return false;
        }
        got += (size_t)n;
    }
    return true;
}

static bool write_frame(int sock, uint8_t type, const uint8_t *payload,
                        uint16_t len)
{
    uint8_t head[3] = {type, (uint8_t)(len >> 8), (uint8_t)(len & 0xff)};
    return send_all(sock, head, sizeof(head)) && send_all(sock, payload, len);
}

static bool read_frame(int sock, uint8_t *type, uint8_t *payload,
                       uint16_t capacity, uint16_t *len)
{
    uint8_t head[3];
    if (!recv_all(sock, head, sizeof(head))) {
        return false;
    }
    *type = head[0];
    *len = (uint16_t)((head[1] << 8) | head[2]);
    if (*len > capacity) {
        ESP_LOGE(TAG, "frame of %u bytes exceeds buffer", *len);
        return false;
    }
    return recv_all(sock, payload, *len);
}

/* -------------------------------------------------------------- connection -- */

static int connect_to_server(const char *host, uint16_t port)
{
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);

    struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_STREAM};
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, port_str, &hints, &res) != 0 || res == NULL) {
        ESP_LOGE(TAG, "cannot resolve %s", host);
        return -1;
    }

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) {
        freeaddrinfo(res);
        return -1;
    }

    struct timeval tv = {.tv_sec = CONNECT_TIMEOUT_MS / 1000,
                         .tv_usec = (CONNECT_TIMEOUT_MS % 1000) * 1000};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(sock, res->ai_addr, res->ai_addrlen) != 0) {
        ESP_LOGE(TAG, "connect to %s:%u failed", host, port);
        close(sock);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);
    return sock;
}

/* --------------------------------------------------------------- handshake -- */

/* Large buffers are static: the handshake needs ~2.4 KB of message alone, and
 * .bss is internal SRAM, so the placement rule from docs/hardware.md holds. */
static uint8_t s_hello[CLIENT_HELLO_LEN];
static uint8_t s_frame[512];

static bool handshake(int sock, pqc_session_t *session)
{
    uint8_t client_nonce[NONCE_LEN];
    uint8_t kem_ct[MLKEM768_CIPHERTEXTBYTES];
    uint8_t ss[SS_LEN];

    /* Both of these need the radio up; randombytes() refuses otherwise. */
    esp_fill_random(client_nonce, sizeof(client_nonce));

    int64_t t_encap = esp_timer_get_time();
    if (mlkem768_enc(kem_ct, ss, SERVER_PUBLIC_KEY) != 0) {
        ESP_LOGE(TAG, "ML-KEM encapsulation failed");
        return false;
    }
    int64_t encap_us = esp_timer_get_time() - t_encap;

    size_t i = 0;
    s_hello[i++] = PROTOCOL_VERSION;
    s_hello[i++] = SUITE_MLKEM768;
    memcpy(s_hello + i, DEVICE_ID_BYTES, DEVICE_ID_LEN); i += DEVICE_ID_LEN;
    memcpy(s_hello + i, SERVER_KEY_ID, KEY_ID_LEN); i += KEY_ID_LEN;
    memcpy(s_hello + i, client_nonce, NONCE_LEN); i += NONCE_LEN;
    memcpy(s_hello + i, kem_ct, sizeof(kem_ct)); i += sizeof(kem_ct);

    /* psk_mac covers the label plus everything above it. */
    hmac_sha256_2(DEVICE_PSK_BYTES, PSK_LEN, (const uint8_t *)LABEL_HELLO,
                  strlen(LABEL_HELLO), s_hello, i, s_hello + i);
    i += MAC_LEN;

    if (i != CLIENT_HELLO_LEN) {
        ESP_LOGE(TAG, "ClientHello is %u bytes, expected %u", (unsigned)i,
                 CLIENT_HELLO_LEN);
        return false;
    }

    if (!write_frame(sock, FRAME_CLIENT_HELLO, s_hello, CLIENT_HELLO_LEN)) {
        ESP_LOGE(TAG, "sending ClientHello failed");
        return false;
    }

    uint8_t type;
    uint16_t len;
    if (!read_frame(sock, &type, s_frame, sizeof(s_frame), &len)) {
        /* Covers both a closed socket and an expired receive timeout; the
         * two are indistinguishable here and both are fatal. */
        ESP_LOGE(TAG, "no ServerHello - no answer or connection closed");
        return false;
    }
    if (type != FRAME_SERVER_HELLO || len != SERVER_HELLO_LEN) {
        ESP_LOGE(TAG, "unexpected frame %#04x of %u bytes", type, len);
        return false;
    }

    const uint8_t *server_nonce = s_frame;
    const uint8_t *session_id = s_frame + NONCE_LEN;
    const uint8_t *server_mac = s_frame + NONCE_LEN + SESSION_ID_LEN;

    /* TH2 = SHA-256(ClientHello || server_nonce || session_id) */
    uint8_t th2[32];
    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);
    mbedtls_sha256_update(&sha, s_hello, CLIENT_HELLO_LEN);
    mbedtls_sha256_update(&sha, server_nonce, NONCE_LEN);
    mbedtls_sha256_update(&sha, session_id, SESSION_ID_LEN);
    mbedtls_sha256_finish(&sha, th2);
    mbedtls_sha256_free(&sha);

    uint8_t salt[NONCE_LEN * 2];
    memcpy(salt, client_nonce, NONCE_LEN);
    memcpy(salt + NONCE_LEN, server_nonce, NONCE_LEN);

    uint8_t ikm[SS_LEN + PSK_LEN];
    memcpy(ikm, ss, SS_LEN);
    memcpy(ikm + SS_LEN, DEVICE_PSK_BYTES, PSK_LEN);

    uint8_t prk[32];
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_hkdf_extract(md, salt, sizeof(salt), ikm, sizeof(ikm), prk);

    session_keys_t keys;
    derive_key(prk, LABEL_SRV_CONFIRM, th2, keys.srv_confirm);
    derive_key(prk, LABEL_CLI_CONFIRM, th2, keys.cli_confirm);
    derive_key(prk, LABEL_C2S, th2, keys.c2s);
    derive_key(prk, LABEL_S2C, th2, keys.s2c);

    /* Wipe the inputs; the derived keys are what the session needs. */
    memset(ikm, 0, sizeof(ikm));
    memset(ss, 0, sizeof(ss));
    memset(prk, 0, sizeof(prk));

    uint8_t expected_mac[32];
    hmac_sha256(keys.srv_confirm, 32, th2, sizeof(th2), expected_mac);
    if (!ct_equal(expected_mac, server_mac, MAC_LEN)) {
        ESP_LOGE(TAG, "server MAC mismatch - this is not the pinned server");
        return false;
    }

    uint8_t client_mac[32];
    hmac_sha256_2(keys.cli_confirm, 32, th2, sizeof(th2), server_mac, MAC_LEN,
                  client_mac);
    if (!write_frame(sock, FRAME_CLIENT_FINISHED, client_mac, MAC_LEN)) {
        return false;
    }

    memcpy(session->session_id, session_id, SESSION_ID_LEN);
    memcpy(session->c2s, keys.c2s, 32);
    session->send_seq = 0;
    session->encap_us = encap_us;
    session->handshake_bytes = 3 + CLIENT_HELLO_LEN + 3 + SERVER_HELLO_LEN + 3
                               + MAC_LEN;
    return true;
}

/* ------------------------------------------------------------ data records -- */

static bool send_record(int sock, pqc_session_t *session, const uint8_t *plain,
                        uint16_t plain_len)
{
    if ((size_t)plain_len + 10 + TAG_LEN > sizeof(s_frame)) {
        return false;
    }

    uint64_t seq = session->send_seq;

    uint8_t nonce[12] = {0};
    for (int b = 0; b < 8; b++) {
        nonce[4 + b] = (uint8_t)(seq >> (56 - 8 * b));
    }

    uint8_t aad[SESSION_ID_LEN + 8 + 2];
    memcpy(aad, session->session_id, SESSION_ID_LEN);
    for (int b = 0; b < 8; b++) {
        aad[SESSION_ID_LEN + b] = (uint8_t)(seq >> (56 - 8 * b));
    }
    aad[SESSION_ID_LEN + 8] = (uint8_t)(plain_len >> 8);
    aad[SESSION_ID_LEN + 9] = (uint8_t)(plain_len & 0xff);

    size_t o = 0;
    memcpy(s_frame + o, aad + SESSION_ID_LEN, 8); o += 8; /* seq */
    s_frame[o++] = (uint8_t)(plain_len >> 8);
    s_frame[o++] = (uint8_t)(plain_len & 0xff);

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, session->c2s, 256);
    if (rc == 0) {
        rc = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plain_len,
                                       nonce, sizeof(nonce), aad, sizeof(aad),
                                       plain, s_frame + o,
                                       TAG_LEN, s_frame + o + plain_len);
    }
    mbedtls_gcm_free(&gcm);
    if (rc != 0) {
        ESP_LOGE(TAG, "AES-GCM failed (%d)", rc);
        return false;
    }

    uint16_t frame_len = (uint16_t)(o + plain_len + TAG_LEN);
    if (!write_frame(sock, FRAME_DATA, s_frame, frame_len)) {
        return false;
    }
    session->send_seq++;
    return true;
}

/* -------------------------------------------------------------------- API -- */

bool pqc_session_run(int record_count)
{
    ESP_LOGI(TAG, "connecting to %s:%d", SERVER_HOST, SERVER_PORT);

    int sock = connect_to_server(SERVER_HOST, SERVER_PORT);
    if (sock < 0) {
        return false;
    }

    pqc_session_t session = {0};
    int64_t t0 = esp_timer_get_time();
    bool ok = handshake(sock, &session);
    int64_t handshake_us = esp_timer_get_time() - t0;

    if (!ok) {
        close(sock);
        return false;
    }

    ESP_LOGI(TAG, "handshake ok in %lld ms (encapsulation %lld ms), %u bytes",
             handshake_us / 1000, session.encap_us / 1000,
             (unsigned)session.handshake_bytes);

    size_t payload_total = 0;
    for (int n = 0; n < record_count; n++) {
        char json[80];
        int len = snprintf(json, sizeof(json),
                           "{\"seq\":%d,\"co2\":%d,\"t\":22.4,\"rh\":47}", n,
                           810 + n);
        if (!send_record(sock, &session, (const uint8_t *)json, (uint16_t)len)) {
            ESP_LOGE(TAG, "sending record %d failed", n);
            close(sock);
            return false;
        }
        payload_total += (size_t)len;
    }

    write_frame(sock, FRAME_CLOSE, NULL, 0);
    close(sock);

    ESP_LOGI(TAG, "%d record(s) sent, %u bytes of payload", record_count,
             (unsigned)payload_total);
    return true;
}
