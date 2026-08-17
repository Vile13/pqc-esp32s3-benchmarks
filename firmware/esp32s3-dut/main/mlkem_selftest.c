/*
 * ML-KEM self-test: round-trip consistency.
 *
 * This is a smoke test, NOT a conformance test. It proves the library is linked,
 * runs on this hardware, and that encapsulation and decapsulation agree on a
 * shared secret.
 *
 * It deliberately does not prove the implementation is ML-KEM. A wrong but
 * internally consistent implementation passes every check in this file. Only
 * the NIST ACVP vectors settle that question - see mlkem_kat.c.
 *
 * All buffers are stack-allocated on purpose: the stack lives in internal SRAM,
 * which keeps the working set out of PSRAM (docs/hardware.md). Sizes are large
 * enough that this matters - the ML-KEM-768 secret key alone is 2400 bytes.
 */

#include <stdio.h>
#include <string.h>

#include "mlkem_native_all.h"
#include "mlkem_selftest.h"

/* Fixed coins. The randomized API is unavailable in a radio-free build by
 * design (see components/mlkem/esp_randombytes.c), and fixed inputs make this
 * test reproducible. These values are arbitrary, not secret, and never used
 * outside the bench. */
static void fill_pattern(uint8_t *buf, size_t len, uint8_t seed)
{
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(seed + i * 7u);
    }
}

static bool roundtrip_512(void)
{
    uint8_t pk[MLKEM512_PUBLICKEYBYTES];
    uint8_t sk[MLKEM512_SECRETKEYBYTES];
    uint8_t ct[MLKEM512_CIPHERTEXTBYTES];
    uint8_t ss_enc[MLKEM_BYTES];
    uint8_t ss_dec[MLKEM_BYTES];
    uint8_t keygen_coins[2 * MLKEM_SYMBYTES];
    uint8_t enc_coins[MLKEM_SYMBYTES];

    fill_pattern(keygen_coins, sizeof(keygen_coins), 0x11);
    fill_pattern(enc_coins, sizeof(enc_coins), 0x22);

    if (mlkem512_keypair_derand(pk, sk, keygen_coins) != 0) {
        printf("FAIL  mlkem512_keypair_derand\n");
        return false;
    }
    if (mlkem512_enc_derand(ct, ss_enc, pk, enc_coins) != 0) {
        printf("FAIL  mlkem512_enc_derand\n");
        return false;
    }
    if (mlkem512_dec(ss_dec, ct, sk) != 0) {
        printf("FAIL  mlkem512_dec\n");
        return false;
    }

    bool match = memcmp(ss_enc, ss_dec, MLKEM_BYTES) == 0;
    printf("%s  ML-KEM-512  pk=%d ct=%d  shared secrets %s\n",
           match ? "ok  " : "FAIL", MLKEM512_PUBLICKEYBYTES,
           MLKEM512_CIPHERTEXTBYTES, match ? "agree" : "DIFFER");
    return match;
}

static bool roundtrip_768(void)
{
    uint8_t pk[MLKEM768_PUBLICKEYBYTES];
    uint8_t sk[MLKEM768_SECRETKEYBYTES];
    uint8_t ct[MLKEM768_CIPHERTEXTBYTES];
    uint8_t ss_enc[MLKEM_BYTES];
    uint8_t ss_dec[MLKEM_BYTES];
    uint8_t keygen_coins[2 * MLKEM_SYMBYTES];
    uint8_t enc_coins[MLKEM_SYMBYTES];

    fill_pattern(keygen_coins, sizeof(keygen_coins), 0x33);
    fill_pattern(enc_coins, sizeof(enc_coins), 0x44);

    if (mlkem768_keypair_derand(pk, sk, keygen_coins) != 0) {
        printf("FAIL  mlkem768_keypair_derand\n");
        return false;
    }
    if (mlkem768_enc_derand(ct, ss_enc, pk, enc_coins) != 0) {
        printf("FAIL  mlkem768_enc_derand\n");
        return false;
    }
    if (mlkem768_dec(ss_dec, ct, sk) != 0) {
        printf("FAIL  mlkem768_dec\n");
        return false;
    }

    bool match = memcmp(ss_enc, ss_dec, MLKEM_BYTES) == 0;
    printf("%s  ML-KEM-768  pk=%d ct=%d  shared secrets %s\n",
           match ? "ok  " : "FAIL", MLKEM768_PUBLICKEYBYTES,
           MLKEM768_CIPHERTEXTBYTES, match ? "agree" : "DIFFER");
    return match;
}

/*
 * A tampered ciphertext must not yield the original shared secret. ML-KEM uses
 * implicit rejection: decapsulation still returns 0 and still produces 32 bytes,
 * but they are derived from the secret key's rejection value instead. Checking
 * this catches an implementation that silently ignores the ciphertext.
 */
static bool implicit_rejection_768(void)
{
    uint8_t pk[MLKEM768_PUBLICKEYBYTES];
    uint8_t sk[MLKEM768_SECRETKEYBYTES];
    uint8_t ct[MLKEM768_CIPHERTEXTBYTES];
    uint8_t ss_enc[MLKEM_BYTES];
    uint8_t ss_dec[MLKEM_BYTES];
    uint8_t keygen_coins[2 * MLKEM_SYMBYTES];
    uint8_t enc_coins[MLKEM_SYMBYTES];

    fill_pattern(keygen_coins, sizeof(keygen_coins), 0x55);
    fill_pattern(enc_coins, sizeof(enc_coins), 0x66);

    if (mlkem768_keypair_derand(pk, sk, keygen_coins) != 0 ||
        mlkem768_enc_derand(ct, ss_enc, pk, enc_coins) != 0) {
        printf("FAIL  setup for implicit rejection test\n");
        return false;
    }

    ct[0] ^= 0x01; /* flip one bit */

    if (mlkem768_dec(ss_dec, ct, sk) != 0) {
        printf("FAIL  mlkem768_dec on tampered ciphertext\n");
        return false;
    }

    bool rejected = memcmp(ss_enc, ss_dec, MLKEM_BYTES) != 0;
    printf("%s  tampered ciphertext -> %s\n", rejected ? "ok  " : "FAIL",
           rejected ? "different secret (implicit rejection)"
                    : "SAME SECRET - ciphertext is being ignored");
    return rejected;
}

bool mlkem_selftest_run(void)
{
    printf("\n=== ML-KEM self-test (consistency only) ===\n");

    bool ok = true;
    ok &= roundtrip_512();
    ok &= roundtrip_768();
    ok &= implicit_rejection_768();

    printf("%s\n", ok ? "consistency: PASS" : "consistency: FAIL");
    printf("note: proves the library runs, not that it is FIPS 203\n");
    return ok;
}
