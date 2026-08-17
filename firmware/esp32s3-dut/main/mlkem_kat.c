/*
 * ML-KEM conformance test against the NIST ACVP vectors (FIPS 203).
 *
 * This is the check that decides whether the firmware implements ML-KEM, as
 * opposed to something self-consistent that merely behaves like it. The vectors
 * are produced by NIST, independently of mlkem-native, so passing them is
 * evidence rather than a tautology - see tests/acvp/generate_kat_header.py.
 *
 * Three groups are run per parameter set:
 *
 *   keyGen  (AFT) - derive (ek, dk) from the seeds d and z, compare both.
 *   encap   (AFT) - encapsulate to a given ek with a given m, compare
 *                   ciphertext and shared secret.
 *   decap   (VAL) - decapsulate a given ciphertext with a given dk, compare
 *                   the shared secret.
 *
 * ACVP supplies d and z separately; mlkem-native takes a single 64-byte coins
 * buffer that is d || z. Verified against mlkem/src/kem.c, where the second
 * half is stored as the implicit-rejection value inside dk.
 *
 * Large buffers are static rather than automatic. They live in .bss, which is
 * internal SRAM, so the placement rule from docs/hardware.md still holds - and
 * keeping multi-kilobyte keys off the stack makes the later stack high-water
 * measurements about the algorithm instead of about this harness.
 */

#include <stdio.h>
#include <string.h>

#include "acvp_vectors.h"
#include "mlkem_kat.h"
#include "mlkem_native_all.h"

typedef struct
{
    int run;
    int failed;
} kat_result_t;

static void report(const char *label, int level, kat_result_t r)
{
    printf("%s  ML-KEM-%d %-7s %2d/%2d vectors\n",
           r.failed == 0 ? "ok  " : "FAIL", level, label, r.run - r.failed,
           r.run);
}

/*
 * The three test bodies are identical apart from the parameter set, and the
 * symbol names encode that set (mlkem512_*, MLKEM768_*, kat512_*). A macro
 * keeps the two instantiations genuinely identical instead of near-identical.
 */
#define DEFINE_KAT_LEVEL(LVL)                                                  \
                                                                               \
    static kat_result_t kat_keygen_##LVL(void)                                 \
    {                                                                          \
        static uint8_t pk[MLKEM##LVL##_PUBLICKEYBYTES];                        \
        static uint8_t sk[MLKEM##LVL##_SECRETKEYBYTES];                        \
        uint8_t coins[2 * MLKEM_SYMBYTES];                                     \
        kat_result_t r = {KAT##LVL##_KEYGEN_COUNT, 0};                         \
                                                                               \
        for (int i = 0; i < KAT##LVL##_KEYGEN_COUNT; i++)                      \
        {                                                                      \
            memcpy(coins, kat##LVL##_keygen_d[i], MLKEM_SYMBYTES);             \
            memcpy(coins + MLKEM_SYMBYTES, kat##LVL##_keygen_z[i],             \
                   MLKEM_SYMBYTES);                                            \
                                                                               \
            if (mlkem##LVL##_keypair_derand(pk, sk, coins) != 0 ||             \
                memcmp(pk, kat##LVL##_keygen_ek[i], sizeof(pk)) != 0 ||        \
                memcmp(sk, kat##LVL##_keygen_dk[i], sizeof(sk)) != 0)          \
            {                                                                  \
                r.failed++;                                                    \
            }                                                                  \
        }                                                                      \
        return r;                                                              \
    }                                                                          \
                                                                               \
    static kat_result_t kat_encap_##LVL(void)                                  \
    {                                                                          \
        static uint8_t ct[MLKEM##LVL##_CIPHERTEXTBYTES];                       \
        uint8_t ss[MLKEM_BYTES];                                               \
        kat_result_t r = {KAT##LVL##_ENCAP_COUNT, 0};                          \
                                                                               \
        for (int i = 0; i < KAT##LVL##_ENCAP_COUNT; i++)                       \
        {                                                                      \
            if (mlkem##LVL##_enc_derand(ct, ss, kat##LVL##_encap_ek[i],        \
                                        kat##LVL##_encap_m[i]) != 0 ||         \
                memcmp(ct, kat##LVL##_encap_c[i], sizeof(ct)) != 0 ||          \
                memcmp(ss, kat##LVL##_encap_k[i], MLKEM_BYTES) != 0)           \
            {                                                                  \
                r.failed++;                                                    \
            }                                                                  \
        }                                                                      \
        return r;                                                              \
    }                                                                          \
                                                                               \
    static kat_result_t kat_decap_##LVL(void)                                  \
    {                                                                          \
        uint8_t ss[MLKEM_BYTES];                                               \
        kat_result_t r = {KAT##LVL##_DECAP_COUNT, 0};                          \
                                                                               \
        for (int i = 0; i < KAT##LVL##_DECAP_COUNT; i++)                       \
        {                                                                      \
            if (mlkem##LVL##_dec(ss, kat##LVL##_decap_c[i],                    \
                                 kat##LVL##_decap_dk[i]) != 0 ||               \
                memcmp(ss, kat##LVL##_decap_k[i], MLKEM_BYTES) != 0)           \
            {                                                                  \
                r.failed++;                                                    \
            }                                                                  \
        }                                                                      \
        return r;                                                              \
    }

DEFINE_KAT_LEVEL(512)
DEFINE_KAT_LEVEL(768)

bool mlkem_kat_run(void)
{
    int total = 0;
    int failed = 0;

    printf("\n=== ML-KEM ACVP conformance (%s) ===\n", ACVP_VERSION);

    const struct
    {
        int level;
        const char *label;
        kat_result_t (*fn)(void);
    } cases[] = {
        {512, "keyGen", kat_keygen_512}, {512, "encap", kat_encap_512},
        {512, "decap", kat_decap_512},   {768, "keyGen", kat_keygen_768},
        {768, "encap", kat_encap_768},   {768, "decap", kat_decap_768},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
    {
        kat_result_t r = cases[i].fn();
        report(cases[i].label, cases[i].level, r);
        total += r.run;
        failed += r.failed;
    }

    printf("%s  %d of %d ACVP vectors\n", failed == 0 ? "ok  " : "FAIL",
           total - failed, total);
    printf("source: usnistgov/ACVP-Server %s (independent of mlkem-native)\n",
           ACVP_VERSION);

    return failed == 0;
}
