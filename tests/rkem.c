// gcc $CFLAGS $LDFLAGS -o rkem rkem.c -lrkem -lkyber -lcrypto

#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <rkem/rkem.h>
#include <rkem/xrkem.h>

#define TEST_N 10000

int test_rkem_exchange()
{
    uint8_t pk[RKEM_len_public_key];
    uint8_t sk[RKEM_len_secret_key];
    RKEM_keygen(pk, sk);
    uint8_t seed[RKEM_len_seed];
    RAND_bytes(seed, RKEM_len_seed);
    uint8_t rand_pk[RKEM_len_public_key];
    RKEM_rand(rand_pk, seed, pk);
    uint8_t ct[RKEM_len_ciphertext];
    uint8_t ss1[RKEM_len_shared_secret];
    RKEM_encaps(ct, ss1, rand_pk);
    uint8_t ss2[RKEM_len_shared_secret];
    RKEM_decaps(ss2, ct, sk, seed);
    for (int i = 0; i < RKEM_len_shared_secret; i++)
    {
        if (ss1[i] != ss2[i])
        {
            return 0;
        }
    }
    return 1;
}

int test_xrkem_exchange()
{
    uint8_t pk[XRKEM_len_public_key];
    uint8_t sk[XRKEM_len_secret_key];
    XRKEM_keygen(pk, sk);
    uint8_t seed[XRKEM_len_seed];
    RAND_bytes(seed, XRKEM_len_seed);
    uint8_t rand_pk[XRKEM_len_public_key];
    XRKEM_rand(rand_pk, seed, pk);
    uint8_t ct[XRKEM_len_ciphertext];
    uint8_t ss1[XRKEM_len_shared_secret];
    XRKEM_encaps(ct, ss1, rand_pk);
    uint8_t ss2[XRKEM_len_shared_secret];
    XRKEM_decaps(ss2, ct, sk, seed);
    for (int i = 0; i < XRKEM_len_shared_secret; i++)
    {
        if (ss1[i] != ss2[i])
        {
            return 0;
        }
    }
    return 1;
}

int test_xrkem_derand_exchange()
{
    uint8_t pk[XRKEM_len_public_key];
    uint8_t sk[XRKEM_len_secret_key];
    XRKEM_keygen(pk, sk);
    uint8_t seed[XRKEM_len_seed];
    RAND_bytes(seed, XRKEM_len_seed);
    uint8_t rand_pk[XRKEM_len_public_key];
    XRKEM_rand(rand_pk, seed, pk);
    XRKEM_derand(pk, seed, rand_pk);
    uint8_t ct[XRKEM_len_ciphertext];
    uint8_t ss1[XRKEM_len_shared_secret];
    XRKEM_encaps(ct, ss1, pk);
    uint8_t ss2[XRKEM_len_shared_secret];
    XRKEM_decaps_derand(ss2, ct, sk);
    for (int i = 0; i < XRKEM_len_shared_secret; i++)
    {
        if (ss1[i] != ss2[i])
        {
            return 0;
        }
    }
    return 1;
}

int main()
{
    for (int i = 0; i < TEST_N; i++)
    {
        if (!test_rkem_exchange())
        {
            return EXIT_FAILURE;
        }
    }
    for (int i = 0; i < TEST_N; i++)
    {
        if (!test_xrkem_exchange())
        {
            return EXIT_FAILURE;
        }
    }
    for (int i = 0; i < TEST_N; i++)
    {
        if (!test_xrkem_derand_exchange())
        {
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}
