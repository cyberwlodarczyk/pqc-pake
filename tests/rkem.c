// gcc $CFLAGS $LDFLAGS -o rkem rkem.c -lrkem -lkyber -lcrypto

#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <rkem/rkem.h>

#define TEST_N 10000

int test_exchange()
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

int main()
{
    for (int i = 0; i < TEST_N; i++)
    {
        if (!test_exchange())
        {
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}
