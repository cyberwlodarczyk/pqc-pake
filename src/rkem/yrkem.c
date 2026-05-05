#include <openssl/rand.h>
#include "yrkem.h"

void YRKEM_keygen(
    uint8_t *public_key,
    uint8_t *secret_key,
    const uint8_t *seed)
{
    uint8_t *a_seed = public_key + RKEM_LEN_PUBLIC_KEY;
    RAND_bytes(a_seed, RKEM_LEN_SEED);
    RKEM_polyvec a[RKEM_K];
    RKEM_gen_matrix(a, a_seed, 0);
    RKEM_keygen_a(public_key, secret_key, a);
    RKEM_rand_a(public_key, seed, public_key, a);
    OPENSSL_cleanse(a, sizeof(a));
}

void YRKEM_encaps(
    uint8_t *ciphertext,
    uint8_t *shared_secret,
    const uint8_t *public_key,
    const uint8_t *seed)
{
    const uint8_t *a_seed = public_key + RKEM_LEN_PUBLIC_KEY;
    RKEM_polyvec a[RKEM_K];
    RKEM_gen_matrix(a, a_seed, 0);
    uint8_t derand_public_key[YRKEM_LEN_PUBLIC_KEY];
    RKEM_derand_a(derand_public_key, seed, public_key, a);
    RKEM_transpose_matrix(a);
    RKEM_encaps_at(ciphertext, shared_secret, derand_public_key, a);
    OPENSSL_cleanse(a, sizeof(a));
}

void YRKEM_decaps(
    uint8_t *shared_secret,
    const uint8_t *ciphertext,
    const uint8_t *secret_key)
{
    RKEM_decaps_derand(shared_secret, ciphertext, secret_key);
}
