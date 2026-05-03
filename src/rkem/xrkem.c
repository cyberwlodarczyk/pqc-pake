#include <string.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include "xrkem.h"

void XRKEM_keygen(uint8_t *public_key, uint8_t *secret_key)
{
    uint8_t *a_seed = public_key + RKEM_LEN_PUBLIC_KEY;
    RAND_bytes(a_seed, RKEM_LEN_SEED);
    RKEM_polyvec a[RKEM_K];
    RKEM_fls(a, a_seed, 0);
    RKEM_keygen_a(public_key, secret_key, a);
    OPENSSL_cleanse(a, sizeof(a));
}

void XRKEM_rand(
    uint8_t *rand_public_key,
    const uint8_t *seed,
    const uint8_t *public_key)
{
    const uint8_t *a_seed = public_key + RKEM_LEN_PUBLIC_KEY;
    RKEM_polyvec a[RKEM_K];
    RKEM_fls(a, a_seed, 0);
    RKEM_rand_a(rand_public_key, seed, public_key, a);
    memcpy(rand_public_key + RKEM_LEN_PUBLIC_KEY, a_seed, RKEM_LEN_SEED);
    OPENSSL_cleanse(a, sizeof(a));
}

void XRKEM_derand(
    uint8_t *public_key,
    const uint8_t *seed,
    const uint8_t *rand_public_key)
{
    const uint8_t *a_seed = rand_public_key + RKEM_LEN_PUBLIC_KEY;
    RKEM_polyvec a[RKEM_K];
    RKEM_fls(a, a_seed, 0);
    RKEM_derand_a(public_key, seed, rand_public_key, a);
    memcpy(public_key + RKEM_LEN_PUBLIC_KEY, a_seed, RKEM_LEN_SEED);
    OPENSSL_cleanse(a, sizeof(a));
}

void XRKEM_encaps(
    uint8_t *ciphertext,
    uint8_t *shared_secret,
    const uint8_t *public_key)
{
    const uint8_t *a_seed = public_key + RKEM_LEN_PUBLIC_KEY;
    RKEM_polyvec at[RKEM_K];
    RKEM_fls(at, a_seed, 1);
    RKEM_encaps_at(ciphertext, shared_secret, public_key, at);
    OPENSSL_cleanse(at, sizeof(at));
}

void XRKEM_decaps(
    uint8_t *shared_secret,
    const uint8_t *ciphertext,
    const uint8_t *secret_key,
    const uint8_t *seed)
{
    RKEM_decaps(shared_secret, ciphertext, secret_key, seed);
}

void XRKEM_decaps_derand(
    uint8_t *shared_secret,
    const uint8_t *ciphertext,
    const uint8_t *secret_key)
{
    RKEM_decaps_derand(shared_secret, ciphertext, secret_key);
}
