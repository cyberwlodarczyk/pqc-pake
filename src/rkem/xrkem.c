#include <string.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include "xrkem.h"
#include "rkem_internal.h"

void XRKEM_keygen(uint8_t *public_key, uint8_t *secret_key)
{
    uint8_t *a_seed = public_key + RKEM_PUBLICKEYBYTES;
    RAND_bytes(a_seed, RKEM_SYMBYTES);
    polyvec a[RKEM_K];
    rkem_fls(a, a_seed, 0);
    rkem_keygen(public_key, secret_key, a);
    OPENSSL_cleanse(a, sizeof(a));
}

void XRKEM_rand(
    uint8_t *rand_public_key,
    const uint8_t *seed,
    const uint8_t *public_key)
{
    const uint8_t *a_seed = public_key + RKEM_PUBLICKEYBYTES;
    polyvec a[RKEM_K];
    rkem_fls(a, a_seed, 0);
    rkem_rand(rand_public_key, seed, public_key, a);
    memcpy(rand_public_key + RKEM_PUBLICKEYBYTES, a_seed, RKEM_SYMBYTES);
    OPENSSL_cleanse(a, sizeof(a));
}

void XRKEM_derand(
    uint8_t *public_key,
    const uint8_t *seed,
    const uint8_t *rand_public_key)
{
    const uint8_t *a_seed = rand_public_key + RKEM_PUBLICKEYBYTES;
    polyvec a[RKEM_K];
    rkem_fls(a, a_seed, 0);
    rkem_derand(public_key, seed, rand_public_key, a);
    memcpy(public_key + RKEM_PUBLICKEYBYTES, a_seed, RKEM_SYMBYTES);
    OPENSSL_cleanse(a, sizeof(a));
}

void XRKEM_encaps(
    uint8_t *ciphertext,
    uint8_t *shared_secret,
    const uint8_t *public_key)
{
    const uint8_t *a_seed = public_key + RKEM_PUBLICKEYBYTES;
    polyvec at[RKEM_K];
    rkem_fls(at, a_seed, 1);
    rkem_encaps(ciphertext, shared_secret, public_key, at);
    OPENSSL_cleanse(at, sizeof(at));
}

void XRKEM_decaps(
    uint8_t *shared_secret,
    const uint8_t *ciphertext,
    const uint8_t *secret_key,
    const uint8_t *seed)
{
    rkem_decaps(shared_secret, ciphertext, secret_key, seed);
}

void XRKEM_decaps_derand(
    uint8_t *shared_secret,
    const uint8_t *ciphertext,
    const uint8_t *secret_key)
{
    rkem_decaps_derand(shared_secret, ciphertext, secret_key);
}
