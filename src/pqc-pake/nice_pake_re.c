#include <string.h>
#include <openssl/rand.h>
#include <rkem/xrkem.h>
#include "nice_pake_re.h"

void NICE_PAKE_RE_keygen(
    uint8_t *seed_a,
    uint8_t *poly,
    uint8_t *secret_key,
    const uint8_t *password)
{
    uint8_t public_key[XRKEM_len_public_key];
    XRKEM_keygen(public_key, secret_key);
    memcpy(seed_a, public_key + XRKEM_len_poly, XRKEM_len_seed);
    memcpy(poly, public_key, XRKEM_len_poly);
    for (int i = 0; i < XRKEM_len_seed; i++)
    {
        seed_a[i] ^= password[i];
    }
    OPENSSL_cleanse(public_key, XRKEM_len_public_key);
}

void NICE_PAKE_RE_encaps(
    uint8_t *seed_b,
    uint8_t *ciphertext,
    uint8_t *shared_secret,
    const uint8_t *seed_a,
    const uint8_t *poly,
    const uint8_t *password)
{
    uint8_t seed_a_copy[XRKEM_len_seed];
    memcpy(seed_a_copy, seed_a, XRKEM_len_seed);
    for (int i = 0; i < XRKEM_len_seed; i++)
    {
        seed_a_copy[i] ^= password[i];
    }
    uint8_t public_key[XRKEM_len_public_key];
    memcpy(public_key + XRKEM_len_poly, seed_a_copy, XRKEM_len_seed);
    memcpy(public_key, poly, XRKEM_len_poly);
    RAND_bytes(seed_b, XRKEM_len_seed);
    uint8_t rand_public_key[XRKEM_len_public_key];
    XRKEM_rand(rand_public_key, seed_b, public_key);
    XRKEM_encaps(ciphertext, shared_secret, rand_public_key);
    for (int i = 0; i < XRKEM_len_seed; i++)
    {
        seed_b[i] ^= password[XRKEM_len_seed + i];
    }
}

void NICE_PAKE_RE_decaps(
    uint8_t *shared_secret,
    const uint8_t *seed_b,
    const uint8_t *ciphertext,
    const uint8_t *secret_key,
    const uint8_t *password)
{
    uint8_t seed_b_copy[XRKEM_len_seed];
    memcpy(seed_b_copy, seed_b, XRKEM_len_seed);
    for (int i = 0; i < XRKEM_len_seed; i++)
    {
        seed_b_copy[i] ^= password[XRKEM_len_seed + i];
    }
    XRKEM_decaps(shared_secret, ciphertext, secret_key, seed_b_copy);
}
