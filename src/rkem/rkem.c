#include "rkem_internal.h"
#include "rkem.h"

void RKEM_keygen(uint8_t *public_key, uint8_t *secret_key)
{
    rkem_keygen(public_key, secret_key, RKEM_A);
}

void RKEM_rand(
    uint8_t *rand_public_key,
    const uint8_t *seed,
    const uint8_t *public_key)
{
    rkem_rand(rand_public_key, seed, public_key, RKEM_A);
}

void RKEM_encaps(
    uint8_t *ciphertext,
    uint8_t *shared_secret,
    const uint8_t *public_key)
{
    rkem_encaps(ciphertext, shared_secret, public_key, RKEM_AT);
}

void RKEM_decaps(
    uint8_t *shared_secret,
    const uint8_t *ciphertext,
    const uint8_t *secret_key,
    const uint8_t *seed)
{
    rkem_decaps(shared_secret, ciphertext, secret_key, seed);
}
