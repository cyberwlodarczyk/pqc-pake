#include <string.h>
#include <openssl/crypto.h>
#include <kyber/kyber.h>
#include "nice_pake.h"

void NICE_PAKE_keygen(
    uint8_t *seed,
    uint8_t *poly,
    uint8_t *secret_key,
    const uint8_t *password)
{
    uint8_t public_key[KYBER_LEN_PUBLIC_KEY];
    KYBER_keygen(public_key, secret_key);
    memcpy(seed, public_key + KYBER_LEN_POLYVEC, KYBER_LEN_SEED);
    memcpy(poly, public_key, KYBER_LEN_POLYVEC);
    for (int i = 0; i < KYBER_LEN_SEED; i++)
    {
        seed[i] ^= password[i];
    }
    OPENSSL_cleanse(public_key, KYBER_LEN_PUBLIC_KEY);
}

void NICE_PAKE_encaps(
    uint8_t *ciphertext,
    uint8_t *shared_secret,
    const uint8_t *seed,
    const uint8_t *poly,
    const uint8_t *password)
{
    uint8_t seed_copy[KYBER_LEN_SEED];
    memcpy(seed_copy, seed, KYBER_LEN_SEED);
    for (int i = 0; i < KYBER_LEN_SEED; i++)
    {
        seed_copy[i] ^= password[i];
    }
    uint8_t public_key[KYBER_LEN_PUBLIC_KEY];
    memcpy(public_key + KYBER_LEN_POLYVEC, seed_copy, KYBER_LEN_SEED);
    memcpy(public_key, poly, KYBER_LEN_POLYVEC);
    KYBER_encaps(ciphertext, shared_secret, public_key);
    OPENSSL_cleanse(seed_copy, KYBER_LEN_SEED);
    OPENSSL_cleanse(public_key, KYBER_LEN_PUBLIC_KEY);
}

void NICE_PAKE_decaps(
    uint8_t *shared_secret,
    const uint8_t *ciphertext,
    const uint8_t *secret_key)
{
    KYBER_decaps(shared_secret, ciphertext, secret_key);
}
