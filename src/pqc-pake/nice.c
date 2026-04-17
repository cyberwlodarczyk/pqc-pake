#include <string.h>
#include <openssl/crypto.h>
#include "kem.h"

void PQC_PAKE_NICE_keygen(
    uint8_t *seed,
    uint8_t *poly,
    uint8_t *secret_key,
    const uint8_t *password)
{
    uint8_t public_key[KYBER_PUBLICKEYBYTES];
    PQC_PAKE_KEM_keygen(public_key, secret_key);
    PQC_PAKE_KEM_split(seed, poly, public_key);
    for (size_t i = 0; i < KYBER_SYMBYTES; i++)
    {
        seed[i] ^= password[i];
    }
    OPENSSL_cleanse(public_key, KYBER_PUBLICKEYBYTES);
}

void PQC_PAKE_NICE_encaps(
    uint8_t *ciphertext,
    uint8_t *shared_secret,
    const uint8_t *seed,
    const uint8_t *poly,
    const uint8_t *password)
{
    uint8_t seed_copy[KYBER_SYMBYTES];
    memcpy(seed_copy, seed, KYBER_SYMBYTES);
    for (size_t i = 0; i < KYBER_SYMBYTES; i++)
    {
        seed_copy[i] ^= password[i];
    }
    uint8_t public_key[KYBER_PUBLICKEYBYTES];
    PQC_PAKE_KEM_join(public_key, seed_copy, poly);
    PQC_PAKE_KEM_encaps(ciphertext, shared_secret, public_key);
    OPENSSL_cleanse(seed_copy, KYBER_SYMBYTES);
    OPENSSL_cleanse(public_key, KYBER_PUBLICKEYBYTES);
}

void PQC_PAKE_NICE_decaps(
    uint8_t *shared_secret,
    const uint8_t *ciphertext,
    const uint8_t *secret_key)
{
    PQC_PAKE_KEM_decaps(shared_secret, ciphertext, secret_key);
}
