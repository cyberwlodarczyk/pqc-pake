#include <string.h>
#include <openssl/crypto.h>
#include <kyber/kem.h>
#include "nice_pake.h"

void NICE_PAKE_keygen(
    uint8_t *seed,
    uint8_t *poly,
    uint8_t *secret_key,
    const uint8_t *password)
{
    uint8_t public_key[KYBER_PUBLICKEYBYTES];
    pqcrystals_kyber768_ref_keypair(public_key, secret_key);
    memcpy(seed, public_key + KYBER_POLYVECBYTES, KYBER_SYMBYTES);
    memcpy(poly, public_key, KYBER_POLYVECBYTES);
    for (size_t i = 0; i < KYBER_SYMBYTES; i++)
    {
        seed[i] ^= password[i];
    }
    OPENSSL_cleanse(public_key, KYBER_PUBLICKEYBYTES);
}

void NICE_PAKE_encaps(
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
    memcpy(public_key + KYBER_POLYVECBYTES, seed_copy, KYBER_SYMBYTES);
    memcpy(public_key, poly, KYBER_POLYVECBYTES);
    pqcrystals_kyber768_ref_enc(ciphertext, shared_secret, public_key);
    OPENSSL_cleanse(seed_copy, KYBER_SYMBYTES);
    OPENSSL_cleanse(public_key, KYBER_PUBLICKEYBYTES);
}

void NICE_PAKE_decaps(
    uint8_t *shared_secret,
    const uint8_t *ciphertext,
    const uint8_t *secret_key)
{
    pqcrystals_kyber768_ref_dec(shared_secret, ciphertext, secret_key);
}
