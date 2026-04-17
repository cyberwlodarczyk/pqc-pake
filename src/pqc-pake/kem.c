#include <string.h>
#include <kyber/kem.h>
#include "kem.h"

void PQC_PAKE_KEM_keygen(uint8_t *public_key, uint8_t *secret_key)
{
    pqcrystals_kyber768_ref_keypair(public_key, secret_key);
}

void PQC_PAKE_KEM_encaps(
    uint8_t *ciphertext,
    uint8_t *shared_secret,
    const uint8_t *public_key)
{
    pqcrystals_kyber768_ref_enc(ciphertext, shared_secret, public_key);
}

void PQC_PAKE_KEM_decaps(
    uint8_t *shared_secret,
    const uint8_t *ciphertext,
    const uint8_t *secret_key)
{
    pqcrystals_kyber768_ref_dec(shared_secret, ciphertext, secret_key);
}

void PQC_PAKE_KEM_split(
    uint8_t *seed,
    uint8_t *poly,
    const uint8_t *public_key)
{
    memcpy(seed, public_key + KYBER_POLYVECBYTES, KYBER_SYMBYTES);
    memcpy(poly, public_key, KYBER_POLYVECBYTES);
}

void PQC_PAKE_KEM_join(
    uint8_t *public_key,
    const uint8_t *seed,
    const uint8_t *poly)
{
    memcpy(public_key + KYBER_POLYVECBYTES, seed, KYBER_SYMBYTES);
    memcpy(public_key, poly, KYBER_POLYVECBYTES);
}
