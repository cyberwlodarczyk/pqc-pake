#ifndef PQC_PAKE_KEM_H
#define PQC_PAKE_KEM_H

#include <stdint.h>
#include <kyber/params.h>

#define PQC_PAKE_KEM_len_public_key KYBER_PUBLICKEYBYTES
#define PQC_PAKE_KEM_len_seed KYBER_SYMBYTES
#define PQC_PAKE_KEM_len_poly KYBER_POLYVECBYTES
#define PQC_PAKE_KEM_len_secret_key KYBER_SECRETKEYBYTES
#define PQC_PAKE_KEM_len_ciphertext KYBER_CIPHERTEXTBYTES
#define PQC_PAKE_KEM_len_shared_secret KYBER_SSBYTES

void PQC_PAKE_KEM_keygen(uint8_t *public_key, uint8_t *secret_key);

void PQC_PAKE_KEM_encaps(
    uint8_t *ciphertext,
    uint8_t *shared_secret,
    const uint8_t *public_key);

void PQC_PAKE_KEM_decaps(
    uint8_t *shared_secret,
    const uint8_t *ciphertext,
    const uint8_t *secret_key);

void PQC_PAKE_KEM_split(
    uint8_t *seed,
    uint8_t *poly,
    const uint8_t *public_key);

void PQC_PAKE_KEM_join(
    uint8_t *public_key,
    const uint8_t *seed,
    const uint8_t *poly);

#endif
