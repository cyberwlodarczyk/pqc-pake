#ifndef PQC_PAKE_NICE_H
#define PQC_PAKE_NICE_H

#include <stdint.h>
#include <kyber/params.h>

#define PQC_PAKE_NICE_len_password KYBER_SYMBYTES
#define PQC_PAKE_NICE_len_seed KYBER_SYMBYTES
#define PQC_PAKE_NICE_len_poly KYBER_PUBLICKEYBYTES
#define PQC_PAKE_NICE_len_secret_key KYBER_SECRETKEYBYTES
#define PQC_PAKE_NICE_len_ciphertext KYBER_CIPHERTEXTBYTES
#define PQC_PAKE_NICE_len_shared_secret KYBER_SSBYTES

void PQC_PAKE_NICE_keygen(
    uint8_t *seed,
    uint8_t *poly,
    uint8_t *secret_key,
    const uint8_t *password);

void PQC_PAKE_NICE_encaps(
    uint8_t *ciphertext,
    uint8_t *shared_secret,
    const uint8_t *seed,
    const uint8_t *poly,
    const uint8_t *password);

void PQC_PAKE_NICE_decaps(
    uint8_t *shared_secret,
    const uint8_t *ciphertext,
    const uint8_t *secret_key);

#endif
