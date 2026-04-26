#ifndef PQC_PAKE_RKEM_H
#define PQC_PAKE_RKEM_H

#include <stdint.h>

void PQC_PAKE_RKEM_keygen(uint8_t *public_key, uint8_t *secret_key);

void PQC_PAKE_RKEM_encaps(
    uint8_t *ciphertext,
    uint8_t *shared_secret,
    const uint8_t *public_key);

void PQC_PAKE_RKEM_decaps(
    uint8_t *shared_secret,
    const uint8_t *ciphertext,
    const uint8_t *secret_key,
    const uint8_t *seed);

void PQC_PAKE_RKEM_rand(
    uint8_t *rand_public_key,
    const uint8_t *seed,
    const uint8_t *public_key);

void PQC_PAKE_RKEM_derand(
    uint8_t *public_key,
    const uint8_t *seed,
    const uint8_t *rand_public_key);

#endif
