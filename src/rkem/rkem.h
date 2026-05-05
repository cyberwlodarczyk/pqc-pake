#ifndef RKEM_H
#define RKEM_H

#include <stdint.h>
#include "params.h"
#include "polyvec.h"

#define RKEM_LEN_PUBLIC_KEY RKEM_LEN_POLYVEC
#define RKEM_LEN_SECRET_KEY RKEM_LEN_POLYVEC
#define RKEM_LEN_CIPHERTEXT (RKEM_LEN_POLYVEC_COMPRESSED + RKEM_LEN_POLY_COMPRESSED)
#define RKEM_LEN_SHARED_SECRET RKEM_LEN_MSG

extern const RKEM_polyvec RKEM_A[RKEM_K];

extern const RKEM_polyvec RKEM_AT[RKEM_K];

void RKEM_gen_matrix(RKEM_polyvec *a, const uint8_t *seed, int transposed);

void RKEM_gen_matrix_fls(RKEM_polyvec *a, const uint8_t *seed, int transposed);

void RKEM_transpose_matrix(RKEM_polyvec *a);

void RKEM_keygen_a(
    uint8_t *public_key,
    uint8_t *secret_key,
    const RKEM_polyvec *a);

void RKEM_keygen(uint8_t *public_key, uint8_t *secret_key);

void RKEM_rand_a(
    uint8_t *rand_public_key,
    const uint8_t *seed,
    const uint8_t *public_key,
    const RKEM_polyvec *a);

void RKEM_rand(
    uint8_t *rand_public_key,
    const uint8_t *seed,
    const uint8_t *public_key);

void RKEM_derand_a(
    uint8_t *public_key,
    const uint8_t *seed,
    const uint8_t *rand_public_key,
    const RKEM_polyvec *a);

void RKEM_derand(
    uint8_t *public_key,
    const uint8_t *seed,
    const uint8_t *rand_public_key);

void RKEM_encaps_at(
    uint8_t *ciphertext,
    uint8_t *shared_secret,
    const uint8_t *public_key,
    const RKEM_polyvec *at);

void RKEM_encaps(
    uint8_t *ciphertext,
    uint8_t *shared_secret,
    const uint8_t *public_key);

void RKEM_decaps(
    uint8_t *shared_secret,
    const uint8_t *ciphertext,
    const uint8_t *secret_key,
    const uint8_t *seed);

void RKEM_decaps_derand(
    uint8_t *shared_secret,
    const uint8_t *ciphertext,
    const uint8_t *secret_key);

#endif
