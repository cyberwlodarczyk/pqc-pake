#ifndef RKEM_INTERNAL_H
#define RKEM_INTERNAL_H

#include <stdint.h>
#include "polyvec.h"
#include "params.h"

extern const polyvec RKEM_A[RKEM_K];

extern const polyvec RKEM_AT[RKEM_K];

void rkem_fls(polyvec *a, const uint8_t *seed, int transposed);

void rkem_keygen(uint8_t *public_key, uint8_t *secret_key, const polyvec *a);

void rkem_rand(
    uint8_t *rand_public_key,
    const uint8_t *seed,
    const uint8_t *public_key,
    const polyvec *a);

void rkem_derand(
    uint8_t *public_key,
    const uint8_t *seed,
    const uint8_t *rand_public_key,
    const polyvec *a);

void rkem_encaps(
    uint8_t *ciphertext,
    uint8_t *shared_secret,
    const uint8_t *public_key,
    const polyvec *at);

void rkem_decaps_derand(
    uint8_t *shared_secret,
    const uint8_t *ciphertext,
    const uint8_t *secret_key);

void rkem_decaps(
    uint8_t *shared_secret,
    const uint8_t *ciphertext,
    const uint8_t *secret_key,
    const uint8_t *seed);

#endif
