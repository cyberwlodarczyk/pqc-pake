#ifndef XRKEM_H
#define XRKEM_H

#include "rkem.h"

#define XRKEM_LEN_POLYVEC RKEM_LEN_POLYVEC
#define XRKEM_LEN_SEED RKEM_LEN_SEED
#define XRKEM_LEN_PUBLIC_KEY (XRKEM_LEN_POLYVEC + XRKEM_LEN_SEED)
#define XRKEM_LEN_SECRET_KEY RKEM_LEN_SECRET_KEY
#define XRKEM_LEN_CIPHERTEXT RKEM_LEN_CIPHERTEXT
#define XRKEM_LEN_SHARED_SECRET RKEM_LEN_MSG

void XRKEM_keygen(uint8_t *public_key, uint8_t *secret_key);

void XRKEM_rand(
    uint8_t *rand_public_key,
    const uint8_t *seed,
    const uint8_t *public_key);

void XRKEM_derand(
    uint8_t *public_key,
    const uint8_t *seed,
    const uint8_t *rand_public_key);

void XRKEM_encaps(
    uint8_t *ciphertext,
    uint8_t *shared_secret,
    const uint8_t *public_key);

void XRKEM_decaps(
    uint8_t *shared_secret,
    const uint8_t *ciphertext,
    const uint8_t *secret_key,
    const uint8_t *seed);

void XRKEM_decaps_derand(
    uint8_t *shared_secret,
    const uint8_t *ciphertext,
    const uint8_t *secret_key);

#endif
