#ifndef XRKEM_H
#define XRKEM_H

#include <stdint.h>

#define XRKEM_len_poly 1040
#define XRKEM_len_seed 32
#define XRKEM_len_public_key (XRKEM_len_poly + XRKEM_len_seed)
#define XRKEM_len_secret_key XRKEM_len_poly
#define XRKEM_len_ciphertext 848
#define XRKEM_len_shared_secret 16

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
