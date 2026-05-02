#ifndef RKEM_H
#define RKEM_H

#include <stdint.h>

#define RKEM_len_public_key 1040
#define RKEM_len_secret_key 1040
#define RKEM_len_seed 32
#define RKEM_len_ciphertext 848
#define RKEM_len_shared_secret 16

void RKEM_keygen(uint8_t *public_key, uint8_t *secret_key);

void RKEM_rand(
    uint8_t *rand_public_key,
    const uint8_t *seed,
    const uint8_t *public_key);

void RKEM_encaps(
    uint8_t *ciphertext,
    uint8_t *shared_secret,
    const uint8_t *public_key);

void RKEM_decaps(
    uint8_t *shared_secret,
    const uint8_t *ciphertext,
    const uint8_t *secret_key,
    const uint8_t *seed);

#endif
