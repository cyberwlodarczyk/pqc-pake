#ifndef NICE_PAKE_H
#define NICE_PAKE_H

#include <stdint.h>

#define NICE_PAKE_len_seed 32
#define NICE_PAKE_len_password NICE_PAKE_len_seed
#define NICE_PAKE_len_poly 1152
#define NICE_PAKE_len_secret_key 2400
#define NICE_PAKE_len_ciphertext 1088
#define NICE_PAKE_len_shared_secret 32

void NICE_PAKE_keygen(
    uint8_t *seed,
    uint8_t *poly,
    uint8_t *secret_key,
    const uint8_t *password);

void NICE_PAKE_encaps(
    uint8_t *ciphertext,
    uint8_t *shared_secret,
    const uint8_t *seed,
    const uint8_t *poly,
    const uint8_t *password);

void NICE_PAKE_decaps(
    uint8_t *shared_secret,
    const uint8_t *ciphertext,
    const uint8_t *secret_key);

#endif
