#ifndef NICE_PAKE_RE_H
#define NICE_PAKE_RE_H

#include <stdint.h>

#define NICE_PAKE_RE_LEN_SEED 32
#define NICE_PAKE_RE_LEN_PASSWORD (2 * NICE_PAKE_RE_LEN_SEED)
#define NICE_PAKE_RE_LEN_POLY 1040
#define NICE_PAKE_RE_LEN_SECRET_KEY NICE_PAKE_RE_LEN_POLY
#define NICE_PAKE_RE_LEN_CIPHERTEXT 848
#define NICE_PAKE_RE_LEN_SHARED_SECRET 16

void NICE_PAKE_RE_keygen(
    uint8_t *seed_a,
    uint8_t *poly,
    uint8_t *secret_key,
    const uint8_t *password);

void NICE_PAKE_RE_encaps(
    uint8_t *seed_b,
    uint8_t *ciphertext,
    uint8_t *shared_secret,
    const uint8_t *seed_a,
    const uint8_t *poly,
    const uint8_t *password);

void NICE_PAKE_RE_decaps(
    uint8_t *shared_secret,
    const uint8_t *seed_b,
    const uint8_t *ciphertext,
    const uint8_t *secret_key,
    const uint8_t *password);

#endif
