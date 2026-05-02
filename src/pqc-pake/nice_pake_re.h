#ifndef NICE_PAKE_RE_H
#define NICE_PAKE_RE_H

#include <stdint.h>

#define NICE_PAKE_RE_len_seed 32
#define NICE_PAKE_RE_len_password (2 * NICE_PAKE_RE_len_seed)
#define NICE_PAKE_RE_len_poly 1040
#define NICE_PAKE_RE_len_secret_key NICE_PAKE_RE_len_poly
#define NICE_PAKE_RE_len_ciphertext 848
#define NICE_PAKE_RE_len_shared_secret 16

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
