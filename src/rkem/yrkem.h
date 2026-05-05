#ifndef YRKEM_H
#define YRKEM_H

#include "rkem.h"

#define YRKEM_LEN_POLYVEC RKEM_LEN_POLYVEC
#define YRKEM_LEN_SEED RKEM_LEN_SEED
#define YRKEM_LEN_PUBLIC_KEY (YRKEM_LEN_POLYVEC + YRKEM_LEN_SEED)
#define YRKEM_LEN_SECRET_KEY RKEM_LEN_SECRET_KEY
#define YRKEM_LEN_CIPHERTEXT RKEM_LEN_CIPHERTEXT
#define YRKEM_LEN_SHARED_SECRET RKEM_LEN_MSG

void YRKEM_keygen(
    uint8_t *public_key,
    uint8_t *secret_key,
    const uint8_t *seed);

void YRKEM_encaps(
    uint8_t *ciphertext,
    uint8_t *shared_secret,
    const uint8_t *public_key,
    const uint8_t *seed);

void YRKEM_decaps(
    uint8_t *shared_secret,
    const uint8_t *ciphertext,
    const uint8_t *secret_key);

#endif
