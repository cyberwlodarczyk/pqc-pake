#ifndef RKEM_H
#define RKEM_H

#include <stdint.h>
#include "params.h"

extern const polyvec RKEM_A[RKEM_K];

extern const polyvec RKEM_AT[RKEM_K];

void RKEM_fls(polyvec *a, const uint8_t *seed, int transposed);

void RKEM_keypair(uint8_t *pk, uint8_t *sk);

void RKEM_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);

void RKEM_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif
