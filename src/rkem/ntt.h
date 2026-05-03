#ifndef RKEM_NTT_H
#define RKEM_NTT_H

#include <stdint.h>
#include "params.h"

extern const int16_t RKEM_NTT_ZETAS[RKEM_N / 2];

int16_t RKEM_ntt_fqmul(int16_t a, int16_t b);

void RKEM_ntt_basemul(
    int16_t r[2],
    const int16_t a[2],
    const int16_t b[2],
    int16_t zeta);

void RKEM_ntt_forward(int16_t r[RKEM_N]);

void RKEM_ntt_inverse(int16_t r[RKEM_N]);

#endif
