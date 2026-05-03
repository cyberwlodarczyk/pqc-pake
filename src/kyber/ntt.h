#ifndef KYBER_NTT_H
#define KYBER_NTT_H

#include <stdint.h>
#include "params.h"

extern const int16_t KYBER_NTT_ZETAS[KYBER_N / 2];

void KYBER_ntt_forward(int16_t poly[KYBER_N]);

void KYBER_ntt_inverse(int16_t poly[KYBER_N]);

void KYBER_ntt_basemul(
    int16_t r[2],
    const int16_t a[2],
    const int16_t b[2],
    int16_t zeta);

#endif
