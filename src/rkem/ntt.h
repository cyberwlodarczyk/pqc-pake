#ifndef RKEM_NTT_H
#define RKEM_NTT_H

#include <stdint.h>

extern const int16_t zetas[64];

void ntt(int16_t r[128]);

void invntt(int16_t r[128]);

void basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta);

#endif
