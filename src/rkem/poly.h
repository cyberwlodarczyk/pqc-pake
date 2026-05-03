#ifndef RKEM_POLY_H
#define RKEM_POLY_H

#include <stdint.h>
#include "params.h"

typedef struct
{
    int16_t coeffs[RKEM_N];
} RKEM_poly;

void RKEM_poly_tobytes(uint8_t r[RKEM_LEN_POLY], const RKEM_poly *a);

void RKEM_poly_frombytes(RKEM_poly *r, const uint8_t a[RKEM_LEN_POLY]);

void RKEM_poly_compress(
    uint8_t r[RKEM_LEN_POLY_COMPRESSED],
    const RKEM_poly *a);

void RKEM_poly_decompress(
    RKEM_poly *r,
    const uint8_t a[RKEM_LEN_POLY_COMPRESSED]);

void RKEM_poly_tomsg(uint8_t msg[RKEM_LEN_MSG], const RKEM_poly *a);

void RKEM_poly_frommsg(RKEM_poly *r, const uint8_t msg[RKEM_LEN_MSG]);

void RKEM_poly_add(RKEM_poly *r, const RKEM_poly *a, const RKEM_poly *b);

void RKEM_poly_sub(RKEM_poly *r, const RKEM_poly *a, const RKEM_poly *b);

void RKEM_poly_reduce(RKEM_poly *r);

void RKEM_poly_ntt(RKEM_poly *r);

void RKEM_poly_invntt_tomont(RKEM_poly *r);

void RKEM_poly_basemul_montgomery(
    RKEM_poly *r,
    const RKEM_poly *a,
    const RKEM_poly *b);

void RKEM_poly_tomont(RKEM_poly *r);

void RKEM_poly_get_noise_eta1(
    RKEM_poly *r,
    const uint8_t seed[RKEM_LEN_SEED],
    uint8_t nonce);

void RKEM_poly_get_noise_eta2(
    RKEM_poly *r,
    const uint8_t seed[RKEM_LEN_SEED],
    uint8_t nonce);

void RKEM_poly_get_noise_eta3(
    RKEM_poly *r,
    const uint8_t seed[RKEM_LEN_SEED],
    uint8_t nonce);

#endif
