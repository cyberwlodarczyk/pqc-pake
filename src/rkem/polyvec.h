#ifndef RKEM_POLYVEC_H
#define RKEM_POLYVEC_H

#include "poly.h"

typedef struct
{
    RKEM_poly vec[RKEM_K];
} RKEM_polyvec;

void RKEM_polyvec_tobytes(uint8_t r[RKEM_LEN_POLYVEC], const RKEM_polyvec *a);

void RKEM_polyvec_frombytes(
    RKEM_polyvec *r,
    const uint8_t a[RKEM_LEN_POLYVEC]);

void RKEM_polyvec_compress(
    uint8_t r[RKEM_LEN_POLYVEC_COMPRESSED],
    const RKEM_polyvec *a);

void RKEM_polyvec_decompress(
    RKEM_polyvec *r,
    const uint8_t a[RKEM_LEN_POLYVEC_COMPRESSED]);

void RKEM_polyvec_ntt(RKEM_polyvec *r);

void RKEM_polyvec_invntt_tomont(RKEM_polyvec *r);

void RKEM_polyvec_basemul_acc_montgomery(
    RKEM_poly *r,
    const RKEM_polyvec *a,
    const RKEM_polyvec *b);

void RKEM_polyvec_reduce(RKEM_polyvec *r);

void RKEM_polyvec_add(
    RKEM_polyvec *r,
    const RKEM_polyvec *a,
    const RKEM_polyvec *b);

void RKEM_polyvec_sub(
    RKEM_polyvec *r,
    const RKEM_polyvec *a,
    const RKEM_polyvec *b);

#endif
