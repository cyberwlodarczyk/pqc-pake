#ifndef KYBER_POLYVEC_H
#define KYBER_POLYVEC_H

#include <stdint.h>
#include "params.h"
#include "poly.h"

typedef struct
{
    KYBER_poly vec[KYBER_K];
} KYBER_polyvec;

void KYBER_polyvec_compress(
    uint8_t r[KYBER_LEN_POLYVEC_COMPRESSED],
    const KYBER_polyvec *a);

void KYBER_polyvec_decompress(
    KYBER_polyvec *r,
    const uint8_t a[KYBER_LEN_POLYVEC_COMPRESSED]);

void KYBER_polyvec_tobytes(
    uint8_t r[KYBER_LEN_POLYVEC],
    const KYBER_polyvec *a);

void KYBER_polyvec_frombytes(
    KYBER_polyvec *r,
    const uint8_t a[KYBER_LEN_POLYVEC]);

void KYBER_polyvec_ntt(KYBER_polyvec *r);

void KYBER_polyvec_invntt_tomont(KYBER_polyvec *r);

void KYBER_polyvec_basemul_acc_montgomery(
    KYBER_poly *r,
    const KYBER_polyvec *a,
    const KYBER_polyvec *b);

void KYBER_polyvec_reduce(KYBER_polyvec *r);

void KYBER_polyvec_add(
    KYBER_polyvec *r,
    const KYBER_polyvec *a,
    const KYBER_polyvec *b);

void KYBER_polyvec_sub(
    KYBER_polyvec *r,
    const KYBER_polyvec *a,
    const KYBER_polyvec *b);

#endif
