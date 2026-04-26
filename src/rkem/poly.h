#ifndef RKEM_POLY_H
#define RKEM_POLY_H

#include <stdint.h>
#include "params.h"

typedef struct
{
    int16_t coeffs[RKEM_N];
} poly;

void poly_tobytes(uint8_t r[RKEM_POLYBYTES], const poly *a);

void poly_frombytes(poly *r, const uint8_t a[RKEM_POLYBYTES]);

void poly_compress(uint8_t r[RKEM_POLYCOMPRESSEDBYTES], const poly *a);

void poly_decompress(poly *r, const uint8_t a[RKEM_POLYCOMPRESSEDBYTES]);

void poly_tomsg(uint8_t msg[RKEM_MSGBYTES], const poly *a);

void poly_frommsg(poly *r, const uint8_t msg[RKEM_MSGBYTES]);

void poly_add(poly *r, const poly *a, const poly *b);

void poly_sub(poly *r, const poly *a, const poly *b);

void poly_reduce(poly *r);

void poly_ntt(poly *r);

void poly_invntt_tomont(poly *r);

void poly_basemul_montgomery(poly *r, const poly *a, const poly *b);

void poly_tomont(poly *r);

void poly_getnoise_eta1(poly *r, const uint8_t seed[RKEM_SYMBYTES], uint8_t nonce);

void poly_getnoise_eta2(poly *r, const uint8_t seed[RKEM_SYMBYTES], uint8_t nonce);

void poly_getnoise_eta3(poly *r, const uint8_t seed[RKEM_SYMBYTES], uint8_t nonce);

#endif
