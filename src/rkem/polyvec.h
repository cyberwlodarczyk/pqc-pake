#ifndef RKEM_POLYVEC_H
#define RKEM_POLYVEC_H

#include "poly.h"

typedef struct
{
    poly vec[RKEM_K];
} polyvec;

void polyvec_tobytes(uint8_t r[RKEM_POLYVECBYTES], const polyvec *a);

void polyvec_frombytes(polyvec *r, const uint8_t a[RKEM_POLYVECBYTES]);

void polyvec_compress(uint8_t r[RKEM_POLYVECCOMPRESSEDBYTES], const polyvec *a);

void polyvec_decompress(polyvec *r, const uint8_t a[RKEM_POLYVECCOMPRESSEDBYTES]);

void polyvec_ntt(polyvec *r);

void polyvec_invntt_tomont(polyvec *r);

void polyvec_basemul_acc_montgomery(poly *r, const polyvec *a, const polyvec *b);

void polyvec_reduce(polyvec *r);

void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b);

#endif
