#ifndef KYBER_POLY_H
#define KYBER_POLY_H

#include <stdint.h>
#include "params.h"

typedef struct
{
    int16_t coeffs[KYBER_N];
} KYBER_poly;

void KYBER_poly_compress(uint8_t r[KYBER_LEN_POLY_COMPRESSED], const KYBER_poly *a);

void KYBER_poly_decompress(KYBER_poly *r, const uint8_t a[KYBER_LEN_POLY_COMPRESSED]);

void KYBER_poly_tobytes(uint8_t r[KYBER_LEN_POLY], const KYBER_poly *a);

void KYBER_poly_frombytes(KYBER_poly *r, const uint8_t a[KYBER_LEN_POLY]);

void KYBER_poly_frommsg(KYBER_poly *r, const uint8_t msg[KYBER_INDCPA_LEN_MSG]);

void KYBER_poly_tomsg(uint8_t msg[KYBER_INDCPA_LEN_MSG], const KYBER_poly *r);

void KYBER_poly_get_noise_eta1(KYBER_poly *r, const uint8_t seed[KYBER_LEN_SEED], uint8_t nonce);

void KYBER_poly_get_noise_eta2(KYBER_poly *r, const uint8_t seed[KYBER_LEN_SEED], uint8_t nonce);

void KYBER_poly_ntt(KYBER_poly *r);

void KYBER_poly_invntt_tomont(KYBER_poly *r);

void KYBER_poly_basemul_montgomery(KYBER_poly *r, const KYBER_poly *a, const KYBER_poly *b);

void KYBER_poly_tomont(KYBER_poly *r);

void KYBER_poly_reduce(KYBER_poly *r);

void KYBER_poly_add(KYBER_poly *r, const KYBER_poly *a, const KYBER_poly *b);

void KYBER_poly_sub(KYBER_poly *r, const KYBER_poly *a, const KYBER_poly *b);

#endif
