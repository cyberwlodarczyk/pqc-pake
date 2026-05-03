#include <stdint.h>
#include "params.h"
#include "poly.h"
#include "polyvec.h"

void KYBER_polyvec_compress(
    uint8_t r[KYBER_LEN_POLYVEC_COMPRESSED],
    const KYBER_polyvec *a)
{
    for (int i = 0; i < KYBER_K; i++)
    {
        for (int j = 0; j < KYBER_N / 4; j++)
        {
            uint16_t t[4];
            for (int k = 0; k < 4; k++)
            {
                t[k] = a->vec[i].coeffs[4 * j + k];
                t[k] += ((int16_t)t[k] >> 15) & KYBER_Q;
                // t[k]  = ((((uint32_t)t[k] << 10) + KYBER_Q / 2) / KYBER_Q) & 0x3ff;
                uint64_t d0 = t[k];
                d0 <<= 10;
                d0 += 1665;
                d0 *= 1290167;
                d0 >>= 32;
                t[k] = d0 & 0x3ff;
            }
            r[0] = (t[0] >> 0);
            r[1] = (t[0] >> 8) | (t[1] << 2);
            r[2] = (t[1] >> 6) | (t[2] << 4);
            r[3] = (t[2] >> 4) | (t[3] << 6);
            r[4] = (t[3] >> 2);
            r += 5;
        }
    }
}

void KYBER_polyvec_decompress(
    KYBER_polyvec *r,
    const uint8_t a[KYBER_LEN_POLYVEC_COMPRESSED])
{
    for (int i = 0; i < KYBER_K; i++)
    {
        for (int j = 0; j < KYBER_N / 4; j++)
        {
            uint16_t t[4];
            t[0] = (a[0] >> 0) | ((uint16_t)a[1] << 8);
            t[1] = (a[1] >> 2) | ((uint16_t)a[2] << 6);
            t[2] = (a[2] >> 4) | ((uint16_t)a[3] << 4);
            t[3] = (a[3] >> 6) | ((uint16_t)a[4] << 2);
            a += 5;
            for (int k = 0; k < 4; k++)
            {
                r->vec[i].coeffs[4 * j + k] =
                    ((uint32_t)(t[k] & 0x3FF) * KYBER_Q + 512) >> 10;
            }
        }
    }
}

void KYBER_polyvec_tobytes(
    uint8_t r[KYBER_LEN_POLYVEC],
    const KYBER_polyvec *a)
{
    for (int i = 0; i < KYBER_K; i++)
    {
        KYBER_poly_tobytes(r + i * KYBER_LEN_POLY, &a->vec[i]);
    }
}

void KYBER_polyvec_frombytes(
    KYBER_polyvec *r,
    const uint8_t a[KYBER_LEN_POLYVEC])
{
    for (int i = 0; i < KYBER_K; i++)
    {
        KYBER_poly_frombytes(&r->vec[i], a + i * KYBER_LEN_POLY);
    }
}

void KYBER_polyvec_ntt(KYBER_polyvec *r)
{
    for (int i = 0; i < KYBER_K; i++)
    {
        KYBER_poly_ntt(&r->vec[i]);
    }
}

void KYBER_polyvec_invntt_tomont(KYBER_polyvec *r)
{
    for (int i = 0; i < KYBER_K; i++)
    {
        KYBER_poly_invntt_tomont(&r->vec[i]);
    }
}

void KYBER_polyvec_basemul_acc_montgomery(
    KYBER_poly *r,
    const KYBER_polyvec *a,
    const KYBER_polyvec *b)
{
    KYBER_poly_basemul_montgomery(r, &a->vec[0], &b->vec[0]);
    for (int i = 1; i < KYBER_K; i++)
    {
        KYBER_poly t;
        KYBER_poly_basemul_montgomery(&t, &a->vec[i], &b->vec[i]);
        KYBER_poly_add(r, r, &t);
    }
    KYBER_poly_reduce(r);
}

void KYBER_polyvec_reduce(KYBER_polyvec *r)
{
    for (int i = 0; i < KYBER_K; i++)
    {
        KYBER_poly_reduce(&r->vec[i]);
    }
}

void KYBER_polyvec_add(
    KYBER_polyvec *r,
    const KYBER_polyvec *a,
    const KYBER_polyvec *b)
{
    for (int i = 0; i < KYBER_K; i++)
    {
        KYBER_poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
    }
}

void KYBER_polyvec_sub(
    KYBER_polyvec *r,
    const KYBER_polyvec *a,
    const KYBER_polyvec *b)
{
    for (int i = 0; i < KYBER_K; i++)
    {
        KYBER_poly_sub(&r->vec[i], &a->vec[i], &b->vec[i]);
    }
}
