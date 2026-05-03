#include "polyvec.h"

void RKEM_polyvec_tobytes(uint8_t r[RKEM_LEN_POLYVEC], const RKEM_polyvec *a)
{
    for (int i = 0; i < RKEM_K; i++)
    {
        RKEM_poly_tobytes(r + i * RKEM_LEN_POLY, &a->vec[i]);
    }
}

void RKEM_polyvec_frombytes(
    RKEM_polyvec *r,
    const uint8_t a[RKEM_LEN_POLYVEC])
{
    for (int i = 0; i < RKEM_K; i++)
    {
        RKEM_poly_frombytes(&r->vec[i], a + i * RKEM_LEN_POLY);
    }
}

void RKEM_polyvec_compress(
    uint8_t r[RKEM_LEN_POLYVEC_COMPRESSED],
    const RKEM_polyvec *a)
{
    for (int i = 0; i < RKEM_K; i++)
    {
        for (int j = 0; j < RKEM_N / 4; j++)
        {
            uint16_t t[4];
            for (int k = 0; k < 4; k++)
            {
                t[k] = a->vec[i].coeffs[4 * j + k];
                t[k] += ((int16_t)t[k] >> 15) & RKEM_Q;
                // t[k] = ((((uint32_t)t[k] << 10) + RKEM_Q / 2) / RKEM_Q) & 0x3ff;
                uint64_t d0 = t[k];
                d0 <<= 10;
                d0 += 3841;
                d0 *= 559167;
                d0 >>= 32;
                t[k] = d0 & 0x3ff;
            }
            r[0] = t[0];
            r[1] = (t[0] >> 8) | (t[1] << 2);
            r[2] = (t[1] >> 6) | (t[2] << 4);
            r[3] = (t[2] >> 4) | (t[3] << 6);
            r[4] = (t[3] >> 2);
            r += 5;
        }
    }
}

void RKEM_polyvec_decompress(
    RKEM_polyvec *r,
    const uint8_t a[RKEM_LEN_POLYVEC_COMPRESSED])
{
    for (int i = 0; i < RKEM_K; i++)
    {
        for (int j = 0; j < RKEM_N / 4; j++)
        {
            uint16_t t[4];
            t[0] = a[0] | ((uint16_t)a[1] << 8);
            t[1] = (a[1] >> 2) | ((uint16_t)a[2] << 6);
            t[2] = (a[2] >> 4) | ((uint16_t)a[3] << 4);
            t[3] = (a[3] >> 6) | ((uint16_t)a[4] << 2);
            a += 5;
            for (int k = 0; k < 4; k++)
            {
                r->vec[i].coeffs[4 * j + k] = ((uint32_t)(t[k] & 0x3ff) * RKEM_Q + 512) >> 10;
            }
        }
    }
}

void RKEM_polyvec_ntt(RKEM_polyvec *r)
{
    for (int i = 0; i < RKEM_K; i++)
    {
        RKEM_poly_ntt(&r->vec[i]);
    }
}

void RKEM_polyvec_invntt_tomont(RKEM_polyvec *r)
{
    for (int i = 0; i < RKEM_K; i++)
    {
        RKEM_poly_invntt_tomont(&r->vec[i]);
    }
}

void RKEM_polyvec_basemul_acc_montgomery(
    RKEM_poly *r,
    const RKEM_polyvec *a,
    const RKEM_polyvec *b)
{
    RKEM_poly_basemul_montgomery(r, &a->vec[0], &b->vec[0]);
    for (int i = 1; i < RKEM_K; i++)
    {
        RKEM_poly t;
        RKEM_poly_basemul_montgomery(&t, &a->vec[i], &b->vec[i]);
        RKEM_poly_add(r, r, &t);
    }
    RKEM_poly_reduce(r);
}

void RKEM_polyvec_reduce(RKEM_polyvec *r)
{
    for (int i = 0; i < RKEM_K; i++)
    {
        RKEM_poly_reduce(&r->vec[i]);
    }
}

void RKEM_polyvec_add(
    RKEM_polyvec *r,
    const RKEM_polyvec *a,
    const RKEM_polyvec *b)
{
    for (int i = 0; i < RKEM_K; i++)
    {
        RKEM_poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
    }
}

void RKEM_polyvec_sub(
    RKEM_polyvec *r,
    const RKEM_polyvec *a,
    const RKEM_polyvec *b)
{
    for (int i = 0; i < RKEM_K; i++)
    {
        RKEM_poly_sub(&r->vec[i], &a->vec[i], &b->vec[i]);
    }
}
