#include "polyvec.h"

void polyvec_tobytes(uint8_t r[RKEM_POLYVECBYTES], const polyvec *a)
{
    for (int i = 0; i < RKEM_K; i++)
    {
        poly_tobytes(r + i * RKEM_POLYBYTES, &a->vec[i]);
    }
}

void polyvec_frombytes(polyvec *r, const uint8_t a[RKEM_POLYVECBYTES])
{
    for (int i = 0; i < RKEM_K; i++)
    {
        poly_frombytes(&r->vec[i], a + i * RKEM_POLYBYTES);
    }
}

void polyvec_compress(uint8_t r[RKEM_POLYVECCOMPRESSEDBYTES], const polyvec *a)
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

void polyvec_decompress(polyvec *r, const uint8_t a[RKEM_POLYVECCOMPRESSEDBYTES])
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

void polyvec_ntt(polyvec *r)
{
    for (int i = 0; i < RKEM_K; i++)
    {
        poly_ntt(&r->vec[i]);
    }
}

void polyvec_invntt_tomont(polyvec *r)
{
    for (int i = 0; i < RKEM_K; i++)
    {
        poly_invntt_tomont(&r->vec[i]);
    }
}

void polyvec_basemul_acc_montgomery(poly *r, const polyvec *a, const polyvec *b)
{
    poly_basemul_montgomery(r, &a->vec[0], &b->vec[0]);
    for (int i = 1; i < RKEM_K; i++)
    {
        poly t;
        poly_basemul_montgomery(&t, &a->vec[i], &b->vec[i]);
        poly_add(r, r, &t);
    }
    poly_reduce(r);
}

void polyvec_reduce(polyvec *r)
{
    for (int i = 0; i < RKEM_K; i++)
    {
        poly_reduce(&r->vec[i]);
    }
}

void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b)
{
    for (int i = 0; i < RKEM_K; i++)
    {
        poly_add(&r->vec[i], &a->vec[i], &b->vec[i]);
    }
}
