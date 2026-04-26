#include <string.h>
#include <kyber/symmetric.h>
#include "cbd.h"
#include "ntt.h"
#include "poly.h"
#include "reduce.h"

void poly_tobytes(uint8_t r[RKEM_POLYBYTES], const poly *a)
{
    for (int i = 0; i < 16; i++)
    {
        int pos = 0;
        for (int j = 0; j < 8; j++)
        {
            uint16_t t = a->coeffs[8 * i + j];
            t += ((int16_t)t >> 15) & RKEM_Q;
            for (int p = 12; p >= 0; p--)
            {
                int k = i * 13 + pos / 8;
                int b = 1 << (7 - (pos % 8));
                if (t & (1 << p))
                {
                    r[k] |= b;
                }
                else
                {
                    r[k] &= ~b;
                }
                pos++;
            }
        }
    }
}

void poly_frombytes(poly *r, const uint8_t a[RKEM_POLYBYTES])
{
    for (int i = 0; i < 16; i++)
    {
        int pos = 0;
        for (int j = 0; j < 8; j++)
        {
            uint16_t t;
            for (int p = 12; p >= 0; p--)
            {
                int k = i * 13 + pos / 8;
                int b = 1 << (7 - (pos % 8));
                if (a[k] & b)
                {
                    t |= (1 << p);
                }
                else
                {
                    t &= ~(1 << p);
                }
                pos++;
            }
            r->coeffs[8 * i + j] = t;
        }
    }
}

void poly_compress(uint8_t r[RKEM_POLYCOMPRESSEDBYTES], const poly *a)
{
    for (int i = 0; i < RKEM_N / 8; i++)
    {
        uint8_t t[8];
        for (int j = 0; j < 8; j++)
        {
            int16_t u = a->coeffs[8 * i + j];
            u += (u >> 15) & RKEM_Q;
            // t[j] = ((((uint16_t)u << 3) + RKEM_Q / 2) / RKEM_Q) & 7;
            uint32_t d0 = u << 3;
            d0 += 3841;
            d0 *= 69895;
            d0 >>= 29;
            t[j] = d0 & 7;
        }
        r[0] = t[0] | (t[1] << 3) | (t[2] << 6);
        r[1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
        r[2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
        r += 3;
    }
}

void poly_decompress(poly *r, const uint8_t a[RKEM_POLYCOMPRESSEDBYTES])
{
    for (int i = 0; i < RKEM_N / 8; i++)
    {
        uint8_t t[8];
        t[0] = a[0];
        t[1] = a[0] >> 3;
        t[2] = (a[0] >> 6) | (a[1] << 2);
        t[3] = (a[1] >> 1);
        t[4] = (a[1] >> 4);
        t[5] = (a[1] >> 7) | (a[2] << 1);
        t[6] = (a[2] >> 2);
        t[7] = (a[2] >> 5);
        for (int j = 0; j < 8; j++)
        {
            r->coeffs[8 * i + j] = (((uint16_t)(t[j] & 7) * RKEM_Q) + 4) >> 3;
        }
        a += 3;
    }
}

void poly_tomsg(uint8_t msg[RKEM_MSGBYTES], const poly *a)
{
    for (int i = 0; i < RKEM_N / 8; i++)
    {
        msg[i] = 0;
        for (int j = 0; j < 8; j++)
        {
            uint32_t t = a->coeffs[8 * i + j];
            // t += ((int16_t)t >> 15) & RKEM_Q;
            // t  = (((t << 1) + RKEM_Q / 2) / RKEM_Q) & 1;
            t <<= 1;
            t += 3841;
            t *= 34947;
            t >>= 28;
            t &= 1;
            msg[i] |= t << j;
        }
    }
}

void cmov_int16(int16_t *r, int16_t v, uint16_t b)
{
    b = -b;
    *r ^= b & ((*r) ^ v);
}

void poly_frommsg(poly *r, const uint8_t msg[RKEM_MSGBYTES])
{
    for (int i = 0; i < RKEM_N / 8; i++)
    {
        for (int j = 0; j < 8; j++)
        {
            r->coeffs[8 * i + j] = 0;
            cmov_int16(r->coeffs + 8 * i + j, ((RKEM_Q + 1) / 2), (msg[i] >> j) & 1);
        }
    }
}

void poly_add(poly *r, const poly *a, const poly *b)
{
    for (int i = 0; i < RKEM_N; i++)
    {
        r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    }
}

void poly_sub(poly *r, const poly *a, const poly *b)
{
    for (int i = 0; i < RKEM_N; i++)
    {
        r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
    }
}

void poly_reduce(poly *r)
{
    for (int i = 0; i < RKEM_N; i++)
    {
        r->coeffs[i] = barrett_reduce(r->coeffs[i]);
    }
}

void poly_ntt(poly *r)
{
    ntt(r->coeffs);
    poly_reduce(r);
}

void poly_invntt_tomont(poly *r)
{
    invntt(r->coeffs);
}

void poly_basemul_montgomery(poly *r, const poly *a, const poly *b)
{
    for (int i = 0; i < RKEM_N / 4; i++)
    {
        basemul(&r->coeffs[4 * i], &a->coeffs[4 * i], &b->coeffs[4 * i], zetas[32 + i]);
        basemul(&r->coeffs[4 * i + 2], &a->coeffs[4 * i + 2], &b->coeffs[4 * i + 2], -zetas[32 + i]);
    }
}

void poly_tomont(poly *r)
{
    const int16_t f = (1ULL << 32) % RKEM_Q;
    for (int i = 0; i < RKEM_N; i++)
    {
        r->coeffs[i] = montgomery_reduce((int32_t)r->coeffs[i] * f);
    }
}

void poly_getnoise_eta1(poly *r, const uint8_t seed[RKEM_SYMBYTES], uint8_t nonce)
{
    uint8_t buf[RKEM_ETA1 * RKEM_N / 4];
    prf(buf, sizeof(buf), seed, nonce);
    poly_cbd_eta1(r, buf);
}

void poly_getnoise_eta2(poly *r, const uint8_t seed[RKEM_SYMBYTES], uint8_t nonce)
{
    uint8_t buf[RKEM_ETA2 * RKEM_N / 4];
    prf(buf, sizeof(buf), seed, nonce);
    poly_cbd_eta2(r, buf);
}

void poly_getnoise_eta3(poly *r, const uint8_t seed[RKEM_SYMBYTES], uint8_t nonce)
{
    uint8_t buf[RKEM_ETA3 * RKEM_N / 4];
    prf(buf, sizeof(buf), seed, nonce);
    poly_cbd_eta3(r, buf);
}
