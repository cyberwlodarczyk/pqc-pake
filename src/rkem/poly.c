#include <kyber/symmetric.h>
#include "cbd.h"
#include "ntt.h"
#include "poly.h"
#include "reduce.h"

void RKEM_poly_tobytes(uint8_t r[RKEM_LEN_POLY], const RKEM_poly *a)
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

void RKEM_poly_frombytes(RKEM_poly *r, const uint8_t a[RKEM_LEN_POLY])
{
    for (int i = 0; i < 16; i++)
    {
        int pos = 0;
        for (int j = 0; j < 8; j++)
        {
            uint16_t t = 0;
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
            t -= (((int16_t)(RKEM_Q / 2 - t)) >> 15) & RKEM_Q;
            r->coeffs[8 * i + j] = t;
        }
    }
}

void RKEM_poly_compress(
    uint8_t r[RKEM_LEN_POLY_COMPRESSED],
    const RKEM_poly *a)
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

void RKEM_poly_decompress(
    RKEM_poly *r,
    const uint8_t a[RKEM_LEN_POLY_COMPRESSED])
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

void RKEM_poly_tomsg(uint8_t msg[RKEM_LEN_MSG], const RKEM_poly *a)
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

static void cmov_int16(int16_t *r, int16_t v, uint16_t b)
{
    b = -b;
    *r ^= b & ((*r) ^ v);
}

void RKEM_poly_frommsg(RKEM_poly *r, const uint8_t msg[RKEM_LEN_MSG])
{
    for (int i = 0; i < RKEM_N / 8; i++)
    {
        for (int j = 0; j < 8; j++)
        {
            r->coeffs[8 * i + j] = 0;
            cmov_int16(
                r->coeffs + 8 * i + j,
                ((RKEM_Q + 1) / 2),
                (msg[i] >> j) & 1);
        }
    }
}

void RKEM_poly_add(RKEM_poly *r, const RKEM_poly *a, const RKEM_poly *b)
{
    for (int i = 0; i < RKEM_N; i++)
    {
        r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    }
}

void RKEM_poly_sub(RKEM_poly *r, const RKEM_poly *a, const RKEM_poly *b)
{
    for (int i = 0; i < RKEM_N; i++)
    {
        r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
    }
}

void RKEM_poly_reduce(RKEM_poly *r)
{
    for (int i = 0; i < RKEM_N; i++)
    {
        r->coeffs[i] = RKEM_reduce_barrett(r->coeffs[i]);
    }
}

void RKEM_poly_ntt(RKEM_poly *r)
{
    RKEM_ntt_forward(r->coeffs);
    RKEM_poly_reduce(r);
}

void RKEM_poly_invntt_tomont(RKEM_poly *r)
{
    RKEM_ntt_inverse(r->coeffs);
}

void RKEM_poly_basemul_montgomery(
    RKEM_poly *r,
    const RKEM_poly *a,
    const RKEM_poly *b)
{
    for (int i = 0; i < RKEM_N / 4; i++)
    {
        RKEM_ntt_basemul(
            &r->coeffs[4 * i],
            &a->coeffs[4 * i],
            &b->coeffs[4 * i],
            RKEM_NTT_ZETAS[RKEM_N / 4 + i]);
        RKEM_ntt_basemul(
            &r->coeffs[4 * i + 2],
            &a->coeffs[4 * i + 2],
            &b->coeffs[4 * i + 2],
            -RKEM_NTT_ZETAS[RKEM_N / 4 + i]);
    }
}

void RKEM_poly_tomont(RKEM_poly *r)
{
    const int16_t f = (1ULL << 32) % RKEM_Q;
    for (int i = 0; i < RKEM_N; i++)
    {
        r->coeffs[i] = RKEM_reduce_montgomery((int32_t)r->coeffs[i] * f);
    }
}

void RKEM_poly_get_noise_eta1(
    RKEM_poly *r,
    const uint8_t seed[RKEM_LEN_SEED],
    uint8_t nonce)
{
    uint8_t buf[RKEM_ETA1 * RKEM_N / 4];
    KYBER_prf(buf, sizeof(buf), seed, nonce);
    RKEM_cbd_poly_eta1(r, buf);
}

void RKEM_poly_get_noise_eta2(
    RKEM_poly *r,
    const uint8_t seed[RKEM_LEN_SEED],
    uint8_t nonce)
{
    uint8_t buf[RKEM_ETA2 * RKEM_N / 4];
    KYBER_prf(buf, sizeof(buf), seed, nonce);
    RKEM_cbd_poly_eta2(r, buf);
}

void RKEM_poly_get_noise_eta3(
    RKEM_poly *r,
    const uint8_t seed[RKEM_LEN_SEED],
    uint8_t nonce)
{
    uint8_t buf[RKEM_ETA3 * RKEM_N / 4];
    KYBER_prf(buf, sizeof(buf), seed, nonce);
    RKEM_cbd_poly_eta3(r, buf);
}
