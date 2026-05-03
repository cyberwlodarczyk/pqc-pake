#include <stdint.h>
#include "params.h"
#include "poly.h"
#include "ntt.h"
#include "reduce.h"
#include "cbd.h"
#include "symmetric.h"
#include "verify.h"

void KYBER_poly_compress(
    uint8_t r[KYBER_LEN_POLY_COMPRESSED],
    const KYBER_poly *a)
{
    for (int i = 0; i < KYBER_N / 8; i++)
    {
        uint8_t t[8];
        for (int j = 0; j < 8; j++)
        {
            int16_t u = a->coeffs[8 * i + j];
            u += (u >> 15) & KYBER_Q;
            // t[j] = ((((uint16_t)u << 4) + KYBER_Q / 2) / KYBER_Q) & 15;
            uint32_t d0 = u << 4;
            d0 += 1665;
            d0 *= 80635;
            d0 >>= 28;
            t[j] = d0 & 0xf;
        }
        r[0] = t[0] | (t[1] << 4);
        r[1] = t[2] | (t[3] << 4);
        r[2] = t[4] | (t[5] << 4);
        r[3] = t[6] | (t[7] << 4);
        r += 4;
    }
}

void KYBER_poly_decompress(
    KYBER_poly *r,
    const uint8_t a[KYBER_LEN_POLY_COMPRESSED])
{
    for (int i = 0; i < KYBER_N / 2; i++)
    {
        r->coeffs[2 * i + 0] = (((uint16_t)(a[0] & 15) * KYBER_Q) + 8) >> 4;
        r->coeffs[2 * i + 1] = (((uint16_t)(a[0] >> 4) * KYBER_Q) + 8) >> 4;
        a += 1;
    }
}

void KYBER_poly_tobytes(uint8_t r[KYBER_LEN_POLY], const KYBER_poly *a)
{
    for (int i = 0; i < KYBER_N / 2; i++)
    {
        uint16_t t0 = a->coeffs[2 * i];
        t0 += ((int16_t)t0 >> 15) & KYBER_Q;
        uint16_t t1 = a->coeffs[2 * i + 1];
        t1 += ((int16_t)t1 >> 15) & KYBER_Q;
        r[3 * i + 0] = (t0 >> 0);
        r[3 * i + 1] = (t0 >> 8) | (t1 << 4);
        r[3 * i + 2] = (t1 >> 4);
    }
}

void KYBER_poly_frombytes(KYBER_poly *r, const uint8_t a[KYBER_LEN_POLY])
{
    for (int i = 0; i < KYBER_N / 2; i++)
    {
        r->coeffs[2 * i] = ((a[3 * i + 0] >> 0) |
                            ((uint16_t)a[3 * i + 1] << 8)) &
                           0xFFF;
        r->coeffs[2 * i + 1] = ((a[3 * i + 1] >> 4) |
                                ((uint16_t)a[3 * i + 2] << 4)) &
                               0xFFF;
    }
}

void KYBER_poly_frommsg(
    KYBER_poly *r,
    const uint8_t msg[KYBER_INDCPA_LEN_MSG])
{
    for (int i = 0; i < KYBER_N / 8; i++)
    {
        for (int j = 0; j < 8; j++)
        {
            r->coeffs[8 * i + j] = 0;
            KYBER_cmov_int16(
                r->coeffs + 8 * i + j,
                ((KYBER_Q + 1) / 2),
                (msg[i] >> j) & 1);
        }
    }
}

void KYBER_poly_tomsg(uint8_t msg[KYBER_INDCPA_LEN_MSG], const KYBER_poly *a)
{
    for (int i = 0; i < KYBER_N / 8; i++)
    {
        msg[i] = 0;
        for (int j = 0; j < 8; j++)
        {
            uint32_t t = a->coeffs[8 * i + j];
            // t += ((int16_t)t >> 15) & KYBER_Q;
            // t  = (((t << 1) + KYBER_Q / 2) / KYBER_Q) & 1;
            t <<= 1;
            t += 1665;
            t *= 80635;
            t >>= 28;
            t &= 1;
            msg[i] |= t << j;
        }
    }
}

void KYBER_poly_get_noise_eta1(
    KYBER_poly *r,
    const uint8_t seed[KYBER_LEN_SEED],
    uint8_t nonce)
{
    uint8_t buf[KYBER_ETA1 * KYBER_N / 4];
    KYBER_prf(buf, sizeof(buf), seed, nonce);
    KYBER_cbd_poly_eta1(r, buf);
}

void KYBER_poly_get_noise_eta2(
    KYBER_poly *r,
    const uint8_t seed[KYBER_LEN_SEED],
    uint8_t nonce)
{
    uint8_t buf[KYBER_ETA2 * KYBER_N / 4];
    KYBER_prf(buf, sizeof(buf), seed, nonce);
    KYBER_cbd_poly_eta2(r, buf);
}

void KYBER_poly_ntt(KYBER_poly *r)
{
    KYBER_ntt_forward(r->coeffs);
    KYBER_poly_reduce(r);
}

void KYBER_poly_invntt_tomont(KYBER_poly *r)
{
    KYBER_ntt_inverse(r->coeffs);
}

void KYBER_poly_basemul_montgomery(KYBER_poly *r, const KYBER_poly *a, const KYBER_poly *b)
{
    for (int i = 0; i < KYBER_N / 4; i++)
    {
        KYBER_ntt_basemul(
            &r->coeffs[4 * i],
            &a->coeffs[4 * i],
            &b->coeffs[4 * i],
            KYBER_NTT_ZETAS[64 + i]);
        KYBER_ntt_basemul(
            &r->coeffs[4 * i + 2],
            &a->coeffs[4 * i + 2],
            &b->coeffs[4 * i + 2],
            -KYBER_NTT_ZETAS[64 + i]);
    }
}

void KYBER_poly_tomont(KYBER_poly *r)
{
    const int16_t f = (1ULL << 32) % KYBER_Q;
    for (int i = 0; i < KYBER_N; i++)
    {
        r->coeffs[i] = KYBER_reduce_montgomery((int32_t)r->coeffs[i] * f);
    }
}

void KYBER_poly_reduce(KYBER_poly *r)
{
    for (int i = 0; i < KYBER_N; i++)
    {
        r->coeffs[i] = KYBER_reduce_barrett(r->coeffs[i]);
    }
}

void KYBER_poly_add(KYBER_poly *r, const KYBER_poly *a, const KYBER_poly *b)
{
    for (int i = 0; i < KYBER_N; i++)
    {
        r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
    }
}

void KYBER_poly_sub(KYBER_poly *r, const KYBER_poly *a, const KYBER_poly *b)
{
    for (int i = 0; i < KYBER_N; i++)
    {
        r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
    }
}
