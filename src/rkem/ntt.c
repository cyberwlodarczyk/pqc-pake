#include "ntt.h"
#include "reduce.h"

const int16_t zetas[64] = {
    -3593, -3777, 3625, -3182, 2456, -2194, 3696, -1100,
    -2319, -2876, 1414, -1701, -2250, 121, -834, -2495,
    -1525, 2557, 1483, 1296, 617, -1921, 2830, 3364,
    -2237, -1986, -2816, -2088, 1993, -1599, -3706, -2006,
    -3772, -2535, 2555, 2440, -3153, 2310, 1535, 549,
    103, 2804, 1431, 2043, -1321, 1399, 514, 2956,
    -810, 1887, 7, 638, 1738, 3689, 3266, 3600,
    1305, -1760, -438, 679, 3174, -396, -3555, 1881};

static int16_t fqmul(int16_t a, int16_t b)
{
    return montgomery_reduce((int32_t)a * b);
}

void ntt(int16_t r[128])
{
    int i = 1;
    for (int len = 64; len >= 2; len >>= 1)
    {
        for (int start = 0; start < 128; start = start + 2 * len)
        {
            int16_t zeta = zetas[i++];
            for (int j = start; j < start + len; j++)
            {
                int16_t t = fqmul(zeta, r[j + len]);
                r[j + len] = r[j] - t;
                r[j] = r[j] + t;
            }
        }
    }
}

void invntt(int16_t r[128])
{
    int i = 63;
    for (int len = 2; len <= 64; len <<= 1)
    {
        for (int start = 0; start < 128; start = start + 2 * len)
        {
            int16_t zeta = zetas[i--];
            for (int j = start; j < start + len; j++)
            {
                int16_t t = r[j];
                r[j] = barrett_reduce(t + r[j + len]);
                r[j + len] = fqmul(zeta, r[j + len] - t);
            }
        }
    }
    const int16_t f = 7648; // mont^2 / 64
    for (int k = 0; k < 128; k++)
    {
        r[k] = fqmul(r[k], f);
    }
}

void basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta)
{
    r[0] = fqmul(a[1], b[1]);
    r[0] = fqmul(r[0], zeta);
    r[0] += fqmul(a[0], b[0]);
    r[1] = fqmul(a[0], b[1]);
    r[1] += fqmul(a[1], b[0]);
}
