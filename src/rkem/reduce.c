#include "reduce.h"
#include "params.h"

int16_t RKEM_reduce_montgomery(int32_t a)
{
    int16_t t;
    t = (int16_t)a * RKEM_QINV;
    t = (a - (int32_t)t * RKEM_Q) >> 16;
    return t;
}

int16_t RKEM_reduce_barrett(int16_t a)
{
    int16_t t;
    const int16_t v = ((1 << 26) + RKEM_Q / 2) / RKEM_Q;
    t = ((int32_t)v * a + (1 << 25)) >> 26;
    t *= RKEM_Q;
    return a - t;
}
