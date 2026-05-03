#include "params.h"
#include "reduce.h"

int16_t KYBER_reduce_montgomery(int32_t a)
{
    int16_t t = (int16_t)a * KYBER_QINV;
    t = (a - (int32_t)t * KYBER_Q) >> 16;
    return t;
}

int16_t KYBER_reduce_barrett(int16_t a)
{
    const int16_t v = ((1 << 26) + KYBER_Q / 2) / KYBER_Q;
    int16_t t = ((int32_t)v * a + (1 << 25)) >> 26;
    t *= KYBER_Q;
    return a - t;
}
