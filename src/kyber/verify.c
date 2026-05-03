#include <stddef.h>
#include <stdint.h>
#include "verify.h"

int KYBER_verify(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t r = 0;
    for (size_t i = 0; i < len; i++)
    {
        r |= a[i] ^ b[i];
    }
    return (-(uint64_t)r) >> 63;
}

void KYBER_cmov(uint8_t *r, const uint8_t *x, size_t len, uint8_t b)
{
#if defined(__GNUC__) || defined(__clang__)
    // Prevent the compiler from
    //    1) inferring that b is 0/1-valued, and
    //    2) handling the two cases with a branch.
    // This is not necessary when verify.c and kem.c are separate translation
    // units, but we expect that downstream consumers will copy this code and/or
    // change how it is built.
    __asm__("" : "+r"(b) : /* no inputs */);
#endif
    b = -b;
    for (size_t i = 0; i < len; i++)
    {
        r[i] ^= b & (r[i] ^ x[i]);
    }
}

void KYBER_cmov_int16(int16_t *r, int16_t v, uint16_t b)
{
    b = -b;
    *r ^= b & ((*r) ^ v);
}
