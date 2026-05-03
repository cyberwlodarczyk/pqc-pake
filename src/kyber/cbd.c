#include "cbd.h"

static uint32_t load32_littleendian(const uint8_t x[4])
{
    uint32_t r;
    r = (uint32_t)x[0];
    r |= (uint32_t)x[1] << 8;
    r |= (uint32_t)x[2] << 16;
    r |= (uint32_t)x[3] << 24;
    return r;
}

static void cbd2(KYBER_poly *r, const uint8_t buf[2 * KYBER_N / 4])
{
    for (int i = 0; i < KYBER_N / 8; i++)
    {
        uint32_t t = load32_littleendian(buf + 4 * i);
        uint32_t d = t & 0x55555555;
        d += (t >> 1) & 0x55555555;
        for (int j = 0; j < 8; j++)
        {
            int16_t a = (d >> (4 * j + 0)) & 0x3;
            int16_t b = (d >> (4 * j + 2)) & 0x3;
            r->coeffs[8 * i + j] = a - b;
        }
    }
}

void KYBER_cbd_poly_eta1(
    KYBER_poly *r,
    const uint8_t buf[KYBER_ETA1 * KYBER_N / 4])
{
    cbd2(r, buf);
}

void KYBER_cbd_poly_eta2(
    KYBER_poly *r,
    const uint8_t buf[KYBER_ETA2 * KYBER_N / 4])
{
    cbd2(r, buf);
}
