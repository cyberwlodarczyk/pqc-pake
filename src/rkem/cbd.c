#include <stdint.h>
#include "params.h"
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

static void cbd2(poly *r, const uint8_t buf[2 * RKEM_N / 4])
{
    for (int i = 0; i < RKEM_N / 8; i++)
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

static void cbd192(poly *r, const uint8_t buf[192 * RKEM_N / 4])
{
    for (int i = 0; i < 128; i++)
    {
        int16_t x[2];
        for (int j = 0; j < 2; j++)
        {
            x[j] = 0;
            for (int k = 0; k < 24; k++)
            {
                uint8_t t = buf[24 * (2 * i + j) + k];
                while (t)
                {
                    t &= (t - 1);
                    x[j]++;
                }
            }
        }
        r->coeffs[i] = x[0] - x[1];
    }
}

void poly_cbd_eta1(poly *r, const uint8_t buf[RKEM_ETA1 * RKEM_N / 4])
{
    cbd2(r, buf);
}

void poly_cbd_eta2(poly *r, const uint8_t buf[RKEM_ETA2 * RKEM_N / 4])
{
    cbd2(r, buf);
}

void poly_cbd_eta3(poly *r, const uint8_t buf[RKEM_ETA3 * RKEM_N / 4])
{
    cbd192(r, buf);
}
