#include <stdlib.h>
#include "poly.h"
#include "test_utils.h"

void center_coeff(int16_t *a)
{
    if (*a > RKEM_Q / 2)
    {
        *a -= RKEM_Q;
    }
}

void poly_rand(poly *p)
{
    for (int i = 0; i < RKEM_N; i++)
    {
        p->coeffs[i] = rand() % RKEM_Q;
    }
}

void poly_rand_centered(poly *p)
{
    poly_rand(p);
    for (int i = 0; i < RKEM_N; i++)
    {
        center_coeff(&p->coeffs[i]);
    }
}

int poly_compare(const poly *p1, const poly *p2)
{
    for (int i = 0; i < RKEM_N; i++)
    {
        if (p1->coeffs[i] != p2->coeffs[i])
        {
            return 0;
        }
    }
    return 1;
}

int compression_check(int16_t a, int16_t b, int d)
{
    int diff1 = abs(a - b);
    int diff2 = RKEM_Q - diff1;
    int diff = diff1 < diff2 ? diff1 : diff2;
    return diff <= (RKEM_Q + (1 << d)) >> (d + 1);
}
