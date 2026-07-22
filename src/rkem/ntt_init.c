#include <stdlib.h>
#include <stdio.h>
#include <rkem/ntt.h>
#include <rkem/reduce.h>

#define RKEM_ROOT_OF_UNITY 202

const uint8_t tree[RKEM_N / 2] = {
    0, 32, 16, 48, 8, 40, 24, 56,
    4, 36, 20, 52, 12, 44, 28, 60,
    2, 34, 18, 50, 10, 42, 26, 58,
    6, 38, 22, 54, 14, 46, 30, 62,
    1, 33, 17, 49, 9, 41, 25, 57,
    5, 37, 21, 53, 13, 45, 29, 61,
    3, 35, 19, 51, 11, 43, 27, 59,
    7, 39, 23, 55, 15, 47, 31, 63};

void init_ntt(int16_t zetas[RKEM_N / 2])
{
    int16_t tmp[RKEM_N / 2];
    tmp[0] = RKEM_MONT;
    for (int i = 1; i < RKEM_N / 2; i++)
    {
        tmp[i] = RKEM_ntt_fqmul(
            tmp[i - 1],
            RKEM_MONT * RKEM_ROOT_OF_UNITY % RKEM_Q);
    }
    for (int i = 0; i < RKEM_N / 2; i++)
    {
        zetas[i] = tmp[tree[i]];
        if (zetas[i] > RKEM_Q / 2)
        {
            zetas[i] -= RKEM_Q;
        }
        if (zetas[i] < -RKEM_Q / 2)
        {
            zetas[i] += RKEM_Q;
        }
    }
}

int main()
{
    int16_t zetas[RKEM_N / 2];
    init_ntt(zetas);
    for (int i = 0; i < RKEM_N / 2; i++)
    {
        if (i != 0)
        {
            putchar(',');
            putchar(' ');
        }
        printf("%d", zetas[i]);
    }
    putchar('\n');
    return EXIT_SUCCESS;
}
