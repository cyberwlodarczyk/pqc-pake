#include <stdlib.h>
#include <stdio.h>
#include <rkem/polyvec.h>
#include <rkem/rkem.h>
#include <rkem/randombytes.h>

void print(polyvec A[RKEM_K])
{
    putchar('{');
    putchar('\n');
    for (int i = 0; i < RKEM_K; i++)
    {
        putchar('{');
        putchar('{');
        putchar('\n');
        for (int j = 0; j < RKEM_K; j++)
        {
            putchar('\t');
            putchar('{');
            putchar('{');
            for (int k = 0; k < RKEM_N; k++)
            {
                if (k != 0)
                {
                    putchar(',');
                    putchar(' ');
                }
                printf("%d", A[i].vec[j].coeffs[k]);
            }
            putchar('}');
            putchar('}');
            if (j != RKEM_K - 1)
            {
                putchar(',');
            }
            putchar('\n');
        }
        putchar('}');
        putchar('}');
        if (i != RKEM_K - 1)
        {
            putchar(',');
        }
        putchar('\n');
    }
    putchar('}');
    putchar(';');
    putchar('\n');
}

int main()
{
    polyvec A[RKEM_K], AT[RKEM_K];
    uint8_t seed[RKEM_SYMBYTES];
    randombytes(seed, RKEM_SYMBYTES);
    rkem_fls(A, seed, 0);
    printf("A\n\n");
    print(A);
    rkem_fls(AT, seed, 1);
    printf("\n\nAT\n\n");
    print(AT);
    return EXIT_SUCCESS;
}
