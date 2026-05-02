// gcc $CFLAGS $LDFLAGS -o rkem_init rkem_init.c polyvec.c poly.c ntt.c cbd.c reduce.c rkem_internal.c -lkyber -lcrypto

#include <stdlib.h>
#include <stdio.h>
#include <openssl/rand.h>
#include "polyvec.h"
#include "rkem_internal.h"

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
    RAND_bytes(seed, RKEM_SYMBYTES);
    fls(A, seed, 0);
    printf("A\n\n");
    print(A);
    fls(AT, seed, 1);
    printf("\n\nAT\n\n");
    print(AT);
    return EXIT_SUCCESS;
}
