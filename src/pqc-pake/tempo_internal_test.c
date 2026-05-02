// gcc $CFLAGS $LDFLAGS -o tempo_internal_test tempo_internal_test.c tempo_internal.c -lkyber -lcrypto

#include <stdlib.h>
#include <openssl/rand.h>
#include <kyber/indcpa.h>
#include "tempo_internal.h"

#define TEST_N 10000

int polyvec_compare(polyvec *v1, polyvec *v2)
{
    for (int i = 0; i < KYBER_K; i++)
    {
        for (int j = 0; j < KYBER_N; j++)
        {
            if (v1->vec[i].coeffs[j] != v2->vec[i].coeffs[j])
            {
                return 0;
            }
        }
    }
    return 1;
}

int test_fls()
{
    uint8_t seed[KYBER_SYMBYTES];
    RAND_bytes(seed, KYBER_SYMBYTES);
    polyvec a1[KYBER_K];
    gen_matrix(a1, seed, 0);
    polyvec a2;
    fls(&a2, seed);
    return polyvec_compare(a1, &a2);
}

int main()
{
    for (int i = 0; i < TEST_N; i++)
    {
        if (!test_fls())
        {
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}
