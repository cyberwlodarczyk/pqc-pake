// gcc $CFLAGS $LDFLAGS -o tempo tempo.c test.c -lpqc-pake -lkyber -lcrypto

#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <pqc-pake/tempo.h>
#include <kyber/indcpa.h>
#include <kyber/polyvec.h>
#include "test.h"

#define ROUNDS 1000

int polyvec_compare(const KYBER_polyvec *a, const KYBER_polyvec *b)
{
    for (int i = 0; i < KYBER_K; i++)
    {
        for (int j = 0; j < KYBER_N; j++)
        {
            if (a->vec[i].coeffs[j] != b->vec[i].coeffs[j])
            {
                return 0;
            }
        }
    }
    return 1;
}

int test_fls()
{
    uint8_t seed[KYBER_LEN_SEED];
    RAND_bytes(seed, KYBER_LEN_SEED);
    KYBER_polyvec a1[KYBER_K];
    KYBER_gen_matrix(a1, seed, 0);
    KYBER_polyvec a2;
    TEMPO_fls(&a2, seed);
    return polyvec_compare(&a1[0], &a2);
}

int main()
{
    int ok = test_run("fls", test_fls, ROUNDS);
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
