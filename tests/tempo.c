// gcc $CFLAGS $LDFLAGS -o tempo tempo.c test.c -lpqc-pake -lkyber -lcrypto

#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <pqc-pake/tempo.h>
#include <kyber/indcpa.h>
#include <kyber/polyvec.h>
#include "test.h"

int matrix_compare(const KYBER_polyvec *a, const KYBER_polyvec *b)
{
    for (int i = 0; i < KYBER_K; i++)
    {
        for (int j = 0; j < KYBER_K; j++)
        {
            for (int k = 0; k < KYBER_N; k++)
            {
                if (a[i].vec[j].coeffs[k] != b[i].vec[j].coeffs[k])
                {
                    return 0;
                }
            }
        }
    }
    return 1;
}

int test_gen_matrix_fls(int transposed)
{
    uint8_t seed[KYBER_LEN_SEED];
    RAND_bytes(seed, KYBER_LEN_SEED);
    KYBER_polyvec a1[KYBER_K];
    KYBER_gen_matrix(a1, seed, transposed);
    KYBER_polyvec a2[KYBER_K];
    TEMPO_gen_matrix_fls(a2, seed, transposed);
    return matrix_compare(a1, a2);
}

int test_gen_matrix_fls_0()
{
    return test_gen_matrix_fls(0);
}

int test_gen_matrix_fls_1()
{
    return test_gen_matrix_fls(1);
}

int test_gen_matrix_flsx()
{
    uint8_t seed[TEMPO_LEN_SEED];
    KYBER_polyvec a1[KYBER_K];
    int res = -1;
    while (res == -1)
    {
        RAND_bytes(seed, TEMPO_LEN_SEED);
        res = TEMPO_gen_matrix_flsx(a1, seed, 0);
    }
    KYBER_polyvec a2[KYBER_K];
    if (TEMPO_gen_matrix_flsx(a2, seed, 0) == -1)
    {
        return 0;
    }
    return matrix_compare(a1, a2);
}

int main()
{
    int ok = test_run("gen_matrix_fls", test_gen_matrix_fls_0);
    ok = test_run("gen_matrix_fls_transposed", test_gen_matrix_fls_1) && ok;
    ok = test_run("gen_matrix_flsx", test_gen_matrix_flsx) && ok;
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
