// gcc $CFLAGS $LDFLAGS -o tempo tempo.c test.c -lpqc-pake -lkyber -lcrypto

#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <pqc-pake/tempo.h>
#include <kyber/indcpa.h>
#include <kyber/polyvec.h>
#include "test.h"

int test_gen_matrix(int transposed)
{
    uint8_t seed[KYBER_LEN_SEED];
    RAND_bytes(seed, KYBER_LEN_SEED);
    KYBER_polyvec a1[KYBER_K];
    KYBER_gen_matrix(a1, seed, transposed);
    KYBER_polyvec a2[KYBER_K];
    TEMPO_gen_matrix_fls(a2, seed, transposed);
    return matrix_compare(a1, a2);
}

int test_gen_matrix_0()
{
    return test_gen_matrix(0);
}

int test_gen_matrix_1()
{
    return test_gen_matrix(1);
}

int main()
{
    int ok = test_run("gen_matrix", test_gen_matrix_0);
    ok = test_run("gen_matrix_transposed", test_gen_matrix_1) && ok;
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
