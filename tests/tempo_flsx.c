// gcc $CFLAGS $LDFLAGS -o tempo_flsx tempo_flsx.c test.c -lpqc-pake -lkyber -lcrypto

#include <stdlib.h>
#include <openssl/rand.h>
#include <pqc-pake/tempo.h>
#include "test.h"

int test_flsx()
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
    return test_run("flsx", test_flsx) ? EXIT_SUCCESS : EXIT_FAILURE;
}
