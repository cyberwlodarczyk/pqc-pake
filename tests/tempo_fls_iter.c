// ./scripts/build.sh -DTEMPO_FLS_LOG_ITER=1
// gcc $CFLAGS $LDFLAGS -o tempo_fls_iter tempo_fls_iter.c test.c -lpqc-pake -lkyber -lcrypto

#include <stdio.h>
#include <stdlib.h>
#include <openssl/rand.h>
#include <pqc-pake/tempo.h>

#define ITERATIONS 100000

int main()
{
    KYBER_polyvec a[KYBER_K];
    uint8_t seed[TEMPO_LEN_SEED];
    printf("%d\n", ITERATIONS * KYBER_K * KYBER_K);
    for (int i = 0; i < ITERATIONS; i++)
    {
        RAND_bytes(seed, TEMPO_LEN_SEED);
        TEMPO_gen_matrix_fls(a, seed, 0);
    }
    return EXIT_SUCCESS;
}
