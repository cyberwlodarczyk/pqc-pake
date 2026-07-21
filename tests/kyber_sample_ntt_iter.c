// ./scripts/build.sh -DKYBER_SAMPLE_NTT_LOG_ITER=1
// gcc $CFLAGS $LDFLAGS -o kyber_sample_ntt_iter kyber_sample_ntt_iter.c -lkyber -lcrypto

#include <stdlib.h>
#include <openssl/rand.h>
#include <kyber/indcpa.h>

#define ITERATIONS 1000000

int main()
{
    KYBER_polyvec a[KYBER_K];
    uint8_t seed[KYBER_LEN_SEED];
    printf("%d\n", ITERATIONS * KYBER_K * KYBER_K);
    for (int i = 0; i < ITERATIONS; i++)
    {
        RAND_bytes(seed, KYBER_LEN_SEED);
        KYBER_gen_matrix(a, seed, 0);
    }
    return EXIT_SUCCESS;
}
