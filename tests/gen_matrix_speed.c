// gcc $CFLAGS $LDFLAGS -o gen_matrix_speed gen_matrix_speed.c test.c -lpqc-pake -lrkem -lkyber -lcrypto

#include <stdlib.h>
#include <openssl/rand.h>
#include <kyber/kyber.h>
#include <kyber/indcpa.h>
#include <rkem/rkem.h>
#include <rkem/xrkem.h>
#include <pqc-pake/nice_pake.h>
#include <pqc-pake/nice_pake_re.h>
#include <pqc-pake/tempo.h>
#include <pqc-pake/tempo_re.h>
#include "test.h"

int kyber_gen_matrix()
{
    uint8_t seed[KYBER_LEN_SEED];
    RAND_bytes(seed, KYBER_LEN_SEED);
    KYBER_polyvec a[KYBER_K];
    KYBER_gen_matrix(a, seed, 0);
    return 1;
}

int rkem_gen_matrix()
{
    uint8_t seed[RKEM_LEN_SEED];
    RAND_bytes(seed, RKEM_LEN_SEED);
    RKEM_polyvec a[RKEM_K];
    RKEM_gen_matrix(a, seed, 0);
    return 1;
}

int rkem_gen_matrix_fls()
{
    uint8_t seed[RKEM_LEN_SEED];
    RAND_bytes(seed, RKEM_LEN_SEED);
    RKEM_polyvec a[RKEM_K];
    RKEM_gen_matrix_fls(a, seed, 0);
    return 1;
}

int tempo_gen_matrix_fls()
{
    uint8_t seed[TEMPO_LEN_SEED];
    RAND_bytes(seed, TEMPO_LEN_SEED);
    KYBER_polyvec a[KYBER_K];
    TEMPO_gen_matrix_fls(a, seed, 0);
    return 1;
}

int tempo_gen_matrix_flsx()
{
    uint8_t seed[TEMPO_LEN_SEED];
    RAND_bytes(seed, TEMPO_LEN_SEED);
    KYBER_polyvec a[KYBER_K];
    TEMPO_gen_matrix_flsx(a, seed, 0);
    return 1;
}

int main()
{
    test_speed("kyber", kyber_gen_matrix);
    test_speed("rkem", rkem_gen_matrix);
    test_speed("rkem_fls", rkem_gen_matrix_fls);
    test_speed("tempo_fls", tempo_gen_matrix_fls);
    test_speed("tempo_flsx", tempo_gen_matrix_flsx);
    return EXIT_SUCCESS;
}
