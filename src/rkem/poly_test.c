// gcc $CFLAGS $LDFLAGS -o poly_test poly_test.c test_utils.c poly.c ntt.c cbd.c reduce.c -lkyber -lcrypto

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/rand.h>
#include "poly.h"
#include "test_utils.h"
#include "reduce.h"

#define TEST_N 10000

int test_bytes()
{
    poly p1;
    poly_rand_centered(&p1);
    uint8_t buf[RKEM_POLYBYTES];
    poly_tobytes(buf, &p1);
    poly p2;
    poly_frombytes(&p2, buf);
    return poly_compare(&p1, &p2);
}

int poly_compression_check(const poly *p1, const poly *p2)
{
    for (int i = 0; i < RKEM_N; i++)
    {
        if (!compression_check(p1->coeffs[i], p2->coeffs[i], 3))
        {
            return 0;
        }
    }
    return 1;
}

int test_compression()
{
    poly p1;
    poly_rand(&p1);
    uint8_t c[RKEM_POLYCOMPRESSEDBYTES];
    poly_compress(c, &p1);
    poly p2;
    poly_decompress(&p2, c);
    return poly_compression_check(&p1, &p2);
}

int test_tomsg()
{
    poly p1;
    poly_rand(&p1);
    uint8_t msg[RKEM_MSGBYTES];
    poly_tomsg(msg, &p1);
    poly p2;
    poly_frommsg(&p2, msg);
    for (int i = 0; i < RKEM_N; i++)
    {
        int diff1a = RKEM_Q - p1.coeffs[i];
        int diff1 = diff1a < p1.coeffs[i] ? diff1a : p1.coeffs[i];
        int half = (RKEM_Q + 1) / 2;
        int diff2 = abs(half - p1.coeffs[i]);
        int x = diff1 <= diff2 ? 0 : half;
        if (x != p2.coeffs[i])
        {
            return 0;
        }
    }
    return 1;
}

int test_frommsg()
{
    uint8_t msg1[RKEM_MSGBYTES];
    RAND_bytes(msg1, RKEM_MSGBYTES);
    poly p1;
    poly_frommsg(&p1, msg1);
    uint8_t msg2[RKEM_MSGBYTES];
    poly_tomsg(msg2, &p1);
    for (int i = 0; i < RKEM_MSGBYTES; i++)
    {
        if (msg1[i] != msg2[i])
        {
            return 0;
        }
    }
    return 1;
}

int test_ntt()
{
    poly p1;
    poly_rand_centered(&p1);
    poly p2;
    memcpy(&p2, &p1, sizeof(poly));
    poly_ntt(&p2);
    poly_invntt_tomont(&p2);
    for (int i = 0; i < RKEM_N; i++)
    {
        if (p1.coeffs[i] != montgomery_reduce(p2.coeffs[i]))
        {
            return 0;
        }
    }
    return 1;
}

int test_eta1()
{
    uint8_t seed[RKEM_SYMBYTES];
    RAND_bytes(seed, RKEM_SYMBYTES);
    poly p;
    poly_getnoise_eta1(&p, seed, 1);
    for (int i = 0; i < RKEM_N; i++)
    {
        if (abs(p.coeffs[i]) > RKEM_ETA1)
        {
            return 0;
        }
    }
    return 1;
}

int test_eta2()
{
    uint8_t seed[RKEM_SYMBYTES];
    RAND_bytes(seed, RKEM_SYMBYTES);
    poly p;
    poly_getnoise_eta2(&p, seed, 1);
    for (int i = 0; i < RKEM_N; i++)
    {
        if (abs(p.coeffs[i]) > RKEM_ETA2)
        {
            return 0;
        }
    }
    return 1;
}

int test_eta3()
{
    uint8_t seed[RKEM_SYMBYTES];
    RAND_bytes(seed, RKEM_SYMBYTES);
    poly p;
    poly_getnoise_eta3(&p, seed, 1);
    for (int i = 0; i < RKEM_N; i++)
    {
        if (abs(p.coeffs[i]) > RKEM_ETA3)
        {
            return 0;
        }
    }
    return 1;
}

int main()
{
    srand(time(NULL));
    for (int i = 0; i < TEST_N; i++)
    {
        if (!test_bytes())
        {
            return EXIT_FAILURE;
        }
    }
    for (int i = 0; i < TEST_N; i++)
    {
        if (!test_compression())
        {
            return EXIT_FAILURE;
        }
    }
    for (int i = 0; i < TEST_N; i++)
    {
        if (!test_tomsg())
        {
            return EXIT_FAILURE;
        }
    }
    for (int i = 0; i < TEST_N; i++)
    {
        if (!test_frommsg())
        {
            return EXIT_FAILURE;
        }
    }
    for (int i = 0; i < TEST_N; i++)
    {
        if (!test_ntt())
        {
            return EXIT_FAILURE;
        }
    }
    for (int i = 0; i < TEST_N; i++)
    {
        if (!test_eta1())
        {
            return EXIT_FAILURE;
        }
    }
    for (int i = 0; i < TEST_N; i++)
    {
        if (!test_eta2())
        {
            return EXIT_FAILURE;
        }
    }
    for (int i = 0; i < TEST_N; i++)
    {
        if (!test_eta3())
        {
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}
