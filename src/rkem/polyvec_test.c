// gcc $CFLAGS $LDFLAGS -o polyvec_test polyvec_test.c polyvec.c test_utils.c poly.c ntt.c cbd.c reduce.c -lkyber -lcrypto

#include <stdlib.h>
#include <time.h>
#include "polyvec.h"
#include "test_utils.h"

#define TEST_N 10000

void polyvec_rand(polyvec *v)
{
    for (int i = 0; i < RKEM_K; i++)
    {
        poly_rand(&v->vec[i]);
    }
}

void polyvec_rand_centered(polyvec *v)
{
    for (int i = 0; i < RKEM_K; i++)
    {
        poly_rand_centered(&v->vec[i]);
    }
}

int polyvec_compare(const polyvec *v1, const polyvec *v2)
{
    for (int i = 0; i < RKEM_K; i++)
    {
        if (!poly_compare(&v1->vec[i], &v2->vec[i]))
        {
            return 0;
        }
    }
    return 1;
}

int polyvec_compression_check(const polyvec *v1, const polyvec *v2)
{
    for (int i = 0; i < RKEM_K; i++)
    {
        for (int j = 0; j < RKEM_N; j++)
        {
            if (!compression_check(v1->vec[i].coeffs[j], v2->vec[i].coeffs[j], 10))
            {
                return 0;
            }
        }
    }
    return 1;
}

int test_bytes()
{
    polyvec v1;
    polyvec_rand_centered(&v1);
    uint8_t buf[RKEM_POLYVECBYTES];
    polyvec_tobytes(buf, &v1);
    polyvec v2;
    polyvec_frombytes(&v2, buf);
    return polyvec_compare(&v1, &v2);
}

int test_compression()
{
    polyvec v1;
    polyvec_rand(&v1);
    uint8_t c[RKEM_POLYVECCOMPRESSEDBYTES];
    polyvec_compress(c, &v1);
    polyvec v2;
    polyvec_decompress(&v2, c);
    return polyvec_compression_check(&v1, &v2);
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
    return EXIT_SUCCESS;
}
