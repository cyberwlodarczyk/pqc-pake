// gcc $CFLAGS $LDFLAGS -o rkem rkem.c test.c -lpqc-pake -lrkem -lkyber -lcrypto

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/rand.h>
#include <rkem/poly.h>
#include <rkem/polyvec.h>
#include <rkem/reduce.h>
#include <rkem/ntt.h>
#include <rkem/rkem.h>
#include "test.h"

void center_coeff(int16_t *a)
{
    if (*a > RKEM_Q / 2)
    {
        *a -= RKEM_Q;
    }
}

void poly_rand(RKEM_poly *p)
{
    for (int i = 0; i < RKEM_N; i++)
    {
        p->coeffs[i] = rand() % RKEM_Q;
    }
}

void poly_rand_centered(RKEM_poly *p)
{
    poly_rand(p);
    for (int i = 0; i < RKEM_N; i++)
    {
        center_coeff(&p->coeffs[i]);
    }
}

void polyvec_rand(RKEM_polyvec *v)
{
    for (int i = 0; i < RKEM_K; i++)
    {
        poly_rand(&v->vec[i]);
    }
}

void polyvec_rand_centered(RKEM_polyvec *v)
{
    for (int i = 0; i < RKEM_K; i++)
    {
        poly_rand_centered(&v->vec[i]);
    }
}

int poly_compare(const RKEM_poly *p1, const RKEM_poly *p2)
{
    for (int i = 0; i < RKEM_N; i++)
    {
        if (p1->coeffs[i] != p2->coeffs[i])
        {
            return 0;
        }
    }
    return 1;
}

int polyvec_compare(const RKEM_polyvec *v1, const RKEM_polyvec *v2)
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

int matrix_compare(const RKEM_polyvec *a, const RKEM_polyvec *b)
{
    for (int i = 0; i < RKEM_K; i++)
    {
        if (!polyvec_compare(&a[i], &b[i]))
        {
            return 0;
        }
    }
    return 1;
}

int compression_check(int16_t a, int16_t b, int d)
{
    int diff1 = abs(a - b);
    int diff2 = RKEM_Q - diff1;
    int diff = diff1 < diff2 ? diff1 : diff2;
    return diff <= (RKEM_Q + (1 << d)) >> (d + 1);
}

int poly_compression_check(const RKEM_poly *p1, const RKEM_poly *p2)
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

int polyvec_compression_check(const RKEM_polyvec *v1, const RKEM_polyvec *v2)
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

int test_ntt()
{
    int16_t p1[128];
    for (int i = 0; i < 128; i++)
    {
        p1[i] = rand() % RKEM_Q;
        center_coeff(&p1[i]);
    }
    int16_t p2[128];
    memcpy(p2, p1, 256);
    RKEM_ntt_forward(p2);
    for (int i = 0; i < 128; i++)
    {
        p2[i] = RKEM_reduce_barrett(p2[i]);
    }
    RKEM_ntt_inverse(p2);
    for (int i = 0; i < 128; i++)
    {
        if (p1[i] != RKEM_reduce_montgomery(p2[i]))
        {
            return 0;
        }
    }
    return 1;
}

int test_poly_bytes()
{
    RKEM_poly p1;
    poly_rand_centered(&p1);
    uint8_t buf[RKEM_LEN_POLY];
    RKEM_poly_tobytes(buf, &p1);
    RKEM_poly p2;
    RKEM_poly_frombytes(&p2, buf);
    return poly_compare(&p1, &p2);
}

int test_poly_compression()
{
    RKEM_poly p1;
    poly_rand(&p1);
    uint8_t c[RKEM_LEN_POLY_COMPRESSED];
    RKEM_poly_compress(c, &p1);
    RKEM_poly p2;
    RKEM_poly_decompress(&p2, c);
    return poly_compression_check(&p1, &p2);
}

int test_poly_tomsg()
{
    RKEM_poly p1;
    poly_rand(&p1);
    uint8_t msg[RKEM_LEN_MSG];
    RKEM_poly_tomsg(msg, &p1);
    RKEM_poly p2;
    RKEM_poly_frommsg(&p2, msg);
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

int test_poly_frommsg()
{
    uint8_t msg1[RKEM_LEN_MSG];
    RAND_bytes(msg1, RKEM_LEN_MSG);
    RKEM_poly p1;
    RKEM_poly_frommsg(&p1, msg1);
    uint8_t msg2[RKEM_LEN_MSG];
    RKEM_poly_tomsg(msg2, &p1);
    for (int i = 0; i < RKEM_LEN_MSG; i++)
    {
        if (msg1[i] != msg2[i])
        {
            return 0;
        }
    }
    return 1;
}

int test_poly_ntt()
{
    RKEM_poly p1;
    poly_rand_centered(&p1);
    RKEM_poly p2;
    memcpy(&p2, &p1, sizeof(RKEM_poly));
    RKEM_poly_ntt(&p2);
    RKEM_poly_invntt_tomont(&p2);
    for (int i = 0; i < RKEM_N; i++)
    {
        if (p1.coeffs[i] != RKEM_reduce_montgomery(p2.coeffs[i]))
        {
            return 0;
        }
    }
    return 1;
}

int test_poly_eta1()
{
    uint8_t seed[RKEM_LEN_SEED];
    RAND_bytes(seed, RKEM_LEN_SEED);
    RKEM_poly p;
    RKEM_poly_get_noise_eta1(&p, seed, 1);
    for (int i = 0; i < RKEM_N; i++)
    {
        if (abs(p.coeffs[i]) > RKEM_ETA1)
        {
            return 0;
        }
    }
    return 1;
}

int test_poly_eta2()
{
    uint8_t seed[RKEM_LEN_SEED];
    RAND_bytes(seed, RKEM_LEN_SEED);
    RKEM_poly p;
    RKEM_poly_get_noise_eta2(&p, seed, 1);
    for (int i = 0; i < RKEM_N; i++)
    {
        if (abs(p.coeffs[i]) > RKEM_ETA2)
        {
            return 0;
        }
    }
    return 1;
}

int test_poly_eta3()
{
    uint8_t seed[RKEM_LEN_SEED];
    RAND_bytes(seed, RKEM_LEN_SEED);
    RKEM_poly p;
    RKEM_poly_get_noise_eta3(&p, seed, 1);
    for (int i = 0; i < RKEM_N; i++)
    {
        if (abs(p.coeffs[i]) > RKEM_ETA3)
        {
            return 0;
        }
    }
    return 1;
}

int test_polyvec_bytes()
{
    RKEM_polyvec v1;
    polyvec_rand_centered(&v1);
    uint8_t buf[RKEM_LEN_POLYVEC];
    RKEM_polyvec_tobytes(buf, &v1);
    RKEM_polyvec v2;
    RKEM_polyvec_frombytes(&v2, buf);
    return polyvec_compare(&v1, &v2);
}

int test_polyvec_compression()
{
    RKEM_polyvec v1;
    polyvec_rand(&v1);
    uint8_t c[RKEM_LEN_POLYVEC_COMPRESSED];
    RKEM_polyvec_compress(c, &v1);
    RKEM_polyvec v2;
    RKEM_polyvec_decompress(&v2, c);
    return polyvec_compression_check(&v1, &v2);
}

int test_gen_matrix(int transposed)
{
    uint8_t seed[RKEM_LEN_SEED];
    RAND_bytes(seed, RKEM_LEN_SEED);
    RKEM_polyvec a1[RKEM_K];
    RKEM_gen_matrix(a1, seed, transposed);
    RKEM_polyvec a2[RKEM_K];
    RKEM_gen_matrix_fls(a2, seed, transposed);
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

int test_transpose_matrix()
{
    uint8_t seed[RKEM_LEN_SEED];
    RAND_bytes(seed, RKEM_LEN_SEED);
    RKEM_polyvec a1[RKEM_K];
    RKEM_gen_matrix(a1, seed, 0);
    RKEM_polyvec a2[RKEM_K];
    RKEM_gen_matrix(a2, seed, 1);
    RKEM_transpose_matrix(a1);
    return matrix_compare(a1, a2);
}

int main()
{
    int ok = 1;
    ok = test_run("ntt", test_ntt) && ok;
    ok = test_run("poly_bytes", test_poly_bytes) && ok;
    ok = test_run("poly_compression", test_poly_compression) && ok;
    ok = test_run("poly_tomsg", test_poly_tomsg) && ok;
    ok = test_run("poly_frommsg", test_poly_frommsg) && ok;
    ok = test_run("poly_ntt", test_poly_ntt) && ok;
    ok = test_run("poly_eta1", test_poly_eta1) && ok;
    ok = test_run("poly_eta2", test_poly_eta2) && ok;
    ok = test_run("poly_eta3", test_poly_eta3) && ok;
    ok = test_run("polyvec_bytes", test_polyvec_bytes) && ok;
    ok = test_run("polyvec_compression", test_polyvec_compression) && ok;
    ok = test_run("gen_matrix", test_gen_matrix_0) && ok;
    ok = test_run("gen_matrix_transposed", test_gen_matrix_1) && ok;
    ok = test_run("transpose_matrix", test_transpose_matrix) && ok;
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
