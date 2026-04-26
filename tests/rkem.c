#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <rkem/cbd.h>
#include <rkem/ntt.h>
#include <rkem/poly.h>
#include <rkem/polyvec.h>
#include <rkem/randombytes.h>
#include <rkem/reduce.h>
#include <rkem/rkem.h>

void coeff_center(int16_t *a)
{
    if (*a > RKEM_Q / 2)
    {
        *a -= RKEM_Q;
    }
}

void poly_rand(poly *p)
{
    for (int i = 0; i < RKEM_N; i++)
    {
        p->coeffs[i] = rand() % RKEM_Q;
    }
}

void poly_rand_center(poly *p)
{
    poly_rand(p);
    for (int i = 0; i < RKEM_N; i++)
    {
        coeff_center(&p->coeffs[i]);
    }
}

void polyvec_rand(polyvec *v)
{
    for (int i = 0; i < RKEM_K; i++)
    {
        poly_rand(&v->vec[i]);
    }
}

void polyvec_rand_center(polyvec *v)
{
    for (int i = 0; i < RKEM_K; i++)
    {
        poly_rand_center(&v->vec[i]);
    }
}

int poly_compare(const poly *p1, const poly *p2)
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

int compression_check(int16_t a, int16_t b, int d)
{
    int diff1 = abs(a - b);
    int diff2 = RKEM_Q - diff1;
    int diff = diff1 < diff2 ? diff1 : diff2;
    return diff <= (RKEM_Q + (1 << d)) >> (d + 1);
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

int test_poly_bytes()
{
    poly p1;
    poly_rand_center(&p1);
    uint8_t buf[RKEM_POLYBYTES];
    poly_tobytes(buf, &p1);
    poly p2;
    poly_frombytes(&p2, buf);
    return poly_compare(&p1, &p2);
}

int test_polyvec_bytes()
{
    polyvec v1;
    polyvec_rand_center(&v1);
    uint8_t buf[RKEM_POLYVECBYTES];
    polyvec_tobytes(buf, &v1);
    polyvec v2;
    polyvec_frombytes(&v2, buf);
    return polyvec_compare(&v1, &v2);
}

int test_poly_compression()
{
    poly p1;
    poly_rand(&p1);
    uint8_t c[RKEM_POLYCOMPRESSEDBYTES];
    poly_compress(c, &p1);
    poly p2;
    poly_decompress(&p2, c);
    return poly_compression_check(&p1, &p2);
}

int test_polyvec_compression()
{
    polyvec v1;
    polyvec_rand(&v1);
    uint8_t c[RKEM_POLYVECCOMPRESSEDBYTES];
    polyvec_compress(c, &v1);
    polyvec v2;
    polyvec_decompress(&v2, c);
    return polyvec_compression_check(&v1, &v2);
}

int test_poly_tomsg()
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

int test_poly_frommsg()
{
    uint8_t msg1[RKEM_MSGBYTES];
    randombytes(msg1, RKEM_MSGBYTES);
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
    int16_t p1[128];
    for (int i = 0; i < 128; i++)
    {
        p1[i] = rand() % RKEM_Q;
        coeff_center(&p1[i]);
    }
    int16_t p2[128];
    memcpy(p2, p1, 256);
    ntt(p2);
    for (int i = 0; i < 128; i++)
    {
        p2[i] = barrett_reduce(p2[i]);
    }
    invntt(p2);
    for (int i = 0; i < 128; i++)
    {
        if (p1[i] != montgomery_reduce(p2[i]))
        {
            return 0;
        }
    }
    return 1;
}

int test_poly_ntt()
{
    poly p1;
    poly_rand_center(&p1);
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

int test_poly_eta1()
{
    uint8_t seed[RKEM_SYMBYTES];
    randombytes(seed, RKEM_SYMBYTES);
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

int test_poly_eta2()
{
    uint8_t seed[RKEM_SYMBYTES];
    randombytes(seed, RKEM_SYMBYTES);
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

int test_poly_eta3()
{
    uint8_t seed[RKEM_SYMBYTES];
    randombytes(seed, RKEM_SYMBYTES);
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

int test_rkem_derand()
{
    uint8_t pk[RKEM_PUBLICKEYBYTES];
    uint8_t sk[RKEM_SECRETKEYBYTES];
    RKEM_keypair(pk, sk);
    uint8_t ct[RKEM_CIPHERTEXTBYTES];
    uint8_t ss1[RKEM_MSGBYTES];
    RKEM_encaps(ct, ss1, pk);
    uint8_t ss2[RKEM_MSGBYTES];
    RKEM_decaps_derand(ss2, ct, sk);
    for (int i = 0; i < RKEM_MSGBYTES; i++)
    {
        if (ss1[i] != ss2[i])
        {
            return 0;
        }
    }
    return 1;
}

int test_rkem()
{
    uint8_t pk[RKEM_PUBLICKEYBYTES];
    uint8_t sk[RKEM_SECRETKEYBYTES];
    RKEM_keypair(pk, sk);
    uint8_t seed[RKEM_SYMBYTES];
    randombytes(seed, RKEM_SYMBYTES);
    uint8_t rand_pk[RKEM_PUBLICKEYBYTES];
    RKEM_rand(rand_pk, seed, pk);
    uint8_t ct[RKEM_CIPHERTEXTBYTES];
    uint8_t ss1[RKEM_MSGBYTES];
    RKEM_encaps(ct, ss1, rand_pk);
    uint8_t ss2[RKEM_MSGBYTES];
    RKEM_decaps(ss2, ct, sk, seed);
    for (int i = 0; i < RKEM_MSGBYTES; i++)
    {
        if (ss1[i] != ss2[i])
        {
            return 0;
        }
    }
    return 1;
}

int main()
{
    srand(time(NULL));
    for (int i = 0; i < 1000; i++)
    {
        if (!test_poly_bytes())
        {
            return EXIT_FAILURE;
        }
    }
    for (int i = 0; i < 1000; i++)
    {
        if (!test_polyvec_bytes())
        {
            return EXIT_FAILURE;
        }
    }
    for (int i = 0; i < 1000; i++)
    {
        if (!test_poly_compression())
        {
            return EXIT_FAILURE;
        }
    }
    for (int i = 0; i < 1000; i++)
    {
        if (!test_polyvec_compression())
        {
            return EXIT_FAILURE;
        }
    }
    for (int i = 0; i < 1000; i++)
    {
        if (!test_poly_tomsg())
        {
            return EXIT_FAILURE;
        }
    }
    for (int i = 0; i < 1000; i++)
    {
        if (!test_poly_frommsg())
        {
            return EXIT_FAILURE;
        }
    }
    for (int i = 0; i < 1000; i++)
    {
        if (!test_ntt())
        {
            return EXIT_FAILURE;
        }
    }
    for (int i = 0; i < 1000; i++)
    {
        if (!test_poly_ntt())
        {
            return EXIT_FAILURE;
        }
    }
    for (int i = 0; i < 1000; i++)
    {
        if (!test_poly_eta1())
        {
            return EXIT_FAILURE;
        }
    }
    for (int i = 0; i < 1000; i++)
    {
        if (!test_poly_eta2())
        {
            return EXIT_FAILURE;
        }
    }
    for (int i = 0; i < 1000; i++)
    {
        if (!test_poly_eta3())
        {
            return EXIT_FAILURE;
        }
    }
    for (int i = 0; i < 1000; i++)
    {
        if (!test_rkem_derand())
        {
            return EXIT_FAILURE;
        }
    }
    for (int i = 0; i < 1000; i++)
    {
        if (!test_rkem())
        {
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}
