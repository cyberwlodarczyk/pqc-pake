#include <openssl/crypto.h>
#include <openssl/rand.h>
#include "poly.h"
#include "polyvec.h"
#include "rkem_internal.h"
#include "rkem.h"

void RKEM_keygen(uint8_t *public_key, uint8_t *secret_key)
{
    polyvec s, e, p;
    uint8_t noiseseed[RKEM_SYMBYTES];
    RAND_bytes(noiseseed, RKEM_SYMBYTES);
    uint8_t nonce = 0;
    for (int i = 0; i < RKEM_K; i++)
    {
        poly_getnoise_eta1(&s.vec[i], noiseseed, nonce++);
    }
    for (int i = 0; i < RKEM_K; i++)
    {
        poly_getnoise_eta1(&e.vec[i], noiseseed, nonce++);
    }
    polyvec_ntt(&s);
    polyvec_ntt(&e);
    for (int i = 0; i < RKEM_K; i++)
    {
        polyvec_basemul_acc_montgomery(&p.vec[i], &RKEM_A[i], &s);
        poly_tomont(&p.vec[i]);
    }
    polyvec_add(&p, &p, &e);
    polyvec_reduce(&p);
    polyvec_tobytes(public_key, &p);
    polyvec_tobytes(secret_key, &s);
    OPENSSL_cleanse(noiseseed, RKEM_SYMBYTES);
    OPENSSL_cleanse(&s, sizeof(polyvec));
    OPENSSL_cleanse(&e, sizeof(polyvec));
}

void RKEM_rand(
    uint8_t *rand_public_key,
    const uint8_t *seed,
    const uint8_t *public_key)
{
    polyvec s, e, p, p1, p2;
    polyvec_frombytes(&p1, public_key);
    uint8_t nonce = 0;
    for (int i = 0; i < RKEM_K; i++)
    {
        poly_getnoise_eta1(&s.vec[i], seed, nonce++);
    }
    for (int i = 0; i < RKEM_K; i++)
    {
        poly_getnoise_eta1(&e.vec[i], seed, nonce++);
    }
    polyvec_ntt(&s);
    polyvec_ntt(&e);
    for (int i = 0; i < RKEM_K; i++)
    {
        polyvec_basemul_acc_montgomery(&p2.vec[i], &RKEM_A[i], &s);
        poly_tomont(&p2.vec[i]);
    }
    polyvec_add(&p2, &p2, &e);
    polyvec_add(&p, &p1, &p2);
    polyvec_reduce(&p);
    polyvec_tobytes(rand_public_key, &p);
    OPENSSL_cleanse(&s, sizeof(polyvec));
    OPENSSL_cleanse(&e, sizeof(polyvec));
}

void RKEM_encaps(
    uint8_t *ciphertext,
    uint8_t *shared_secret,
    const uint8_t *public_key)
{
    polyvec r, e1, p, u;
    poly e2, v, k;
    uint8_t noiseseed[RKEM_SYMBYTES];
    RAND_bytes(noiseseed, RKEM_SYMBYTES);
    uint8_t nonce = 0;
    for (int i = 0; i < RKEM_K; i++)
    {
        poly_getnoise_eta2(&r.vec[i], noiseseed, nonce++);
    }
    for (int i = 0; i < RKEM_K; i++)
    {
        poly_getnoise_eta2(&e1.vec[i], noiseseed, nonce++);
    }
    poly_getnoise_eta3(&e2, noiseseed, nonce);
    RAND_bytes(shared_secret, RKEM_MSGBYTES);
    poly_frommsg(&k, shared_secret);
    polyvec_ntt(&r);
    for (int i = 0; i < RKEM_K; i++)
    {
        polyvec_basemul_acc_montgomery(&u.vec[i], &RKEM_AT[i], &r);
    }
    polyvec_invntt_tomont(&u);
    polyvec_add(&u, &u, &e1);
    polyvec_reduce(&u);
    polyvec_frombytes(&p, public_key);
    polyvec_basemul_acc_montgomery(&v, &p, &r);
    poly_invntt_tomont(&v);
    poly_add(&v, &v, &e2);
    poly_add(&v, &v, &k);
    poly_reduce(&v);
    polyvec_compress(ciphertext, &u);
    poly_compress(ciphertext + RKEM_POLYVECCOMPRESSEDBYTES, &v);
    OPENSSL_cleanse(noiseseed, RKEM_SYMBYTES);
    OPENSSL_cleanse(&r, sizeof(polyvec));
    OPENSSL_cleanse(&e1, sizeof(polyvec));
    OPENSSL_cleanse(&e2, sizeof(poly));
    OPENSSL_cleanse(&k, sizeof(poly));
}

void RKEM_decaps(
    uint8_t *shared_secret,
    const uint8_t *ciphertext,
    const uint8_t *secret_key,
    const uint8_t *seed)
{
    polyvec u, s, s1, s2;
    poly v, z;
    polyvec_frombytes(&s1, secret_key);
    uint8_t nonce = 0;
    for (int i = 0; i < RKEM_K; i++)
    {
        poly_getnoise_eta1(&s2.vec[i], seed, nonce++);
    }
    polyvec_ntt(&s2);
    polyvec_add(&s, &s1, &s2);
    polyvec_reduce(&s);
    polyvec_decompress(&u, ciphertext);
    poly_decompress(&v, ciphertext + RKEM_POLYVECCOMPRESSEDBYTES);
    polyvec_ntt(&u);
    polyvec_basemul_acc_montgomery(&z, &s, &u);
    poly_invntt_tomont(&z);
    poly_sub(&z, &v, &z);
    poly_reduce(&z);
    poly_tomsg(shared_secret, &z);
    OPENSSL_cleanse(&s, sizeof(polyvec));
    OPENSSL_cleanse(&s1, sizeof(polyvec));
    OPENSSL_cleanse(&s2, sizeof(polyvec));
    OPENSSL_cleanse(&z, sizeof(poly));
}
