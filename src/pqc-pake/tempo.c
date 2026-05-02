#include <string.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <kyber/kem.h>
#include "tempo.h"
#include "tempo_internal.h"

void TEMPO_keygen(
    uint8_t *public_key,
    uint8_t *secret_key,
    TEMPO_apk *apk,
    const TEMPO_session sess)
{
    pqcrystals_kyber768_ref_keypair(public_key, secret_key);
    uint8_t poly[KYBER_POLYVECBYTES];
    memcpy(apk->seed, public_key + KYBER_POLYVECBYTES, KYBER_SYMBYTES);
    memcpy(poly, public_key, KYBER_POLYVECBYTES);
    uint8_t r_seed[LEN_3LAMBDA];
    RAND_bytes(r_seed, LEN_3LAMBDA);
    polyvec r;
    hash_1(&r, sess, apk->seed, r_seed);
    polyvec t;
    polyvec_frombytes(&t, poly);
    polyvec v;
    polyvec_add(&v, &t, &r);
    polyvec_reduce(&v);
    polyvec_tobytes(apk->v, &v);
    uint8_t v_hash[LEN_3LAMBDA];
    hash_2(v_hash, sess, apk->seed, apk->v);
    for (size_t i = 0; i < LEN_3LAMBDA; i++)
    {
        apk->u[i] = v_hash[i] ^ r_seed[i];
    }
    OPENSSL_cleanse(poly, KYBER_POLYVECBYTES);
    OPENSSL_cleanse(&r, sizeof(polyvec));
    OPENSSL_cleanse(&t, sizeof(polyvec));
    OPENSSL_cleanse(r_seed, LEN_3LAMBDA);
    OPENSSL_cleanse(v_hash, LEN_3LAMBDA);
}

void TEMPO_encaps(
    uint8_t *ciphertext,
    uint8_t *tag,
    uint8_t *shared_secret,
    const TEMPO_session sess,
    const TEMPO_apk *apk)
{
    uint8_t v_hash[LEN_3LAMBDA];
    hash_2(v_hash, sess, apk->seed, apk->v);
    uint8_t r_seed[LEN_3LAMBDA];
    for (size_t i = 0; i < LEN_3LAMBDA; i++)
    {
        r_seed[i] = v_hash[i] ^ apk->u[i];
    }
    polyvec r;
    hash_1(&r, sess, apk->seed, r_seed);
    polyvec v;
    polyvec_frombytes(&v, apk->v);
    polyvec t;
    polyvec_sub(&t, &v, &r);
    polyvec_reduce(&t);
    uint8_t poly[KYBER_POLYVECBYTES];
    polyvec_tobytes(poly, &t);
    uint8_t public_key[KYBER_PUBLICKEYBYTES];
    memcpy(public_key + KYBER_POLYVECBYTES, apk->seed, KYBER_SYMBYTES);
    memcpy(public_key, poly, KYBER_POLYVECBYTES);
    uint8_t key[KYBER_SSBYTES];
    pqcrystals_kyber768_ref_enc(ciphertext, key, public_key);
    hash_key(tag, shared_secret, sess, public_key, apk, ciphertext, key);
    OPENSSL_cleanse(key, KYBER_SSBYTES);
    OPENSSL_cleanse(public_key, KYBER_PUBLICKEYBYTES);
    OPENSSL_cleanse(poly, KYBER_POLYVECBYTES);
    OPENSSL_cleanse(&r, sizeof(polyvec));
    OPENSSL_cleanse(&t, sizeof(polyvec));
    OPENSSL_cleanse(v_hash, LEN_3LAMBDA);
    OPENSSL_cleanse(r_seed, LEN_3LAMBDA);
}

void TEMPO_decaps(
    uint8_t *shared_secret,
    const TEMPO_session sess,
    const TEMPO_apk *apk,
    const uint8_t *ciphertext,
    const uint8_t *tag,
    const uint8_t *public_key,
    const uint8_t *secret_key)
{
    uint8_t key[KYBER_SSBYTES];
    pqcrystals_kyber768_ref_dec(key, ciphertext, secret_key);
    uint8_t local_tag[LEN_TAG];
    uint8_t real_shared_secret[LEN_LAMBDA];
    hash_key(
        local_tag,
        real_shared_secret,
        sess,
        public_key,
        apk,
        ciphertext,
        key);
    uint8_t alt_shared_secret[LEN_LAMBDA];
    RAND_bytes(alt_shared_secret, LEN_LAMBDA);
    if (CRYPTO_memcmp(local_tag, tag, LEN_TAG) != 0)
    {
        memcpy(shared_secret, alt_shared_secret, LEN_LAMBDA);
    }
    else
    {
        memcpy(shared_secret, real_shared_secret, LEN_LAMBDA);
    }
    OPENSSL_cleanse(key, KYBER_SSBYTES);
    OPENSSL_cleanse(alt_shared_secret, LEN_LAMBDA);
    OPENSSL_cleanse(real_shared_secret, LEN_LAMBDA);
}
