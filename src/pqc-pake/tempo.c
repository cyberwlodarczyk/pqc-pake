#include <string.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <kyber/kem.h>
#include <kyber/symmetric.h>
#include "tempo.h"
#include "tempo_internal.h"

void hash_1(
    polyvec *r,
    const TEMPO_session sess,
    const uint8_t *seed,
    const uint8_t *r_seed)
{
    keccak_state state;
    shake256_init(&state);
    shake256_absorb(&state, (uint8_t *)&sess.fsid, sizeof(TEMPO_fsid));
    shake256_absorb(&state, sess.password, KYBER_SYMBYTES);
    shake256_absorb(&state, seed, KYBER_SYMBYTES);
    shake256_absorb(&state, r_seed, TEMPO_len_3lambda);
    uint8_t hash[KYBER_SYMBYTES];
    shake256_squeeze(hash, KYBER_SYMBYTES, &state);
    tempo_fls(r, hash);
    OPENSSL_cleanse(&state, sizeof(keccak_state));
    OPENSSL_cleanse(hash, KYBER_SYMBYTES);
}

void hash_2(
    uint8_t *v_hash,
    const TEMPO_session sess,
    const uint8_t *seed,
    const uint8_t *v_buf)
{
    keccak_state state;
    shake256_init(&state);
    shake256_absorb(&state, (uint8_t *)&sess.fsid, sizeof(TEMPO_fsid));
    shake256_absorb(&state, sess.password, KYBER_SYMBYTES);
    shake256_absorb(&state, seed, KYBER_SYMBYTES);
    shake256_absorb(&state, v_buf, KYBER_POLYVECBYTES);
    shake256_squeeze(v_hash, TEMPO_len_3lambda, &state);
    OPENSSL_cleanse(&state, sizeof(keccak_state));
}

void hash_key(
    uint8_t *tag,
    uint8_t *shared_secret,
    const TEMPO_session sess,
    const uint8_t *public_key,
    const TEMPO_apk *apk,
    const uint8_t *ciphertext,
    const uint8_t *key)
{
    keccak_state state;
    shake256_init(&state);
    shake256_absorb(&state, (uint8_t *)&sess.fsid, sizeof(TEMPO_fsid));
    shake256_absorb(&state, sess.password, KYBER_SYMBYTES);
    shake256_absorb(&state, public_key, KYBER_PUBLICKEYBYTES);
    shake256_absorb(&state, (uint8_t *)apk, sizeof(TEMPO_apk));
    shake256_absorb(&state, ciphertext, KYBER_CIPHERTEXTBYTES);
    shake256_absorb(&state, key, KYBER_SSBYTES);
    shake256_squeeze(tag, TEMPO_len_tag, &state);
    shake256_squeeze(shared_secret, TEMPO_len_lambda, &state);
    OPENSSL_cleanse(&state, sizeof(keccak_state));
}

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
    uint8_t r_seed[TEMPO_len_3lambda];
    RAND_bytes(r_seed, TEMPO_len_3lambda);
    polyvec r;
    hash_1(&r, sess, apk->seed, r_seed);
    polyvec t;
    polyvec_frombytes(&t, poly);
    polyvec v;
    polyvec_add(&v, &t, &r);
    polyvec_reduce(&v);
    polyvec_tobytes(apk->v, &v);
    uint8_t v_hash[TEMPO_len_3lambda];
    hash_2(v_hash, sess, apk->seed, apk->v);
    for (int i = 0; i < TEMPO_len_3lambda; i++)
    {
        apk->u[i] = v_hash[i] ^ r_seed[i];
    }
    OPENSSL_cleanse(poly, KYBER_POLYVECBYTES);
    OPENSSL_cleanse(&r, sizeof(polyvec));
    OPENSSL_cleanse(&t, sizeof(polyvec));
    OPENSSL_cleanse(r_seed, TEMPO_len_3lambda);
    OPENSSL_cleanse(v_hash, TEMPO_len_3lambda);
}

void TEMPO_encaps(
    uint8_t *ciphertext,
    uint8_t *tag,
    uint8_t *shared_secret,
    const TEMPO_session sess,
    const TEMPO_apk *apk)
{
    uint8_t v_hash[TEMPO_len_3lambda];
    hash_2(v_hash, sess, apk->seed, apk->v);
    uint8_t r_seed[TEMPO_len_3lambda];
    for (int i = 0; i < TEMPO_len_3lambda; i++)
    {
        r_seed[i] = v_hash[i] ^ apk->u[i];
    }
    polyvec r;
    hash_1(&r, sess, apk->seed, r_seed);
    polyvec v;
    polyvec_frombytes(&v, apk->v);
    polyvec t;
    for (int i = 0; i < KYBER_K; i++)
    {
        poly_sub(&t.vec[i], &v.vec[i], &r.vec[i]);
    }
    polyvec_reduce(&t);
    uint8_t poly[KYBER_POLYVECBYTES];
    polyvec_tobytes(poly, &t);
    uint8_t public_key[KYBER_PUBLICKEYBYTES];
    memcpy(public_key + KYBER_POLYVECBYTES, apk->seed, KYBER_SYMBYTES);
    memcpy(public_key, poly, KYBER_POLYVECBYTES);
    uint8_t key[KYBER_SSBYTES];
    pqcrystals_kyber768_ref_enc(ciphertext, key, public_key);
    hash_key(
        tag,
        shared_secret,
        sess,
        public_key,
        apk,
        ciphertext,
        key);
    OPENSSL_cleanse(key, KYBER_SSBYTES);
    OPENSSL_cleanse(public_key, KYBER_PUBLICKEYBYTES);
    OPENSSL_cleanse(poly, KYBER_POLYVECBYTES);
    OPENSSL_cleanse(&r, sizeof(polyvec));
    OPENSSL_cleanse(&t, sizeof(polyvec));
    OPENSSL_cleanse(v_hash, TEMPO_len_3lambda);
    OPENSSL_cleanse(r_seed, TEMPO_len_3lambda);
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
    uint8_t local_tag[TEMPO_len_tag];
    uint8_t real_shared_secret[TEMPO_len_lambda];
    hash_key(
        local_tag,
        real_shared_secret,
        sess,
        public_key,
        apk,
        ciphertext,
        key);
    uint8_t alt_shared_secret[TEMPO_len_lambda];
    RAND_bytes(alt_shared_secret, TEMPO_len_lambda);
    if (CRYPTO_memcmp(local_tag, tag, TEMPO_len_tag) != 0)
    {
        memcpy(shared_secret, alt_shared_secret, TEMPO_len_lambda);
    }
    else
    {
        memcpy(shared_secret, real_shared_secret, TEMPO_len_lambda);
    }
    OPENSSL_cleanse(key, KYBER_SSBYTES);
    OPENSSL_cleanse(alt_shared_secret, TEMPO_len_lambda);
    OPENSSL_cleanse(real_shared_secret, TEMPO_len_lambda);
}
