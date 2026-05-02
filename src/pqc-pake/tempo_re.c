#include <string.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <kyber/symmetric.h>
#include <rkem/xrkem.h>
#include "tempo_re.h"
#include "tempo_internal.h"

void hash(
    uint8_t *v_hash,
    const TEMPO_RE_session sess,
    const uint8_t *seed,
    const uint8_t *v_buf)
{
    keccak_state state;
    shake256_init(&state);
    shake256_absorb(&state, (uint8_t *)&sess.fsid, sizeof(TEMPO_RE_fsid));
    shake256_absorb(&state, sess.password, TEMPO_RE_len_password);
    shake256_absorb(&state, seed, TEMPO_RE_len_seed);
    shake256_absorb(&state, v_buf, TEMPO_RE_len_poly);
    shake256_squeeze(v_hash, TEMPO_RE_len_3lambda, &state);
    OPENSSL_cleanse(&state, sizeof(keccak_state));
}

void hash_key(
    uint8_t *tag,
    uint8_t *shared_secret,
    const TEMPO_RE_session sess,
    const uint8_t *public_key,
    const TEMPO_RE_apk *apk,
    const uint8_t *ciphertext,
    const uint8_t *key)
{
    keccak_state state;
    shake256_init(&state);
    shake256_absorb(&state, (uint8_t *)&sess.fsid, sizeof(TEMPO_RE_fsid));
    shake256_absorb(&state, sess.password, TEMPO_RE_len_password);
    shake256_absorb(&state, public_key, TEMPO_RE_len_public_key);
    shake256_absorb(&state, (uint8_t *)apk, sizeof(TEMPO_RE_apk));
    shake256_absorb(&state, ciphertext, TEMPO_RE_len_ciphertext);
    shake256_absorb(&state, key, XRKEM_len_shared_secret);
    shake256_squeeze(tag, TEMPO_RE_len_tag, &state);
    shake256_squeeze(shared_secret, TEMPO_RE_len_shared_secret, &state);
    OPENSSL_cleanse(&state, sizeof(keccak_state));
}

void TEMPO_RE_keygen(
    uint8_t *public_key,
    uint8_t *secret_key,
    TEMPO_RE_apk *apk,
    const TEMPO_RE_session sess)
{
    XRKEM_keygen(public_key, secret_key);
    memcpy(apk->seed, public_key + XRKEM_len_poly, XRKEM_len_seed);
    uint8_t r_seed[TEMPO_RE_len_3lambda];
    RAND_bytes(r_seed, TEMPO_RE_len_3lambda);
    uint8_t rand_public_key[XRKEM_len_public_key];
    XRKEM_rand(rand_public_key, r_seed, public_key);
    memcpy(apk->v, rand_public_key, XRKEM_len_poly);
    uint8_t v_hash[TEMPO_RE_len_3lambda];
    hash(v_hash, sess, apk->seed, apk->v);
    for (int i = 0; i < TEMPO_RE_len_3lambda; i++)
    {
        apk->u[i] = v_hash[i] ^ r_seed[i];
    }
    OPENSSL_cleanse(rand_public_key, XRKEM_len_public_key);
    OPENSSL_cleanse(r_seed, TEMPO_RE_len_3lambda);
    OPENSSL_cleanse(v_hash, TEMPO_RE_len_3lambda);
}

void TEMPO_RE_encaps(
    uint8_t *ciphertext,
    uint8_t *tag,
    uint8_t *shared_secret,
    const TEMPO_RE_session sess,
    const TEMPO_RE_apk *apk)
{
    uint8_t v_hash[TEMPO_RE_len_3lambda];
    hash(v_hash, sess, apk->seed, apk->v);
    uint8_t r_seed[TEMPO_RE_len_3lambda];
    for (int i = 0; i < TEMPO_RE_len_3lambda; i++)
    {
        r_seed[i] = v_hash[i] ^ apk->u[i];
    }
    uint8_t rand_public_key[XRKEM_len_public_key];
    memcpy(rand_public_key, apk->v, XRKEM_len_poly);
    memcpy(rand_public_key + XRKEM_len_poly, apk->seed, XRKEM_len_seed);
    uint8_t public_key[XRKEM_len_public_key];
    XRKEM_derand(public_key, r_seed, rand_public_key);
    uint8_t key[XRKEM_len_shared_secret];
    XRKEM_encaps(ciphertext, key, public_key);
    hash_key(
        tag,
        shared_secret,
        sess,
        public_key,
        apk,
        ciphertext,
        key);
    OPENSSL_cleanse(key, XRKEM_len_shared_secret);
    OPENSSL_cleanse(rand_public_key, XRKEM_len_public_key);
    OPENSSL_cleanse(public_key, XRKEM_len_public_key);
    OPENSSL_cleanse(v_hash, TEMPO_RE_len_3lambda);
    OPENSSL_cleanse(r_seed, TEMPO_RE_len_3lambda);
}

void TEMPO_RE_decaps(
    uint8_t *shared_secret,
    const TEMPO_RE_session sess,
    const TEMPO_RE_apk *apk,
    const uint8_t *ciphertext,
    const uint8_t *tag,
    const uint8_t *public_key,
    const uint8_t *secret_key)
{
    uint8_t key[XRKEM_len_shared_secret];
    XRKEM_decaps_derand(key, ciphertext, secret_key);
    uint8_t local_tag[TEMPO_RE_len_tag];
    uint8_t real_shared_secret[TEMPO_RE_len_shared_secret];
    hash_key(
        local_tag,
        real_shared_secret,
        sess,
        public_key,
        apk,
        ciphertext,
        key);
    uint8_t alt_shared_secret[TEMPO_RE_len_shared_secret];
    RAND_bytes(alt_shared_secret, TEMPO_RE_len_shared_secret);
    if (CRYPTO_memcmp(local_tag, tag, TEMPO_RE_len_tag) != 0)
    {
        memcpy(shared_secret, alt_shared_secret, TEMPO_RE_len_shared_secret);
    }
    else
    {
        memcpy(shared_secret, real_shared_secret, TEMPO_RE_len_shared_secret);
    }
    OPENSSL_cleanse(key, XRKEM_len_shared_secret);
    OPENSSL_cleanse(alt_shared_secret, TEMPO_RE_len_shared_secret);
    OPENSSL_cleanse(real_shared_secret, TEMPO_RE_len_shared_secret);
}
