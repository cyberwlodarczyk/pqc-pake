#include <string.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <kyber/polyvec.h>
#include <kyber/symmetric.h>
#include "tempo.h"

#define LEN_LAMBDA PQC_PAKE_TEMPO_len_lambda
#define LEN_3LAMBDA (3 * LEN_LAMBDA)
#define LEN_TAG PQC_PAKE_TEMPO_len_tag
#define LEN_FSID sizeof(PQC_PAKE_TEMPO_fsid)
#define LEN_APK sizeof(PQC_PAKE_TEMPO_apk)

void PQC_PAKE_TEMPO_fls(polyvec *v, const uint8_t *seed)
{
    xof_state state;
    uint8_t buf[5 * XOF_BLOCKBYTES];
    for (uint8_t x = 0; x < KYBER_K; x++)
    {
        xof_absorb(&state, seed, x, 0);
        xof_squeezeblocks(buf, 5, &state);
        int ctr = 0;
        for (int i = 0, buf_i = 0; i <= 279; i++, buf_i += 3)
        {
            uint16_t d[2];
            int d_ok[2];
            d[0] = ((buf[buf_i + 0] >> 0) |
                    ((uint16_t)buf[buf_i + 1] << 8)) &
                   0xFFF;
            d[1] = ((buf[buf_i + 1] >> 4) |
                    ((uint16_t)buf[buf_i + 2] << 4)) &
                   0xFFF;
            d_ok[0] = (d[0] < KYBER_Q);
            d_ok[1] = (d[1] < KYBER_Q);
            for (int d_i = 0; d_i < 2; d_i++)
            {
                int flag = 0;
                for (int j = 0; j < KYBER_N; j++)
                {
                    int match = (j == ctr);
                    int mask = match * d_ok[d_i];
                    int16_t *coeffs = v->vec[x].coeffs;
                    coeffs[j] = coeffs[j] * (1 - mask) + d[d_i] * mask;
                    flag += mask;
                }
                ctr += flag;
            }
        }
    }
    OPENSSL_cleanse(&state, sizeof(xof_state));
    OPENSSL_cleanse(buf, 5 * XOF_BLOCKBYTES);
}

void hash_1(
    polyvec *r,
    const PQC_PAKE_TEMPO_session sess,
    const uint8_t *seed,
    const uint8_t *r_seed)
{
    keccak_state state;
    shake256_init(&state);
    shake256_absorb(&state, (uint8_t *)&sess.fsid, LEN_FSID);
    shake256_absorb(&state, sess.password, KYBER_SYMBYTES);
    shake256_absorb(&state, seed, KYBER_SYMBYTES);
    shake256_absorb(&state, r_seed, LEN_3LAMBDA);
    uint8_t hash[KYBER_SYMBYTES];
    shake256_squeeze(hash, KYBER_SYMBYTES, &state);
    PQC_PAKE_TEMPO_fls(r, hash);
    OPENSSL_cleanse(&state, sizeof(keccak_state));
    OPENSSL_cleanse(hash, KYBER_SYMBYTES);
}

void hash_2(
    uint8_t *v_hash,
    const PQC_PAKE_TEMPO_session sess,
    const uint8_t *seed,
    const uint8_t *v_buf)
{
    keccak_state state;
    shake256_init(&state);
    shake256_absorb(&state, (uint8_t *)&sess.fsid, LEN_FSID);
    shake256_absorb(&state, sess.password, KYBER_SYMBYTES);
    shake256_absorb(&state, seed, KYBER_SYMBYTES);
    shake256_absorb(&state, v_buf, KYBER_POLYVECBYTES);
    shake256_squeeze(v_hash, LEN_3LAMBDA, &state);
    OPENSSL_cleanse(&state, sizeof(keccak_state));
}

void hash_key(
    uint8_t *tag,
    uint8_t *shared_secret,
    const PQC_PAKE_TEMPO_session sess,
    const uint8_t *public_key,
    const PQC_PAKE_TEMPO_apk *apk,
    const uint8_t *ciphertext,
    const uint8_t *key)
{
    keccak_state state;
    shake256_init(&state);
    shake256_absorb(&state, (uint8_t *)&sess.fsid, LEN_FSID);
    shake256_absorb(&state, sess.password, KYBER_SYMBYTES);
    shake256_absorb(&state, public_key, KYBER_PUBLICKEYBYTES);
    shake256_absorb(&state, (uint8_t *)apk, LEN_APK);
    shake256_absorb(&state, ciphertext, KYBER_CIPHERTEXTBYTES);
    shake256_absorb(&state, key, KYBER_SSBYTES);
    shake256_squeeze(tag, LEN_TAG, &state);
    shake256_squeeze(shared_secret, LEN_LAMBDA, &state);
    OPENSSL_cleanse(&state, sizeof(keccak_state));
}

void PQC_PAKE_TEMPO_keygen(
    uint8_t *public_key,
    uint8_t *secret_key,
    PQC_PAKE_TEMPO_apk *apk,
    const PQC_PAKE_TEMPO_session sess)
{
    PQC_PAKE_KEM_keygen(public_key, secret_key);
    uint8_t poly[KYBER_POLYVECBYTES];
    PQC_PAKE_KEM_split(apk->seed, poly, public_key);
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

void polyvec_sub(polyvec *r, const polyvec *a, const polyvec *b)
{
    for (int i = 0; i < KYBER_K; i++)
    {
        poly_sub(&r->vec[i], &a->vec[i], &b->vec[i]);
    }
}

void PQC_PAKE_TEMPO_encaps(
    uint8_t *ciphertext,
    uint8_t *tag,
    uint8_t *shared_secret,
    const PQC_PAKE_TEMPO_session sess,
    const PQC_PAKE_TEMPO_apk *apk)
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
    PQC_PAKE_KEM_join(public_key, apk->seed, poly);
    uint8_t key[KYBER_SSBYTES];
    PQC_PAKE_KEM_encaps(ciphertext, key, public_key);
    hash_key(tag, shared_secret, sess, public_key, apk, ciphertext, key);
    OPENSSL_cleanse(key, KYBER_SSBYTES);
    OPENSSL_cleanse(public_key, KYBER_PUBLICKEYBYTES);
    OPENSSL_cleanse(poly, KYBER_POLYVECBYTES);
    OPENSSL_cleanse(&r, sizeof(polyvec));
    OPENSSL_cleanse(&t, sizeof(polyvec));
    OPENSSL_cleanse(v_hash, LEN_3LAMBDA);
    OPENSSL_cleanse(r_seed, LEN_3LAMBDA);
}

void PQC_PAKE_TEMPO_decaps(
    uint8_t *shared_secret,
    const PQC_PAKE_TEMPO_session sess,
    const PQC_PAKE_TEMPO_apk *apk,
    const uint8_t *ciphertext,
    const uint8_t *tag,
    const uint8_t *public_key,
    const uint8_t *secret_key)
{
    uint8_t key[KYBER_SSBYTES];
    PQC_PAKE_KEM_decaps(key, ciphertext, secret_key);
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
