#include <string.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <kyber/kyber.h>
#include <kyber/polyvec.h>
#include <kyber/symmetric.h>
#include "tempo.h"

static void fls(KYBER_polyvec *a, const uint8_t *seed, int transposed, int n)
{
    xof_state state;
    uint8_t buf[5 * XOF_BLOCKBYTES];
    for (uint8_t y = 0; y < n; y++)
    {
        for (uint8_t x = 0; x < KYBER_K; x++)
        {
            if (transposed)
            {
                KYBER_xof_absorb(&state, seed, y, x);
            }
            else
            {
                KYBER_xof_absorb(&state, seed, x, y);
            }
            KYBER_xof_squeezeblocks(buf, 5, &state);
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
                        int16_t *coeffs = a[y].vec[x].coeffs;
                        coeffs[j] = coeffs[j] * (1 - mask) + d[d_i] * mask;
                        flag += mask;
                    }
                    ctr += flag;
                }
            }
        }
    }
    OPENSSL_cleanse(&state, sizeof(xof_state));
    OPENSSL_cleanse(buf, 5 * XOF_BLOCKBYTES);
}

void TEMPO_gen_matrix_fls(
    KYBER_polyvec *a,
    const uint8_t *seed,
    int tranposed)
{
    fls(a, seed, tranposed, KYBER_K);
}

static void hash_1(
    KYBER_polyvec *r,
    const TEMPO_session sess,
    const uint8_t *seed,
    const uint8_t *r_seed)
{
    keccak_state state;
    shake256_init(&state);
    shake256_absorb(&state, (uint8_t *)&sess.fsid, sizeof(TEMPO_fsid));
    shake256_absorb(&state, sess.password, KYBER_LEN_SEED);
    shake256_absorb(&state, seed, KYBER_LEN_SEED);
    shake256_absorb(&state, r_seed, TEMPO_LEN_3LAMBDA);
    uint8_t hash[KYBER_LEN_SEED];
    shake256_squeeze(hash, KYBER_LEN_SEED, &state);
    fls(r, hash, 0, 1);
    OPENSSL_cleanse(&state, sizeof(keccak_state));
    OPENSSL_cleanse(hash, KYBER_LEN_SEED);
}

static void hash_2(
    uint8_t *v_hash,
    const TEMPO_session sess,
    const uint8_t *seed,
    const uint8_t *v_buf)
{
    keccak_state state;
    shake256_init(&state);
    shake256_absorb(&state, (uint8_t *)&sess.fsid, sizeof(TEMPO_fsid));
    shake256_absorb(&state, sess.password, KYBER_LEN_SEED);
    shake256_absorb(&state, seed, KYBER_LEN_SEED);
    shake256_absorb(&state, v_buf, KYBER_LEN_POLYVEC);
    shake256_squeeze(v_hash, TEMPO_LEN_3LAMBDA, &state);
    OPENSSL_cleanse(&state, sizeof(keccak_state));
}

static void hash_key(
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
    shake256_absorb(&state, sess.password, KYBER_LEN_SEED);
    shake256_absorb(&state, public_key, KYBER_LEN_PUBLIC_KEY);
    shake256_absorb(&state, (uint8_t *)apk, sizeof(TEMPO_apk));
    shake256_absorb(&state, ciphertext, KYBER_LEN_CIPHERTEXT);
    shake256_absorb(&state, key, KYBER_LEN_SHARED_SECRET);
    shake256_squeeze(tag, TEMPO_LEN_TAG, &state);
    shake256_squeeze(shared_secret, TEMPO_LEN_LAMBDA, &state);
    OPENSSL_cleanse(&state, sizeof(keccak_state));
}

void TEMPO_keygen(
    uint8_t *public_key,
    uint8_t *secret_key,
    TEMPO_apk *apk,
    const TEMPO_session sess)
{
    KYBER_keygen(public_key, secret_key);
    uint8_t poly[KYBER_LEN_POLYVEC];
    memcpy(apk->seed, public_key + KYBER_LEN_POLYVEC, KYBER_LEN_SEED);
    memcpy(poly, public_key, KYBER_LEN_POLYVEC);
    uint8_t r_seed[TEMPO_LEN_3LAMBDA];
    RAND_bytes(r_seed, TEMPO_LEN_3LAMBDA);
    KYBER_polyvec r;
    hash_1(&r, sess, apk->seed, r_seed);
    KYBER_polyvec t;
    KYBER_polyvec_frombytes(&t, poly);
    KYBER_polyvec v;
    KYBER_polyvec_add(&v, &t, &r);
    KYBER_polyvec_reduce(&v);
    KYBER_polyvec_tobytes(apk->v, &v);
    uint8_t v_hash[TEMPO_LEN_3LAMBDA];
    hash_2(v_hash, sess, apk->seed, apk->v);
    for (int i = 0; i < TEMPO_LEN_3LAMBDA; i++)
    {
        apk->u[i] = v_hash[i] ^ r_seed[i];
    }
    OPENSSL_cleanse(poly, KYBER_LEN_POLYVEC);
    OPENSSL_cleanse(&r, sizeof(KYBER_polyvec));
    OPENSSL_cleanse(&t, sizeof(KYBER_polyvec));
    OPENSSL_cleanse(r_seed, TEMPO_LEN_3LAMBDA);
    OPENSSL_cleanse(v_hash, TEMPO_LEN_3LAMBDA);
}

void TEMPO_encaps(
    uint8_t *ciphertext,
    uint8_t *tag,
    uint8_t *shared_secret,
    const TEMPO_session sess,
    const TEMPO_apk *apk)
{
    uint8_t v_hash[TEMPO_LEN_3LAMBDA];
    hash_2(v_hash, sess, apk->seed, apk->v);
    uint8_t r_seed[TEMPO_LEN_3LAMBDA];
    for (int i = 0; i < TEMPO_LEN_3LAMBDA; i++)
    {
        r_seed[i] = v_hash[i] ^ apk->u[i];
    }
    KYBER_polyvec r;
    hash_1(&r, sess, apk->seed, r_seed);
    KYBER_polyvec v;
    KYBER_polyvec_frombytes(&v, apk->v);
    KYBER_polyvec t;
    KYBER_polyvec_sub(&t, &v, &r);
    KYBER_polyvec_reduce(&t);
    uint8_t poly[KYBER_LEN_POLYVEC];
    KYBER_polyvec_tobytes(poly, &t);
    uint8_t public_key[KYBER_LEN_PUBLIC_KEY];
    memcpy(public_key + KYBER_LEN_POLYVEC, apk->seed, KYBER_LEN_SEED);
    memcpy(public_key, poly, KYBER_LEN_POLYVEC);
    uint8_t key[KYBER_LEN_SHARED_SECRET];
    KYBER_encaps(ciphertext, key, public_key);
    hash_key(
        tag,
        shared_secret,
        sess,
        public_key,
        apk,
        ciphertext,
        key);
    OPENSSL_cleanse(key, KYBER_LEN_SHARED_SECRET);
    OPENSSL_cleanse(public_key, KYBER_LEN_PUBLIC_KEY);
    OPENSSL_cleanse(poly, KYBER_LEN_POLYVEC);
    OPENSSL_cleanse(&r, sizeof(KYBER_polyvec));
    OPENSSL_cleanse(&t, sizeof(KYBER_polyvec));
    OPENSSL_cleanse(v_hash, TEMPO_LEN_3LAMBDA);
    OPENSSL_cleanse(r_seed, TEMPO_LEN_3LAMBDA);
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
    uint8_t key[KYBER_LEN_SHARED_SECRET];
    KYBER_decaps(key, ciphertext, secret_key);
    uint8_t local_tag[TEMPO_LEN_TAG];
    uint8_t real_shared_secret[TEMPO_LEN_LAMBDA];
    hash_key(
        local_tag,
        real_shared_secret,
        sess,
        public_key,
        apk,
        ciphertext,
        key);
    uint8_t alt_shared_secret[TEMPO_LEN_LAMBDA];
    RAND_bytes(alt_shared_secret, TEMPO_LEN_LAMBDA);
    if (CRYPTO_memcmp(local_tag, tag, TEMPO_LEN_TAG) != 0)
    {
        memcpy(shared_secret, alt_shared_secret, TEMPO_LEN_LAMBDA);
    }
    else
    {
        memcpy(shared_secret, real_shared_secret, TEMPO_LEN_LAMBDA);
    }
    OPENSSL_cleanse(key, KYBER_LEN_SHARED_SECRET);
    OPENSSL_cleanse(alt_shared_secret, TEMPO_LEN_LAMBDA);
    OPENSSL_cleanse(real_shared_secret, TEMPO_LEN_LAMBDA);
}
