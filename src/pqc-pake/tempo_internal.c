#include <openssl/crypto.h>
#include <kyber/symmetric.h>
#include <kyber/poly.h>
#include "tempo_internal.h"

void fls(polyvec *v, const uint8_t *seed)
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
    const TEMPO_session sess,
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
    fls(r, hash);
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
    const TEMPO_session sess,
    const uint8_t *public_key,
    const TEMPO_apk *apk,
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

void polyvec_sub(polyvec *r, const polyvec *a, const polyvec *b)
{
    for (int i = 0; i < KYBER_K; i++)
    {
        poly_sub(&r->vec[i], &a->vec[i], &b->vec[i]);
    }
}
