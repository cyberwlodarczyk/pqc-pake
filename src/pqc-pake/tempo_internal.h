#ifndef TEMPO_INTERNAL_H
#define TEMPO_INTERNAL_H

#include <stdint.h>
#include <kyber/polyvec.h>
#include "tempo.h"

#define LEN_LAMBDA TEMPO_len_lambda
#define LEN_3LAMBDA (3 * LEN_LAMBDA)
#define LEN_TAG TEMPO_len_tag
#define LEN_FSID sizeof(TEMPO_fsid)
#define LEN_APK sizeof(TEMPO_apk)

void fls(polyvec *v, const uint8_t *seed);

void hash_1(
    polyvec *r,
    const TEMPO_session sess,
    const uint8_t *seed,
    const uint8_t *r_seed);

void hash_2(
    uint8_t *v_hash,
    const TEMPO_session sess,
    const uint8_t *seed,
    const uint8_t *v_buf);

void hash_key(
    uint8_t *tag,
    uint8_t *shared_secret,
    const TEMPO_session sess,
    const uint8_t *public_key,
    const TEMPO_apk *apk,
    const uint8_t *ciphertext,
    const uint8_t *key);

void polyvec_sub(polyvec *r, const polyvec *a, const polyvec *b);

#endif
