#ifndef TEMPO_H
#define TEMPO_H

#include <stdint.h>

#define TEMPO_len_lambda 24
#define TEMPO_len_password 32
#define TEMPO_len_seed 32
#define TEMPO_len_poly 1152
#define TEMPO_len_public_key (TEMPO_len_seed + TEMPO_len_poly)
#define TEMPO_len_secret_key 2400
#define TEMPO_len_ciphertext 1088
#define TEMPO_len_tag (2 * TEMPO_len_lambda)
#define TEMPO_len_shared_secret TEMPO_len_lambda

typedef struct
{
    uint8_t u[3 * TEMPO_len_lambda];
    uint8_t v[TEMPO_len_poly];
    uint8_t seed[TEMPO_len_seed];
} TEMPO_apk;

typedef struct
{
    uint64_t sid;
    uint64_t a;
    uint64_t b;
} TEMPO_fsid;

typedef struct
{
    TEMPO_fsid fsid;
    const uint8_t *password;
} TEMPO_session;

void TEMPO_keygen(
    uint8_t *public_key,
    uint8_t *secret_key,
    TEMPO_apk *apk,
    const TEMPO_session sess);

void TEMPO_encaps(
    uint8_t *ciphertext,
    uint8_t *tag,
    uint8_t *shared_secret,
    const TEMPO_session sess,
    const TEMPO_apk *apk);

void TEMPO_decaps(
    uint8_t *shared_secret,
    const TEMPO_session sess,
    const TEMPO_apk *apk,
    const uint8_t *ciphertext,
    const uint8_t *tag,
    const uint8_t *public_key,
    const uint8_t *secret_key);

#endif
