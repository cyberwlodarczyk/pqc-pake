#ifndef TEMPO_RE_H
#define TEMPO_RE_H

#include <stdint.h>

#define TEMPO_RE_len_lambda 24
#define TEMPO_RE_len_3lambda (3 * TEMPO_RE_len_lambda)
#define TEMPO_RE_len_password 32
#define TEMPO_RE_len_seed 32
#define TEMPO_RE_len_poly 1040
#define TEMPO_RE_len_public_key (TEMPO_RE_len_seed + TEMPO_RE_len_poly)
#define TEMPO_RE_len_secret_key TEMPO_RE_len_poly
#define TEMPO_RE_len_ciphertext 848
#define TEMPO_RE_len_tag (2 * TEMPO_RE_len_lambda)
#define TEMPO_RE_len_shared_secret TEMPO_RE_len_lambda

typedef struct
{
    uint8_t u[TEMPO_RE_len_3lambda];
    uint8_t v[TEMPO_RE_len_poly];
    uint8_t seed[TEMPO_RE_len_seed];
} TEMPO_RE_apk;

typedef struct
{
    uint64_t sid;
    uint64_t a;
    uint64_t b;
} TEMPO_RE_fsid;

typedef struct
{
    TEMPO_RE_fsid fsid;
    const uint8_t *password;
} TEMPO_RE_session;

void TEMPO_RE_keygen(
    uint8_t *public_key,
    uint8_t *secret_key,
    TEMPO_RE_apk *apk,
    const TEMPO_RE_session sess);

void TEMPO_RE_encaps(
    uint8_t *ciphertext,
    uint8_t *tag,
    uint8_t *shared_secret,
    const TEMPO_RE_session sess,
    const TEMPO_RE_apk *apk);

void TEMPO_RE_decaps(
    uint8_t *shared_secret,
    const TEMPO_RE_session sess,
    const TEMPO_RE_apk *apk,
    const uint8_t *ciphertext,
    const uint8_t *tag,
    const uint8_t *public_key,
    const uint8_t *secret_key);

#endif
