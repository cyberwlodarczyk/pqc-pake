#ifndef TEMPO_RE_H
#define TEMPO_RE_H

#include <stdint.h>

#define TEMPO_RE_LEN_LAMBDA 24
#define TEMPO_RE_LEN_3LAMBDA (3 * TEMPO_RE_LEN_LAMBDA)
#define TEMPO_RE_LEN_PASSWORD 32
#define TEMPO_RE_LEN_SEED 32
#define TEMPO_RE_LEN_POLY 1040
#define TEMPO_RE_LEN_PUBLIC_KEY (TEMPO_RE_LEN_SEED + TEMPO_RE_LEN_POLY)
#define TEMPO_RE_LEN_SECRET_KEY TEMPO_RE_LEN_POLY
#define TEMPO_RE_LEN_CIPHERTEXT 848
#define TEMPO_RE_LEN_TAG (2 * TEMPO_RE_LEN_LAMBDA)
#define TEMPO_RE_LEN_SHARED_SECRET TEMPO_RE_LEN_LAMBDA

typedef struct
{
    uint8_t u[TEMPO_RE_LEN_3LAMBDA];
    uint8_t v[TEMPO_RE_LEN_POLY];
    uint8_t seed[TEMPO_RE_LEN_SEED];
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
