#ifndef TEMPO_H
#define TEMPO_H

#include <stdint.h>
#include <kyber/polyvec.h>

#define TEMPO_LEN_LAMBDA 24
#define TEMPO_LEN_3LAMBDA (3 * TEMPO_LEN_LAMBDA)
#define TEMPO_LEN_PASSWORD 32
#define TEMPO_LEN_SEED 32
#define TEMPO_LEN_POLY 1152
#define TEMPO_LEN_PUBLIC_KEY (TEMPO_LEN_SEED + TEMPO_LEN_POLY)
#define TEMPO_LEN_SECRET_KEY 2400
#define TEMPO_LEN_CIPHERTEXT 1088
#define TEMPO_LEN_TAG (2 * TEMPO_LEN_LAMBDA)
#define TEMPO_LEN_SHARED_SECRET TEMPO_LEN_LAMBDA

typedef struct
{
    uint8_t u[TEMPO_LEN_3LAMBDA];
    uint8_t v[TEMPO_LEN_POLY];
    uint8_t seed[TEMPO_LEN_SEED];
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

void TEMPO_fls(KYBER_polyvec *v, const uint8_t *seed);

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
