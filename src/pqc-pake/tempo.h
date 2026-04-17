#ifndef PQC_PAKE_TEMPO_H
#define PQC_PAKE_TEMPO_H

#include <kyber/params.h>
#include <kyber/polyvec.h>
#include "kem.h"

#define PQC_PAKE_TEMPO_len_lambda 24
#define PQC_PAKE_TEMPO_len_password KYBER_SYMBYTES
#define PQC_PAKE_TEMPO_len_seed KYBER_SYMBYTES
#define PQC_PAKE_TEMPO_len_public_key KYBER_PUBLICKEYBYTES
#define PQC_PAKE_TEMPO_len_secret_key KYBER_SECRETKEYBYTES
#define PQC_PAKE_TEMPO_len_ciphertext KYBER_CIPHERTEXTBYTES
#define PQC_PAKE_TEMPO_len_tag (2 * PQC_PAKE_TEMPO_len_lambda)
#define PQC_PAKE_TEMPO_len_shared_secret PQC_PAKE_TEMPO_len_lambda

void PQC_PAKE_TEMPO_fls(polyvec *a, const uint8_t *seed);

typedef struct
{
    uint8_t u[3 * PQC_PAKE_TEMPO_len_lambda];
    uint8_t v[KYBER_POLYVECBYTES];
    uint8_t seed[KYBER_SYMBYTES];
} PQC_PAKE_TEMPO_apk;

typedef struct
{
    uint64_t sid;
    uint64_t a;
    uint64_t b;
} PQC_PAKE_TEMPO_fsid;

typedef struct
{
    PQC_PAKE_TEMPO_fsid fsid;
    const uint8_t *password;
} PQC_PAKE_TEMPO_session;

void PQC_PAKE_TEMPO_keygen(
    uint8_t *public_key,
    uint8_t *secret_key,
    PQC_PAKE_TEMPO_apk *apk,
    const PQC_PAKE_TEMPO_session sess);

void PQC_PAKE_TEMPO_encaps(
    uint8_t *ciphertext,
    uint8_t *tag,
    uint8_t *shared_secret,
    const PQC_PAKE_TEMPO_session sess,
    const PQC_PAKE_TEMPO_apk *apk);

void PQC_PAKE_TEMPO_decaps(
    uint8_t *shared_secret,
    const PQC_PAKE_TEMPO_session sess,
    const PQC_PAKE_TEMPO_apk *apk,
    const uint8_t *ciphertext,
    const uint8_t *tag,
    const uint8_t *public_key,
    const uint8_t *secret_key);

#endif
