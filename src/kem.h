#ifndef PQC_PAKE_KEM_H
#define PQC_PAKE_KEM_H

#include <oqs/kem.h>

#define PQC_PAKE_KEM_alg_kyber_512 "kyber-512"
#define PQC_PAKE_KEM_alg_kyber_768 "kyber-768"
#define PQC_PAKE_KEM_alg_kyber_1024 "kyber-1024"

typedef struct
{
    const char *alg;
    const char *oqs_alg;
    OQS_KEM *oqs_kem;
    size_t len_public_key;
    size_t len_public_seed;
    size_t len_public_poly;
    size_t len_secret_key;
    size_t len_ciphertext;
    size_t len_shared_secret;
} PQC_PAKE_KEM;

PQC_PAKE_KEM *PQC_PAKE_KEM_new(const char *alg);

int PQC_PAKE_KEM_keygen(
    const PQC_PAKE_KEM *kem,
    uint8_t **public_key,
    uint8_t **secret_key);

int PQC_PAKE_KEM_encaps(
    const PQC_PAKE_KEM *kem,
    uint8_t **ciphertext,
    uint8_t **shared_secret,
    const uint8_t *public_key);

int PQC_PAKE_KEM_decaps(
    const PQC_PAKE_KEM *kem,
    uint8_t **shared_secret,
    const uint8_t *ciphertext,
    const uint8_t *secret_key);

int PQC_PAKE_KEM_split(
    const PQC_PAKE_KEM *kem,
    uint8_t **seed,
    uint8_t **poly,
    const uint8_t *public_key);

int PQC_PAKE_KEM_join(
    const PQC_PAKE_KEM *kem,
    uint8_t **public_key,
    const uint8_t *seed,
    const uint8_t *poly);

void PQC_PAKE_KEM_free(PQC_PAKE_KEM *kem);

#endif
