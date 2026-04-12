#include <string.h>
#include <oqs/oqs.h>
#include <oqs/kem.h>
#include "kem.h"

PQC_PAKE_KEM *PQC_PAKE_KEM_new(const char *alg)
{
    PQC_PAKE_KEM *kem = OQS_MEM_malloc(sizeof(PQC_PAKE_KEM));
    if (kem == NULL)
    {
        return NULL;
    }
    if (strcmp(alg, PQC_PAKE_KEM_alg_kyber_512) == 0)
    {
        kem->alg = alg;
        kem->oqs_alg = OQS_KEM_alg_ml_kem_512;
    }
    else if (strcmp(alg, PQC_PAKE_KEM_alg_kyber_768) == 0)
    {
        kem->alg = alg;
        kem->oqs_alg = OQS_KEM_alg_ml_kem_768;
    }
    else if (strcmp(alg, PQC_PAKE_KEM_alg_kyber_1024) == 0)
    {
        kem->alg = alg;
        kem->oqs_alg = OQS_KEM_alg_ml_kem_1024;
    }
    else
    {
        OQS_MEM_secure_free(kem, sizeof(PQC_PAKE_KEM));
        return NULL;
    }
    OQS_KEM *oqs_kem = OQS_KEM_new(kem->oqs_alg);
    if (oqs_kem == NULL)
    {
        OQS_MEM_secure_free(kem, sizeof(PQC_PAKE_KEM));
        return NULL;
    }
    kem->oqs_kem = oqs_kem;
    kem->len_public_key = oqs_kem->length_public_key;
    kem->len_public_seed = 32;
    kem->len_public_poly = kem->len_public_key - kem->len_public_seed;
    kem->len_secret_key = oqs_kem->length_secret_key;
    kem->len_ciphertext = oqs_kem->length_ciphertext;
    kem->len_shared_secret = oqs_kem->length_shared_secret;
    return kem;
}

int PQC_PAKE_KEM_keygen(
    const PQC_PAKE_KEM *kem,
    uint8_t **public_key,
    uint8_t **secret_key)
{
    *public_key = OQS_MEM_malloc(kem->len_public_key);
    if (*public_key == NULL)
    {
        return 0;
    }
    *secret_key = OQS_MEM_malloc(kem->len_secret_key);
    if (*secret_key == NULL)
    {
        OQS_MEM_secure_free(*public_key, kem->len_public_key);
        return 0;
    }
    if (OQS_KEM_keypair(kem->oqs_kem, *public_key, *secret_key) !=
        OQS_SUCCESS)
    {
        OQS_MEM_secure_free(*public_key, kem->len_public_key);
        OQS_MEM_secure_free(*secret_key, kem->len_secret_key);
        return 0;
    }
    return 1;
}

int PQC_PAKE_KEM_encaps(
    const PQC_PAKE_KEM *kem,
    uint8_t **ciphertext,
    uint8_t **shared_secret,
    const uint8_t *public_key)
{
    *ciphertext = OQS_MEM_malloc(kem->len_ciphertext);
    if (*ciphertext == NULL)
    {
        return 0;
    }
    *shared_secret = OQS_MEM_malloc(kem->len_shared_secret);
    if (*shared_secret == NULL)
    {
        OQS_MEM_secure_free(*ciphertext, kem->len_ciphertext);
        return 0;
    }
    if (OQS_KEM_encaps(
            kem->oqs_kem,
            *ciphertext,
            *shared_secret,
            public_key) != OQS_SUCCESS)
    {
        OQS_MEM_secure_free(*ciphertext, kem->len_ciphertext);
        OQS_MEM_secure_free(
            *shared_secret,
            kem->len_shared_secret);
        return 0;
    }
    return 1;
}

int PQC_PAKE_KEM_decaps(
    const PQC_PAKE_KEM *kem,
    uint8_t **shared_secret,
    const uint8_t *ciphertext,
    const uint8_t *secret_key)
{
    *shared_secret = OQS_MEM_malloc(kem->len_shared_secret);
    if (*shared_secret == NULL)
    {
        return 0;
    }
    if (OQS_KEM_decaps(
            kem->oqs_kem,
            *shared_secret,
            ciphertext,
            secret_key) != OQS_SUCCESS)
    {
        return 0;
    }
    return 1;
}

int PQC_PAKE_KEM_split(
    const PQC_PAKE_KEM *kem,
    uint8_t **seed,
    uint8_t **poly,
    const uint8_t *public_key)
{
    *seed = OQS_MEM_malloc(kem->len_public_seed);
    if (*seed == NULL)
    {
        return 0;
    }
    *poly = OQS_MEM_malloc(kem->len_public_poly);
    if (*poly == NULL)
    {
        OQS_MEM_secure_free(*seed, kem->len_public_seed);
        return 0;
    }
    memcpy(*seed, public_key + kem->len_public_poly, kem->len_public_seed);
    memcpy(*poly, public_key, kem->len_public_poly);
    return 1;
}

int PQC_PAKE_KEM_join(
    const PQC_PAKE_KEM *kem,
    uint8_t **public_key,
    const uint8_t *seed,
    const uint8_t *poly)
{
    *public_key = OQS_MEM_malloc(kem->len_public_key);
    if (*public_key == NULL)
    {
        return 0;
    }
    memcpy(*public_key + kem->len_public_poly, seed, kem->len_public_seed);
    memcpy(*public_key, poly, kem->len_public_poly);
    return 1;
}

void PQC_PAKE_KEM_free(PQC_PAKE_KEM *kem)
{
    OQS_KEM_free(kem->oqs_kem);
    OQS_MEM_secure_free(kem, sizeof(PQC_PAKE_KEM));
}
