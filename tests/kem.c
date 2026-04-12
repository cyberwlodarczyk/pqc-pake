#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>
#include <pqc-pake/kem.h>

int main()
{
    PQC_PAKE_KEM *kem = PQC_PAKE_KEM_new(PQC_PAKE_KEM_alg_kyber_768);
    if (kem == NULL)
    {
        return EXIT_FAILURE;
    }
    uint8_t *public_key = NULL;
    uint8_t *secret_key = NULL;
    if (!PQC_PAKE_KEM_keygen(kem, &public_key, &secret_key))
    {
        PQC_PAKE_KEM_free(kem);
        return EXIT_FAILURE;
    }
    uint8_t *seed = NULL;
    uint8_t *poly = NULL;
    if (!PQC_PAKE_KEM_split(kem, &seed, &poly, public_key))
    {
        OQS_MEM_secure_free(public_key, kem->len_public_key);
        OQS_MEM_secure_free(secret_key, kem->len_secret_key);
        PQC_PAKE_KEM_free(kem);
        return EXIT_FAILURE;
    }
    OQS_MEM_secure_free(public_key, kem->len_public_key);
    public_key = NULL;
    if (!PQC_PAKE_KEM_join(kem, &public_key, seed, poly))
    {
        OQS_MEM_secure_free(seed, kem->len_public_seed);
        OQS_MEM_secure_free(poly, kem->len_public_poly);
        OQS_MEM_secure_free(secret_key, kem->len_secret_key);
        PQC_PAKE_KEM_free(kem);
        return EXIT_FAILURE;
    }
    OQS_MEM_secure_free(seed, kem->len_public_seed);
    seed = NULL;
    OQS_MEM_secure_free(poly, kem->len_public_poly);
    poly = NULL;
    uint8_t *ciphertext = NULL;
    uint8_t *a_shared_secret = NULL;
    if (!PQC_PAKE_KEM_encaps(kem, &ciphertext, &a_shared_secret, public_key))
    {
        OQS_MEM_secure_free(public_key, kem->len_public_key);
        OQS_MEM_secure_free(secret_key, kem->len_secret_key);
        PQC_PAKE_KEM_free(kem);
        return EXIT_FAILURE;
    }
    OQS_MEM_secure_free(public_key, kem->len_public_key);
    public_key = NULL;
    uint8_t *b_shared_secret = NULL;
    if (!PQC_PAKE_KEM_decaps(kem, &b_shared_secret, ciphertext, secret_key))
    {
        OQS_MEM_secure_free(ciphertext, kem->len_ciphertext);
        OQS_MEM_secure_free(secret_key, kem->len_secret_key);
        OQS_MEM_secure_free(a_shared_secret, kem->len_shared_secret);
        PQC_PAKE_KEM_free(kem);
        return EXIT_FAILURE;
    }
    int cmp = memcmp(a_shared_secret, b_shared_secret, kem->len_shared_secret);
    OQS_MEM_secure_free(ciphertext, kem->len_ciphertext);
    OQS_MEM_secure_free(secret_key, kem->len_secret_key);
    OQS_MEM_secure_free(a_shared_secret, kem->len_shared_secret);
    OQS_MEM_secure_free(b_shared_secret, kem->len_shared_secret);
    PQC_PAKE_KEM_free(kem);
    if (cmp == 0)
    {
        return EXIT_SUCCESS;
    }
    else
    {
        return EXIT_FAILURE;
    }
}
