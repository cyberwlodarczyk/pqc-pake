#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <kyber/polyvec.h>
#include <kyber/indcpa.h>
#include <pqc-pake/tempo.h>

int polyvec_compare(polyvec *v1, polyvec *v2)
{
    for (int i = 0; i < KYBER_K; i++)
    {
        for (int j = 0; j < KYBER_N; j++)
        {
            if (v1->vec[i].coeffs[j] != v2->vec[i].coeffs[j])
            {
                return 0;
            }
        }
    }
    return 1;
}

int test_fls()
{
    uint8_t seed[KYBER_SYMBYTES];
    RAND_bytes(seed, KYBER_SYMBYTES);
    polyvec a1[KYBER_K];
    gen_matrix(a1, seed, 0);
    polyvec a2;
    PQC_PAKE_TEMPO_fls(&a2, seed);
    return polyvec_compare(a1, &a2);
}

int test_exchange(const uint8_t *password1, const uint8_t *password2, int ok)
{
    uint8_t public_key[PQC_PAKE_TEMPO_len_public_key];
    uint8_t secret_key[PQC_PAKE_TEMPO_len_secret_key];
    PQC_PAKE_TEMPO_apk apk;
    PQC_PAKE_TEMPO_fsid fsid;
    fsid.sid = 100;
    fsid.a = 1;
    fsid.b = 2;
    PQC_PAKE_TEMPO_session sess1;
    sess1.fsid = fsid;
    sess1.password = password1;
    PQC_PAKE_TEMPO_keygen(public_key, secret_key, &apk, sess1);
    uint8_t ciphertext[PQC_PAKE_TEMPO_len_ciphertext];
    uint8_t tag[PQC_PAKE_TEMPO_len_tag];
    uint8_t shared_secret_1[PQC_PAKE_TEMPO_len_shared_secret];
    PQC_PAKE_TEMPO_session sess2;
    sess2.fsid = fsid;
    sess2.password = password2;
    PQC_PAKE_TEMPO_encaps(ciphertext, tag, shared_secret_1, sess2, &apk);
    uint8_t shared_secret_2[PQC_PAKE_TEMPO_len_shared_secret];
    PQC_PAKE_TEMPO_decaps(
        shared_secret_2,
        sess1,
        &apk,
        ciphertext,
        tag,
        public_key,
        secret_key);
    int cmp = memcmp(
        shared_secret_1,
        shared_secret_2,
        PQC_PAKE_TEMPO_len_shared_secret);
    if ((ok && cmp == 0) || (!ok && cmp != 0))
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

int test_exchange_correct_password()
{
    uint8_t password[PQC_PAKE_TEMPO_len_password];
    RAND_bytes(password, PQC_PAKE_TEMPO_len_password);
    return test_exchange(password, password, 1);
}

int test_exchange_incorrect_password()
{
    uint8_t password1[PQC_PAKE_TEMPO_len_password];
    RAND_bytes(password1, PQC_PAKE_TEMPO_len_password);
    uint8_t password2[PQC_PAKE_TEMPO_len_password];
    RAND_bytes(password2, PQC_PAKE_TEMPO_len_password);
    return test_exchange(password1, password2, 0);
}

int main()
{
    for (int i = 0; i < 1000; i++)
    {
        if (!test_fls())
        {
            return EXIT_FAILURE;
        }
    }
    for (int i = 0; i < 1000; i++)
    {
        if (!test_exchange_correct_password())
        {
            return EXIT_FAILURE;
        }
    }
    for (int i = 0; i < 1000; i++)
    {
        if (!test_exchange_incorrect_password())
        {
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}
