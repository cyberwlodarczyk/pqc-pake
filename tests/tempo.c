// gcc $CFLAGS $LDFLAGS -o tempo tempo.c -lpqc-pake -lkyber -lcrypto

#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <pqc-pake/tempo.h>

#define TEST_N 10000

int test_exchange(const uint8_t *password1, const uint8_t *password2, int ok)
{
    uint8_t public_key[TEMPO_len_public_key];
    uint8_t secret_key[TEMPO_len_secret_key];
    TEMPO_apk apk;
    TEMPO_fsid fsid;
    fsid.sid = 100;
    fsid.a = 1;
    fsid.b = 2;
    TEMPO_session sess1;
    sess1.fsid = fsid;
    sess1.password = password1;
    TEMPO_keygen(public_key, secret_key, &apk, sess1);
    uint8_t ciphertext[TEMPO_len_ciphertext];
    uint8_t tag[TEMPO_len_tag];
    uint8_t shared_secret_1[TEMPO_len_shared_secret];
    TEMPO_session sess2;
    sess2.fsid = fsid;
    sess2.password = password2;
    TEMPO_encaps(ciphertext, tag, shared_secret_1, sess2, &apk);
    uint8_t shared_secret_2[TEMPO_len_shared_secret];
    TEMPO_decaps(
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
        TEMPO_len_shared_secret);
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
    uint8_t password[TEMPO_len_password];
    RAND_bytes(password, TEMPO_len_password);
    return test_exchange(password, password, 1);
}

int test_exchange_incorrect_password()
{
    uint8_t password1[TEMPO_len_password];
    RAND_bytes(password1, TEMPO_len_password);
    uint8_t password2[TEMPO_len_password];
    RAND_bytes(password2, TEMPO_len_password);
    return test_exchange(password1, password2, 0);
}

int main()
{
    for (int i = 0; i < TEST_N; i++)
    {
        if (!test_exchange_correct_password())
        {
            return EXIT_FAILURE;
        }
    }
    for (int i = 0; i < TEST_N; i++)
    {
        if (!test_exchange_incorrect_password())
        {
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}
