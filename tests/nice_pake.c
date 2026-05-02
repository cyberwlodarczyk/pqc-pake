// gcc $CFLAGS $LDFLAGS -o nice_pake nice_pake.c -lpqc-pake -lkyber -lcrypto

#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <pqc-pake/nice_pake.h>

#define TEST_N 10000

int test_exchange(const uint8_t *password1, const uint8_t *password2, int ok)
{
    uint8_t seed[NICE_PAKE_len_seed];
    uint8_t poly[NICE_PAKE_len_poly];
    uint8_t secret_key[NICE_PAKE_len_secret_key];
    NICE_PAKE_keygen(seed, poly, secret_key, password1);
    uint8_t ciphertext[NICE_PAKE_len_ciphertext];
    uint8_t shared_secret_1[NICE_PAKE_len_shared_secret];
    NICE_PAKE_encaps(ciphertext, shared_secret_1, seed, poly, password2);
    uint8_t shared_secret_2[NICE_PAKE_len_shared_secret];
    NICE_PAKE_decaps(shared_secret_2, ciphertext, secret_key);
    int cmp = memcmp(
        shared_secret_1,
        shared_secret_2,
        NICE_PAKE_len_shared_secret);
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
    uint8_t password[NICE_PAKE_len_password];
    RAND_bytes(password, NICE_PAKE_len_password);
    return test_exchange(password, password, 1);
}

int test_exchange_incorrect_password()
{
    uint8_t password1[NICE_PAKE_len_password];
    RAND_bytes(password1, NICE_PAKE_len_password);
    uint8_t password2[NICE_PAKE_len_password];
    RAND_bytes(password2, NICE_PAKE_len_password);
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
