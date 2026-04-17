#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pqc-pake/kem.h>

int test_exchange()
{
    uint8_t public_key_1[PQC_PAKE_KEM_len_public_key];
    uint8_t secret_key[PQC_PAKE_KEM_len_secret_key];
    PQC_PAKE_KEM_keygen(public_key_1, secret_key);
    uint8_t seed[PQC_PAKE_KEM_len_seed];
    uint8_t poly[PQC_PAKE_KEM_len_poly];
    PQC_PAKE_KEM_split(seed, poly, public_key_1);
    uint8_t public_key_2[PQC_PAKE_KEM_len_public_key];
    PQC_PAKE_KEM_join(public_key_2, seed, poly);
    uint8_t ciphertext[PQC_PAKE_KEM_len_ciphertext];
    uint8_t shared_secret_1[PQC_PAKE_KEM_len_shared_secret];
    PQC_PAKE_KEM_encaps(ciphertext, shared_secret_1, public_key_2);
    uint8_t shared_secret_2[PQC_PAKE_KEM_len_shared_secret];
    PQC_PAKE_KEM_decaps(shared_secret_2, ciphertext, secret_key);
    if (memcmp(
            shared_secret_1,
            shared_secret_2,
            PQC_PAKE_KEM_len_shared_secret) == 0)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

int main()
{
    for (int i = 0; i < 1000; i++)
    {
        if (!test_exchange())
        {
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}
