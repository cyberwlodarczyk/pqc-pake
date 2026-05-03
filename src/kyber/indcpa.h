#ifndef KYBER_INDCPA_H
#define KYBER_INDCPA_H

#include <stdint.h>
#include "params.h"
#include "polyvec.h"

void KYBER_gen_matrix(
    KYBER_polyvec *a,
    const uint8_t seed[KYBER_LEN_SEED],
    int transposed);

void KYBER_indcpa_keygen_derand(
    uint8_t pk[KYBER_INDCPA_LEN_PUBLIC_KEY],
    uint8_t sk[KYBER_INDCPA_LEN_SECRET_KEY],
    const uint8_t coins[KYBER_LEN_SEED]);

void KYBER_indcpa_encaps(
    uint8_t c[KYBER_INDCPA_LEN_CIPHERTEXT],
    const uint8_t m[KYBER_INDCPA_LEN_MSG],
    const uint8_t pk[KYBER_INDCPA_LEN_PUBLIC_KEY],
    const uint8_t coins[KYBER_LEN_SEED]);

void KYBER_indcpa_decaps(
    uint8_t m[KYBER_INDCPA_LEN_MSG],
    const uint8_t c[KYBER_INDCPA_LEN_CIPHERTEXT],
    const uint8_t sk[KYBER_INDCPA_LEN_SECRET_KEY]);

#endif
