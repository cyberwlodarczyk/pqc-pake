#ifndef KYBER_H
#define KYBER_H

#include <stdint.h>
#include "params.h"

void KYBER_keygen_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);

void KYBER_keygen(uint8_t *pk, uint8_t *sk);

void KYBER_encaps_derand(
    uint8_t *ct,
    uint8_t *ss,
    const uint8_t *pk,
    const uint8_t *coins);

void KYBER_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);

void KYBER_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif
