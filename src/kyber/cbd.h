#ifndef KYBER_CBD_H
#define KYBER_CBD_H

#include "params.h"
#include "poly.h"

void KYBER_cbd_poly_eta1(
    KYBER_poly *r,
    const uint8_t buf[KYBER_ETA1 * KYBER_N / 4]);

void KYBER_cbd_poly_eta2(
    KYBER_poly *r,
    const uint8_t buf[KYBER_ETA2 * KYBER_N / 4]);

#endif
