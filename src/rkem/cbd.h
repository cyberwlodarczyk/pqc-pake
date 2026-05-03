#ifndef RKEM_CBD_H
#define RKEM_CBD_H

#include <stdint.h>
#include "params.h"
#include "poly.h"

void RKEM_cbd_poly_eta1(
    RKEM_poly *r,
    const uint8_t buf[RKEM_ETA1 * RKEM_N / 4]);

void RKEM_cbd_poly_eta2(
    RKEM_poly *r,
    const uint8_t buf[RKEM_ETA2 * RKEM_N / 4]);

void RKEM_cbd_poly_eta3(
    RKEM_poly *r,
    const uint8_t buf[RKEM_ETA3 * RKEM_N / 4]);

#endif
