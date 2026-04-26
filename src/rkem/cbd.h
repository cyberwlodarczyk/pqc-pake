#ifndef RKEM_CBD_H
#define RKEM_CBD_H

#include <stdint.h>
#include "params.h"
#include "poly.h"

void poly_cbd_eta1(poly *r, const uint8_t buf[RKEM_ETA1 * RKEM_N / 4]);

void poly_cbd_eta2(poly *r, const uint8_t buf[RKEM_ETA2 * RKEM_N / 4]);

void poly_cbd_eta3(poly *r, const uint8_t buf[RKEM_ETA3 * RKEM_N / 4]);

#endif
