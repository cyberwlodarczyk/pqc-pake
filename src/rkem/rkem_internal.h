#ifndef RKEM_INTERNAL_H
#define RKEM_INTERNAL_H

#include <stdint.h>
#include "polyvec.h"
#include "params.h"

extern const polyvec RKEM_A[RKEM_K];

extern const polyvec RKEM_AT[RKEM_K];

void fls(polyvec *a, const uint8_t *seed, int transposed);

#endif
