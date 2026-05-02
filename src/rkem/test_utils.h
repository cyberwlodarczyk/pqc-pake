#ifndef RKEM_TEST_UTILS_H
#define RKEM_TEST_UTILS_H

#include "poly.h"

void center_coeff(int16_t *a);

void poly_rand(poly *p);

void poly_rand_centered(poly *p);

int poly_compare(const poly *p1, const poly *p2);

int compression_check(int16_t a, int16_t b, int d);

#endif
