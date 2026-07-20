#ifndef TEST_H
#define TEST_H

#include <kyber/polyvec.h>

int matrix_compare(const KYBER_polyvec *a, const KYBER_polyvec *b);

int test_run(const char *name, int t());

void test_speed(const char *name, int t());

#endif
