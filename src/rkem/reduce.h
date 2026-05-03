#ifndef RKEM_REDUCE_H
#define RKEM_REDUCE_H

#include <stdint.h>

#define RKEM_MONT -3593 // 2^16 mod q
#define RKEM_QINV -7679 // q^-1 mod 2^16

int16_t RKEM_reduce_montgomery(int32_t a);

int16_t RKEM_reduce_barrett(int16_t a);

#endif
