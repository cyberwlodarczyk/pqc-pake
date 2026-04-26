#ifndef RKEM_REDUCE_H
#define RKEM_REDUCE_H

#include <stdint.h>
#include "params.h"

#define MONT -3593 // 2^16 mod q
#define QINV -7679 // q^-1 mod 2^16

int16_t montgomery_reduce(int32_t a);

int16_t barrett_reduce(int16_t a);

#endif
