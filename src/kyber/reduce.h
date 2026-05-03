#ifndef KYBER_REDUCE_H
#define KYBER_REDUCE_H

#include <stdint.h>

#define KYBER_MONT -1044 // 2^16 mod q
#define KYBER_QINV -3327 // q^-1 mod 2^16

int16_t KYBER_reduce_montgomery(int32_t a);

int16_t KYBER_reduce_barrett(int16_t a);

#endif
