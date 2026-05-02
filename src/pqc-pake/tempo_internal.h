#ifndef TEMPO_INTERNAL_H
#define TEMPO_INTERNAL_H

#include <stdint.h>
#include <kyber/polyvec.h>
#include "tempo.h"

void tempo_fls(polyvec *v, const uint8_t *seed);

#endif
