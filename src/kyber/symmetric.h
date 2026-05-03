#ifndef KYBER_SYMMETRIC_H
#define KYBER_SYMMETRIC_H

#include <stddef.h>
#include <stdint.h>
#include "params.h"
#include "fips202.h"

typedef keccak_state xof_state;

void KYBER_shake128_absorb(
    keccak_state *s,
    const uint8_t seed[KYBER_LEN_SEED],
    uint8_t x,
    uint8_t y);

void KYBER_shake256_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_LEN_SEED], uint8_t nonce);

void KYBER_shake256_rkprf(uint8_t out[KYBER_LEN_SHARED_SECRET], const uint8_t key[KYBER_LEN_SEED], const uint8_t input[KYBER_LEN_CIPHERTEXT]);

#define XOF_BLOCKBYTES SHAKE128_RATE

#define KYBER_hash_h(OUT, IN, INBYTES) sha3_256(OUT, IN, INBYTES)
#define KYBER_hash_g(OUT, IN, INBYTES) sha3_512(OUT, IN, INBYTES)
#define KYBER_xof_absorb(STATE, SEED, X, Y) KYBER_shake128_absorb(STATE, SEED, X, Y)
#define KYBER_xof_squeezeblocks(OUT, OUTBLOCKS, STATE) shake128_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define KYBER_prf(OUT, OUTBYTES, KEY, NONCE) KYBER_shake256_prf(OUT, OUTBYTES, KEY, NONCE)
#define KYBER_rkprf(OUT, KEY, INPUT) KYBER_shake256_rkprf(OUT, KEY, INPUT)

#endif
