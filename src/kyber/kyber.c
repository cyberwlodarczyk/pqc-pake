#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "params.h"
#include "kyber.h"
#include "indcpa.h"
#include "verify.h"
#include "symmetric.h"
#include "randombytes.h"

void KYBER_keygen_derand(
	uint8_t *pk,
	uint8_t *sk,
	const uint8_t *coins)
{
	KYBER_indcpa_keygen_derand(pk, sk, coins);
	memcpy(sk + KYBER_INDCPA_LEN_SECRET_KEY, pk, KYBER_LEN_PUBLIC_KEY);
	KYBER_hash_h(sk + KYBER_LEN_SECRET_KEY - 2 * KYBER_LEN_SEED, pk, KYBER_LEN_PUBLIC_KEY);
	memcpy(sk + KYBER_LEN_SECRET_KEY - KYBER_LEN_SEED, coins + KYBER_LEN_SEED, KYBER_LEN_SEED);
}

void KYBER_keygen(uint8_t *pk, uint8_t *sk)
{
	uint8_t coins[2 * KYBER_LEN_SEED];
	KYBER_randombytes(coins, 2 * KYBER_LEN_SEED);
	KYBER_keygen_derand(pk, sk, coins);
}

void KYBER_encaps_derand(
	uint8_t *ct,
	uint8_t *ss,
	const uint8_t *pk,
	const uint8_t *coins)
{
	uint8_t buf[2 * KYBER_LEN_SEED];
	uint8_t kr[2 * KYBER_LEN_SEED];
	memcpy(buf, coins, KYBER_LEN_SEED);
	KYBER_hash_h(buf + KYBER_LEN_SEED, pk, KYBER_LEN_PUBLIC_KEY);
	KYBER_hash_g(kr, buf, 2 * KYBER_LEN_SEED);
	KYBER_indcpa_encaps(ct, buf, pk, kr + KYBER_LEN_SEED);
	memcpy(ss, kr, KYBER_LEN_SEED);
}

void KYBER_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
	uint8_t coins[KYBER_LEN_SEED];
	KYBER_randombytes(coins, KYBER_LEN_SEED);
	KYBER_encaps_derand(ct, ss, pk, coins);
}

void KYBER_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
	int fail;
	uint8_t buf[2 * KYBER_LEN_SEED];
	uint8_t kr[2 * KYBER_LEN_SEED];
	uint8_t cmp[KYBER_LEN_CIPHERTEXT];
	const uint8_t *pk = sk + KYBER_INDCPA_LEN_SECRET_KEY;
	KYBER_indcpa_decaps(buf, ct, sk);
	memcpy(buf + KYBER_LEN_SEED, sk + KYBER_LEN_SECRET_KEY - 2 * KYBER_LEN_SEED, KYBER_LEN_SEED);
	KYBER_hash_g(kr, buf, 2 * KYBER_LEN_SEED);
	KYBER_indcpa_encaps(cmp, buf, pk, kr + KYBER_LEN_SEED);
	fail = KYBER_verify(ct, cmp, KYBER_LEN_CIPHERTEXT);
	KYBER_rkprf(ss, sk + KYBER_LEN_SECRET_KEY - KYBER_LEN_SEED, ct);
	KYBER_cmov(ss, kr, KYBER_LEN_SEED, !fail);
}
