// gcc $CFLAGS $LDFLAGS -o exchange_speed exchange_speed.c exchange.c test.c -lpqc-pake -lrkem -lkyber -lcrypto

#include <stdlib.h>
#include "exchange.h"
#include "test.h"

#define ROUNDS 1000

int main()
{
    test_speed("kyber", exchange_kyber, ROUNDS);
    test_speed("rkem", exchange_rkem, ROUNDS);
    test_speed("xrkem", exchange_xrkem, ROUNDS);
    test_speed("xrkem_derand", exchange_xrkem_derand, ROUNDS);
    test_speed("nice_pake_correct", exchange_nice_pake_correct, ROUNDS);
    test_speed("nice_pake_incorrect", exchange_nice_pake_incorrect, ROUNDS);
    test_speed("nice_pake_re_correct", exchange_nice_pake_re_correct, ROUNDS);
    test_speed("nice_pake_re_incorrect", exchange_nice_pake_re_incorrect, ROUNDS);
    test_speed("tempo_correct", exchange_tempo_correct, ROUNDS);
    test_speed("tempo_incorrect", exchange_tempo_incorrect, ROUNDS);
    test_speed("tempo_re_correct", exchange_tempo_re_correct, ROUNDS);
    test_speed("tempo_re_incorrect", exchange_tempo_re_incorrect, ROUNDS);
    return EXIT_SUCCESS;
}
