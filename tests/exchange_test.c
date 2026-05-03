// gcc $CFLAGS $LDFLAGS -o exchange_test exchange_test.c exchange.c test.c -lpqc-pake -lrkem -lkyber -lcrypto

#include <stdlib.h>
#include <stdio.h>
#include "exchange.h"
#include "test.h"

#define ROUNDS 1000

int main()
{
    int ok = 1;
    ok = test_run("kyber", exchange_kyber, ROUNDS) && ok;
    ok = test_run("rkem", exchange_rkem, ROUNDS) && ok;
    ok = test_run("xrkem", exchange_xrkem, ROUNDS) && ok;
    ok = test_run("xrkem_derand", exchange_xrkem_derand, ROUNDS) && ok;
    ok = test_run("nice_pake_correct", exchange_nice_pake_correct, ROUNDS) && ok;
    ok = test_run("nice_pake_incorrect", exchange_nice_pake_incorrect, ROUNDS) && ok;
    ok = test_run("nice_pake_re_correct", exchange_nice_pake_re_correct, ROUNDS) && ok;
    ok = test_run("nice_pake_re_incorrect", exchange_nice_pake_re_incorrect, ROUNDS) && ok;
    ok = test_run("tempo_correct", exchange_tempo_correct, ROUNDS) && ok;
    ok = test_run("tempo_incorrect", exchange_tempo_incorrect, ROUNDS) && ok;
    ok = test_run("tempo_re_correct", exchange_tempo_re_correct, ROUNDS) && ok;
    ok = test_run("tempo_re_incorrect", exchange_tempo_re_incorrect, ROUNDS) && ok;
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
