// gcc $CFLAGS $LDFLAGS -o exchange_test exchange_test.c exchange.c test.c -lpqc-pake -lrkem -lkyber -lcrypto

#include <stdlib.h>
#include <stdio.h>
#include "exchange.h"
#include "test.h"

int main()
{
    int ok = 1;
    ok = test_run("kyber", exchange_kyber) && ok;
    ok = test_run("rkem", exchange_rkem) && ok;
    ok = test_run("xrkem", exchange_xrkem) && ok;
    ok = test_run("yrkem", exchange_yrkem) && ok;
    ok = test_run("nice_pake_correct", exchange_nice_pake_correct) && ok;
    ok = test_run("nice_pake_incorrect", exchange_nice_pake_incorrect) && ok;
    ok = test_run("nice_pake_re_correct", exchange_nice_pake_re_correct) && ok;
    ok = test_run("nice_pake_re_incorrect", exchange_nice_pake_re_incorrect) && ok;
    ok = test_run("tempo_correct", exchange_tempo_correct) && ok;
    ok = test_run("tempo_incorrect", exchange_tempo_incorrect) && ok;
    ok = test_run("tempo_re_correct", exchange_tempo_re_correct) && ok;
    ok = test_run("tempo_re_incorrect", exchange_tempo_re_incorrect) && ok;
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
