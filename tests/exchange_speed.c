// gcc $CFLAGS $LDFLAGS -o exchange_speed exchange_speed.c exchange.c test.c -lpqc-pake -lrkem -lkyber -lcrypto

#include <stdlib.h>
#include "exchange.h"
#include "test.h"

int main()
{
    test_speed("kyber", exchange_kyber);
    test_speed("rkem", exchange_rkem);
    test_speed("xrkem", exchange_xrkem);
    test_speed("yrkem", exchange_yrkem);
    test_speed("nice_pake_correct", exchange_nice_pake_correct);
    test_speed("nice_pake_incorrect", exchange_nice_pake_incorrect);
    test_speed("nice_pake_re_correct", exchange_nice_pake_re_correct);
    test_speed("nice_pake_re_incorrect", exchange_nice_pake_re_incorrect);
    test_speed("tempo_correct", exchange_tempo_correct);
    test_speed("tempo_incorrect", exchange_tempo_incorrect);
    test_speed("tempo_re_correct", exchange_tempo_re_correct);
    test_speed("tempo_re_incorrect", exchange_tempo_re_incorrect);
    return EXIT_SUCCESS;
}
