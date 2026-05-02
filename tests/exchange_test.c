// gcc $CFLAGS $LDFLAGS -o exchange_test exchange_test.c exchange.c -lpqc-pake -lrkem -lkyber -lcrypto

#include <stdlib.h>
#include <stdio.h>
#include <openssl/rand.h>
#include <pqc-pake/nice_pake.h>
#include <pqc-pake/nice_pake_re.h>
#include <pqc-pake/tempo.h>
#include <pqc-pake/tempo_re.h>
#include <rkem/rkem.h>
#include <rkem/xrkem.h>
#include "exchange.h"

#define ROUNDS 1000

int ok = 1;

int run_exchange(const char *name, int t())
{
    printf("%s: ", name);
    fflush(stdout);
    for (int i = 0; i < ROUNDS; i++)
    {
        if (!t())
        {
            ok = 0;
            printf("fail\n");
            return 0;
        }
    }
    printf("ok\n");
    return 1;
}

int main()
{
    run_exchange("kyber", exchange_kyber);
    run_exchange("rkem", exchange_rkem);
    run_exchange("xrkem", exchange_xrkem);
    run_exchange("xrkem_derand", exchange_xrkem_derand);
    run_exchange("nice_pake_correct", exchange_nice_pake_correct);
    run_exchange("nice_pake_incorrect", exchange_nice_pake_incorrect);
    run_exchange("nice_pake_re_correct", exchange_nice_pake_re_correct);
    run_exchange("nice_pake_re_incorrect", exchange_nice_pake_re_incorrect);
    run_exchange("tempo_correct", exchange_tempo_correct);
    run_exchange("tempo_incorrect", exchange_tempo_incorrect);
    run_exchange("tempo_re_correct", exchange_tempo_re_correct);
    run_exchange("tempo_re_incorrect", exchange_tempo_re_incorrect);
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
