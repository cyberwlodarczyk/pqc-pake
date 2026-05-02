// gcc $CFLAGS $LDFLAGS -o exchange_speed exchange_speed.c exchange.c -lpqc-pake -lrkem -lkyber -lcrypto

#define _POSIX_C_SOURCE 199309L
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "exchange.h"

#define ROUNDS 1000

uint64_t time_ns()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

void run_exchange(const char *name, int t())
{
    printf("%s: ", name);
    fflush(stdout);
    uint64_t start = time_ns();
    for (int i = 0; i < ROUNDS; i++)
    {
        t();
    }
    uint64_t end = time_ns();
    uint64_t avg = (end - start) / ROUNDS;
    printf("%.3fµs\n", (double)avg / 1000);
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
    return EXIT_SUCCESS;
}
