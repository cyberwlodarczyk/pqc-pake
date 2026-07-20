#define _POSIX_C_SOURCE 199309L
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "test.h"

#define N 10000

int test_run(const char *name, int t())
{
    printf("%s: ", name);
    fflush(stdout);
    int f = 0;
    for (int i = 0; i < N; i++)
    {
        if (!t())
        {
            f++;
        }
    }
    if (f == 0)
    {
        printf("ok (%d/%d)\n", N, N);
        return 1;
    }
    else
    {
        printf("fail (%d/%d)\n", N - f, N);
        return 0;
    }
}

static uint64_t time_ns()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

void test_speed(const char *name, int t())
{
    printf("%s: ", name);
    fflush(stdout);
    uint64_t start = time_ns();
    for (int i = 0; i < N; i++)
    {
        t();
    }
    uint64_t end = time_ns();
    uint64_t avg = (end - start) / N;
    printf("%.3fµs\n", (double)avg / 1000);
}
