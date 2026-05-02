// gcc -o ntt_test ntt_test.c ntt.c reduce.c test_utils.c

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "ntt.h"
#include "params.h"
#include "reduce.h"
#include "test_utils.h"

#define TEST_N 1000000

int test_ntt()
{
    int16_t p1[128];
    for (int i = 0; i < 128; i++)
    {
        p1[i] = rand() % RKEM_Q;
        center_coeff(&p1[i]);
    }
    int16_t p2[128];
    memcpy(p2, p1, 256);
    ntt(p2);
    for (int i = 0; i < 128; i++)
    {
        p2[i] = barrett_reduce(p2[i]);
    }
    invntt(p2);
    for (int i = 0; i < 128; i++)
    {
        if (p1[i] != montgomery_reduce(p2[i]))
        {
            return 0;
        }
    }
    return 1;
}

int main()
{
    for (int i = 0; i < TEST_N; i++)
    {
        if (!test_ntt())
        {
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}
