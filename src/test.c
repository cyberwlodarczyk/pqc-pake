#include <stdio.h>
#include <oqs/oqs.h>
#include "test.h"

void test()
{
    OQS_init();
    printf("liboqs works!\n");
    OQS_destroy();
}
