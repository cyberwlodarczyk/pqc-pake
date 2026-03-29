#include <stdio.h>
#include <stdlib.h>
#include <oqs/oqs.h>

int main()
{
    OQS_init();
    printf("liboqs is ready!\n");
    OQS_destroy();
    return EXIT_SUCCESS;
}
