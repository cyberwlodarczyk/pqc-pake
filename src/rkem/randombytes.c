#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include "randombytes.h"

void randombytes(uint8_t *out, size_t outlen)
{
    ssize_t ret;
    while (outlen > 0)
    {
        ret = syscall(SYS_getrandom, out, outlen, 0);
        if (ret == -1 && errno == EINTR)
        {
            continue;
        }
        else if (ret == -1)
        {
            abort();
        }
        out += ret;
        outlen -= ret;
    }
}
