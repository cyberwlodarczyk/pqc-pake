#!/bin/bash

cd src/rkem
gcc $CFLAGS $LDFLAGS -o ntt_init ntt_init.c -lrkem -lcrypto -lkyber
./ntt_init
