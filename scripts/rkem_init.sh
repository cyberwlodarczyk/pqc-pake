#!/bin/bash

cd src/rkem
gcc $CFLAGS $LDFLAGS -o rkem_init rkem_init.c -lrkem -lcrypto -lkyber
./rkem_init
