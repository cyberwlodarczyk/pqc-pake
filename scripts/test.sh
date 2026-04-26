#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <test>"
    exit 2
fi

mkdir -p bin
gcc $CFLAGS $LDFLAGS -o "bin/$1" "tests/$1.c" -lpqc-pake -lcrypto -lrkem
exec "bin/$1"
