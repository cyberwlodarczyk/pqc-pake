#!/bin/bash

cmake -S src -B build $@ -DCMAKE_INSTALL_PREFIX="$PWD/dist"
cmake --build build
cmake --install build
