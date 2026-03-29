cmake_minimum_required(VERSION 3.28)

project(pqc-pakes C)

add_library(pqc-pakes SHARED)

set(CMAKE_INSTALL_PREFIX $ENV{PQC_PAKES_DIR})

target_sources(
    pqc-pakes
    PRIVATE
        src/test.c
    PUBLIC
        FILE_SET HEADERS
        BASE_DIRS
            src
        FILES
            src/test.h
)

install(
    TARGETS pqc-pakes
    FILE_SET HEADERS
        DESTINATION include/pqc-pakes
)