cmake_minimum_required(VERSION 3.28)

project(pqc-pake C)

set(CMAKE_INSTALL_PREFIX $ENV{PQC_PAKE_DIR})
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_subdirectory(kyber)
add_subdirectory(rkem)
add_subdirectory(pqc-pake)