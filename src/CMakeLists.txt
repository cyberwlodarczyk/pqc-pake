cmake_minimum_required(VERSION 3.22)

project(pqc-pake C)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_subdirectory(kyber)
add_subdirectory(rkem)
add_subdirectory(pqc-pake)