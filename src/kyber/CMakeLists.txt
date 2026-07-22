add_library(kyber STATIC
    cbd.c fips202.c indcpa.c kyber.c ntt.c poly.c polyvec.c randombytes.c
    reduce.c symmetric-shake.c verify.c
)

if(KYBER_SAMPLE_NTT_LOG_ITER)
    add_compile_definitions(KYBER_SAMPLE_NTT_LOG_ITER)
endif()

target_compile_options(kyber PRIVATE -Wall -Wextra -O3 -march=native)

target_include_directories(kyber
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
        $<INSTALL_INTERFACE:include/kyber>
)

install(TARGETS kyber
    ARCHIVE DESTINATION lib
    INCLUDES DESTINATION include/kyber
)

install(FILES
    cbd.h fips202.h indcpa.h kyber.h ntt.h params.h poly.h polyvec.h
    randombytes.h reduce.h symmetric.h verify.h
    DESTINATION include/kyber
)