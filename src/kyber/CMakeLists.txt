add_library(kyber STATIC
    cbd.c fips202.c indcpa.c kem.c ntt.c poly.c polyvec.c randombytes.c
    reduce.c symmetric-shake.c verify.c
)

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
    cbd.h fips202.h indcpa.h kem.h ntt.h params.h poly.h polyvec.h
    randombytes.h reduce.h symmetric.h verify.h
    DESTINATION include/kyber
)