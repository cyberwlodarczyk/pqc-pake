add_library(rkem SHARED
    cbd.c
    ntt.c
    poly.c
    polyvec.c
    randombytes.c
    rkem.c
    reduce.c
)

target_include_directories(rkem
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
        $<INSTALL_INTERFACE:include/rkem>
)

install(TARGETS rkem
    ARCHIVE DESTINATION lib
    INCLUDES DESTINATION include/rkem
)

install(FILES
    cbd.h ntt.h params.h poly.h polyvec.h
    randombytes.h reduce.h rkem.h
    DESTINATION include/rkem
)