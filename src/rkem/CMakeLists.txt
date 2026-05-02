add_library(rkem STATIC
    cbd.c
    ntt.c
    poly.c
    polyvec.c
    reduce.c
    rkem_internal.c
    rkem.c
)

target_link_libraries(rkem PUBLIC kyber)

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
    rkem.h
    DESTINATION include/rkem
)