add_library(rkem STATIC
    cbd.c ntt.c poly.c polyvec.c reduce.c rkem.c xrkem.c yrkem.c
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
    cbd.h ntt.h params.h poly.h polyvec.h reduce.h rkem.h xrkem.h yrkem.h
    DESTINATION include/rkem
)