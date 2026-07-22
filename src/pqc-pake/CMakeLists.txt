add_library(pqc-pake STATIC
    nice_pake_re.c
    nice_pake.c
    tempo_re.c
    tempo.c
)

if(TEMPO_FLS_LOG_ITER)
    add_compile_definitions(TEMPO_FLS_LOG_ITER)
endif()

if(TEMPO_USE_FLSX)
    add_compile_definitions(TEMPO_USE_FLSX)
endif()

if(TEMPO_ENCAPS_FORCE_DUMMY)
    add_compile_definitions(TEMPO_ENCAPS_FORCE_DUMMY)
endif()

target_compile_options(pqc-pake PRIVATE -Wall -Wextra -O3 -march=native)

target_link_libraries(pqc-pake PUBLIC kyber)

target_include_directories(pqc-pake
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>
        $<INSTALL_INTERFACE:include/pqc-pake>
)

install(TARGETS pqc-pake
    LIBRARY DESTINATION lib
    INCLUDES DESTINATION include
)

install(FILES
    nice_pake_re.h nice_pake.h tempo_re.h tempo.h
    DESTINATION include/pqc-pake
)