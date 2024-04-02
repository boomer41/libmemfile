set(MEMFILE_PUBLIC_SRC
        include/memory_file.h
)

set(MEMFILE_SRC
        memory_file.c
)

if (MEMFILE_SHARED)
    set(MEMFILE_LIBRARY_MODE SHARED)
else()
    set(MEMFILE_LIBRARY_MODE STATIC)
endif()

add_library(${MEMFILE_LIBNAME} ${MEMFILE_LIBRARY_MODE} ${MEMFILE_SRC} ${MEMFILE_PUBLIC_SRC})
target_compile_definitions(${MEMFILE_LIBNAME} PRIVATE "-D_LARGEFILE64_SOURCE")

if (MEMFILE_DISABLE_LOCKS)
    target_compile_definitions(${MEMFILE_LIBNAME} PRIVATE "-DMEMFILE_NO_MUTEX")
endif()

# Set properties for public headers
target_include_directories(${MEMFILE_LIBNAME} PUBLIC include)
set_target_properties(${MEMFILE_LIBNAME} PROPERTIES
        PUBLIC_HEADER ${MEMFILE_PUBLIC_SRC}
)

# Install files
if (MEMFILE_GENERATE_PKGCONFIG)
    configure_file(libmemfile.pc.in lib${MEMFILE_LIBNAME}.pc @ONLY)
    install(
            FILES ${CMAKE_CURRENT_BINARY_DIR}/lib${MEMFILE_LIBNAME}.pc
            DESTINATION pkgconfig
    )
endif()

if (MEMFILE_INSTALL_HEADERS)
    install(TARGETS ${MEMFILE_LIBNAME}
            PUBLIC_HEADER DESTINATION include/${MEMFILE_LIBNAME}
    )
endif()
