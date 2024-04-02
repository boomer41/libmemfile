function(memfile_add_example NAME SOURCES)
    add_executable(${MEMFILE_LIBNAME}-example-${NAME} ${SOURCES})
    target_link_libraries(${MEMFILE_LIBNAME}-example-${NAME} PRIVATE ${MEMFILE_LIBNAME})
endfunction()

memfile_add_example(simple-file simple-file.c)
