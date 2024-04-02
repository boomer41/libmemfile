cmake_minimum_required(VERSION 3.10)
project(libmemfile
        VERSION 0.1
        DESCRIPTION "Library to help with memory allocations backed by files"
)

# option() honors normal variables.
cmake_policy(SET CMP0077 NEW)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 20)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if (NOT (MEMFILE_LIBNAME))
    set(MEMFILE_LIBNAME "memfile")
endif()

get_directory_property(HAS_PARENT PARENT_DIRECTORY)
if (HAS_PARENT)
    message(STATUS "libmemfile: Detected build as submodule")
    set(MEMFILE_OPTDEF_SUBMODULE_ON ON)
    set(MEMFILE_OPTDEF_SUBMODULE_OFF OFF)
else()
    set(MEMFILE_OPTDEF_SUBMODULE_ON OFF)
    set(MEMFILE_OPTDEF_SUBMODULE_OFF ON)
endif()

option(MEMFILE_SHARED "Whether to build the library as a shared library (else static)" ON)
option(MEMFILE_GENERATE_PKGCONFIG "Whether to generate the appropriate pkgconfig files." ${MEMFILE_OPTDEF_SUBMODULE_OFF})
option(MEMFILE_INSTALL_HEADERS "Whether to install the public headers." ${MEMFILE_OPTDEF_SUBMODULE_OFF})
option(MEMFILE_ENABLE_EXAMPLES "Whether to enable the examples." ${MEMFILE_OPTDEF_SUBMODULE_OFF})
option(MEMFILE_DISABLE_LOCKS "Whether to disable the multithreading locks." OFF)

add_subdirectory(lib)

if (${MEMFILE_ENABLE_EXAMPLES})
    add_subdirectory(examples)
endif()
