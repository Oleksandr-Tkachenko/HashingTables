cmake_minimum_required(VERSION 3.14)
cmake_policy(SET CMP0088 NEW)
project(HashingTables)

set(CMAKE_CXX_STANDARD 17)


# DEPENDENCIES

find_package(fmt QUIET)
if (fmt_FOUND)
    message(STATUS "Found fmt")
elseif (NOT fmt_FOUND AND NOT TARGET fmt::fmt)
    message("fmt was not found: add fmt subdirectory")
    if (NOT EXISTS "${PROJECT_SOURCE_DIR}/extern/fmt/CMakeLists.txt")
        find_package(Git REQUIRED)
        message("initialize Git submodule: extern/fmt")
        execute_process(COMMAND git submodule update --init extern/fmt
                WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")
    endif ()
    set(BUILD_SHARED_LIBS ON)
    set(FMT_TEST OFF)
    add_subdirectory(extern/fmt EXCLUDE_FROM_ALL)
endif ()


# LIBRARY

add_library(HashingTables STATIC
        cuckoo_hashing/cuckoo_hashing.cpp
        simple_hashing/simple_hashing.cpp
        )

target_include_directories(HashingTables PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR})

option(HASHING_TABLES_BUILD_TESTS OFF)
option(HASHING_TABLES_BUILD_EXE OFF)


# TESTS

if (HASHING_TABLES_BUILD_TESTS)
    if (NOT EXISTS "${PROJECT_SOURCE_DIR}/extern/googletest/CMakeLists.txt")
        find_package(Git REQUIRED)
        message("initialize Git submodule: extern/googletest")
        execute_process(COMMAND git submodule update --init extern/googletest
                WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")
    endif ()

    set(BUILD_GMOCK OFF)
    add_subdirectory(extern/googletest EXCLUDE_FROM_ALL)
    add_subdirectory(src/test)
endif (HASHING_TABLES_BUILD_TESTS)


# EXAMPLES

if (HASHING_TABLES_BUILD_EXE)
    add_subdirectory(src/examples)
endif (HASHING_TABLES_BUILD_EXE)