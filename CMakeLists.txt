# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 avwarez

cmake_minimum_required(VERSION 3.16)
# The version is written once, in include/natd/version.hpp.
file(STRINGS ${CMAKE_CURRENT_SOURCE_DIR}/include/natd/version.hpp NATD_VERSION_LINES
     REGEX "^#define NATD_VERSION_(MAJOR|MINOR|PATCH) ")
foreach(line ${NATD_VERSION_LINES})
    string(REGEX REPLACE "^#define NATD_VERSION_([A-Z]+) +([0-9]+).*" "\\1;\\2" kv "${line}")
    list(GET kv 0 k)
    list(GET kv 1 v)
    set(NATD_VERSION_${k} ${v})
endforeach()
project(natd VERSION ${NATD_VERSION_MAJOR}.${NATD_VERSION_MINOR}.${NATD_VERSION_PATCH} LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(natd STATIC
    src/types.cpp
    src/protocol.cpp
    src/reflector.cpp
    src/classify.cpp
    src/discovery.cpp
    src/punch.cpp
    src/stun.cpp
    src/agent.cpp
    src/version.cpp
    src/sha256.cpp
)
if(WIN32)
    target_sources(natd PRIVATE src/winsock_io.cpp)
    target_link_libraries(natd PUBLIC ws2_32 bcrypt)
else()
    target_sources(natd PRIVATE src/posix_io.cpp)
endif()
target_include_directories(natd PUBLIC include)
if(MSVC)
    target_compile_options(natd PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/W4>)
else()
    target_compile_options(natd PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-Wall -Wextra -Wshadow>)
endif()

option(NATD_EXAMPLES "Build example tools" ON)
if(NATD_EXAMPLES)
    add_executable(natd_reflector examples/natd_reflector.cpp)
    target_link_libraries(natd_reflector PRIVATE natd)
    add_executable(natd_probe examples/natd_probe.cpp)
    target_link_libraries(natd_probe PRIVATE natd)
    add_executable(natd_stunlist examples/natd_stunlist.cpp)
    target_link_libraries(natd_stunlist PRIVATE natd)
endif()

option(NATD_TESTS "Build tests" ON)

if(NATD_TESTS)
    enable_testing()
    add_executable(natd_tests tests/test_main.cpp)
    target_link_libraries(natd_tests PRIVATE natd)
    add_test(NAME natd_tests COMMAND natd_tests)
    add_executable(natd_io_tests tests/test_io.cpp)
    target_link_libraries(natd_io_tests PRIVATE natd)
    add_test(NAME natd_io_tests COMMAND natd_io_tests)
endif()

# Robustness against hostile datagrams (tests/fuzz_main.cpp). Build it with
# UBSan, e.g. -DCMAKE_CXX_FLAGS="-fsanitize=undefined -fno-sanitize-recover=undefined";
# the standard library's range checks are on for this target.
option(NATD_FUZZ "Build the fuzz driver" OFF)
if(NATD_FUZZ)
    add_executable(natd_fuzz tests/fuzz_main.cpp)
    target_link_libraries(natd_fuzz PRIVATE natd)
    target_compile_definitions(natd PRIVATE _GLIBCXX_ASSERTIONS)
    target_compile_definitions(natd_fuzz PRIVATE _GLIBCXX_ASSERTIONS)
endif()
