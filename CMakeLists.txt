cmake_minimum_required(VERSION 3.20)
project(post-quantum-kem-benchmarker
    VERSION 1.0.0
    DESCRIPTION "Reference C++20 NIST FIPS 203 ML-KEM Benchmarker and Exploration Suite"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Werror -pedantic -Wconversion -Wsign-conversion -O3)
endif()

# Core Cryptographic Library
add_library(kem_core STATIC
    src/reduce.cpp
    src/ntt.cpp
    src/poly.cpp
    src/polyvec.cpp
    src/fips202.cpp
    src/cbd.cpp
    src/indcpa.cpp
)

target_include_directories(kem_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# CLI Binary
add_executable(kem_benchmarker src/main.cpp)
target_link_libraries(kem_benchmarker PRIVATE kem_core)

# Standalone Microbenchmark Binary
add_executable(benchmark_kem benchmarks/benchmark_kem.cpp)
target_link_libraries(benchmark_kem PRIVATE kem_core)

# Unit & Verification Tests
enable_testing()

set(TEST_SOURCES
    test_fips202
    test_reduce_ntt
    test_poly
    test_mlkem_roundtrip
)

foreach(TEST_NAME ${TEST_SOURCES})
    add_executable(${TEST_NAME} tests/${TEST_NAME}.cpp)
    target_link_libraries(${TEST_NAME} PRIVATE kem_core)
    target_compile_options(${TEST_NAME} PRIVATE -UNDEBUG)
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
endforeach()

# Installation
include(GNUInstallDirs)
install(TARGETS kem_core kem_benchmarker
    EXPORT kemTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(DIRECTORY include/kem DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
