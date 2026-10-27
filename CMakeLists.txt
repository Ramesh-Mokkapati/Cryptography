# CMake build for crypto_wrapper (static library), crypto_samples and crypto_tests.
# Windows: configure with a preset from CMakePresets.json (OpenSSL comes from vcpkg.json).
# Linux/macOS: install libssl-dev (or Homebrew openssl) and run `cmake ..` as in the runbook.
#
# 3.10 is the minimum from the runbook; the policy range opts into current behaviour on newer CMake.
cmake_minimum_required(VERSION 3.10...3.31)
project(CryptoWrapper VERSION 1.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)   # -std=c++11, not gnu++11

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Find OpenSSL (1.1.1 or 3.x). On Windows it comes from vcpkg (see vcpkg.json / CMakePresets.json).
find_package(OpenSSL 1.1.1 REQUIRED)
message(STATUS "OpenSSL ${OPENSSL_VERSION}: ${OPENSSL_CRYPTO_LIBRARY}")

if(MSVC)
    set(CRYPTO_WARNINGS /W4 /permissive- /utf-8)
else()
    set(CRYPTO_WARNINGS -Wall -Wextra -Wpedantic -Wconversion -Wno-sign-conversion)
endif()

# Library Source Files
set(LIB_SOURCES
    src/AES.cpp
    src/RSA.cpp
    src/ECDSA.cpp
    src/KDF.cpp
    src/Random.cpp
    src/HMAC.cpp
    src/SHA.cpp
    src/Internal.cpp
)

# Build Static Library: libcrypto_wrapper.a (GCC/Clang) or crypto_wrapper.lib (MSVC)
add_library(crypto_wrapper STATIC ${LIB_SOURCES})
target_include_directories(crypto_wrapper
    PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(crypto_wrapper PRIVATE OpenSSL::Crypto)
target_compile_options(crypto_wrapper PRIVATE ${CRYPTO_WARNINGS})

# Build Samples Executable
add_executable(crypto_samples samples/main.cpp)
target_link_libraries(crypto_samples PRIVATE crypto_wrapper OpenSSL::Crypto)
target_compile_options(crypto_samples PRIVATE ${CRYPTO_WARNINGS})

# Known-answer and negative tests
option(CRYPTO_BUILD_TESTS "Build crypto_tests and register them with CTest" ON)
if(CRYPTO_BUILD_TESTS)
    enable_testing()
    add_executable(crypto_tests tests/crypto_tests.cpp)
    target_link_libraries(crypto_tests PRIVATE crypto_wrapper OpenSSL::Crypto)
    target_compile_options(crypto_tests PRIVATE ${CRYPTO_WARNINGS})
    add_test(NAME crypto_tests COMMAND crypto_tests)
    add_test(NAME crypto_samples COMMAND crypto_samples)
endif()

# `cmake --install` lays out lib/ + include/crypto/ for consumers.
install(TARGETS crypto_wrapper ARCHIVE DESTINATION lib)
install(DIRECTORY include/crypto DESTINATION include)
