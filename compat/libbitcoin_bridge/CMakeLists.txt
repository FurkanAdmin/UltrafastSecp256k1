cmake_minimum_required(VERSION 3.18)
project(ufsecp_libbitcoin_bridge LANGUAGES CXX)

# UltrafastSecp256k1 ⇄ libbitcoin acceleration bridge.
#
# Two build modes:
#   A) Integrated: added via add_subdirectory() under the engine build, where the
#      `fastsecp256k1` target exists. Links it directly.
#   B) Standalone: built on its own; locates an installed/!prebuilt `ufsecp`
#      library via UFSECP_LIBRARY / find_library and the engine headers via
#      UFSECP_INCLUDE_DIR.
#
# GPU acceleration is OFF by default (CPU-only consensus reference). Turn on with
# -DUFSECP_LBTC_WITH_GPU=ON when linking an engine library that exports the GPU
# ABI (ufsecp_gpu_*).

option(UFSECP_LBTC_WITH_GPU "Enable GPU dispatch (requires engine GPU ABI)" OFF)
option(UFSECP_LBTC_BUILD_TESTS "Build the bridge correctness test" ON)
option(UFSECP_LBTC_BUILD_EXAMPLE "Build the example harness" ON)

add_library(ufsecp_lbtc_bridge STATIC src/ufsecp_libbitcoin.cpp)
target_compile_features(ufsecp_lbtc_bridge PUBLIC cxx_std_17)
target_include_directories(ufsecp_lbtc_bridge PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Engine headers (ufsecp.h, ufsecp_gpu.h). Override with -DUFSECP_INCLUDE_DIR=...
if(NOT UFSECP_INCLUDE_DIR)
    set(UFSECP_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../include/ufsecp)
endif()
target_include_directories(ufsecp_lbtc_bridge PUBLIC ${UFSECP_INCLUDE_DIR})

if(UFSECP_LBTC_WITH_GPU)
    target_compile_definitions(ufsecp_lbtc_bridge PUBLIC UFSECP_LBTC_WITH_GPU)
endif()

# Link the engine.
if(TARGET fastsecp256k1)
    target_link_libraries(ufsecp_lbtc_bridge PUBLIC fastsecp256k1)        # mode A
elseif(TARGET secp256k1_fast)
    target_link_libraries(ufsecp_lbtc_bridge PUBLIC secp256k1_fast)       # mode A
else()
    find_library(UFSECP_LIBRARY NAMES ufsecp                              # mode B
        HINTS ${UFSECP_LIB_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/../../out)
    if(UFSECP_LIBRARY)
        target_link_libraries(ufsecp_lbtc_bridge PUBLIC ${UFSECP_LIBRARY})
    else()
        message(WARNING
            "ufsecp_lbtc_bridge: no engine target/library found. "
            "Set -DUFSECP_LIBRARY=/path/to/libufsecp.so or build under the engine.")
    endif()
endif()

if(UFSECP_LBTC_BUILD_TESTS)
    enable_testing()
    add_executable(test_lbtc_bridge tests/test_lbtc_bridge.cpp)
    target_link_libraries(test_lbtc_bridge PRIVATE ufsecp_lbtc_bridge)
    add_test(NAME lbtc_bridge COMMAND test_lbtc_bridge)
endif()

if(UFSECP_LBTC_BUILD_EXAMPLE)
    add_executable(lbtc_batch_demo example/lbtc_batch_demo.cpp)
    target_link_libraries(lbtc_batch_demo PRIVATE ufsecp_lbtc_bridge)
endif()
