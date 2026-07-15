# Standalone, dependency-free MITM wire recorder.
#
# Consumed two ways:
#   * the OSS `obn` plugin adds this dir and links `bbl_mitm_recorder` at its
#     network choke points (the source of the wire fixtures);
#   * the BambuStudio slicer, when -DBBL_MITM_LOGGING=ON, adds this dir for an
#     ABI-level cross-check tap.
#
# It has no external dependencies, so it also builds and self-tests on its own:
#   cmake -S . -B build && cmake --build build && ./build/wire_recorder_smoke

cmake_minimum_required(VERSION 3.13)
project(bbl_mitm_recorder CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(bbl_mitm_recorder STATIC wire_recorder.cpp)
target_include_directories(bbl_mitm_recorder PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Standalone smoke target: exercises every record_* entry point and asserts a
# session file was produced. Only built when this is the top-level project.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    add_executable(wire_recorder_smoke wire_recorder_smoke.cpp)
    target_link_libraries(wire_recorder_smoke PRIVATE bbl_mitm_recorder)
    enable_testing()
    add_test(NAME wire_recorder_smoke COMMAND wire_recorder_smoke)
endif()
