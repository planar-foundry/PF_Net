cmake_minimum_required(VERSION 3.8)
project(PF_Net VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)

option(PFNET_BUILD_TESTS "Builds all unit tests" OFF)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
find_package(Sodium REQUIRED)

add_subdirectory(ext)
add_subdirectory(src)

if (${PFNET_BUILD_TESTS})
    add_subdirectory(tests)
endif()