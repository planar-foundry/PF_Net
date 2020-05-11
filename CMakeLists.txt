cmake_minimum_required(VERSION 3.8)
project(PF_Net VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)

option(BUILD_SHARED_LIBS "Builds as a shared library")

option(PFNET_BUILD_TESTS "Builds all unit tests" OFF)
option(PFNET_ENABLE_ASSERTS "Enables asserts" ON)
option(PFNET_ENABLE_LOG "Enables logging" ON)
option(PFNET_ENABLE_DEBUG "Enables debug features" OFF)
option(PFNET_ENABLE_INSTRUMENTATION "Enables instrumentation" ON)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
find_package(Sodium REQUIRED)

add_subdirectory(ext)
add_subdirectory(src)

if (${PFNET_BUILD_TESTS})
    add_subdirectory(tests)
endif()