cmake_minimum_required(VERSION 3.8)
project(PF_Net VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

option(BUILD_SHARED_LIBS "Builds as a shared library")

# If you're reading this trying to figure out how to turn off
# debug stuff for retail builds, do this:
#   option(PN_ENABLE_ASSERTS "" OFF)
#   add_subdirectory(External/PF_Net)

option(PN_BUILD_TESTS "Builds all unit tests" ON)
option(PN_ENABLE_ASSERTS "Enables asserts" ON)
option(PN_ENABLE_LOG "Enables logging" ON)
option(PN_ENABLE_DEBUG "Enables debug features" ON)
option(PN_ENABLE_INSTRUMENTATION "Enables instrumentation" ON)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
find_package(Sodium REQUIRED)

add_subdirectory(src)

if (${PN_BUILD_TESTS})
    add_subdirectory(tests)
endif()