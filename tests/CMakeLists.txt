add_executable(UnitTests
    unittests/Test_Address.cpp
    unittests/Test_Endian.cpp
    unittests/Test_Host.cpp
    unittests/Test_HostFrameBuffer.cpp
    unittests/Test_NetworkByteStream.cpp
    unittests/Test_Protocol.cpp
    unittests/Test_Protocol_Fuzz.cpp
    unittests/Test_Socket.cpp
    unittests/UnitTest.cpp unittests/UnitTest.hpp)
target_link_libraries(UnitTests PF_Net)

if (MSVC)
    target_compile_definitions(UnitTests PRIVATE "_CRT_SECURE_NO_WARNINGS")
else()
    set(THREADS_PREFER_PTHREAD_FLAG ON)
    find_package(Threads REQUIRED)
    target_link_libraries(UnitTests Threads::Threads)
endif()
