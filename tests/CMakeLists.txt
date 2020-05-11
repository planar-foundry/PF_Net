add_executable(PF_Net_UnitTests
    unittests/Test_Address.cpp
    unittests/Test_Host.cpp
    unittests/Test_HostFrameBuffer.cpp
    unittests/Test_NetworkByteStream.cpp
    unittests/Test_Protocol.cpp
    unittests/Test_Protocol_Fuzz.cpp
    unittests/Test_Socket.cpp
    unittests/UnitTest.cpp unittests/UnitTest.hpp)
target_link_libraries(PF_Net_UnitTests PF_Net PF_Test)

set_target_properties(PF_Net_UnitTests PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

if (MSVC)
    target_compile_definitions(PF_Net_UnitTests PRIVATE "_CRT_SECURE_NO_WARNINGS")
endif()
