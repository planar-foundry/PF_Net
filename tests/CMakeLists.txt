add_executable(PF_Net_UnitTests
    unittests/Test_Address.cpp
    unittests/Test_Host.cpp
    unittests/Test_HostFrameBuffer.cpp
    unittests/Test_NetworkByteStream.cpp
    unittests/Test_Protocol.cpp
    unittests/Test_Protocol_Fuzz.cpp
    unittests/Test_Socket.cpp
    unittests/UnitTest.cpp unittests/UnitTest.hpp)

target_link_libraries(PF_Net_UnitTests PF_Debug PF_Net PF_Test)

target_compile_options(PF_Net_UnitTests PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/W4>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -pedantic>)

add_custom_command(TARGET PF_Net_UnitTests POST_BUILD 
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    $<TARGET_FILE:sodium>
    $<TARGET_FILE:PF_Debug>
    $<TARGET_FILE:PF_Net>
    $<TARGET_FILE_DIR:PF_Net_UnitTests>)
