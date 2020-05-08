set(sources
    PF_Net/Address.cpp PF_Net/Address.hpp
    PF_Net/Endian.hpp
    PF_Net/Host.cpp PF_Net/Host.hpp
    PF_Net/Net.cpp PF_Net/Net.hpp
    PF_Net/NetworkByteStream.cpp PF_Net/NetworkByteStream.hpp

    PF_Net/Detail/Alloc.cpp PF_Net/Detail/Alloc.hpp
    PF_Net/Detail/Assert.hpp
    PF_Net/Detail/Host_impl.cpp PF_Net/Detail/Host_impl.hpp
    PF_Net/Detail/HostFrameBuffer.cpp PF_Net/Detail/HostFrameBuffer.hpp
    PF_Net/Detail/Instrumentation.hpp
    PF_Net/Detail/Log.cpp PF_Net/Detail/Log.hpp
    PF_Net/Detail/Protocol.cpp PF_Net/Detail/Protocol.hpp
    PF_Net/Detail/Socket.cpp PF_Net/Detail/Socket.hpp
    PF_Net/Detail/Util.cpp PF_Net/Detail/Util.hpp
)

add_library(PF_Net ${sources})
target_include_directories(PF_Net PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(PF_Net PRIVATE ${sodium_LIBRARIES})
target_include_directories(PF_Net PRIVATE ${sodium_INCLUDE_DIR})

add_custom_command(TARGET PF_Net POST_BUILD 
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    $<TARGET_FILE:sodium>              
    $<TARGET_FILE_DIR:PF_Net>)

if (MSVC)
    target_link_libraries(PF_Net PRIVATE wsock32 ws2_32)
    target_compile_options(PF_Net PRIVATE /W4 /permissive-)
    target_compile_definitions(PF_Net PRIVATE "_CRT_SECURE_NO_WARNINGS")

    if (${BUILD_SHARED_LIBS})
        target_compile_definitions(PF_Net PRIVATE   "PFNET_API=_declspec(dllexport)")
        target_compile_definitions(PF_Net INTERFACE "PFNET_API=_declspec(dllimport)")
    else()
        target_compile_definitions(PF_Net PUBLIC "PFNET_API=")
    endif()
else()
    target_compile_options(PF_Net PRIVATE -Wall -Wextra)

    # This is disabled because our assert and log macros invoke sprintf with the
    # format string in the macro. This is totally valid but the compiler whines.
    target_compile_options(PF_Net PRIVATE -Wno-format-security)

    target_compile_definitions(PF_Net PUBLIC "PFNET_API=")
endif()

INCLUDE(TestBigEndian)
TEST_BIG_ENDIAN(BIG_ENDIAN)
if (${BIG_ENDIAN})
    target_compile_definitions(PF_Net PUBLIC "PFNET_BIG_ENDIAN")
endif()

if (${PN_ENABLE_ASSERTS})
    target_compile_definitions(PF_Net PRIVATE "PFNET_ASSERTS_ENABLED")
endif()

if (${PN_ENABLE_LOG})
    target_compile_definitions(PF_Net PRIVATE "PFNET_LOG_ENABLED")
endif()

if (${PN_ENABLE_INSTRUMENTATION})
    target_compile_definitions(PF_Net PRIVATE "PFNET_INSTRUMENTATION_ENABLED")
endif()

if (${PN_ENABLE_DEBUG})
    target_compile_definitions(PF_Net PUBLIC "PFNET_DEBUG_ENABLED")
endif()
