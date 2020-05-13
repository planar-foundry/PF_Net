set(sources
    PF_Net/Address.cpp PF_Net/Address.hpp
    PF_Net/Host.cpp PF_Net/Host.hpp
    PF_Net/Net.cpp PF_Net/Net.hpp
    PF_Net/NetworkByteStream.cpp PF_Net/NetworkByteStream.hpp

    PF_Net/Detail/Alloc.cpp PF_Net/Detail/Alloc.hpp
    PF_Net/Detail/Host_impl.cpp PF_Net/Detail/Host_impl.hpp
    PF_Net/Detail/HostFrameBuffer.cpp PF_Net/Detail/HostFrameBuffer.hpp
    PF_Net/Detail/Instrumentation.hpp
    PF_Net/Detail/Protocol.cpp PF_Net/Detail/Protocol.hpp
    PF_Net/Detail/Socket.cpp PF_Net/Detail/Socket.hpp
    PF_Net/Detail/Util.cpp PF_Net/Detail/Util.hpp
)

add_library(PF_Net ${sources})
target_include_directories(PF_Net PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(PF_Net PRIVATE PF_Debug PF_Endian)
target_link_libraries(PF_Net PRIVATE ${sodium_LIBRARIES})
target_include_directories(PF_Net PRIVATE ${sodium_INCLUDE_DIR})

target_compile_options(PF_Net PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/W4>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -pedantic>)

if (MSVC)
    target_link_libraries(PF_Net PRIVATE wsock32 ws2_32)
endif()
