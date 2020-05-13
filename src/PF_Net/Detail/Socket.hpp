#pragma once

#include <PF_Net/Address.hpp>
#include <PF_Net/Detail/Export.hpp>

#include <stddef.h>

namespace pf::net::detail
{

class Socket
{
public:
    enum Type
    {
        IPV4,
        IPV6
    };

    enum Options : uint8_t
    {
        DualStack   = 1 << 0,
        NonBlocking = 1 << 1
    };

    struct Buffer
    {
        // This order is swapped to match with the platform layout
        // requirements for the scatter/gather functions.
    #if defined(WIN32)
        int len;
        void* data;
    #else
        void* data;
        size_t len;
    #endif

        Buffer(void* _data, int _len) : data(_data), len(_len) {}
    };

    PFNET_API Socket(Type type, int options = 0);
    PFNET_API ~Socket();

    PFNET_API bool listen(uint16_t port);
    PFNET_API int send_to(Buffer* buffers, int count, Address address);
    PFNET_API int recv_from(void* buf, int len, Address* address_out);
    PFNET_API bool select_read(int timeout);

private:
    uintptr_t m_socket;
    Type m_type;
    int m_options;

    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
};

PFNET_API void socket_init();
PFNET_API void socket_free();

// TODO: These should be removed to address.hpp/cpp.
PFNET_API bool address_parse(const char* address, Socket::Type type, AddressStorage* storage_out);
PFNET_API bool address_to_string(const Address& address, char* buf, size_t buf_len);
PFNET_API bool hostname_resolve(const char* hostname, Socket::Type type, AddressStorage* storage_out);

}
