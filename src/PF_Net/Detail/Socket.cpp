#include <PF_Net/Detail/Socket.hpp>
#include <PF_Net/Detail/Assert.hpp>
#include <PF_Net/Detail/Instrumentation.hpp>
#include <PF_Net/Detail/Log.hpp>

#if defined(WIN32)
    #include <WS2tcpip.h>
#else
    #include <arpa/inet.h>
    #include <errno.h>
    #include <fcntl.h>
    #include <netinet/in.h>
    #include <string>
    #include <string.h>
    #include <sys/time.h>
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <unistd.h>
#endif

namespace pf::net::detail
{

#if defined(WIN32)
    #define PFNET_SOCK_TYPE SOCKET
    #define PFNET_SOCK_ERROR INVALID_SOCKET
    #define PFNET_SOCK_ADDR4_CHAIN S_un.S_addr
    #define PFNET_SOCK_ADDR6_CHAIN u.Byte
#else
    #define PFNET_SOCK_TYPE int
    #define PFNET_SOCK_ERROR -1
    #define PFNET_SOCK_ADDR4_CHAIN s_addr
    #define PFNET_SOCK_ADDR6_CHAIN s6_addr
#endif

Address address_from_sockaddr(const sockaddr_storage* storage)
{
    Address ret;

    if (storage->ss_family == AF_INET)
    {
        sockaddr_in addr4;
        memcpy(&addr4, storage, sizeof(addr4));
        ret = Address(ntohl(addr4.sin_addr.PFNET_SOCK_ADDR4_CHAIN), ntohs(addr4.sin_port));
    }
    else if (storage->ss_family == AF_INET6)
    {
        sockaddr_in6 addr6;
        memcpy(&addr6, storage, sizeof(addr6));
        static_assert(sizeof(addr6.sin6_addr.PFNET_SOCK_ADDR6_CHAIN) == sizeof(AddressStorageV6::addr));
        ret = Address(addr6.sin6_addr.PFNET_SOCK_ADDR6_CHAIN, ntohs(addr6.sin6_port));
    }
    else
    {
        PFNET_ASSERT_FAIL_MSG("Unhandled ss_family type %d.", storage->ss_family);
    }

    return ret;
}

sockaddr_storage storage_from_address(const Address& address)
{
    sockaddr_storage storage;

    if (address.is_ipv4())
    {
        sockaddr_in addr4 = {};
        addr4.sin_family = AF_INET;
        addr4.sin_addr.PFNET_SOCK_ADDR4_CHAIN = htonl(address.get_address_ipv4());
        addr4.sin_port = htons(address.get_port());
        memcpy(&storage, &addr4, sizeof(addr4));
    }
    else if (address.is_ipv6())
    {
        sockaddr_in6 addr6 = {};
        addr6.sin6_family = AF_INET6;
        static_assert(sizeof(addr6.sin6_addr.PFNET_SOCK_ADDR6_CHAIN) == sizeof(AddressStorageV6::addr));
        memcpy(addr6.sin6_addr.PFNET_SOCK_ADDR6_CHAIN, address.get_address_ipv6(), sizeof(addr6.sin6_addr.PFNET_SOCK_ADDR6_CHAIN));
        addr6.sin6_port = htons(address.get_port());
        memcpy(&storage, &addr6, sizeof(addr6));
    }
    else
    {
        PFNET_ASSERT_FAIL_MSG("Unhandled address type.");
        memset(&storage, 0, sizeof(storage));
    }


    return storage;
}

sockaddr_storage storage_from_port_type(uint16_t port, Socket::Type type)
{
    sockaddr_storage storage;

    if (type == Socket::Type::IPV4)
    {
        sockaddr_in addr4 = {};
        addr4.sin_family = AF_INET;
        addr4.sin_addr.PFNET_SOCK_ADDR4_CHAIN = INADDR_ANY;
        addr4.sin_port = htons(port);
        memcpy(&storage, &addr4, sizeof(addr4));
    }
    else if (type == Socket::Type::IPV6)
    {
        sockaddr_in6 addr6 = {};
        addr6.sin6_family = AF_INET6;
        addr6.sin6_addr = in6addr_any;
        addr6.sin6_port = htons(port);
        memcpy(&storage, &addr6, sizeof(addr6));
    }
    else
    {
        PFNET_ASSERT_FAIL_MSG("Unhandled address type.");
        memset(&storage, 0, sizeof(storage));
    }
   
    return storage;
}

int get_last_error()
{
#if defined(WIN32)
    return WSAGetLastError();
#else
    return errno;
#endif
}

Socket::Socket(Socket::Type type, int options)
    : m_socket(PFNET_SOCK_ERROR), m_type(type), m_options(options)
{
    PFNET_SOCK_TYPE sock = 
#if defined(WIN32)
        WSASocketW(type == Type::IPV6 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, 0);
#else
        socket(type == Type::IPV6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
#endif

    if (sock == PFNET_SOCK_ERROR)
    {
        PFNET_LOG_ERROR("Failed to open socket with error %d.", get_last_error());
        return;
    }

    m_socket = (uintptr_t)sock;

    if (options & Options::DualStack)
    {
        char zero[4] = { 0, 0, 0, 0 };
        if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&zero, sizeof(zero)) == PFNET_SOCK_ERROR)
        {
            PFNET_LOG_ERROR("Failed to setsockopt socket %d with error %d.", sock, get_last_error());
        }
    }

    if (options & Options::NonBlocking)
    {
#if defined(WIN32)
        u_long blocking_off = 1;
        if (ioctlsocket(sock, FIONBIO, &blocking_off) == PFNET_SOCK_ERROR)
        {
            PFNET_LOG_ERROR("Failed to ioctlsocket socket %d with error %d.", sock, WSAGetLastError());
        }
#else
        if (fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK) == PFNET_SOCK_ERROR)
        {
            PFNET_LOG_ERROR("Failed to fcntl socket %d with error %d.", sock, errno);
        }
#endif
    }
}

Socket::~Socket()
{
    int err = 
#if defined(WIN32)
        closesocket((PFNET_SOCK_TYPE)m_socket);
#else
        close((PFNET_SOCK_TYPE)m_socket);
#endif

    if (err == PFNET_SOCK_ERROR)
    {
        PFNET_LOG_ERROR("Failed to close socket with error %d.", get_last_error());
    }
}

bool Socket::listen(uint16_t port)
{
    sockaddr_storage addr = storage_from_port_type(port, m_type);

    if (bind((PFNET_SOCK_TYPE)m_socket, (sockaddr*)&addr, sizeof(addr)) == PFNET_SOCK_ERROR)
    {
        PFNET_LOG_ERROR("Failed to bind socket %d on port %d with error %d.", (PFNET_SOCK_TYPE)m_socket, port, get_last_error());
        return false;
    }

    return true;
}

int Socket::send_to(Buffer* buffers, int count, Address address)
{
    PFNET_PERF_FUNC_SCOPE();

    if (address.is_ipv4() && m_type == Socket::Type::IPV6)
    {
        if ((m_options & Options::DualStack) == 0)
        {
            PFNET_ASSERT_FAIL_MSG("Attempted to send to an IPV4 address with an IPV6 socket"
                " when dual stack mode was not turned on.");
            return 0;
        }

        // We're an V6 socket sending to a V4 address, so just convert the address to V4-on-V6 format before sending.
        uint32_t addr = htonl(address.get_address_ipv4());
        uint8_t v6[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF };
        memcpy(v6 + 12, &addr, sizeof(v6) - 12);
        address = Address(v6, address.get_port());
    }

    sockaddr_storage addr = storage_from_address(address);

#if defined(WIN32)
    DWORD bytes = 0;
    if (WSASendTo((PFNET_SOCK_TYPE)m_socket, (WSABUF*)buffers, (DWORD)count, &bytes, 0, (sockaddr*)&addr, sizeof(addr), NULL, NULL) == SOCKET_ERROR)
    {
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK)
        {
            PFNET_LOG_ERROR("Failed to WSASendTo on socket %d with error %d.", (PFNET_SOCK_TYPE)m_socket, err);
        }
        bytes = 0;
    }
    return bytes;
#else
    msghdr msg;
    msg.msg_name = (sockaddr*)&addr;
    msg.msg_namelen = sizeof(addr);
    msg.msg_iov = (iovec*)buffers;
    msg.msg_iovlen = count;
    msg.msg_control = nullptr;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    ssize_t bytes = sendmsg((PFNET_SOCK_TYPE)m_socket, &msg, 0);
    if (bytes == PFNET_SOCK_ERROR)
    {
        int err = errno;
        if (err != EWOULDBLOCK)
        {
            PFNET_LOG_ERROR("Failed to sendmsg on socket %d with error %d.", (PFNET_SOCK_TYPE)m_socket, err);
        }
        bytes = 0;
    }
    return (int)bytes;
#endif
}

int Socket::recv_from(void* buf, int len, Address* address_out)
{
    PFNET_PERF_FUNC_SCOPE();

    sockaddr_storage addr;

#if defined(WIN32)
    WSABUF buff;
    buff.buf = (CHAR*)buf;
    buff.len = (ULONG)len;

    DWORD bytes = 0;
    DWORD flags = 0;

    INT addr_len = sizeof(addr);
    if (WSARecvFrom((PFNET_SOCK_TYPE)m_socket, &buff, 1, &bytes, &flags, (sockaddr*)&addr, &addr_len, NULL, NULL) == PFNET_SOCK_ERROR)
    {
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK)
        {
            PFNET_LOG_ERROR("Failed to WSARecvFrom on socket %d with error %d.", (PFNET_SOCK_TYPE)m_socket, err);
        }
        bytes = 0;
    }
#else
    socklen_t addr_len = sizeof(addr);
    ssize_t bytes = recvfrom((PFNET_SOCK_TYPE)m_socket, buf, len, 0, (sockaddr*)&addr, &addr_len);
    if (bytes == PFNET_SOCK_ERROR)
    {
        int err = errno;
        if (err != EWOULDBLOCK)
        {
            PFNET_LOG_ERROR("Failed to recvfrom on socket %d with error %d.", (PFNET_SOCK_TYPE)m_socket, err);
        }
        bytes = 0;
    }
#endif

    if (bytes)
    {
        *address_out = address_from_sockaddr(&addr);
    }

    return (int)bytes;
}

bool Socket::select_read(int timeout)
{
    PFNET_PERF_FUNC_SCOPE();

    fd_set read_set;
    FD_ZERO(&read_set);
    FD_SET(m_socket, &read_set);

#if defined(WIN32)
    TIMEVAL tv;
    int nfds = 0;
#else
    timeval tv;
    int nfds = (PFNET_SOCK_TYPE)m_socket + 1;
#endif

    if (timeout == -1)
    {
        tv.tv_sec = 0;
        tv.tv_usec = 0;
    }
    else if (timeout != 0)
    {
        tv.tv_sec = timeout / 1000;
        tv.tv_usec = timeout % 1000 * 1000;
    }

    int ret = select(nfds, &read_set, NULL, NULL, timeout == 0 ? nullptr : &tv);
    if (ret == PFNET_SOCK_ERROR)
    {
        PFNET_LOG_ERROR("Failed to select on socket %d with error %d.", (PFNET_SOCK_TYPE)m_socket, get_last_error());
    }

    return ret > 0;
}

void socket_init()
{
#if defined(WIN32)
    WSADATA data;
    if (WSAStartup(MAKEWORD(2, 2), &data))
    {
        PFNET_LOG_ERROR("Failed the call to WSAStartup with error %d.", WSAGetLastError());
    }
#endif
}

void socket_free()
{
#if defined(WIN32)
    if (WSACleanup())
    {
        PFNET_LOG_ERROR("Failed the call to WSACleanup with error %d.", WSAGetLastError());
    }
#endif
}

bool address_parse(const char* address, Socket::Type type, AddressStorage* storage_out)
{
    union
    {
        in_addr v4;
        in6_addr v6;
    } storage;

    int net = type == Socket::Type::IPV6 ? AF_INET6 : AF_INET;

    int err = 
#if defined(WIN32)
        InetPton(net, address, &storage);
#else
        inet_pton(net, address, &storage);
#endif

    if (err != 1)
    {
        PFNET_LOG_ERROR("Failed InetPton on address %s with error %d.", address, err);
        return false;
    }

    if (type == Socket::Type::IPV4)
    {
        AddressStorageV4 storage_v4;
        storage_v4.addr = ntohl(storage.v4.PFNET_SOCK_ADDR4_CHAIN);
        *storage_out = std::move(storage_v4);
    }
    else if (type == Socket::Type::IPV6)
    {
        AddressStorageV6 storage_v6;
        static_assert(sizeof(storage.v6.PFNET_SOCK_ADDR6_CHAIN) == sizeof(storage_v6.addr));
        memcpy(storage_v6.addr, storage.v6.PFNET_SOCK_ADDR6_CHAIN, sizeof(storage_v6.addr));
        *storage_out = std::move(storage_v6);
    }
    else
    {
        PFNET_ASSERT_FAIL_MSG("Unhandled Socket::Type %d.", type);
        return false;
    }

    return true;
}

bool hostname_resolve(const char* hostname, Socket::Type type, AddressStorage* storage_out)
{
    // TODO
    return {};
}

bool address_to_string(const Address& address, char* buf, size_t buf_len)
{
    PFNET_ASSERT(address.is_valid());

#if defined(WIN32)
    sockaddr_storage storage = storage_from_address(address);

    PCSTR ret;

    if (address.is_ipv4())
    {
        sockaddr_in* addr4 = (sockaddr_in*)&storage;
        PFNET_ASSERT(buf_len >= 16);
        ret = InetNtop(AF_INET, &addr4->sin_addr, buf, buf_len);
    }
    else if (address.is_ipv6())
    {
        sockaddr_in6* addr6 = (sockaddr_in6*)&storage;
        PFNET_ASSERT(buf_len >= 46);
        ret = InetNtop(AF_INET6, &addr6->sin6_addr, buf, buf_len);
    }
    else
    {
        PFNET_ASSERT_FAIL_MSG("Unhandled address type.");
        return false;
    }

    if (ret == NULL)
    {
        PFNET_LOG_ERROR("Failed InetNtop with error %d.", WSAGetLastError());
        return false;
    }

    return true;
#else
    PFNET_ASSERT_FAIL_MSG("address_to_string() not yet implemented on Linux.");
    return false;
#endif
}

}
