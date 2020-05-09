#pragma once

#include <PF_Net/Address.hpp>
#include <PF_Net/Detail/Alloc.hpp>
#include <PF_Net/Detail/Protocol.hpp>
#include <stddef.h>

namespace pf::net
{

namespace detail { class Host_impl; }

enum PacketLifetime
{
    // A copy of this data will be made by the host during the send call.
    AllocateCopy,

    // The host adopts ownership of this data pointer, and will free it by calling the provided deleter function.
    CallerRelievesOwnership,

    // The caller guarantees that the data pointer will live until the packet_sent event is called with this packet.
    // This is similar to CallerRelievesOwnership except that there is no deleter call.
    CallerGuaranteesLifetime
};

using PacketId = uint64_t;
static constexpr PacketId InvalidPacketId = PacketId(~0ull);

using ConnectionId = uint64_t;
static constexpr ConnectionId InvalidConnectionId = ConnectionId(~0ull);

struct HostCallbacks
{
    // Called when a connection has successfully been made.
    void(*connected)(ConnectionId conn) = nullptr;

    // Called when a connection has been disconnected, or when a connection attempt has failed.
    void(*disconnected)(ConnectionId conn) = nullptr;

    // Called when a packet has been sent.
    // For unreliable packets, this will be called right away.
    // For reliable packets, this will be called when the corresponding acknowledge has been received.
    // For fragments, this will be called when the entire fragment has been acknowledged.
    void(*packet_sent)(ConnectionId conn, PacketId id, std::byte* data, int len, uint8_t channel) = nullptr;

    // Called when a packet has been received.
    // For unreliable and reliable packets, this will be called right away.
    // For fragments, this will be called when the entire fragment has been received.
    // If the deleter is nullptr, you MUST use the data before this function returns or make a copy yourself.
    // If the deleter is not nullptr, you MUST call the deleter on the data once you are done with it.
    // This distinction is an optimization - we can give you a read-only view of the data for small
    // packets, but for packets which have been fragmented, we must dynamically allocate space for it.
    void(*packet_received)(ConnectionId conn, std::byte* data, int len, uint8_t channel, void(*deleter)(void*)) = nullptr;
};

struct HostExtendedOptions
{
    // If true, the socket will be created in the legacy IPV4 mode.
    // If false, the socket will be created in IPV6 mode with dual stack support, so it
    // can make and accept connections with IPV4 and IPV6 hosts.
    bool use_legacy_ipv4 = false;

    // When traffic is received from the socket, it stored in an internal buffers.
    // This constants dictates the maximum size of the buffer.
    // If there is not enough space in the internal buffes to fit another frame, the oldest
    // frame in the buffer will immediately be processed to make room.
    uint32_t in_buffer_max_size_in_bytes = 1024 * 1024 * 10; // 10mb
};

// All functions in Host are thread-safe unless documented otherwise.
class Host
{

public:
    // Client constructors; may not receive incoming connections.
    PFNET_API Host(const HostCallbacks& cbs, HostExtendedOptions options = HostExtendedOptions());

    // Server constructors; may accept incoming connections on given port.
    PFNET_API Host(const HostCallbacks& cbs, uint16_t port, HostExtendedOptions options = HostExtendedOptions());

    PFNET_API Host(const Host&) = delete;
    PFNET_API Host(Host&& rhs);
    PFNET_API ~Host();

    // Receives incoming network traffic from the OS.
    // By default, this function will return immediately if there is no data ready to read.
    // A timeout can be set which will block with the select() OS call until the timeout has expired
    // or data is ready to read.
    // If timeout_in_ms is set to 0, it will return immediately.
    // If timeout_in_ms is set to > 0, it will be clamped in the range [0..100].
    // Returns true if any work was completed.
    PFNET_API bool update_socket(int timeout_in_ms = 0);

    // Responsible for processing incoming network traffic.
    PFNET_API void update_incoming();

    // Responsible for processing outgoing network traffic.
    PFNET_API void update_outgoing();

    // Sends to the connection. This packet is UNRELIABLE. Transmission is not guaranteed.
    // Len must be <= 1023. (cannot be fragmented)
    // Channel must be <= 63.
    // Channel is unimportant for unreliable traffic, but may be useful to the user.
    // If lifetime is CallerRelievesOwnership, deleter must be valid, else the deleter is ignored.
    PFNET_API PacketId send_unreliable(ConnectionId conn, std::byte* data, int len, uint8_t channel = 0,
        PacketLifetime lifetime = PacketLifetime::AllocateCopy, void(*deleter)(void*) = nullptr);

    // Attempts to connect to the remote_host. Returns the POTENTIAL CONNECTION ID.
    // This connection ID does not become valid until the connected event is broadcast.
    PFNET_API ConnectionId connect(const Address& remote_host);

    // Disconnects the connection. The remote host will be notified.
    PFNET_API void disconnect(ConnectionId conn);

private:
    detail::unique_ptr<detail::Host_impl> m_impl;
};

}
