#include <PF_Net/Detail/Host_impl.hpp>
#include <PF_Net/Detail/Assert.hpp>
#include <PF_Net/Detail/Instrumentation.hpp>
#include <PF_Net/Detail/Log.hpp>

#include <atomic>
#include <string.h>

namespace pf::net::detail
{

// The ConnectionId is:
//
// OFFSET_INTO_CONNECTION_ARRAY  |  UNIQUE_CONNECTION_ID
//                 ^                              ^
//          ConnIndexBits bits           ConnUidBits bits
//
// OFFSET_INTO_CONNECTION_ARRAY may be reused when a connection is closed.
// UNIQUE_CONNECTION_ID is atomically incrementing and may never repeat.

static constexpr uint64_t ConnIndexBits  = 20ull; // 10 mil connections - if you have more than this you have a PROBLEM
static constexpr uint64_t ConnIndexShift = 0ull;
static constexpr uint64_t ConnIndexMask  = ((1ull << ConnIndexBits) - 1ull) << ConnIndexShift;
static constexpr uint64_t ConnUidBits    = 44ull;
static constexpr uint64_t ConnUidShift   = ConnIndexBits;
static constexpr uint64_t ConnUidMask    = ((1ull << ConnUidBits) - 1ull) << ConnUidShift;

Host_impl::Host_impl(HostCallbacks cbs, uint16_t port, HostExtendedOptions options)
    : m_cbs(cbs),
      m_options(options),
      m_pending_in_list(options.in_buffer_max_size_in_bytes / protocol::MaxPacketSize)
{
    int sock_options = Socket::Options::NonBlocking;

    if (!options.use_legacy_ipv4)
    {
        sock_options |= Socket::Options::DualStack;
    }

    m_socket = make_unique<Socket>(options.use_legacy_ipv4 ? Socket::Type::IPV4 : Socket::Type::IPV6, sock_options);

    if (port != 0)
    {
        m_socket->listen(port);
    }

    if (!m_cbs.packet_received)
    {
        // This ensures that the data is correctly released even if the user hasn't set a callback.
        m_cbs.packet_received = [](ConnectionId, std::byte* data, int, void(*deleter)(void*)) { if (deleter) deleter(data); };
    }
}

Host_impl::~Host_impl()
{ }

bool Host_impl::update_socket(int timeout_in_ms)
{
    PFNET_PERF_FUNC_SCOPE();
    PFNET_ASSERT(timeout_in_ms >= 0);

    if (timeout_in_ms != 0 && !m_socket->select_read(std::min(timeout_in_ms, 100)))
    {
        return false;
    }

    unique_ptr<HostFrameBuffer> buffer = get_scratch_frame();
    buffer->len = (uint16_t)m_socket->recv_from(buffer->frame, buffer->len, &buffer->address);

    if (bool valid_packet = buffer->len > 0; valid_packet)
    {
        buffer = submit_pending_in_frame(std::move(buffer));

        if (buffer)
        {
            process_in_frame(std::move(buffer));
        }

        return true;
    }
    else
    {
        return_scratch_frame(std::move(buffer));
    }

    return false;
}

void Host_impl::update_incoming()
{
    PFNET_PERF_FUNC_SCOPE();

    while (unique_ptr<HostFrameBuffer> buffer = get_pending_in_frame())
    {
        process_in_frame(std::move(buffer));
    }
}

void Host_impl::update_outgoing()
{
    PFNET_PERF_FUNC_SCOPE();

    HostPendingOut out;
    while (get_pending_out_frame(&out))
    {
        process_out_frame(&out);
    }
}

PacketId Host_impl::send_unreliable(ConnectionId conn, const std::byte* data, int len, PacketLifetime lifetime, void(*deleter)(void*))
{
    return InvalidPacketId;
}

ConnectionId Host_impl::connect(const Address& remote_host)
{
    PFNET_ASSERT(remote_host.is_valid());

    if (ConnectionId existing_connection = id_from_address(remote_host);
        existing_connection != InvalidConnectionId)
    {
        PFNET_ASSERT_FAIL_MSG("Tried to connect to a host we are already connected to!");
        return InvalidConnectionId;
    }

    if (ConnectionId new_connection = open_new_connection(remote_host);
        new_connection != InvalidConnectionId)
    {
        queue_pending_out_frame(new_connection, make_command(protocol::CommandType::L2RC_Begin));
        return new_connection;
    }

    return InvalidConnectionId;
}

void Host_impl::disconnect(ConnectionId conn)
{
    queue_pending_out_frame(conn, make_command(protocol::CommandType::System_Disconnect));
}

ConnectionId Host_impl::id_from_address(const Address& address)
{
    std::lock_guard<std::mutex> lock(m_connections_lock);
    return id_from_address_lockless(address);
}

ConnectionId Host_impl::id_from_address_lockless(const Address& address)
{
    auto iter = m_connections_lookup.find(address);
    if (iter != std::end(m_connections_lookup))
    {
        return iter->second;
    }
    return InvalidConnectionId;
}

shared_ptr<HostConnectionInfo> Host_impl::connection_info_from_id(ConnectionId id)
{
    std::lock_guard<std::mutex> lock(m_connections_lock);
    return m_connections[id & ConnIndexMask];
}

ConnectionId Host_impl::open_new_connection(const Address& address)
{
    std::lock_guard<std::mutex> lock(m_connections_lock);

    if (id_from_address_lockless(address) != InvalidConnectionId)
    {
        return InvalidConnectionId;
    }

    shared_ptr<HostConnectionInfo> info = make_shared<HostConnectionInfo>();
    info->address = address;

    static std::atomic<ConnectionId> s_uid = 0;
    ConnectionId new_id = (s_uid++ << ConnUidShift);

    if (m_free_conections.empty())
    {
        size_t offset = m_connections.size();
        new_id |= offset;
        info->id = new_id;
        m_connections.emplace_back(std::move(info));
    }
    else
    {
        size_t offset = m_free_conections.back();
        m_free_conections.pop_back();
        PFNET_ASSERT(!m_connections[offset]);
        new_id |= offset;
        info->id = new_id;
        m_connections[offset] = std::move(info);
    }
    
    m_connections_lookup.insert(std::make_pair(address, new_id));
    return new_id;
}

void Host_impl::close_connection(ConnectionId conn)
{
    std::lock_guard<std::mutex> lock(m_connections_lock);

    ConnectionId offset = conn & ConnIndexMask;
    shared_ptr<HostConnectionInfo> connection;
    std::swap(connection, m_connections[offset]);

    if (connection)
    {
        auto iter = m_connections_lookup.find(connection->address);
        PFNET_ASSERT(iter != std::end(m_connections_lookup));
        m_free_conections.emplace_back(offset);
    }
    else
    {
        PFNET_LOG_WARN("Received an attempt to close a connection %u that was not open.", conn);
    }
}

void Host_impl::process_in_frame(unique_ptr<HostFrameBuffer>&& buffer)
{
    protocol::Command in;
    if (protocol::read_from_buffer(buffer->frame, buffer->len, &in) != -1)
    {
        switch (in.command)
        {
            case protocol::CommandType::L2RC_Begin:
                incoming_l2rc_begin(in.data.begin, buffer->address);
                break;

            case protocol::CommandType::R2LC_Response:
                incoming_r2lc_response(in.data.response, buffer->address);
                break;

            //case protocol::CommandType::L2RC_Complete: break;
            //case protocol::CommandType::System_Disconnect: break;
            //case protocol::CommandType::System_Ping: break;
            //case protocol::CommandType::Payload_Send: break;
            //case protocol::CommandType::Payload_SendReliableOrdered: break;
            //case protocol::CommandType::Payload_SendFragmented: break;
            default: PFNET_ASSERT_FAIL_MSG("Unhandled outgoing command %u.", in.command);
        }
    }

    return_scratch_frame(std::move(buffer));
}

void Host_impl::process_out_frame(HostPendingOut* out)
{
    shared_ptr<HostConnectionInfo> info = connection_info_from_id(out->target);

    if (info)
    {
        int bytes_written = -1;
        std::byte buff[protocol::MaxPacketSize];

        switch (out->command.command)
        {
            case protocol::CommandType::L2RC_Begin:
                bytes_written = outgoing_l2rc_begin(out->command, *info, buff, sizeof(buff));
                break;

            case protocol::CommandType::R2LC_Response:
                bytes_written = outgoing_r2lc_response(out->command, *info, buff, sizeof(buff));
                break;

            //case protocol::CommandType::L2RC_Complete: break;
            //case protocol::CommandType::System_Disconnect: break;
            //case protocol::CommandType::System_Ping: break;
            //case protocol::CommandType::Payload_Send: break;
            //case protocol::CommandType::Payload_SendReliableOrdered: break;
            //case protocol::CommandType::Payload_SendFragmented: break;
            default: PFNET_ASSERT_FAIL_MSG("Unhandled incoming command %u.", out->command.command);
        }

        if (bytes_written != -1)
        {
            Socket::Buffer buffer(buff, bytes_written);
            if (m_socket->send_to(&buffer, 1, info->address) == 0)
            {
                PFNET_LOG_ERROR("Failed to send packet due to OS failure.");
            }
        }
    }
    else
    {
        PFNET_LOG_WARN("Outgoing connection %u terminated while processing outgoing command.", out->target);
    }
}

unique_ptr<HostFrameBuffer> Host_impl::get_scratch_frame()
{
    std::lock_guard<std::mutex> lock(m_free_list_lock);
    return m_free_list.get_or_make();
}

void Host_impl::return_scratch_frame(unique_ptr<HostFrameBuffer>&& buffer)
{
    std::lock_guard<std::mutex> lock(m_free_list_lock);
    m_free_list.submit(std::move(buffer));
}

unique_ptr<HostFrameBuffer> Host_impl::get_pending_in_frame()
{
    std::lock_guard<std::mutex> lock(m_pending_in_list_lock);
    return m_pending_in_list.get();
}

unique_ptr<HostFrameBuffer> Host_impl::submit_pending_in_frame(unique_ptr<HostFrameBuffer>&& buffer)
{
    std::lock_guard<std::mutex> lock(m_pending_in_list_lock);
    return m_pending_in_list.submit(std::move(buffer));
}

void Host_impl::queue_pending_out_frame(ConnectionId target, protocol::Command&& command)
{
    std::lock_guard<std::mutex> lock(m_pending_out_list_lock);
    
    HostPendingOut out;
    out.target = target;
    out.command = std::move(command);

    m_pending_out_list.push(std::move(out));
}

bool Host_impl::get_pending_out_frame(HostPendingOut* frame)
{
    std::lock_guard<std::mutex> lock(m_pending_out_list_lock);

    if (!m_pending_out_list.empty())
    {
        *frame = std::move(m_pending_out_list.front());
        m_pending_out_list.pop();
        return true;
    }

    return false;
}

protocol::Command Host_impl::make_command(protocol::CommandType command)
{
    protocol::Command ret;
    ret.command = command;
    return ret;
}

void Host_impl::incoming_l2rc_begin(const protocol::Body_L2RC_Begin& cmd, const Address& address)
{
    ConnectionId id = id_from_address(address);
    if (id != InvalidConnectionId)             
    {
        PFNET_LOG_WARN("Received L2RC_Begin when there was already an active connection.");
        return;
    }

    id = open_new_connection(address);
    PFNET_ASSERT(id != InvalidConnectionId);

    shared_ptr<HostConnectionInfo> info = connection_info_from_id(id);
    PFNET_ASSERT(info);

    if (memcmp(cmd.version, protocol::ProtocolVersion, sizeof(protocol::ProtocolVersion)) != 0)
    {
        PFNET_LOG_WARN("Received L2RC_Begin from mismatched protocol version %.*s.",
            sizeof(protocol::ProtocolVersion), cmd.version);
        info->rejected = true;
    }
    else
    {
        memcpy(info->their_pubkey, cmd.pubkey, sizeof(info->their_pubkey));
        info->auth_recv_pubkey = true;
        protocol::generate_keypair(info->our_pubkey, info->our_privkey);
        if (protocol::generate_session_keys_server(info->our_pubkey, info->our_privkey, info->their_pubkey,
            info->shared_incoming_key, info->shared_outgoing_key) != 0)
        {
            PFNET_LOG_WARN("Received L2RC_Begin with suspicious public key.");
            info->rejected = true;
        }
    }

    queue_pending_out_frame(id, make_command(protocol::CommandType::R2LC_Response));
}

void Host_impl::incoming_r2lc_response(const protocol::Body_R2LC_Response& cmd, const Address& address)
{
    PFNET_ASSERT_FAIL_MSG("Unimplemented");
}

void Host_impl::incoming_l2rc_complete(const protocol::Body_L2RC_Complete& cmd, const Address& address)
{
    PFNET_ASSERT_FAIL_MSG("Unimplemented");
}

int Host_impl::outgoing_l2rc_begin(protocol::Command& cmd, HostConnectionInfo& info, std::byte* buffer, int buffer_len)
{
    memcpy(cmd.data.begin.version, protocol::ProtocolVersion, sizeof(protocol::ProtocolVersion));
    protocol::generate_keypair(info.our_pubkey, info.our_privkey);
    memcpy(cmd.data.begin.pubkey, info.our_pubkey, sizeof(info.our_pubkey));
    info.auth_sent_pubkey = true;
    return protocol::write_to_buffer(buffer, buffer_len, &cmd.data.begin);
}

int Host_impl::outgoing_r2lc_response(protocol::Command& cmd, HostConnectionInfo& info, std::byte* buffer, int buffer_len)
{
    cmd.data.response.accepted = !info.rejected;
    if (cmd.data.response.accepted)
    {
        memcpy(cmd.data.response.pubkey, info.our_pubkey, sizeof(info.our_pubkey));
        info.auth_sent_pubkey = true;
    }
    else
    {
        close_connection(info.id);
    }
    return protocol::write_to_buffer(buffer, buffer_len, &cmd.data.response);
}

int Host_impl::outgoing_l2rc_complete(protocol::Command& cmd, HostConnectionInfo& info, std::byte* buffer, int buffer_len)
{
    PFNET_ASSERT_FAIL_MSG("Unimplemented");
    return -1;
}

}
