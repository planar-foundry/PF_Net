#include <PF_Net/Detail/Host_impl.hpp>
#include <PF_Net/Detail/Instrumentation.hpp>

#include <PF_Debug/Assert.hpp>
#include <PF_Debug/Log.hpp>

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

template <typename T, typename ... Args>
void dispatch_callback(T cb, Args&& ... args)
{
    if (cb)
    {
        cb(std::forward<Args>(args)...);
    }
}

protocol::Command make_command(protocol::CommandType command)
{
    protocol::Command ret;
    ret.command = command;
    return ret;
}

Host_impl::Host_impl(const HostCallbacks& cbs, uint16_t port, const HostExtendedOptions& options)
    : m_cbs(cbs),
      m_options(options),
      m_pending_in_list(options.in_buffer_max_size_in_bytes / protocol::MaxPacketSize),
      m_next_packet_id(0)
{
    int sock_options = Socket::Options::NonBlocking;

    if (!options.use_legacy_ipv4)
    {
        sock_options |= Socket::Options::DualStack;
    }

    m_socket = make_unique<Socket>(options.use_legacy_ipv4 ? Socket::Type::IPV4 : Socket::Type::IPV6, sock_options);

    // We listen even when we're not in server mode (e.g. with port 0).
    // This is required so we get bound to a port before we send traffic, so we can run update_socket()
    // without receiving an OS error.
    m_socket->listen(port);

    if (!m_cbs.packet_received)
    {
        // This ensures that the data is correctly released even if the user hasn't set a callback.
        m_cbs.packet_received = 
            [](ConnectionId, std::byte* data, int, uint8_t, void(*deleter)(void*))
        { 
            if (deleter) deleter(data);
        };
    }
}

Host_impl::~Host_impl()
{ }

bool Host_impl::update_socket(int timeout_in_ms)
{
    PFNET_PERF_FUNC_SCOPE();
    PFDEBUG_ASSERT(timeout_in_ms >= 0);

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

PacketId Host_impl::send_unreliable(ConnectionId conn, std::byte* data, int len, uint8_t channel, PacketLifetime lifetime, void(*deleter)(void*))
{
    if (len > protocol::MaxPayloadSize)
    {
        PFDEBUG_ASSERT_FAIL_MSG(
            "Tried to send message of length %d. "
            "Unreliable messages must not exceed the MTU %u; only reliable messages may be fragmented.",
            len, protocol::MaxPayloadSize);

        return InvalidPacketId;
    }

    if (channel > protocol::MaxPayloadChannel)
    {
        PFDEBUG_ASSERT_FAIL_MSG("Tried to send message with channel %u. Max channel is %u.",
            channel, protocol::MaxPayloadChannel);

        return InvalidPacketId;
    }
    
    PFDEBUG_ASSERT(
        (lifetime == PacketLifetime::AllocateCopy && !deleter) ||
        (lifetime == PacketLifetime::CallerGuaranteesLifetime && !deleter) ||
        (lifetime == PacketLifetime::CallerRelievesOwnership && deleter));

    protocol::Command packet = make_command(protocol::CommandType::Payload_Send);

    packet.send.body.ps.set_channel(channel);
    packet.send.body.ps.set_size((uint16_t)len);

    switch (lifetime)
    {
        case PacketLifetime::AllocateCopy:
            packet.send.payload = (std::byte*)custom_alloc(len);
            memcpy(packet.send.payload, data, len);
            deleter = &custom_free;
            break;

        case PacketLifetime::CallerGuaranteesLifetime:
            packet.send.payload = data;
            deleter = nullptr;
            break;

        case PacketLifetime::CallerRelievesOwnership:
            packet.send.payload = data;
            break;

        default:
            PFDEBUG_ASSERT_FAIL_MSG("Unhandled PacketLifetime.");
            return InvalidPacketId;
    }

    PacketId id = get_next_packet_id();
    queue_pending_out_frame(conn, std::move(packet), lifetime, deleter, id);
    return id;
}

ConnectionId Host_impl::connect(const Address& remote_host)
{
    PFDEBUG_ASSERT(remote_host.is_valid());

    if (ConnectionId existing_connection = id_from_address(remote_host);
        existing_connection != InvalidConnectionId)
    {
        PFDEBUG_ASSERT_FAIL_MSG("Tried to connect to a host we are already connected to!");
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
    return connection_info_from_id_lockless(id);
}

shared_ptr<HostConnectionInfo> Host_impl::connection_info_from_id_lockless(ConnectionId id)
{
    return m_connections[id & ConnIndexMask];
}

shared_ptr<HostConnectionInfo> Host_impl::connection_info_from_address(const Address& address)
{
    std::lock_guard<std::mutex> lock(m_connections_lock);

    ConnectionId id = id_from_address_lockless(address);
    if (id == InvalidConnectionId)             
    {
        return nullptr;
    }

    shared_ptr<HostConnectionInfo> info = connection_info_from_id_lockless(id);
    PFDEBUG_ASSERT(info);

    return info;
}

ConnectionId Host_impl::open_new_connection(const Address& address)
{
    std::lock_guard<std::mutex> lock(m_connections_lock);
    return open_new_connection_lockless(address);
}

ConnectionId Host_impl::open_new_connection_lockless(const Address& address)
{
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
        PFDEBUG_ASSERT(!m_connections[offset]);
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
        PFDEBUG_ASSERT(iter != std::end(m_connections_lookup));
        m_connections_lookup.erase(iter);
        m_free_conections.emplace_back(offset);
    }
    else
    {
        PFDEBUG_LOG_WARN("Received an attempt to close a connection %u that was not open.", conn);
    }
}

void Host_impl::process_in_frame(unique_ptr<HostFrameBuffer>&& buffer)
{
    shared_ptr<HostConnectionInfo> info = connection_info_from_address(buffer->address);

    protocol::Command in;
    if (protocol::read_from_buffer(buffer->frame, buffer->len, info ? info->shared_incoming_key : nullptr, &in) != -1)
    {
        if (info || in.command == protocol::CommandType::L2RC_Begin)
        {
            switch (in.command)
            {
                case protocol::CommandType::L2RC_Begin:
                    incoming_l2rc_begin(in.begin, buffer->address);
                    break;

                case protocol::CommandType::R2LC_Response:
                    incoming_r2lc_response(in.response, *info);
                    break;

                case protocol::CommandType::L2RC_Complete:
                    incoming_l2rc_complete(in.complete, *info);
                    break;

                case protocol::CommandType::System_Disconnect:
                    incoming_system_disconnect(in.disconnect, *info);
                    break;

                //case protocol::CommandType::System_Ping: break;
        
                case protocol::CommandType::Payload_Send: 
                    incoming_payload_send(in.send.body, in.send.payload, *info);
                    break;

                //case protocol::CommandType::Payload_SendReliableOrdered: break;
                //case protocol::CommandType::Payload_SendFragmented: break;
                default: PFDEBUG_ASSERT_FAIL_MSG("Unhandled outgoing command %u.", in.command);
            }
            
        }
        else
        {
            PFDEBUG_LOG_WARN("Received command %d without a valid connection.", in.command);
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
                bytes_written = outgoing_l2rc_begin(out->command.begin, *info, buff, sizeof(buff));
                break;

            case protocol::CommandType::R2LC_Response:
                bytes_written = outgoing_r2lc_response(out->command.response, *info, buff, sizeof(buff));
                break;

            case protocol::CommandType::L2RC_Complete:
                bytes_written = outgoing_l2rc_complete(out->command.complete, *info, buff, sizeof(buff));
                break;

            case protocol::CommandType::System_Disconnect: 
                bytes_written = outgoing_system_disconnect(out->command.disconnect, *info, buff, sizeof(buff));
                break;

            //case protocol::CommandType::System_Ping: break;

            case protocol::CommandType::Payload_Send:
                bytes_written = outgoing_payload_send(out->command.send.body, out->command.send.payload, out->payload, *info, buff, sizeof(buff));
                break;

            //case protocol::CommandType::Payload_SendReliableOrdered: break;
            //case protocol::CommandType::Payload_SendFragmented: break;
            default: PFDEBUG_ASSERT_FAIL_MSG("Unhandled incoming command %u.", out->command.command);
        }

        if (bytes_written != -1)
        {
            Socket::Buffer buffer(buff, bytes_written);
            if (m_socket->send_to(&buffer, 1, info->address) == 0)
            {
                PFDEBUG_LOG_ERROR("Failed to send packet due to OS failure.");
            }
        }
    }
    else
    {
        PFDEBUG_LOG_WARN("Outgoing connection %u terminated while processing outgoing command.", out->target);
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
    queue_pending_out_frame(target, std::move(command), PacketLifetime::AllocateCopy, nullptr, InvalidPacketId);
}

void Host_impl::queue_pending_out_frame(ConnectionId target, protocol::Command&& command,
    PacketLifetime lifetime, void(*deleter)(void*), PacketId id)
{
    std::lock_guard<std::mutex> lock(m_pending_out_list_lock);
    
    HostPendingOut out;
    out.target = target;
    out.command = std::move(command);
    out.payload.lifetime = lifetime;
    out.payload.deleter = deleter;
    out.payload.id = id;

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

PacketId Host_impl::get_next_packet_id()
{
    return m_next_packet_id++;
}

// handshake handlers

// SERVER HANDSHAKE MESSAGE
// outgoing_l2rc_begin (client sends connection attempt to server)
// --> incoming_l2rc_begin (server receives connection attempt and processes it)
//
// * opens connection
// * auth_recv_pubkey is now true on the server
// * generates server keypair
// * creates session key from client keypair 
void Host_impl::incoming_l2rc_begin(const protocol::Body_L2RC_Begin& cmd, const Address& address)
{
    shared_ptr<HostConnectionInfo> info;

    {
        std::lock_guard<std::mutex> lock(m_connections_lock);

        ConnectionId id = open_new_connection_lockless(address);
        if (id == InvalidConnectionId)             
        {
            return; // Received L2RC_Begin when there was already an active connection; ignoring.
        }

        info = connection_info_from_id_lockless(id);
        PFDEBUG_ASSERT(info);
    }

    if (memcmp(cmd.version, protocol::ProtocolVersion, sizeof(cmd.version)) != 0)
    {
        PFDEBUG_LOG_WARN("Received L2RC_Begin from mismatched protocol version %.*s; the connection will be rejected.", sizeof(cmd.version), cmd.version);
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
            PFDEBUG_LOG_WARN("Received L2RC_Begin with suspicious public key; the connection will be rejected.");
            info->rejected = true;
        }
    }

    queue_pending_out_frame(info->id, make_command(protocol::CommandType::R2LC_Response));
}

// CLIENT HANDSHAKE MESSAGE
// outgoing_l2rc_begin (client sends connection attempt to server)
// --> incoming_l2rc_begin (server receives connection attempt and processes it)
// --> outgoing_r2lc_response (server sends response to client)
// --> incoming_r2lc_response (client receives response from server)
//
// * auth_recv_pubkey is now true on the client
// * creates session key from server keypair
void Host_impl::incoming_r2lc_response(const protocol::Body_R2LC_Response& cmd, HostConnectionInfo& info)
{
    if (!info.auth_sent_pubkey)
    {
        PFDEBUG_LOG_WARN("Received R2LC_Response with out-of-order authentication; the connection will be closed.");
        close_connection(info.id);
        return;
    }

    if (info.auth_recv_pubkey || info.auth_complete)
    {
        return; // Received R2LC_Response when we were already authenticated past this stage; ignoring.
    }

    if (cmd.rejected)
    {
        PFDEBUG_LOG_WARN("Received R2LC_Response with rejection code %d; the connection will be closed.", cmd.rejected);
        close_connection(info.id);
        return;
    }

    memcpy(info.their_pubkey, cmd.pubkey, sizeof(info.their_pubkey));
    info.auth_recv_pubkey = true;
    if (protocol::generate_session_keys_client(info.our_pubkey, info.our_privkey, info.their_pubkey,
        info.shared_incoming_key, info.shared_outgoing_key) != 0)
    {
        PFDEBUG_LOG_WARN("Received R2LC_Response with suspicious public key; the connection will be closed.");
        close_connection(info.id);
        return;
    }

    queue_pending_out_frame(info.id, make_command(protocol::CommandType::L2RC_Complete));
}

// SERVER HANDSHAKE MESSAGE
// outgoing_l2rc_begin (client sends connection attempt to server)
// --> incoming_l2rc_begin (server receives connection attempt and processes it)
// --> outgoing_r2lc_response (server sends response to client)
// --> incoming_r2lc_response (client receives response from server)
// --> outgoing_l2rc_complete (client sends response to server)
// --> incoming_l2rc_complete (server receives response from client)
//
// * auth_complete is now true on the server
void Host_impl::incoming_l2rc_complete(const protocol::Body_L2RC_Complete&, HostConnectionInfo& info)
{
    if (!info.auth_sent_pubkey || !info.auth_recv_pubkey)
    {
        PFDEBUG_LOG_WARN("Received L2RC_Complete with out-of-order authentication; the connection will be closed.");
        close_connection(info.id);
        return;
    }

    if (info.auth_complete)
    {
        return; // Received R2LC_Response when we were already authenticated past this stage; ignoring.
    }

    info.auth_complete = true;
    dispatch_callback(m_cbs.connected, info.id);
}

// CLIENT HANDSHAKE MESSAGE
// outgoing_l2rc_begin (client sends connection attempt to server)
//
// * auth_sent_pubkey is now true on the client
// * generates client keypair
int Host_impl::outgoing_l2rc_begin(protocol::Body_L2RC_Begin& cmd, HostConnectionInfo& info, std::byte* buffer, int buffer_len)
{
    memcpy(cmd.version, protocol::ProtocolVersion, sizeof(cmd.version));
    protocol::generate_keypair(info.our_pubkey, info.our_privkey);
    memcpy(cmd.pubkey, info.our_pubkey, sizeof(info.our_pubkey));
    info.auth_sent_pubkey = true;
    return protocol::write_to_buffer(buffer, buffer_len, &cmd);
}

// SERVER HANDSHAKE MESSAGE
// outgoing_l2rc_begin (client sends connection attempt to server)
// --> incoming_l2rc_begin (server receives connection attempt and processes it)
// --> outgoing_r2lc_response (server sends response to client)
//
// * auth_sent_pubkey is now true on the server
// * closes connection if attempt rejected
int Host_impl::outgoing_r2lc_response(protocol::Body_R2LC_Response& cmd, HostConnectionInfo& info, std::byte* buffer, int buffer_len)
{
    cmd.rejected = info.rejected;
    if (cmd.rejected)
    {
        close_connection(info.id);
    }
    else
    {
        memcpy(cmd.pubkey, info.our_pubkey, sizeof(info.our_pubkey));
        info.auth_sent_pubkey = true;
    }
    return protocol::write_to_buffer(buffer, buffer_len, &cmd);
}

// CLIENT HANDSHAKE MESSAGE
// outgoing_l2rc_begin (client sends connection attempt to server)
// --> incoming_l2rc_begin (server receives connection attempt and processes it)
// --> outgoing_r2lc_response (server sends response to client)
// --> incoming_r2lc_response (client receives response from server)
// --> outgoing_l2rc_complete (client sends response to server)
//
// * auth_complete is now true on the client
int Host_impl::outgoing_l2rc_complete(protocol::Body_L2RC_Complete& cmd, HostConnectionInfo& info, std::byte* buffer, int buffer_len)
{
    info.auth_complete = true;
    dispatch_callback(m_cbs.connected, info.id);
    return protocol::write_to_buffer(buffer, buffer_len, info.shared_outgoing_key, info.next_sequence_id++, &cmd);
}

// system handlers

void Host_impl::incoming_system_disconnect(const protocol::Body_System_Disconnect&, HostConnectionInfo& info)
{
    dispatch_callback(m_cbs.disconnected, info.id);
    close_connection(info.id);
}

int Host_impl::outgoing_system_disconnect(protocol::Body_System_Disconnect& cmd, HostConnectionInfo& info, std::byte* buffer, int buffer_len)
{
    dispatch_callback(m_cbs.disconnected, info.id);
    close_connection(info.id);
    return protocol::write_to_buffer(buffer, buffer_len, info.shared_outgoing_key, info.next_sequence_id++, &cmd);
}

// payload handlers

void Host_impl::incoming_payload_send(const protocol::Body_Payload_Send& cmd, std::byte* payload, HostConnectionInfo& info)
{
    dispatch_callback(m_cbs.packet_received, info.id, payload, cmd.ps.get_size(), cmd.ps.get_channel(), nullptr);
}

int Host_impl::outgoing_payload_send(protocol::Body_Payload_Send& cmd, std::byte* payload,
    HostPayloadInfo& payload_info, HostConnectionInfo& info, std::byte* buffer, int buffer_len)
{
    int bytes = protocol::write_to_buffer(buffer, buffer_len, info.shared_outgoing_key, info.next_sequence_id++, &cmd, payload);
    dispatch_callback(m_cbs.packet_sent, info.id, payload_info.id, payload, cmd.ps.get_size(), cmd.ps.get_channel());

    if (payload_info.deleter)
    {
        PFDEBUG_ASSERT(
            payload_info.lifetime == PacketLifetime::AllocateCopy ||
            payload_info.lifetime == PacketLifetime::CallerRelievesOwnership);

        payload_info.deleter(payload);
    }

    return bytes;
}

}
