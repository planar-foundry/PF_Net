#pragma once

#include <PF_Net/Host.hpp>
#include <PF_Net/Detail/Export.hpp>
#include <PF_Net/Detail/HostFrameBuffer.hpp>
#include <PF_Net/Detail/Protocol.hpp>
#include <PF_Net/Detail/Socket.hpp>

#include <atomic>
#include <mutex>

namespace pf::net::detail
{

struct HostConnectionInfo
{
    ConnectionId id;
    Address address;

    // this connection was rejected and is soon to be disposed
    bool rejected = false;

    // a connection is considered ready / authenticated when both the below are set to true
    bool auth_sent_pubkey = false; // true when we've sent our public key to remote
    bool auth_recv_pubkey = false; // true when we've received our public key from remote
    bool auth_complete = false; // true when the client sents the complete msg, or the server receives it

    // the keys associated with this connection.
    // https://libsodium.gitbook.io/doc/key_exchange
    std::byte our_pubkey[protocol::EncryptionKeySize];
    std::byte our_privkey[protocol::EncryptionKeySize];
    std::byte their_pubkey[protocol::EncryptionKeySize];
    std::byte shared_incoming_key[protocol::EncryptionKeySize];
    std::byte shared_outgoing_key[protocol::EncryptionKeySize];

    // for each packet we send, we additionally increment this counter and use it as a nonce.
    std::atomic<uint64_t> next_sequence_id = 0;
};

struct HostPayloadInfo
{
    PacketLifetime lifetime;
    void(*deleter)(void*);
    PacketId id;
};

struct HostPendingOut
{
    ConnectionId target;
    protocol::Command command;
    HostPayloadInfo payload;
};

class Host_impl
{
public:
    PFNET_API Host_impl(const HostCallbacks& cbs, uint16_t port, const HostExtendedOptions& options);
    PFNET_API ~Host_impl();

    PFNET_API bool update_socket(int timeout_in_ms);
    PFNET_API void update_incoming();
    PFNET_API void update_outgoing();
    PFNET_API PacketId send_unreliable(ConnectionId conn, std::byte* data, int len, uint8_t channel, PacketLifetime lifetime, void(*deleter)(void*));
    PFNET_API ConnectionId connect(const Address& remote_host);
    PFNET_API void disconnect(ConnectionId conn);

private:
    HostCallbacks m_cbs;
    HostExtendedOptions m_options;
    unique_ptr<Socket> m_socket;

    // This list contains all of our free-for-use frame buffers.
    std::mutex m_free_list_lock;
    HostFrameBufferFreeList m_free_list;

    // This list contains all of the pending incoming frames.
    std::mutex m_pending_in_list_lock;
    HostFrameBufferPendingList m_pending_in_list;

    // This list contains all of our pending outgoing frames.
    std::mutex m_pending_out_list_lock;
    queue<HostPendingOut> m_pending_out_list;

    // This lock should be acquired when manipulating:
    // - m_connections
    // - m_connections_lookup
    // - m_free_conections
    // You do not need to hold this lock when manipulating the HostConnectionInfo beyond the point
    // where you capture a copy of the shared_ptr which owns it.
    std::mutex m_connections_lock;

    // This vector will never downsize; it will only increase.
    // Entries that are nullptr are disconnected connections.
    vector<shared_ptr<HostConnectionInfo>> m_connections;

    // This maps between address and connection ID.
    // Used when receiving data.
    unordered_map<Address, ConnectionId> m_connections_lookup;

    // A list of indices into m_connections of free connections. For every empty entry, there will be an index here.
    vector<ConnectionId> m_free_conections;

    // The PacketIds just increment from 0 upwards, as a unique identifier for each payload message.
    std::atomic<PacketId> m_next_packet_id;

    PFNET_API ConnectionId id_from_address(const Address& address);
    PFNET_API ConnectionId id_from_address_lockless(const Address& address);
    PFNET_API shared_ptr<HostConnectionInfo> connection_info_from_id(ConnectionId id);
    PFNET_API shared_ptr<HostConnectionInfo> connection_info_from_id_lockless(ConnectionId id);
    PFNET_API shared_ptr<HostConnectionInfo> connection_info_from_address(const Address& address);
    PFNET_API ConnectionId open_new_connection(const Address& address);
    PFNET_API ConnectionId open_new_connection_lockless(const Address& address);
    PFNET_API void close_connection(ConnectionId conn);

    PFNET_API void process_in_frame(unique_ptr<HostFrameBuffer>&& buffer);
    PFNET_API void process_out_frame(HostPendingOut* out);

    PFNET_API unique_ptr<HostFrameBuffer> get_scratch_frame();
    PFNET_API void return_scratch_frame(unique_ptr<HostFrameBuffer>&& buffer);
    PFNET_API unique_ptr<HostFrameBuffer> get_pending_in_frame();
    PFNET_API unique_ptr<HostFrameBuffer> submit_pending_in_frame(unique_ptr<HostFrameBuffer>&& buffer);

    PFNET_API void queue_pending_out_frame(ConnectionId target, protocol::Command&& command);
    PFNET_API void queue_pending_out_frame(ConnectionId target, protocol::Command&& command,
        PacketLifetime lifetime, void(*deleter)(void*), PacketId id);

    PFNET_API bool get_pending_out_frame(HostPendingOut* frame);

    PFNET_API PacketId get_next_packet_id();

    // handshake handlers

    PFNET_API void incoming_l2rc_begin(const protocol::Body_L2RC_Begin& cmd, const Address& address);
    PFNET_API void incoming_r2lc_response(const protocol::Body_R2LC_Response& cmd, HostConnectionInfo& info);
    PFNET_API void incoming_l2rc_complete(const protocol::Body_L2RC_Complete& cmd, HostConnectionInfo& info);

    PFNET_API int outgoing_l2rc_begin(protocol::Body_L2RC_Begin& cmd, HostConnectionInfo& info, std::byte* buffer, int buffer_len);
    PFNET_API int outgoing_r2lc_response(protocol::Body_R2LC_Response& cmd, HostConnectionInfo& info, std::byte* buffer, int buffer_len);
    PFNET_API int outgoing_l2rc_complete(protocol::Body_L2RC_Complete& cmd, HostConnectionInfo& info, std::byte* buffer, int buffer_len);

    // system handlers

    PFNET_API void incoming_system_disconnect(const protocol::Body_System_Disconnect& cmd, HostConnectionInfo& info);
    PFNET_API int outgoing_system_disconnect(protocol::Body_System_Disconnect& cmd, HostConnectionInfo& info, std::byte* buffer, int buffer_len);

    // payload handlers

    PFNET_API void incoming_payload_send(const protocol::Body_Payload_Send& cmd, std::byte* payload, HostConnectionInfo& info);
    PFNET_API int outgoing_payload_send(protocol::Body_Payload_Send& cmd, std::byte* payload,
        HostPayloadInfo& payload_info, HostConnectionInfo& info, std::byte* buffer, int buffer_len);
};

}
