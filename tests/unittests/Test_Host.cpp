#include "UnitTest.hpp"
#include <PF_Net/Host.hpp>
#include <stdint.h>
#include <string.h>

using namespace pf::net;

std::pair<Host, Host> create_connected_pair(HostCallbacks client_cbs, HostCallbacks server_cbs)
{
    uint16_t server_port = get_unique_port();

    Host client(client_cbs);
    Host server(server_cbs, server_port);

    client.connect(Address(AddressStrIPV6("::1"), server_port));

    bool auth_in_progress = true;

    while (auth_in_progress)
    {
        bool client_socket = client.update_socket();
        client.update_incoming();
        client.update_outgoing();

        bool server_socket = server.update_socket();
        server.update_incoming();
        server.update_outgoing();

        auth_in_progress = client_socket || server_socket;
    }

    return std::make_pair(std::move(client), std::move(server));
}

PFTEST_CREATE(Host_Connection)
{
    static bool s_server_connected_to_client = false;
    static bool s_client_connected_to_server = false;

    uint16_t server_port = get_unique_port();

    HostCallbacks client_cbs;
    client_cbs.connected = [](ConnectionId) { s_client_connected_to_server = true; };
    client_cbs.disconnected = [](ConnectionId) { s_client_connected_to_server = false; };
    Host client(client_cbs);

    HostCallbacks server_cbs;
    server_cbs.connected = [](ConnectionId) { s_server_connected_to_client = true; };
    server_cbs.disconnected = [](ConnectionId) { s_server_connected_to_client = false; };
    Host server(server_cbs, server_port);

    ConnectionId id = client.connect(Address(AddressStrIPV6("::1"), server_port));
    PFTEST_EXPECT(id != InvalidConnectionId);
    PFTEST_EXPECT(!s_client_connected_to_server);

    client.update_outgoing();
    PFTEST_EXPECT(!s_client_connected_to_server);

    server.update_socket();
    server.update_incoming();
    server.update_outgoing();
    PFTEST_EXPECT(!s_server_connected_to_client);

    client.update_socket();
    client.update_incoming();
    client.update_outgoing();
    PFTEST_EXPECT(s_client_connected_to_server);

    server.update_socket();
    server.update_incoming();
    PFTEST_EXPECT(s_server_connected_to_client);

    client.disconnect(id);
    PFTEST_EXPECT(s_client_connected_to_server);

    client.update_outgoing();
    PFTEST_EXPECT(!s_client_connected_to_server);

    server.update_socket();
    server.update_incoming();
    PFTEST_EXPECT(!s_server_connected_to_client);
    PFTEST_EXPECT(!s_client_connected_to_server);
}

PFTEST_CREATE(Host_Send)
{
    static ConnectionId s_conn;
    static PacketId s_packet_id;
    static int s_data;
    static uint8_t s_len;
    static uint8_t s_channel;
    static void (*s_deleter)(void*);

    HostCallbacks client_cbs;
    client_cbs.connected = [](ConnectionId conn) { s_conn = conn; };
    client_cbs.packet_sent = [](ConnectionId conn, PacketId id, std::byte* data, int len, uint8_t channel)
    {
        s_packet_id = id;
        memcpy(&s_data, data, sizeof(s_data));
        s_len = len;
        s_channel = channel;
    };

    HostCallbacks server_cbs;
    server_cbs.packet_received = [](ConnectionId conn, std::byte* data, int len, uint8_t channel, void(*deleter)(void*))
    { 
        memcpy(&s_data, data, sizeof(s_data));
        s_len = len;
        s_channel = channel;
        s_deleter = deleter;
    };

    auto [client, server] = create_connected_pair(client_cbs, server_cbs);

    // default usage

    for (int i = 0; i < 64; ++i)
    {
        PacketId packet_id = client.send_unreliable(s_conn, (std::byte*)&i, sizeof(i), i);

        client.update_outgoing();
        PFTEST_EXPECT(s_packet_id == packet_id);
        PFTEST_EXPECT(s_data == i);
        PFTEST_EXPECT(s_len == sizeof(i));
        PFTEST_EXPECT(s_channel == i);

        server.update_incoming();
        PFTEST_EXPECT(s_data == i);
        PFTEST_EXPECT(s_len == sizeof(i));
        PFTEST_EXPECT(s_channel == i);
        PFTEST_EXPECT(!s_deleter);
    }

    // test other allocation modes

    int data = 52;
    client.send_unreliable(s_conn, (std::byte*)&data, sizeof(data), 0, PacketLifetime::CallerGuaranteesLifetime);
    client.update_outgoing();
    server.update_incoming();

    static bool s_freed = false;
    client.send_unreliable(s_conn, (std::byte*)&data, sizeof(data), 0, PacketLifetime::CallerRelievesOwnership, [](void*) { s_freed = true; });
    client.update_outgoing();
    server.update_incoming();

    PFTEST_EXPECT(s_freed);
}
