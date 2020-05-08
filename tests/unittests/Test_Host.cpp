#include "UnitTest.hpp"
#include <PF_Net/Host.hpp>
#include <stdint.h>

using namespace pf::net;

PFNET_TEST_CREATE(Host_Basic)
{
    static bool s_server_connected_to_client = false;
    static bool s_client_connected_to_server = false;

    HostCallbacks server_cbs;
    server_cbs.connected = [](ConnectionId) { s_server_connected_to_client = true; };
    server_cbs.disconnected = [](ConnectionId) { s_server_connected_to_client = false; };

    HostCallbacks client_cbs;
    client_cbs.connected = [](ConnectionId) { s_client_connected_to_server = true; };
    client_cbs.disconnected = [](ConnectionId) { s_client_connected_to_server = false; };

    uint16_t server_port = get_unique_port();

    Host server(server_cbs, server_port);
    Host client(client_cbs);

    ConnectionId id = client.connect(Address(AddressStrIPV6("::1"), server_port));
    PFNET_TEST_EXPECT(id != InvalidConnectionId);
    PFNET_TEST_EXPECT(!s_client_connected_to_server);

    client.update_outgoing();
    PFNET_TEST_EXPECT(!s_client_connected_to_server);

    server.update_socket();
    server.update_incoming();
    server.update_outgoing();
    PFNET_TEST_EXPECT(!s_server_connected_to_client);

    client.update_socket();
    client.update_incoming();
    client.update_outgoing();
    PFNET_TEST_EXPECT(s_client_connected_to_server);

    server.update_socket();
    server.update_incoming();
    PFNET_TEST_EXPECT(s_server_connected_to_client);

    client.disconnect(id);
    PFNET_TEST_EXPECT(s_client_connected_to_server);

    client.update_outgoing();
    PFNET_TEST_EXPECT(!s_client_connected_to_server);

    server.update_socket();
    server.update_incoming();
    PFNET_TEST_EXPECT(!s_server_connected_to_client);
    PFNET_TEST_EXPECT(!s_client_connected_to_server);
}
