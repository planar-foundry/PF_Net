#include "UnitTest.hpp"
#include <PF_Net/Detail/Socket.hpp>
#include <stdio.h>
#include <string.h>

using namespace pf::net;
using namespace pf::net::detail;

bool verify_send_and_response(char* send_buff, Socket::Buffer* buffers, Socket& from, Socket& to, const Address& address)
{
    // from -> to
    int from_send_bytes = from.send_to(buffers, 2, address);
    if (from_send_bytes != 500) return false;

    // to select
    bool ready_read_to = to.select_read(0);
    if (!ready_read_to) return false;

    // to read
    char to_recv_buff[500];
    Address recv_address;
    int to_recv_bytes = to.recv_from(to_recv_buff, 500, &recv_address);
    if (to_recv_bytes != from_send_bytes) return false;
    if (memcmp(send_buff, to_recv_buff, 500) != 0) return false;

    // to select
    ready_read_to = to.select_read(-1);
    if (ready_read_to) return false;

    // to -> from
    int to_send_bytes = from.send_to(buffers, 2, recv_address);
    if (from_send_bytes != to_send_bytes) return false;

    // from select
    bool ready_read_from = from.select_read(0);
    if (!ready_read_from) return false;

    // from read
    char from_recv_buff[500];
    int from_recv_bytes = from.recv_from(from_recv_buff, 500, &recv_address);
    if (from_recv_bytes != to_send_bytes) return false;
    if (memcmp(send_buff, from_recv_buff, 500) != 0) return false;

    // from select
    ready_read_from = from.select_read(-1);
    if (ready_read_from) return false;

    return true;
}

PFTEST_CREATE(Socket_SendRecvSelect)
{
    Socket server_v4(Socket::Type::IPV4);
    Socket server_v6(Socket::Type::IPV6, Socket::Options::DualStack);

    Socket client_v4(Socket::Type::IPV4);
    Socket client_v6(Socket::Type::IPV6, Socket::Options::DualStack);

    Address send_address_v4(AddressStrIPV4("127.0.0.1"), get_unique_port());
    Address send_address_v6(AddressStrIPV6("::1"), get_unique_port());

    PFTEST_EXPECT(server_v4.listen(send_address_v4.get_port()));
    PFTEST_EXPECT(server_v6.listen(send_address_v6.get_port()));
    PFTEST_EXPECT(client_v4.listen(0));
    PFTEST_EXPECT(client_v6.listen(0));

    bool ready_to_read_server_v4 = server_v4.select_read(-1);
    bool ready_to_read_server_v6 = server_v6.select_read(-1);
    bool ready_to_read_client_v4 = client_v4.select_read(-1);
    bool ready_to_read_client_v6 = client_v6.select_read(-1);

    PFTEST_EXPECT(!ready_to_read_server_v4);
    PFTEST_EXPECT(!ready_to_read_server_v6);
    PFTEST_EXPECT(!ready_to_read_client_v4);
    PFTEST_EXPECT(!ready_to_read_client_v6);

    char send_buff[500];
    snprintf(send_buff, sizeof(send_buff), "Hello network test!");

    Socket::Buffer buffers[2] =
    {
        Socket::Buffer(send_buff, 10),
        Socket::Buffer(send_buff + 10, sizeof(send_buff) - 10)
    };

    PFTEST_EXPECT(verify_send_and_response(send_buff, buffers, client_v4, server_v4, send_address_v4));
    PFTEST_EXPECT(verify_send_and_response(send_buff, buffers, client_v6, server_v4, send_address_v4));
    PFTEST_EXPECT(verify_send_and_response(send_buff, buffers, client_v6, server_v6, send_address_v6));

    // expected to fail
    PFTEST_IGNORE_LOG(true);
    PFTEST_EXPECT(!verify_send_and_response(send_buff, buffers, client_v4, server_v6, send_address_v6));
    PFTEST_IGNORE_LOG(false);
}
