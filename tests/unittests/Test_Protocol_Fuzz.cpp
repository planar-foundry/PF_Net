#include "UnitTest.hpp"
#include <PF_Net/Detail/Protocol.hpp>
#include <PF_Net/Detail/Util.hpp>
#include <string.h>

using namespace pf::net;
using namespace pf::net::detail;
using namespace pf::net::detail::protocol;

static constexpr std::byte TestKey[EncryptionKeySize] = { std::byte(0) };

int write_random_data(std::byte* buff, int len)
{
    int bytes = fast_rand() % (len - 4);
    
    for (int i = 0; i < bytes; i += 4)
    {
        uint32_t rng = fast_rand();
        memcpy(buff + i, &rng, 4);
    }

    return bytes;
}

PFNET_TEST_CREATE(Protocol_Fuzz)
{
    PFNET_TEST_IGNORE_LOG(true);

    std::byte buff[1500];

    for (int i = 0; i < 100000; ++i)
    {
        int random_bytes_written = write_random_data(buff, sizeof(buff));

        Command incoming_command;
        read_from_buffer(buff, random_bytes_written, TestKey, &incoming_command);
    }
}
