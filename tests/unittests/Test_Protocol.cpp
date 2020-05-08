#include "UnitTest.hpp"
#include <PF_Net/Detail/Protocol.hpp>
#include <functional>
#include <string.h>

using namespace pf::net;
using namespace pf::net::detail;
using namespace pf::net::detail::protocol;

static constexpr std::byte TestKey[EncryptionKeySize] = { std::byte(0) };
static constexpr uint64_t TestNonce = 0;
static constexpr std::byte EmptyByteArray[256] = { std::byte(0) };

// These exist because we can't memcmp due to:
// * Uninitialized padding
// * Zero-sized structures

bool proto_cmp(const Body_L2RC_Begin* lhs, const Body_L2RC_Begin* rhs)
{
    static_assert(Body_L2RC_Begin::MinSize == 42);
    return
        memcmp(lhs->version, rhs->version, sizeof(Body_L2RC_Begin::version)) == 0 &&
        memcmp(lhs->pubkey, rhs->pubkey, sizeof(Body_L2RC_Begin::pubkey)) == 0;
}

bool proto_cmp(const Body_R2LC_Response* lhs, const Body_R2LC_Response* rhs)
{
    static_assert(Body_R2LC_Response::MinSize == 33);
    return
        lhs->rejected == rhs->rejected &&
        memcmp(lhs->pubkey, rhs->pubkey, sizeof(Body_L2RC_Begin::pubkey)) == 0;
}

bool proto_cmp(const Body_L2RC_Complete* lhs, const Body_L2RC_Complete* rhs)
{ 
    static_assert(Body_L2RC_Complete::MinSize == 0);
    return
        true;
}

bool proto_cmp(const Body_System_Disconnect* lhs, const Body_System_Disconnect* rhs)
{ 
    static_assert(Body_System_Disconnect::MinSize == 0);
    return
        true;
}

bool proto_cmp(const Body_System_Ping* lhs, const Body_System_Ping* rhs)
{ 
    static_assert(Body_System_Ping::MinSize == 0);
    return
        true;
}

bool proto_cmp(const Body_Payload_Send* lhs, const Body_Payload_Send* rhs)
{
    static_assert(Body_Payload_Send::MinSize == 2);
    return 
        lhs->ps.size == rhs->ps.size;
}

bool proto_cmp(const Body_Payload_SendReliableOrdered* lhs, const Body_Payload_SendReliableOrdered* rhs)
{
    static_assert(Body_Payload_SendReliableOrdered::MinSize == 10);
    return
        lhs->a32.sequence == rhs->a32.sequence &&
        lhs->a32.ack == rhs->a32.ack &&
        lhs->a32.ack32 == rhs->a32.ack32 &&
        lhs->ps.size == rhs->ps.size;
}

bool proto_cmp(const Body_Payload_SendFragmented* lhs, const Body_Payload_SendFragmented* rhs)
{
    static_assert(Body_Payload_SendFragmented::MinSize == 20);
    return
        lhs->a32.sequence == rhs->a32.sequence &&
        lhs->a32.ack == rhs->a32.ack &&
        lhs->a32.ack32 == rhs->a32.ack32 &&
        lhs->frag.fragment_id == rhs->frag.fragment_id &&
        lhs->frag.count == rhs->frag.count &&
        lhs->frag.index == rhs->frag.index &&
        lhs->ps.size == rhs->ps.size;
}

template <typename T>
void do_rw_test_unencrypted(PFNET_TEST_THIS_ARG)
{
    std::byte buff[MaxPacketSizeUnencrypted] = { std::byte(0xFF) };

    T original_command;
    int len = write_to_buffer(buff, sizeof(buff), &original_command);
    PFNET_TEST_EXPECT(len >= Header_Command::MinSize + T::MinSize);

    Command new_command;
    PFNET_TEST_EXPECT(read_from_buffer(buff, len, &new_command) == len);
    PFNET_TEST_EXPECT(new_command.command == TypeToCommandType<T>::type);

    void* command_data_ptr = nullptr;

    switch (new_command.command)
    {
        case CommandType::L2RC_Begin: command_data_ptr = &new_command.data.begin; break;
        case CommandType::R2LC_Response: command_data_ptr = &new_command.data.response; break;
        default: PFNET_TEST_FAIL(); break;
    }

    PFNET_TEST_EXPECT(proto_cmp(&original_command, (T*)command_data_ptr));
}

template <typename T>
void do_rw_test_overflow_unencrypted(PFNET_TEST_THIS_ARG)
{
    PFNET_TEST_IGNORE_LOG(true);
        
    std::byte buff[1];

    T original_command;
    PFNET_TEST_IGNORE_ASSERTS(true);
    PFNET_TEST_EXPECT(write_to_buffer(buff, sizeof(buff), &original_command) == -1);

    Command new_command;
    PFNET_TEST_IGNORE_ASSERTS(false);
    PFNET_TEST_EXPECT(read_from_buffer(buff, sizeof(buff), &new_command) == -1);

    PFNET_TEST_IGNORE_LOG(false);
}

template <typename T>
void do_test_suite_unencrypted(PFNET_TEST_THIS_ARG)
{
    do_rw_test_unencrypted<T>(PFNET_TEST_THIS);
    do_rw_test_overflow_unencrypted<T>(PFNET_TEST_THIS);
}

PFNET_TEST_CREATE(Protocol_Unencrypted)
{
    do_test_suite_unencrypted<Body_L2RC_Begin>(PFNET_TEST_THIS);
    do_test_suite_unencrypted<Body_R2LC_Response>(PFNET_TEST_THIS);
}

template <typename T>
void do_rw_test_encrypted(PFNET_TEST_THIS_ARG)
{
    std::byte buff[MaxPacketSizeEncrypted] = { std::byte(0xFF) };

    T original_command;
    int len = write_to_buffer(buff, sizeof(buff), TestKey, TestNonce, &original_command);

    Command new_command;
    PFNET_TEST_EXPECT(read_from_buffer(buff, len, TestKey, &new_command) == len);
    PFNET_TEST_EXPECT(new_command.command == TypeToCommandType<T>::type);

    void* command_data_ptr = nullptr;

    switch (new_command.command)
    {
        case CommandType::L2RC_Complete: command_data_ptr = &new_command.data.complete; break;
        case CommandType::System_Disconnect: command_data_ptr = &new_command.data.disconnect; break;
        case CommandType::System_Ping: command_data_ptr = &new_command.data.ping; break;
        default: PFNET_TEST_FAIL(); break;
    }

    PFNET_TEST_EXPECT(proto_cmp(&original_command, (T*)command_data_ptr));
}

template <typename T>
void do_rw_test_overflow_encrypted(PFNET_TEST_THIS_ARG)
{
    PFNET_TEST_IGNORE_LOG(true);
        
    std::byte buff[1] = { std::byte(0xFF) };

    T original_command;
    PFNET_TEST_IGNORE_ASSERTS(true);
    PFNET_TEST_EXPECT(write_to_buffer(buff, sizeof(buff), TestKey, TestNonce, &original_command) == -1);

    Command new_command;
    PFNET_TEST_IGNORE_ASSERTS(false);
    PFNET_TEST_EXPECT(read_from_buffer(buff, sizeof(buff), TestKey, &new_command) == -1);

    PFNET_TEST_IGNORE_LOG(false);
}

template <typename T>
void do_test_suite_encrypted(PFNET_TEST_THIS_ARG)
{
    do_rw_test_encrypted<T>(PFNET_TEST_THIS);
    do_rw_test_overflow_encrypted<T>(PFNET_TEST_THIS);
}

PFNET_TEST_CREATE(Protocol_Encrypted)
{
    do_test_suite_encrypted<Body_L2RC_Complete>(PFNET_TEST_THIS);
    do_test_suite_encrypted<Body_System_Disconnect>(PFNET_TEST_THIS);
    do_test_suite_encrypted<Body_System_Ping>(PFNET_TEST_THIS);
}

template <typename T>
void do_rw_test_payload(PFNET_TEST_THIS_ARG)
{
    std::byte buff[MaxPacketSizeEncrypted] = { std::byte(0xFF) };

    static constexpr uint8_t PayloadChannel = 5;
    std::byte payload[MaxPayloadSize] = { std::byte(0x6F) };

    T original_command;
    original_command.ps.set_size(MaxPayloadSize);
    original_command.ps.set_channel(PayloadChannel);

    int len = write_to_buffer(buff, sizeof(buff), TestKey, TestNonce, &original_command, payload);

    Command new_command;
    PFNET_TEST_EXPECT(read_from_buffer(buff, len, TestKey, &new_command) == len);
    PFNET_TEST_EXPECT(new_command.command == TypeToCommandType<T>::type);

    Body_Payload_Size ps;
    void* command_data_ptr = nullptr;
    std::byte* payload_ptr = nullptr;

    switch (new_command.command)
    {
        case CommandType::Payload_Send:
            command_data_ptr = &new_command.data.send.body;
            ps = new_command.data.send.body.ps;
            payload_ptr = new_command.data.send.payload;
            break;

        case CommandType::Payload_SendReliableOrdered:
            command_data_ptr = &new_command.data.send_rel.body;
            ps = new_command.data.send_rel.body.ps;
            payload_ptr = new_command.data.send_rel.payload;
            break;

        case CommandType::Payload_SendFragmented:
            command_data_ptr = &new_command.data.send_frag.body;
            ps = new_command.data.send_frag.body.ps;
            payload_ptr = new_command.data.send_frag.payload;
            break;

        default: PFNET_TEST_FAIL(); break;
    }

    PFNET_TEST_EXPECT(proto_cmp(&original_command, (T*)command_data_ptr));
    PFNET_TEST_EXPECT(memcmp(payload, payload_ptr, MaxPayloadSize) == 0);
}

template <typename T>
void do_rw_test_overflow_payload(PFNET_TEST_THIS_ARG)
{
    PFNET_TEST_IGNORE_LOG(true);
        
    std::byte buff[1] = { std::byte(0xFF) };
    std::byte payload[1] = { std::byte(0x6F) };

    T original_command;
    PFNET_TEST_IGNORE_ASSERTS(true);
    PFNET_TEST_EXPECT(write_to_buffer(buff, sizeof(buff), TestKey, TestNonce, &original_command, payload) == -1);

    Command new_command;
    PFNET_TEST_IGNORE_ASSERTS(false);
    PFNET_TEST_EXPECT(read_from_buffer(buff, sizeof(buff), TestKey, &new_command) == -1);

    PFNET_TEST_IGNORE_LOG(false);
}

template <typename T>
void do_test_suite_payload(PFNET_TEST_THIS_ARG)
{
    do_rw_test_payload<T>(PFNET_TEST_THIS);
    do_rw_test_overflow_payload<T>(PFNET_TEST_THIS);
}

PFNET_TEST_CREATE(Protocol_Payload)
{
    do_test_suite_payload<Body_Payload_Send>(PFNET_TEST_THIS);
    do_test_suite_payload<Body_Payload_SendReliableOrdered>(PFNET_TEST_THIS);
    do_test_suite_payload<Body_Payload_SendFragmented>(PFNET_TEST_THIS);
}
