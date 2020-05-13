#pragma once

#include <PF_Net/Detail/Export.hpp>

#include <algorithm>
#include <cstddef>
#include <stdint.h>
#include <type_traits>

namespace pf::net { class NetworkByteStream; }

namespace pf::net::detail::protocol
{

#define PFNET_PROTOCOL_VERSION_MAJOR 0
#define PFNET_PROTOCOL_VERSION_MINOR 1

static constexpr char ProtocolVersion[10] =
{
    'P', 'F', '_', 'N', 'e', 't', 
    'v',
    '0' + PFNET_PROTOCOL_VERSION_MAJOR, '.' , '0' + PFNET_PROTOCOL_VERSION_MINOR
};

static constexpr uint32_t EncryptionPadding = 16u;
static constexpr uint32_t EncryptionKeySize = 32u;

// HEADER

enum class CommandType : uint8_t
{
    L2RC_Begin = 0, // local begins handshake with remote
    R2LC_Response = 1, // remote rejects
    L2RC_Complete = 2, // local completes handshake 
    System_Disconnect = 3, // disconnects a connection
    System_Ping = 4, // keep-alive
    Payload_Send = 5, // unreliable user data
    Payload_SendReliableOrdered = 6, // reliable and ordered user data
    Payload_SendFragmented = 7 // fragmented user data
};

struct Header_Command
{
    // Low 3 bits are a sentinel.
    // This is a quick and easy reject for 7/8ths random traffic and encryption failures.
    static constexpr uint8_t SentinelValue = 5;
    static constexpr uint8_t SentinelBits = 3u;
    static constexpr uint8_t SentinelShift = 0u;
    static constexpr uint8_t SentinelMask  = ((1u << SentinelBits) - 1u) << SentinelShift;

    // Next 3 bits refer to the command type (CommandType)
    static constexpr uint8_t CommandTypeBits = 3u;
    static constexpr uint8_t CommandTypeShift = SentinelShift + SentinelBits;
    static constexpr uint8_t CommandTypeMask  = ((1u << CommandTypeBits) - 1u) << CommandTypeShift;

    // Next 2 bits represent the number of bytes that comprise the nonce (2, 4, 6, 8)
    static constexpr uint8_t NonceBytesSentinelValue = 6; // used by unencrypted packets as additional sentinel
    static constexpr uint8_t NonceBytesBits = 2u;
    static constexpr uint8_t NonceBytesShift = CommandTypeShift + CommandTypeBits;
    static constexpr uint8_t NonceBytesMask  = ((1u << NonceBytesBits) - 1u) << NonceBytesShift;

    uint8_t data;

    static constexpr uint32_t MinSize =
        sizeof(data);

    PFNET_API uint8_t get_sentinel() const;
    PFNET_API CommandType get_command_type() const;
    PFNET_API uint8_t get_nonce_bytes() const;

    PFNET_API void set_sentinel(uint8_t sentinel);
    PFNET_API void set_command_type(CommandType command_type);
    PFNET_API void set_nonce_bytes(uint8_t bytes);
};

struct Header_Encrypted
{
    uint64_t nonce;

    static constexpr uint32_t MinSize =
        2; // variable length nonce

    static constexpr uint32_t MaxSize =
        8; // variable length nonce
};

// BODY (SYSTEM, UNENCRYPTED)

struct Body_L2RC_Begin
{
    char version[sizeof(ProtocolVersion)]; // PFNETvx.y - see ProtocolVersion
    std::byte pubkey[EncryptionKeySize]; // local's public key

    static constexpr uint32_t MinSize =
        sizeof(version) + 
        sizeof(pubkey);
};

struct Body_R2LC_Response
{
    uint8_t rejected; // if 0, accepted, else, rejected reason
    std::byte pubkey[EncryptionKeySize]; // remote's public key

    static constexpr uint32_t MinSize =
        sizeof(rejected) +
        sizeof(pubkey);
};

// BODY (SYSTEM, ENCRYPTED)

struct Body_L2RC_Complete
{
    static constexpr uint32_t MinSize = 0;
};

struct Body_System_Disconnect
{
    static constexpr uint32_t MinSize = 0;
};

struct Body_System_Ping
{
    static constexpr uint32_t MinSize = 0;
};

// BODY (PAYLOAD, ENCRYPTED)

struct Body_Payload_Size
{
    // First 10 bits are the payload size.
    static constexpr uint16_t SizeBits     = 10u;
    static constexpr uint16_t SizeShift    = 0u;
    static constexpr uint16_t SizeMask     = ((1u << SizeBits) - 1u) << SizeShift;

    // Remaining 6 bits are the channel.
    static constexpr uint16_t ChannelBits  = 6u;
    static constexpr uint16_t ChannelShift = SizeShift + SizeBits;
    static constexpr uint16_t ChannelMask  = ((1u << ChannelBits) - 1u) << ChannelShift;

    uint16_t size;

    static constexpr uint32_t MinSize =
        sizeof(size);

    PFNET_API uint16_t get_size() const;
    PFNET_API uint8_t get_channel() const;

    PFNET_API void set_size(uint16_t size);
    PFNET_API void set_channel(uint8_t channel);
};

struct Body_Payload_Acks32
{
    uint16_t sequence; // sequence number of this packet
    uint16_t ack; // sequence number of last received packet
    uint32_t ack32; // bitset where bit (ack - n) has been received if true

    static constexpr uint32_t MinSize =
        sizeof(sequence) + 
        sizeof(ack) + 
        sizeof(ack32);
};

struct Body_Payload_FragmentInfo
{
    uint16_t fragment_id; // the unique fragment this refers to
    uint32_t count; // number of fragments
    uint32_t index; // index of this fragment

    static constexpr uint32_t MinSize =
        sizeof(fragment_id) + 
        sizeof(count) + 
        sizeof(index);
};

struct Body_Payload_Send
{
    Body_Payload_Size ps;
    // [payload]

    static constexpr uint32_t MinSize =
        decltype(ps)::MinSize;
};

struct Body_Payload_SendReliableOrdered
{
    Body_Payload_Acks32 a32;
    Body_Payload_Size ps;
    // [payload]

    static constexpr uint32_t MinSize =
        decltype(a32)::MinSize +
        decltype(ps)::MinSize;
};

struct Body_Payload_SendFragmented
{
    Body_Payload_Acks32 a32;
    Body_Payload_FragmentInfo frag;
    Body_Payload_Size ps;
    // [payload]

    static constexpr uint32_t MinSize =
        decltype(a32)::MinSize +
        decltype(frag)::MinSize +
        decltype(ps)::MinSize;
};

static constexpr uint32_t MinPacketSizeUnencrypted =
    std::min
    ({
        Body_L2RC_Begin::MinSize,
        Body_R2LC_Response::MinSize
    }) + Header_Command::MinSize;
static constexpr uint32_t MinPacketSizeEncrypted =
    std::min
    ({
        Body_L2RC_Complete::MinSize,
        Body_System_Disconnect::MinSize,
        Body_System_Ping::MinSize,
        Body_Payload_Send::MinSize,
        Body_Payload_SendReliableOrdered::MinSize,
        Body_Payload_SendFragmented::MinSize 
    }) + Header_Command::MinSize + Header_Encrypted::MinSize + EncryptionPadding;
static constexpr uint32_t MinPacketSize = std::min({ MinPacketSizeUnencrypted, MinPacketSizeEncrypted });
static constexpr uint32_t MaxPayloadSize = (~0u & Body_Payload_Size::SizeMask) >> Body_Payload_Size::SizeShift;
static constexpr uint32_t MaxPayloadChannel = (~0u & Body_Payload_Size::ChannelMask) >> Body_Payload_Size::ChannelShift;
static constexpr uint32_t MaxPacketSizeUnencrypted =
    std::max
    ({
        Body_L2RC_Begin::MinSize,
        Body_R2LC_Response::MinSize
    }) + Header_Command::MinSize;
static constexpr uint32_t MaxPacketSizeEncrypted =
    std::max
    ({
        Body_L2RC_Complete::MinSize,
        Body_System_Disconnect::MinSize,
        Body_System_Ping::MinSize,
        Body_Payload_Send::MinSize,
        Body_Payload_SendReliableOrdered::MinSize,
        Body_Payload_SendFragmented::MinSize 
    }) + Header_Command::MinSize + Header_Encrypted::MaxSize + MaxPayloadSize + EncryptionPadding;
static constexpr uint32_t MaxPacketSize = std::max({ MaxPacketSizeUnencrypted, MaxPacketSizeEncrypted });

// The following provides an easy method to map between types and their command types (enum).

#define PFNET_WRITE_CMD_TYPE(T) template<> struct TypeToCommandType<Body_##T> { static constexpr CommandType type = CommandType::T; }

template <typename T> struct TypeToCommandType { };
PFNET_WRITE_CMD_TYPE(L2RC_Begin);
PFNET_WRITE_CMD_TYPE(R2LC_Response);
PFNET_WRITE_CMD_TYPE(L2RC_Complete);
PFNET_WRITE_CMD_TYPE(System_Disconnect);
PFNET_WRITE_CMD_TYPE(System_Ping);
PFNET_WRITE_CMD_TYPE(Payload_Send);
PFNET_WRITE_CMD_TYPE(Payload_SendReliableOrdered);
PFNET_WRITE_CMD_TYPE(Payload_SendFragmented);

#undef PFNET_WRITE_CMD_TYPE

// Note: The below functions (write_to_buffer and read_from_buffer) handle encryption.

PFNET_API int write_to_buffer(std::byte* buff, int buff_len, const Body_L2RC_Begin* body);
PFNET_API int write_to_buffer(std::byte* buff, int buff_len, const Body_R2LC_Response* body);
PFNET_API int write_to_buffer(std::byte* buff, int buff_len, const std::byte* key, uint64_t nonce, const Body_L2RC_Complete* body);
PFNET_API int write_to_buffer(std::byte* buff, int buff_len, const std::byte* key, uint64_t nonce, const Body_System_Disconnect* body);
PFNET_API int write_to_buffer(std::byte* buff, int buff_len, const std::byte* key, uint64_t nonce, const Body_System_Ping* body);
PFNET_API int write_to_buffer(std::byte* buff, int buff_len, const std::byte* key, uint64_t nonce, const Body_Payload_Send* body, const std::byte* payload);
PFNET_API int write_to_buffer(std::byte* buff, int buff_len, const std::byte* key, uint64_t nonce, const Body_Payload_SendReliableOrdered* body, const std::byte* payload);
PFNET_API int write_to_buffer(std::byte* buff, int buff_len, const std::byte* key, uint64_t nonce, const Body_Payload_SendFragmented* body, const std::byte* payload);

// Implementation note: it would be lovely to use std::variant here, but the code is just too slow and bloated
struct Command
{
    CommandType command;

    union
    {
        Body_L2RC_Begin begin;
        Body_R2LC_Response response;
        Body_L2RC_Complete complete;
        Body_System_Disconnect disconnect;
        Body_System_Ping ping;
        struct { Body_Payload_Send body; std::byte* payload; } send;
        struct { Body_Payload_SendReliableOrdered body; std::byte* payload; } send_rel;
        struct { Body_Payload_SendFragmented body; std::byte* payload; } send_frag;     
    };
};

static_assert(std::is_pod<Command>::value);

PFNET_API int read_from_buffer(std::byte* buff, int buff_len, Command* out); // unencrypted
PFNET_API int read_from_buffer(std::byte* buff, int buff_len, const std::byte* key, Command* out); // encrypted

// Generates a random key in the provided buffer.
int generate_keypair(std::byte* public_key, std::byte* private_key);
int generate_session_keys_client(const std::byte* our_public_key, const std::byte* our_private_key, const std::byte* their_public_key,
    std::byte* shared_incoming_key, std::byte* shared_outgoing_key);
int generate_session_keys_server(const std::byte* our_public_key, const std::byte* our_private_key, const std::byte* their_public_key,
    std::byte* shared_incoming_key, std::byte* shared_outgoing_key);

}
