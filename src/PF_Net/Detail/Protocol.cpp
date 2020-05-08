#include <PF_Net/Detail/Protocol.hpp>
#include <PF_Net/NetworkByteStream.hpp>
#include <PF_Net/Detail/Assert.hpp>
#include <PF_Net/Detail/Instrumentation.hpp>
#include <PF_Net/Detail/Log.hpp>

#include <string.h>

#include "sodium.h"

namespace pf::net::detail::protocol
{

static_assert(EncryptionKeySize == crypto_secretbox_KEYBYTES,
    "EncryptionKeySize may need to be updated in the header.");

static_assert(EncryptionPadding == crypto_secretbox_MACBYTES,
    "EncryptionPadding may need to be updated in the header.");

// Helpers

bool decrypt(std::byte* buff, int buff_len, int data_len, const std::byte* key, uint64_t nonce)
{
    PFNET_PERF_FUNC_SCOPE();
    PFNET_ASSERT(buff_len >= data_len + (int)EncryptionPadding);

    unsigned char nonce_arr[crypto_secretbox_NONCEBYTES] = { 0 };
    memcpy(nonce_arr, &nonce, sizeof(nonce));

    if (crypto_secretbox_open_easy(
        (unsigned char*)buff,
        (unsigned char*)buff,
        data_len + EncryptionPadding,
        nonce_arr,
        (unsigned char*)key))
    {
        PFNET_LOG_WARN("Failed to decrypt data of length %d.\n", data_len);
        return false;
    }

    return true;
}

bool encrypt(std::byte* buff, int buff_len, int data_len, const std::byte* key, uint64_t nonce)
{
    PFNET_PERF_FUNC_SCOPE();
    PFNET_ASSERT(buff_len >= data_len + (int)EncryptionPadding);

    unsigned char nonce_arr[crypto_secretbox_NONCEBYTES] = { 0 };
    memcpy(nonce_arr, &nonce, sizeof(nonce));

    if (crypto_secretbox_easy(
        (unsigned char*)buff,
        (unsigned char*)buff,
        data_len,
        nonce_arr,
        (unsigned char*)key))
    {
        PFNET_LOG_WARN("Failed to encrypt data of length %d.\n", data_len);
        return false;
    }

    return true;
}

uint8_t Header_Command::get_sentinel() const { return (data & SentinelMask) >> SentinelShift; }
CommandType Header_Command::get_command_type() const { return (CommandType)((data & CommandTypeMask) >> CommandTypeShift); }
uint8_t Header_Command::get_nonce_bytes() const { return ((data & NonceBytesMask) >> NonceBytesShift) * 2 + 2; }
uint16_t Body_Payload_Size::get_size() const { return (size & SizeMask) >> SizeShift; }
uint8_t Body_Payload_Size::get_channel() const { return (size & ChannelMask) >> ChannelShift; }

void Header_Command::set_sentinel(uint8_t sentinel)
{
    PFNET_ASSERT_MSG(sentinel == SentinelValue,
        "Protocol: Attempting to set the sentinel incorrectly to %u.", sentinel);

    data &= ~SentinelMask;
    data |= sentinel << SentinelShift;
}

void Header_Command::set_command_type(CommandType command_type)
{
    data &= ~CommandTypeMask;
    data |= (uint8_t)command_type << CommandTypeShift;
}

void Header_Command::set_nonce_bytes(uint8_t bytes)
{
    PFNET_ASSERT_MSG(
        bytes == 2 || bytes == 4 || bytes == 6 || bytes == 8,
        "Protocol: Nonce cannot be size %d.", bytes);

    bytes -= 2;
    bytes /= 2;

    data &= ~NonceBytesMask;
    data |= bytes << NonceBytesShift;
}

void Body_Payload_Size::set_size(uint16_t _size)
{
    PFNET_ASSERT_MSG(_size <= MaxPayloadSize,
        "Protocol: Payload size was %u too big.", _size);

    size &= ~SizeMask;
    size |= _size << SizeShift;
}

void Body_Payload_Size::set_channel(uint8_t channel)
{
    size &= ~ChannelMask;
    size |= channel << ChannelShift;
}

// HEADER

void serialize(NetworkByteStream* stream, Header_Command* header)
{
    stream->do_u8(&header->data);
}

void serialize(NetworkByteStream* stream, Header_Encrypted* header, uint8_t bytes_required_for_nonce)
{
    stream->do_uvar(&header->nonce, bytes_required_for_nonce);
}

// BODY (SYSTEM, UNENCRYPTED)

void serialize(NetworkByteStream* stream, Body_L2RC_Begin* body)
{
    stream->do_bytes(sizeof(body->version), (std::byte*)body->version);
    stream->do_bytes(sizeof(body->pubkey), body->pubkey);
}

void serialize(NetworkByteStream* stream, Body_R2LC_Response* body)
{
    stream->do_u8(&body->rejected);
    stream->do_bytes(sizeof(body->pubkey), body->pubkey);
}

// BODY (SYSTEM, ENCRYPTED)

void serialize(NetworkByteStream* stream, Body_L2RC_Complete* body)
{
    (void)stream; (void)body;
}

void serialize(NetworkByteStream* stream, Body_System_Disconnect* body)
{
    (void)stream; (void)body;
}

void serialize(NetworkByteStream* stream, Body_System_Ping* body)
{
    (void)stream; (void)body;
}

// BODY (PAYLOAD, ENCRYPTED)

void serialize(NetworkByteStream* stream, Body_Payload_Size* header)
{
    stream->do_u16(&header->size);
}

void serialize(NetworkByteStream* stream, Body_Payload_Acks32* header)
{
    stream->do_u16(&header->sequence);
    stream->do_u16(&header->ack);
    stream->do_u32(&header->ack32);
}

void serialize(NetworkByteStream* stream, Body_Payload_FragmentInfo* header)
{
    stream->do_u16(&header->fragment_id);
    stream->do_u32(&header->count);
    stream->do_u32(&header->index);
}

void serialize_payload(NetworkByteStream* stream, std::byte** payload, uint16_t len)
{
    if (stream->mode() == NetworkByteStream::Mode::Read)
    {
        // This is an optimization. There's no point copying it out of the buffer - let's leave that up to the user.
        // Instead, we grab a raw pointer from inside the stream and return it.
        *payload = stream->buffer() + stream->head();
        stream->seek(stream->head() + len);
    }
    else
    {
        stream->do_bytes(len, *payload);
    }
}

void serialize(NetworkByteStream* stream, Body_Payload_Send* body, std::byte** payload)
{
    serialize(stream, &body->ps);
    serialize_payload(stream, payload, body->ps.get_size());
}

void serialize(NetworkByteStream* stream, Body_Payload_SendReliableOrdered* body, std::byte** payload)
{
    serialize(stream, &body->a32);
    serialize(stream, &body->ps);
    serialize_payload(stream, payload, body->ps.get_size());
}

void serialize(NetworkByteStream* stream, Body_Payload_SendFragmented* body, std::byte** payload)
{
    serialize(stream, &body->a32);
    serialize(stream, &body->frag);
    serialize(stream, &body->ps);
    serialize_payload(stream, payload, body->ps.get_size());
}

uint8_t get_nonce_bytes(uint64_t nonce)
{
    uint8_t bytes = 2;
    while (nonce >>= 16)
    { 
        bytes += 2;
    }
    return bytes;
}

template <typename T>
void serialize_body(NetworkByteStream* stream, const T* body, const std::byte* payload);

template <>
void serialize_body(NetworkByteStream* stream, const Body_Payload_Send* body, const std::byte* payload)
{
    serialize(stream, const_cast<Body_Payload_Send*>(body), const_cast<std::byte**>(&payload));
}

template <>
void serialize_body(NetworkByteStream* stream, const Body_Payload_SendReliableOrdered* body, const std::byte* payload)
{
    serialize(stream, const_cast<Body_Payload_SendReliableOrdered*>(body), const_cast<std::byte**>(&payload));
}

template <>
void serialize_body(NetworkByteStream* stream, const Body_Payload_SendFragmented* body, const std::byte* payload)
{
    serialize(stream, const_cast<Body_Payload_SendFragmented*>(body), const_cast<std::byte**>(&payload));
}

template <typename T>
void serialize_body(NetworkByteStream* stream, const T* body, const std::byte*)
{
    serialize(stream, const_cast<T*>(body));
}

template <typename T>
int write_to_buffer_impl(NetworkByteStream* stream, const T* body,
    const std::byte* key = nullptr, uint64_t nonce = 0, const std::byte* payload = nullptr)
{
    PFNET_PERF_FUNC_SCOPE();

    bool has_encryption = key != nullptr;

    Header_Command hc;
    hc.set_sentinel(Header_Command::SentinelValue);
    hc.set_command_type(TypeToCommandType<T>::type);
    hc.set_nonce_bytes(has_encryption ? get_nonce_bytes(nonce) : Header_Command::NonceBytesSentinelValue);
    serialize(stream, &hc);

    if (has_encryption)
    {
        Header_Encrypted he;
        he.nonce = nonce;
        serialize(stream, &he, hc.get_nonce_bytes());
    }

    int header_size = stream->head();
    serialize_body(stream, const_cast<T*>(body), payload);

    if (stream->overflow())
    {
        PFNET_ASSERT_FAIL_MSG("Protocol: Outgoing buffer overflow.");
        return -1;
    }

    if (has_encryption)
    {
        if (stream->len_remaining() < (int)EncryptionPadding)
        {
            PFNET_ASSERT_FAIL_MSG("Protocol: Failed to write encrypted traffic, not enough buffer space.");
            return -1;
        }

        if (!encrypt(
            stream->buffer() + header_size,
            stream->len(),
            stream->head() - header_size,
            key,
            nonce))
        {
            PFNET_ASSERT_FAIL_MSG("Protocol: Failed to encrypt traffic.");
            return -1;
        }

        stream->seek(stream->head() + EncryptionPadding);
    }

    return stream->head();
}

int write_to_buffer(std::byte* buff, int buff_len, const Body_L2RC_Begin* body)
{
    NetworkByteStream stream(NetworkByteStream::Mode::Write, buff, buff_len);
    return write_to_buffer_impl(&stream, body);
}

int write_to_buffer(std::byte* buff, int buff_len, const Body_R2LC_Response* body)
{
    NetworkByteStream stream(NetworkByteStream::Mode::Write, buff, buff_len);
    return write_to_buffer_impl(&stream, body);
}

int write_to_buffer(std::byte* buff, int buff_len, const std::byte* key, uint64_t nonce, const Body_L2RC_Complete* body)
{
    NetworkByteStream stream(NetworkByteStream::Mode::Write, buff, buff_len);
    return write_to_buffer_impl(&stream, body, key, nonce);
}

int write_to_buffer(std::byte* buff, int buff_len, const std::byte* key, uint64_t nonce, const Body_System_Disconnect* body)
{
    NetworkByteStream stream(NetworkByteStream::Mode::Write, buff, buff_len);
    return write_to_buffer_impl(&stream, body, key, nonce);
}

int write_to_buffer(std::byte* buff, int buff_len, const std::byte* key, uint64_t nonce, const Body_System_Ping* body)
{
    NetworkByteStream stream(NetworkByteStream::Mode::Write, buff, buff_len);
    return write_to_buffer_impl(&stream, body, key, nonce);
}

int write_to_buffer(std::byte* buff, int buff_len, const std::byte* key, uint64_t nonce, const Body_Payload_Send* body, const std::byte* payload)
{
    NetworkByteStream stream(NetworkByteStream::Mode::Write, buff, buff_len);
    return write_to_buffer_impl(&stream, body, key, nonce, payload);
}

int write_to_buffer(std::byte* buff, int buff_len, const std::byte* key, uint64_t nonce, const Body_Payload_SendReliableOrdered* body, const std::byte* payload)
{
    NetworkByteStream stream(NetworkByteStream::Mode::Write, buff, buff_len);
    return write_to_buffer_impl(&stream, body, key, nonce, payload);
}

int write_to_buffer(std::byte* buff, int buff_len, const std::byte* key, uint64_t nonce, const Body_Payload_SendFragmented* body, const std::byte* payload)
{
    NetworkByteStream stream(NetworkByteStream::Mode::Write, buff, buff_len);
    return write_to_buffer_impl(&stream, body, key, nonce, payload);
}

int read_from_buffer(std::byte* buff, int buff_len, Command* out)
{
    return read_from_buffer(buff, buff_len, nullptr, out);
}

int read_from_buffer(std::byte* buff, int buff_len, const std::byte* key, Command* out)
{
    PFNET_PERF_FUNC_SCOPE();

    NetworkByteStream stream(NetworkByteStream::Mode::Read, buff, buff_len);

    Header_Command header_command;
    serialize(&stream, &header_command);

    if (header_command.get_sentinel() != Header_Command::SentinelValue)
    {
        PFNET_LOG_WARN("Protocol: Sentinel %u did not match.", header_command.get_sentinel());
        return -1;
    }

    CommandType command_type = header_command.get_command_type();

    bool encryption =
        command_type != CommandType::L2RC_Begin &&
        command_type != CommandType::R2LC_Response; 

    if (encryption)
    {
        PFNET_ASSERT(key);

        if (stream.len() < (int)MinPacketSizeEncrypted)
        {
            PFNET_LOG_WARN("Protocol: Encrypted traffic without enough space for the smallest packet.");
            return -1;
        }

        if (stream.len() > (int)MaxPacketSizeEncrypted)
        {
            PFNET_LOG_WARN("Protocol: Encrypted traffic taking more space than the biggest packet.");
            return -1;
        }

        Header_Encrypted header_encrypted;
        serialize(&stream, &header_encrypted, header_command.get_nonce_bytes());

        if (!decrypt(buff + stream.head(), 
            stream.len_remaining(), 
            stream.len_remaining() - EncryptionPadding,
            key, 
            header_encrypted.nonce))
        {
            PFNET_LOG_WARN("Protocol: Encrypted traffic failed to decrypt.");
            return -1;
        }
    }
    else
    {
        if (header_command.get_nonce_bytes() != Header_Command::NonceBytesSentinelValue)
        {
            PFNET_LOG_WARN("Protocol: Nonce sentinel %d did not match.", header_command.get_nonce_bytes());
            return -1;
        }

        if (stream.len() < (int)MinPacketSizeUnencrypted)
        {
            PFNET_LOG_WARN("Protocol: Unencrypted traffic without enough space for the smallest packet.");
            return -1;
        }

        if (stream.len() > (int)MaxPacketSizeUnencrypted)
        {
            PFNET_LOG_WARN("Protocol: Unencrypted traffic taking more space than the biggest packet.");
            return -1;
        }
    }

    out->command = command_type;

    switch (command_type)
    {
        case CommandType::L2RC_Begin:                  serialize(&stream, &out->data.begin); break;
        case CommandType::R2LC_Response:               serialize(&stream, &out->data.response); break;
        case CommandType::L2RC_Complete:               serialize(&stream, &out->data.complete); break;
        case CommandType::System_Disconnect:           serialize(&stream, &out->data.disconnect); break;
        case CommandType::System_Ping:                 serialize(&stream, &out->data.ping); break;
        case CommandType::Payload_Send:                serialize(&stream, &out->data.send.body,      &out->data.send.payload); break;
        case CommandType::Payload_SendReliableOrdered: serialize(&stream, &out->data.send_rel.body,  &out->data.send_rel.payload); break;
        case CommandType::Payload_SendFragmented:      serialize(&stream, &out->data.send_frag.body, &out->data.send_frag.payload); break;
        default: PFNET_LOG_WARN("Unrecognised command %u.", command_type); return -1;
    }

    if (stream.overflow())
    {
        PFNET_LOG_WARN("Protocol: Incoming packet overflow.");
        return -1;
    }

    if (encryption)
    {
        stream.seek(stream.head() + EncryptionPadding);
    }

    if (stream.len_remaining() != 0)
    {
        PFNET_LOG_WARN("Protocol: Incoming packet underflow.");
        return -1;
    }

    return stream.head();
}

int generate_keypair(std::byte* public_key, std::byte* private_key)
{
    return crypto_kx_keypair((unsigned char*)public_key, (unsigned char*)private_key);
}

int generate_session_keys_client(const std::byte* our_public_key, const std::byte* our_private_key, const std::byte* their_public_key,
    std::byte* shared_incoming_key, std::byte* shared_outgoing_key)
{
    return crypto_kx_client_session_keys(
        (unsigned char*)shared_incoming_key,
        (unsigned char*)shared_outgoing_key, 
        (unsigned char*)our_public_key,
        (unsigned char*)our_private_key, 
        (unsigned char*)their_public_key);
}

int generate_session_keys_server(const std::byte* our_public_key, const std::byte* our_private_key, const std::byte* their_public_key,
    std::byte* shared_incoming_key, std::byte* shared_outgoing_key)
{
    return crypto_kx_server_session_keys(
        (unsigned char*)shared_incoming_key,
        (unsigned char*)shared_outgoing_key, 
        (unsigned char*)our_public_key,
        (unsigned char*)our_private_key, 
        (unsigned char*)their_public_key);
}

}
