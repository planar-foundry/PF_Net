#include <PF_Net/NetworkByteStream.hpp>
#include <PF_Net/Detail/Assert.hpp>
#include <PF_Net/Detail/Log.hpp>
#include <PF_Net/Endian.hpp>

#include <string.h>

namespace pf::net
{

NetworkByteStream::NetworkByteStream(Mode mode, std::byte* buff, int len)
    : m_mode(mode), m_buff(buff), m_len(len), m_head(0)
{ }

NetworkByteStream::Mode NetworkByteStream::mode() const
{
    return m_mode;
}

std::byte* NetworkByteStream::buffer() const
{
    return m_buff;
}

int NetworkByteStream::len() const
{
    return m_len;
}

int NetworkByteStream::len_remaining() const
{
    return m_len - m_head;
}

int NetworkByteStream::head() const
{
    return m_head;
}

bool NetworkByteStream::overflow() const
{
    return len_remaining() < 0;
}

void NetworkByteStream::seek(int at)
{
    m_head = at;
}

bool NetworkByteStream::do_u8(uint8_t* address)
{
    if (m_mode == Mode::Read)
    {
        return read_bytes(address, 1);
    }

    return write_bytes(address, 1);
}

bool NetworkByteStream::do_u16(uint16_t* address)
{
    if (m_mode == Mode::Read)
    {
        uint16_t ret;
        bool success = read_bytes(&ret, 2);
        *address = PFNET_ENDIAN_SWAP_16(ret);
        return success;
    }

    uint16_t ret = PFNET_ENDIAN_SWAP_16(*address);
    return write_bytes(&ret, 2);
}

bool NetworkByteStream::do_u32(uint32_t* address)
{
    if (m_mode == Mode::Read)
    {
        uint32_t ret;
        bool success = read_bytes(&ret, 4);
        *address = PFNET_ENDIAN_SWAP_32(ret);
        return success;
    }

    uint32_t ret = PFNET_ENDIAN_SWAP_32(*address);
    return write_bytes(&ret, 4);
}

bool NetworkByteStream::do_u64(uint64_t* address)
{
    if (m_mode == Mode::Read)
    {
        uint64_t ret;
        bool success = read_bytes(&ret, 8);
        *address = PFNET_ENDIAN_SWAP_64(ret);
        return success;
    }

    uint64_t ret = PFNET_ENDIAN_SWAP_64(*address);
    return write_bytes(&ret, 8);
}

bool NetworkByteStream::do_uvar(uint64_t* address, uint8_t size)
{
    PFNET_ASSERT(size <= sizeof(*address));

#if defined(PFNET_BYTE_ORDER_BIG_ENDIAN)
    uint8_t offset = sizeof(*address) - size;
#else
    uint8_t offset = 0;
#endif

    if (m_mode == Mode::Read)
    {
        uint64_t ret = 0;
        bool success = read_bytes(((std::byte*)&ret) + offset, size);
        *address = PFNET_ENDIAN_SWAP_64(ret);
        return success;
    }

    uint64_t ret = PFNET_ENDIAN_SWAP_64(*address);
    return write_bytes(((std::byte*)&ret) + offset, size);
}

bool NetworkByteStream::do_i8(int8_t* address)
{
    return do_u8((uint8_t*)address);
}

bool NetworkByteStream::do_i16(int16_t* address)
{
    return do_u16((uint16_t*)address);
}

bool NetworkByteStream::do_i32(int32_t* address)
{
    return do_u32((uint32_t*)address);
}

bool NetworkByteStream::do_i64(int64_t* address)
{
    return do_u64((uint64_t*)address);
}

bool NetworkByteStream::do_f32(float* address)
{
    return do_u32((uint32_t*)address);
}

bool NetworkByteStream::do_f64(double* address)
{
    return do_u64((uint64_t*)address);
}

bool NetworkByteStream::do_bytes(int len, std::byte* address)
{
    if (m_mode == Mode::Read)
    {
        return read_bytes((void*)address, len);
    }

    return write_bytes((void*)address, len);
}

bool NetworkByteStream::read_bytes(void* dst, int bytes)
{
    bool valid = true;
    int new_head = m_head + bytes;
    if (new_head > m_len)
    {
        PFNET_LOG_WARN("NetworkByteStream buffer overflow when reading.");
        valid = false;
        memset(dst, 0, bytes);
    }
    else
    {
        memcpy(dst, m_buff + m_head, bytes);
    }
    m_head = new_head;
    return valid;
}

bool NetworkByteStream::write_bytes(void* data, int bytes)
{
    bool valid = true;
    int new_head = m_head + bytes;
    if (new_head > m_len)
    {
        PFNET_ASSERT_FAIL_MSG("NetworkByteStream buffer overflow when writing.");
        valid = false;
    }
    else
    {
        PFNET_ASSERT(data);
        memcpy(m_buff + m_head, data, bytes);
    }
    m_head = new_head;
    return valid;
}

}
