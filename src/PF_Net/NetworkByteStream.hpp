#pragma once

#include <PF_Net/Detail/Export.hpp>

#include <cstddef>
#include <stdint.h>
#include <utility>

namespace pf::net
{

class NetworkByteStream
{
public:
    enum class Mode
    {
        Read,
        Write
    };

    PFNET_API NetworkByteStream(Mode mode, std::byte* buff, int len);

    PFNET_API Mode mode() const;
    PFNET_API std::byte* buffer() const;
    PFNET_API int len() const;
    PFNET_API int len_remaining() const;
    PFNET_API int head() const;
    PFNET_API bool overflow() const;
    PFNET_API void seek(int at);

    PFNET_API bool do_u8(uint8_t* address);
    PFNET_API bool do_u16(uint16_t* address);
    PFNET_API bool do_u32(uint32_t* address);
    PFNET_API bool do_u64(uint64_t* address);
    PFNET_API bool do_uvar(uint64_t* address, uint8_t size);

    PFNET_API bool do_i8(int8_t* address);
    PFNET_API bool do_i16(int16_t* address);
    PFNET_API bool do_i32(int32_t* address);
    PFNET_API bool do_i64(int64_t* address);

    PFNET_API bool do_f32(float* address);
    PFNET_API bool do_f64(double* address);

    PFNET_API bool do_bytes(int len, std::byte* address);

private:
    Mode m_mode;
    std::byte* m_buff;
    int m_len;
    int m_head;

    bool read_bytes(void* dst, int bytes);
    bool write_bytes(void* data, int bytes);
};

}
