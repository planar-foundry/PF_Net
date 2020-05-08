#include "UnitTest.hpp"
#include <PF_Net/NetworkByteStream.hpp>
#include <string.h>

using namespace pf::net;

PFNET_TEST_CREATE(NetworkByteStream_Primitive)
{
    std::byte buff[128] = { std::byte(0) };

    NetworkByteStream wstream(NetworkByteStream::Mode::Write, buff, sizeof(buff));
    NetworkByteStream rstream(NetworkByteStream::Mode::Read, buff, sizeof(buff));

    uint8_t w_u8 = 0x6F;
    uint16_t w_u16 = 0x6F2F;
    uint32_t w_u32 = 0x6F2F6F2F;
    uint64_t w_u64 = 0x6F2F6F2F6F2F6F2F;
    int8_t w_i8 = 0x6F;
    int16_t w_i16 = 0x6F2F;
    int32_t w_i32 = 0x6F2F6F2F;
    int64_t w_i64 = 0x6F2F6F2F6F2F6F2F;
    float w_f32 = 0.1234f;
    double w_f64 = 0.12345678f;

    PFNET_TEST_EXPECT(wstream.do_u8(&w_u8));
    PFNET_TEST_EXPECT(wstream.do_u16(&w_u16));
    PFNET_TEST_EXPECT(wstream.do_u32(&w_u32));
    PFNET_TEST_EXPECT(wstream.do_u64(&w_u64));
    PFNET_TEST_EXPECT(wstream.do_i8(&w_i8));
    PFNET_TEST_EXPECT(wstream.do_i16(&w_i16));
    PFNET_TEST_EXPECT(wstream.do_i32(&w_i32));
    PFNET_TEST_EXPECT(wstream.do_i64(&w_i64));
    PFNET_TEST_EXPECT(wstream.do_f32(&w_f32));
    PFNET_TEST_EXPECT(wstream.do_f64(&w_f64));
    PFNET_TEST_EXPECT(!wstream.overflow());

    uint8_t r_u8;
    uint16_t r_u16;
    uint32_t r_u32;
    uint64_t r_u64;
    int8_t r_i8;
    int16_t r_i16;
    int32_t r_i32;
    int64_t r_i64;
    float r_f32;
    double r_f64;

    PFNET_TEST_EXPECT(rstream.do_u8(&r_u8));
    PFNET_TEST_EXPECT(rstream.do_u16(&r_u16));
    PFNET_TEST_EXPECT(rstream.do_u32(&r_u32));
    PFNET_TEST_EXPECT(rstream.do_u64(&r_u64));
    PFNET_TEST_EXPECT(rstream.do_i8(&r_i8));
    PFNET_TEST_EXPECT(rstream.do_i16(&r_i16));
    PFNET_TEST_EXPECT(rstream.do_i32(&r_i32));
    PFNET_TEST_EXPECT(rstream.do_i64(&r_i64));
    PFNET_TEST_EXPECT(rstream.do_f32(&r_f32));
    PFNET_TEST_EXPECT(rstream.do_f64(&r_f64));
    PFNET_TEST_EXPECT(!rstream.overflow());

    PFNET_TEST_EXPECT(w_u8 == r_u8);
    PFNET_TEST_EXPECT(w_u16 == r_u16);
    PFNET_TEST_EXPECT(w_u32 == r_u32);
    PFNET_TEST_EXPECT(w_u64 == r_u64);
    PFNET_TEST_EXPECT(w_i8 == r_i8);
    PFNET_TEST_EXPECT(w_i16 == r_i16);
    PFNET_TEST_EXPECT(w_i32 == r_i32);
    PFNET_TEST_EXPECT(w_i64 == r_i64);
    PFNET_TEST_EXPECT(w_f32 == r_f32);
    PFNET_TEST_EXPECT(w_f64 == r_f64);
}

PFNET_TEST_CREATE(NetworkByteStream_Variable)
{    
    std::byte buff[128] = { std::byte(0) };
    NetworkByteStream wstream(NetworkByteStream::Mode::Write, buff, sizeof(buff));
    NetworkByteStream rstream(NetworkByteStream::Mode::Read, buff, sizeof(buff));

    uint64_t w_1 = 0x0F;
    uint64_t w_2 = 0x2F0F;
    uint64_t w_3 = 0x4F2F0F;
    uint64_t w_4 = 0x6F4F2F0F;
    uint64_t w_5 = 0x8F6F4F2F0F;
    uint64_t w_6 = 0xAF8F6F4F2F0F;
    uint64_t w_7 = 0xCFAF8F6F4F2F0F;
    uint64_t w_8 = 0xEFCFAF8F6F4F2F0F;

    PFNET_TEST_EXPECT(wstream.do_uvar(&w_1, 1));
    PFNET_TEST_EXPECT(wstream.do_uvar(&w_2, 2));
    PFNET_TEST_EXPECT(wstream.do_uvar(&w_3, 3));
    PFNET_TEST_EXPECT(wstream.do_uvar(&w_4, 4));
    PFNET_TEST_EXPECT(wstream.do_uvar(&w_5, 5));
    PFNET_TEST_EXPECT(wstream.do_uvar(&w_6, 6));
    PFNET_TEST_EXPECT(wstream.do_uvar(&w_7, 7));
    PFNET_TEST_EXPECT(wstream.do_uvar(&w_8, 8));

    uint64_t r_1;
    uint64_t r_2;
    uint64_t r_3;
    uint64_t r_4;
    uint64_t r_5;
    uint64_t r_6;
    uint64_t r_7;
    uint64_t r_8;

    PFNET_TEST_EXPECT(rstream.do_uvar(&r_1, 1));
    PFNET_TEST_EXPECT(rstream.do_uvar(&r_2, 2));
    PFNET_TEST_EXPECT(rstream.do_uvar(&r_3, 3));
    PFNET_TEST_EXPECT(rstream.do_uvar(&r_4, 4));
    PFNET_TEST_EXPECT(rstream.do_uvar(&r_5, 5));
    PFNET_TEST_EXPECT(rstream.do_uvar(&r_6, 6));
    PFNET_TEST_EXPECT(rstream.do_uvar(&r_7, 7));
    PFNET_TEST_EXPECT(rstream.do_uvar(&r_8, 8));

    PFNET_TEST_EXPECT(w_1 == r_1);
    PFNET_TEST_EXPECT(w_2 == r_2);
    PFNET_TEST_EXPECT(w_3 == r_3);
    PFNET_TEST_EXPECT(w_4 == r_4);
    PFNET_TEST_EXPECT(w_5 == r_5);
    PFNET_TEST_EXPECT(w_6 == r_6);
    PFNET_TEST_EXPECT(w_7 == r_7);
    PFNET_TEST_EXPECT(w_8 == r_8);
}

PFNET_TEST_CREATE(NetworkByteStream_BytesString)
{
    std::byte buff[64] = { std::byte(0) };
    NetworkByteStream wstream(NetworkByteStream::Mode::Write, buff, sizeof(buff));
    NetworkByteStream rstream(NetworkByteStream::Mode::Read, buff, sizeof(buff));

    std::byte binary_data[] = { std::byte(0), std::byte(1), std::byte(2), std::byte(3) };
    std::byte new_binary_data[sizeof(binary_data)];
    wstream.do_bytes(sizeof(binary_data), binary_data);
    PFNET_TEST_EXPECT(rstream.do_bytes(sizeof(binary_data), new_binary_data));
    PFNET_TEST_EXPECT(memcmp(new_binary_data, binary_data, sizeof(binary_data)) == 0);

    PFNET_TEST_EXPECT(!wstream.overflow());
    PFNET_TEST_EXPECT(!rstream.overflow());
}

PFNET_TEST_CREATE(NetworkByteStream_Overflow)
{
    NetworkByteStream wstream(NetworkByteStream::Mode::Write, nullptr, 0);
    NetworkByteStream rstream(NetworkByteStream::Mode::Read, nullptr, 0);

    PFNET_TEST_EXPECT(!wstream.overflow());
    PFNET_TEST_EXPECT(!rstream.overflow());

    PFNET_TEST_IGNORE_LOG(true);
    PFNET_TEST_IGNORE_ASSERTS(true); // We expect failures here - but no crashes!

    PFNET_TEST_EXPECT(!wstream.do_u8(nullptr));

    uint8_t u8 = 0xFF;
    PFNET_TEST_EXPECT(!rstream.do_u8(&u8));
    PFNET_TEST_EXPECT(u8 == 0);

    PFNET_TEST_EXPECT(wstream.overflow());
    PFNET_TEST_EXPECT(rstream.overflow());
}

PFNET_TEST_CREATE(NetworkByteStream_Seek)
{
    std::byte buff[64] = { std::byte(0) };
    NetworkByteStream stream(NetworkByteStream::Mode::Write, buff, sizeof(buff));

    stream.seek(0);
    PFNET_TEST_EXPECT(stream.head() == 0);
    PFNET_TEST_EXPECT(!stream.overflow());

    stream.seek(4);
    PFNET_TEST_EXPECT(stream.head() == 4);
    PFNET_TEST_EXPECT(!stream.overflow());

    stream.seek(sizeof(buff));
    PFNET_TEST_EXPECT(stream.head() == sizeof(buff));
    PFNET_TEST_EXPECT(!stream.overflow());
}
