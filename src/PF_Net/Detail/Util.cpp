#include <PF_Net/Detail/Util.hpp>

#if defined(WIN32)
    #include <Windows.h>
#else
    #include <time.h>
#endif

namespace pf::net::detail
{

#if defined(WIN32)

LARGE_INTEGER query_hpc()
{
    LARGE_INTEGER hpc;
    QueryPerformanceFrequency(&hpc);
    return hpc;
}

#endif

uint64_t get_timestamp_in_ns()
{
#if defined (WIN32)
    static LARGE_INTEGER freq = query_hpc();

    LARGE_INTEGER time;
    QueryPerformanceCounter(&time);

    time.QuadPart *= 1000 * 1000 * 1000; // To nanoseconds (in system units)
    time.QuadPart /= freq.QuadPart; // To time units

    return time.QuadPart;
#else
    timespec spec;
    clock_gettime(CLOCK_REALTIME, &spec);
    return (uint64_t)spec.tv_sec * 1000 * 1000 * 1000 + spec.tv_nsec;
#endif
}

uint64_t get_timestamp_in_ms()
{
    return get_timestamp_in_ns() / 1000 / 1000;
}

uint32_t fast_rand()
{
    // See https://stackoverflow.com/questions/1640258/need-a-fast-random-generator-for-c
    // This is approximately 40x faster to fill an array using std::generate with rand().

    static uint32_t s_x = 123456789;
    static uint32_t s_y = 362436069;
    static uint32_t s_z = 521288629;

    s_x ^= s_x << 16;
    s_x ^= s_x >> 5;
    s_x ^= s_x << 1;

    uint32_t temp = s_x;
    s_x = s_y;
    s_y = s_z;
    s_z = temp ^ s_x ^ s_y;

    return s_z;
}

}
