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
#if defined(WIN32)
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

}
