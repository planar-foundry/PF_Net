#include "UnitTest.hpp"

#include <PF_Debug/Assert.hpp>
#include <PF_Debug/Log.hpp>
#include <PF_Net/Net.hpp>

uint16_t get_unique_port()
{
    static uint16_t s_port = 42512; return s_port++;
}

void pf::test::unit_test_init(UnitTestResult** result)
{
    pf::net::CustomAllocators allocators;
    allocators.custom_alloc = &custom_alloc;
    allocators.custom_free = &custom_free;

    pf::net::net_init(allocators);

    static UnitTestResult** s_current_test = result;

    pf::debug::set_assert_handler(
        [](const char* cond, const char* file, int line, const char* msg)
    {
        if (!(*s_current_test)->ignore_asserts)
        {
            printf(" Failed assert %s at %s:%d %s ", cond, file, line, msg);
            fflush(stdout);
            (*s_current_test)->failed_assert = true;
            debug_break();
        }
    });

    pf::debug::set_log_handler(
        [](pf::debug::Severity sev, const char* msg)
    {
        if (!(*s_current_test)->ignore_log)
        {
            printf(" %d %s ", (int)sev, msg);
            fflush(stdout);
            if (sev == pf::debug::Error || sev == pf::debug::Warn)
            {
                (*s_current_test)->failed_log = true;
                debug_break();
            }
        }
    });
}

void pf::test::unit_test_free()
{
    pf::net::net_free();
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
