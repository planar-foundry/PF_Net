#include "UnitTest.hpp"
#include <PF_Net/Net.hpp>
#include <stdio.h>

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

    pf::net::set_assert_handler(
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

    pf::net::set_log_handler(
        [](pf::net::LogSeverity sev, const char* msg)
    {
        if (!(*s_current_test)->ignore_log)
        {
            printf(" %d %s ", (int)sev, msg);
            fflush(stdout);
            if (sev == pf::net::LogSeverity::Error || sev == pf::net::LogSeverity::Warn)
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
