#include "UnitTest.hpp"
#include <PF_Net/Net.hpp>

#if defined(_WIN32)
    #include <Windows.h>
#endif

#include <atomic>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>

std::vector<UnitTest>& get_tests()
{
    static std::vector<UnitTest> s_tests;
    return s_tests;
}

void register_unit_test(const char* name, UnitTestFunc function)
{
    get_tests().push_back({ name, function });
}

void debug_break()
{
#if defined(WIN32)
    if (IsDebuggerPresent())
    {
        __debugbreak();
    }
#endif
}

uint16_t get_unique_port()
{
    static uint16_t port = 42512; return port++;
}

uint32_t get_test_timeout()
{
    return 5000;
}

static std::atomic<int64_t> s_bytes_allocated = 0;
static std::atomic<int64_t> s_total_bytes_allocated = 0;

void* custom_alloc(size_t size)
{
    void* data = ::malloc(size + 8);
    memcpy(data, &size, 8);
    s_bytes_allocated += size;
    s_total_bytes_allocated += size;
    return (unsigned char*)data + 8;
}

void* custom_realloc(void* data, size_t size)
{
    size_t original_size;
    void* data_start = (unsigned char*)data - 8;
    memcpy(&original_size, data_start, 8);
    void* data_new = ::realloc(data_start, size + 8);
    memcpy(data_new, &size, 8);
    s_bytes_allocated += (int64_t)size - original_size;
    s_total_bytes_allocated += (int64_t)size - original_size;
    return (unsigned char*)data + 8;
}

void custom_free(void* data)
{
    if (data)
    {
        size_t size;
        void* data_start = (unsigned char*)data - 8;
        memcpy(&size, data_start, 8);
        ::free(data_start);
        s_bytes_allocated -= size;
    }
}

int main(int argc, char** argv)
{
    char* whitelist = argc == 2 ? argv[1] : nullptr;

    pf::net::CustomAllocators allocators;
    allocators.custom_alloc = &custom_alloc;
    allocators.custom_realloc = &custom_realloc;
    allocators.custom_free = &custom_free;

    pf::net::net_init(allocators);

    static UnitTestResult* current_test;

    pf::net::set_assert_handler(
        [](const char* cond, const char* file, int line, const char* msg)
    {
        if (!current_test->ignore_asserts)
        {
            printf(" Failed assert %s at %s:%d %s ", cond, file, line, msg);
            fflush(stdout);
            current_test->failed_assert = true;
            debug_break();
        }
    });

    pf::net::set_log_handler(
        [](pf::net::LogSeverity sev, const char* msg)
    {
        if (!current_test->ignore_log)
        {
            printf(" %d %s ", (int)sev, msg);
            fflush(stdout);
            if (sev == pf::net::LogSeverity::Error || sev == pf::net::LogSeverity::Warn)
            {
                current_test->failed_log = true;
                debug_break();
            }
        }
    });

    bool any_failures = false;

    for (const UnitTest& test : get_tests())
    {
        if (whitelist && !strstr(test.name, whitelist))
        {
            printf("Skipping test %s\n", test.name);
            continue;
        }

        UnitTestResult result;
        current_test = &result;

        printf("Running test %s ...", test.name);
        fflush(stdout);

        size_t total_bytes_before = s_total_bytes_allocated;
        size_t bytes_before = s_bytes_allocated;

        test.function(&result);

        if (result.failed_condition)
        {
            printf(" FAILED!\n    %s:%d\n    %s\n", result.failed_file, result.failed_line, result.failed_condition);
            any_failures = true;
        }
        else if (current_test->failed_assert || current_test->failed_log)
        {
            printf(" FAILED!\n    Assert or log event in PF_Net.\n");
            any_failures = true;
        }
        else if (bytes_before != s_bytes_allocated)
        {
            printf(" FAILED!\n    %zu bytes before test, %zu bytes after test. Memory leak?\n", bytes_before, s_bytes_allocated.load());
            any_failures = true;
        }
        else
        {
            printf(" SUCCESS! (alloc: %zu)\n", s_total_bytes_allocated - total_bytes_before);
        }

        fflush(stdout);
        current_test = nullptr;
    }

    pf::net::net_free();

    if (s_bytes_allocated)
    {
        printf("FAILED!\n    %zu bytes were still allocated at teardown.\n", s_bytes_allocated.load());
        any_failures = true;
    }

    if (any_failures)
    {
        debug_break();
        return 1;
    }
}
