#pragma once

#include <stdint.h>

struct UnitTestResult
{
    const char* failed_condition = nullptr;
    const char* failed_file;
    int failed_line;
    bool ignore_asserts = false;
    bool ignore_log = false;
    bool failed_assert = false;
    bool failed_log = false;
};

using UnitTestFunc = void(*)(UnitTestResult* _pf_result);

struct UnitTest
{
    const char* name;
    UnitTestFunc function;
};

void register_unit_test(const char* name, UnitTestFunc function);

struct ScopedUnitTest
{
    ScopedUnitTest(const char* name, UnitTestFunc function)
    {
        register_unit_test(name, function);
    }
};

void debug_break();

// This is necessary because on some Linux systems it is not possible to rebind a port you just
// used without setting some socket options which I don't want to code cross platform support for.
uint16_t get_unique_port();

// Returns the timeout of this test - the test can check it and early out.
uint32_t get_test_timeout();

#define PFNET_TEST_THIS _pf_result
#define PFNET_TEST_THIS_ARG UnitTestResult* PFNET_TEST_THIS

#define PFNET_TEST_CREATE(name) \
    void _test_##name(PFNET_TEST_THIS_ARG); \
    static ::ScopedUnitTest s_test__##name(#name, &_test_##name); \
    void _test_##name(PFNET_TEST_THIS_ARG)

#define PFNET_TEST_EXPECT(cond) \
    do \
    { \
        if (!(cond) && !_pf_result->failed_condition) \
        { \
            ::debug_break(); \
            _pf_result->failed_condition = (#cond); \
            _pf_result->failed_file = __FILE__; \
            _pf_result->failed_line = __LINE__; \
        } \
    } while (0)

#define PFNET_TEST_FAIL() PFNET_TEST_EXPECT(false)

#define PFNET_TEST_IGNORE_ASSERTS(status) _pf_result->ignore_asserts = status
#define PFNET_TEST_IGNORE_LOG(status) _pf_result->ignore_log = status
