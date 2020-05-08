#pragma once

#include <PF_Net/Net.hpp>
#include <stdio.h>

namespace pf::net::detail
{

#if defined(PFNET_ASSERTS_ENABLED)
    #define PFNET_ASSERT(condition) \
        do \
        { \
            if (!(condition)) ::pf::net::get_assert_handler()((#condition), __FILE__, __LINE__, ""); \
        } while (0)

    #define PFNET_ASSERT_MSG(condition, format, ...) \
        do \
        { \
            if (!(condition)) ::pf::net::detail::format_assert((#condition), __FILE__, __LINE__, (format), ##__VA_ARGS__); \
        } while (0)

    #define PFNET_ASSERT_FAIL() \
        ::pf::net::get_assert_handler()("", __FILE__, __LINE__, "")

    #define PFNET_ASSERT_FAIL_MSG(format, ...) \
        ::pf::net::detail::format_assert("", __FILE__, __LINE__, (format), ##__VA_ARGS__)

    template <typename ... Args>
    void format_assert(const char* condition, const char* file, int line, const char* format, Args ... args)
    {     
        if (AssertFunc handler = get_assert_handler())
        {
            static char buffer[4096];
            sprintf(buffer, format, args ...);
            handler(condition, file, line, buffer);
        }
    }
#else
    #define PFNET_ASSERT(condition) (void)0
    #define PFNET_ASSERT_MSG(condition, format, ...) (void)0
    #define PFNET_ASSERT_FAIL() (void)0
    #define PFNET_ASSERT_FAIL_MSG(format, ...) (void)0
#endif

}
