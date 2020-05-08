#pragma once

#include <PF_Net/Net.hpp>
#include <stdio.h>

namespace pf::net::detail
{

#if defined(PFNET_LOG_ENABLED)
    #define PFNET_LOG_DEBUG(format, ...) \
        ::pf::net::detail::format_log(::pf::net::LogSeverity::Debug, (format), ##__VA_ARGS__)

    #define PFNET_LOG_INFO(format, ...) \
        ::pf::net::detail::format_log(::pf::net::LogSeverity::Info, (format), ##__VA_ARGS__)

    #define PFNET_LOG_WARN(format, ...) \
        ::pf::net::detail::format_log(::pf::net::LogSeverity::Warn, (format), ##__VA_ARGS__)

    #define PFNET_LOG_ERROR(format, ...) \
        ::pf::net::detail::format_log(::pf::net::LogSeverity::Error, (format), ##__VA_ARGS__)

    template <typename ... Args>
    void format_log(LogSeverity severity, const char* format, Args ... args)
    {
        if (LogFunc handler = get_log_handler())
        {
            static char buffer[4096];
            sprintf(buffer, format, args ...);
            handler(severity, buffer);
        }
    }

    PFNET_API void default_log_handler(LogSeverity severity, const char* message);
#else
    #define PFNET_LOG_DEBUG(format, ...) (void)0
    #define PFNET_LOG_INFO(format, ...) (void)0
    #define PFNET_LOG_WARN(format, ...) (void)0
    #define PFNET_LOG_ERROR(format, ...) (void)0
#endif

}
