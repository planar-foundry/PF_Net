#include <PF_Net/Detail/Log.hpp>
#include <PF_Net/Detail/Assert.hpp>

#if defined(PFNET_LOG_ENABLED)

namespace pf::net::detail
{

void default_log_handler(LogSeverity severity, const char* message)
{
    if (severity == LogSeverity::Error)
    {
        PFNET_ASSERT_FAIL_MSG(message);
    }
    else
    {
        fputs(message, stdout);
        fflush(stdout);
    }
}

}

#endif
