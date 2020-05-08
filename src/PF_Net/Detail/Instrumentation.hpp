
#pragma once

namespace pf::net::detail
{

#if defined(PFNET_INSTRUMENTATION_ENABLED)
    #define PFNET_PERF_SCOPE(...) do {} while(0) // TODO
    #define PFNET_PERF_FUNC_SCOPE(...) do {} while(0) // TODO
#else
    #define PFNET_PERF_SCOPE(...) do {} while(0)
    #define PFNET_PERF_FUNC_SCOPE(...) do {} while(0)
#endif

}
