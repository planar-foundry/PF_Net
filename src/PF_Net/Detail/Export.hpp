#pragma once

#if defined(WIN32) && defined(PF_Net_EXPORTS)
    #define PFNET_API __declspec(dllexport)
#else
    #define PFNET_API
#endif
