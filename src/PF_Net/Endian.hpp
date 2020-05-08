#pragma once

#if defined(WIN32)
    #include <intrin.h>
#else
    #include <byteswap.h>
#endif

namespace pf::net
{

// The network byte order is little endian to minimise the byte swapping we have to do
// in the typical case.
// In debug configuration we swap the network byte order.
// This is done because because most developers work on little-endian machines which will
// never test the endian swapping code otherwise.

#if defined(PFNET_DEBUG_ENABLED)
    #define PFNET_BYTE_ORDER_BIG_ENDIAN 
#endif

#if defined(PFNET_BYTE_ORDER_BIG_ENDIAN)
    #if defined(PFNET_BIG_ENDIAN)
        #define PFNET_NEED_ENDIAN_SWAP 0
    #else
        #define PFNET_NEED_ENDIAN_SWAP 1
    #endif
#else
    #if defined(PFNET_BIG_ENDIAN)
        #define PFNET_NEED_ENDIAN_SWAP 1
    #else
        #define PFNET_NEED_ENDIAN_SWAP 0
    #endif
#endif

// The underscore variants can be used if you need to endian swap for reasons of your own.
#if defined (WIN32)
    #define _PFNET_ENDIAN_SWAP_16(x) _byteswap_ushort(x)
    #define _PFNET_ENDIAN_SWAP_32(x) _byteswap_ulong(x)
    #define _PFNET_ENDIAN_SWAP_64(x) _byteswap_uint64(x)
#else
    #define _PFNET_ENDIAN_SWAP_16(x) __bswap_16(x)
    #define _PFNET_ENDIAN_SWAP_32(x) __bswap_32(x)
    #define _PFNET_ENDIAN_SWAP_64(x) __bswap_64(x)
#endif

// The regular variants should be used when endian swapping per the network byte order.
#if PFNET_NEED_ENDIAN_SWAP
    #define PFNET_ENDIAN_SWAP_16(x) _PFNET_ENDIAN_SWAP_16(x)
    #define PFNET_ENDIAN_SWAP_32(x) _PFNET_ENDIAN_SWAP_32(x)
    #define PFNET_ENDIAN_SWAP_64(x) _PFNET_ENDIAN_SWAP_64(x)
#else
    #define PFNET_ENDIAN_SWAP_16(x) x
    #define PFNET_ENDIAN_SWAP_32(x) x
    #define PFNET_ENDIAN_SWAP_64(x) x
#endif

}
