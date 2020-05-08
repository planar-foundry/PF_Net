#pragma once

#include <stdint.h>

namespace pf::net::detail
{

PFNET_API uint64_t get_timestamp_in_ns();
PFNET_API uint64_t get_timestamp_in_ms();

PFNET_API uint32_t fast_rand();

}
