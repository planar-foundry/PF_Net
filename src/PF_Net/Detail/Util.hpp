#pragma once

#include <PF_Net/Detail/Export.hpp>
#include <stdint.h>

namespace pf::net::detail
{

PFNET_API uint64_t get_timestamp_in_ns();
PFNET_API uint64_t get_timestamp_in_ms();

}
