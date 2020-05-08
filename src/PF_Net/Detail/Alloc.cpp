#include <PF_Net/Detail/Alloc.hpp>

namespace pf::net::detail
{

PFNET_API CustomAllocators g_custom_allocators;

void set_custom_allocators(CustomAllocators allocators)
{
    if (!allocators.custom_alloc)   allocators.custom_alloc   = &malloc;
    if (!allocators.custom_free)    allocators.custom_free    = &free;

    g_custom_allocators = allocators;
}

CustomAllocators get_custom_allocators()
{
    return g_custom_allocators;
}

void* custom_alloc(size_t len)
{
    return get_custom_allocators().custom_alloc(len);
}

void custom_free(void* data)
{
    get_custom_allocators().custom_free(data);
}

}
