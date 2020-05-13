#include <PF_Net/Net.hpp>
#include <PF_Net/Detail/Alloc.hpp>
#include <PF_Net/Detail/Socket.hpp>
#include <malloc.h>

namespace pf::net
{

void net_init(CustomAllocators allocators)
{
    detail::set_custom_allocators(std::move(allocators));
    detail::socket_init();
}

void net_free()
{
    detail::socket_free();
}

#if defined(PFNET_INSTRUMENTATION_ENABLED)
PFNET_API InstrumentationFunc g_instrumentation_handler_push = nullptr;
PFNET_API InstrumentationFunc g_instrumentation_handler_pop = nullptr;
#endif

void set_instrumentation_handler(InstrumentationFunc push_handler, InstrumentationFunc pop_handler)
{
#if defined(PFNET_INSTRUMENTATION_ENABLED)
    g_instrumentation_handler_push = push_handler;
    g_instrumentation_handler_pop = pop_handler;
#else
    (void)push_handler;
    (void)pop_handler;
#endif
}

InstrumentationFunc get_instrumentation_handler_push()
{
#if defined(PFNET_INSTRUMENTATION_ENABLED)
    return g_instrumentation_handler_push;
#else
    return nullptr;
#endif
}

InstrumentationFunc get_instrumentation_handler_pop()
{
#if defined(PFNET_INSTRUMENTATION_ENABLED)
    return g_instrumentation_handler_pop;
#else
    return nullptr;
#endif
}

}
