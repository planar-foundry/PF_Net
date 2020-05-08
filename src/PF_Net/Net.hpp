#pragma once

#include <stddef.h>
#include <stdint.h>

namespace pf::net
{

constexpr uint32_t PFNET_VERSION_MAJOR = 0;
constexpr uint32_t PFNET_VERSION_MINOR = 1;

struct CustomAllocators
{
    void*(*custom_alloc)(size_t len) = nullptr;
    void(*custom_free)(void* ptr) = nullptr;
};

// Must be called before PF_Net is used.
PFNET_API void net_init(CustomAllocators allocators = CustomAllocators());

// Should be called when PF_Net will no longer be used.
PFNET_API void net_free();

using AssertFunc = void(*)(const char* condition, const char* file, int line, const char* message);
PFNET_API void set_assert_handler(AssertFunc handler);
PFNET_API AssertFunc get_assert_handler();

enum class LogSeverity
{
    Debug,
    Info,
    Warn,
    Error
};

using LogFunc = void(*)(LogSeverity severity, const char* message);
PFNET_API void set_log_handler(LogFunc handler);
PFNET_API LogFunc get_log_handler();

using InstrumentationFunc = void(*)(const char* name, uint32_t colour);
PFNET_API void set_instrumentation_handler(InstrumentationFunc push_handler, InstrumentationFunc pop_handler);
PFNET_API InstrumentationFunc get_instrumentation_handler_push();
PFNET_API InstrumentationFunc get_instrumentation_handler_pop();

}
