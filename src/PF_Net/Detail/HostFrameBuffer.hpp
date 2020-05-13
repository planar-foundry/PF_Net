#pragma once

#include <PF_Net/Address.hpp>
#include <PF_Net/Detail/Alloc.hpp>
#include <PF_Net/Detail/Export.hpp>
#include <mutex>

namespace pf::net::detail
{

struct HostFrameBuffer
{
    PFNET_API HostFrameBuffer();
    PFNET_API ~HostFrameBuffer();

    PFNET_API void reset();

    Address address;
    uint16_t len;
    std::byte* frame;
};

// This is a convenient thread-safe wrapper around std::vector that acts
// like an std::stack. Buffers will be taken and returned when finished with.
class HostFrameBufferFreeList
{
public:
    // Returns a frame buffer. If none are available, returns nullptr.
    PFNET_API unique_ptr<HostFrameBuffer> get();

    // Returns a frame buffer. If none are available, allocates a new one.
    PFNET_API unique_ptr<HostFrameBuffer> get_or_make();

    // Submit a frame buffer to this collection.
    PFNET_API void submit(unique_ptr<HostFrameBuffer>&& buf);

private:
    std::mutex m_lock;
    vector<unique_ptr<HostFrameBuffer>> m_data;
};

// This is similar to HostFrameBufferFreeList, but instead of acting like a stack,
// this is effectively a size-bounded deque.
class HostFrameBufferPendingList
{
public:
    PFNET_API HostFrameBufferPendingList(size_t max_size);

    // Returns a frame buffer. If none are available, returns nullptr.
    PFNET_API unique_ptr<HostFrameBuffer> get();

    // Submit a frame buffer to this collection.
    // This may return a frame buffer if the collection has overflowed, in which
    // case this should be returned to the free list.
    PFNET_API unique_ptr<HostFrameBuffer> submit(unique_ptr<HostFrameBuffer>&& buf);

private:
    std::mutex m_lock;
    queue<unique_ptr<HostFrameBuffer>> m_data;
    size_t m_max_size;
};

}
