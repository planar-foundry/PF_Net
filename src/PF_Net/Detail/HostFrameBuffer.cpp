#include <PF_Net/Detail/HostFrameBuffer.hpp>
#include <PF_Net/Detail/Protocol.hpp>
#include <algorithm>

namespace pf::net::detail
{

HostFrameBuffer::HostFrameBuffer()
{
    len = protocol::MaxPacketSize;
    frame = (std::byte*)custom_alloc(len);
}

HostFrameBuffer::~HostFrameBuffer()
{
    custom_free(frame);
    frame = nullptr;
}

unique_ptr<HostFrameBuffer> HostFrameBufferFreeList::get()
{
    std::lock_guard<std::mutex> lock(m_lock);

    if (m_data.size())
    {
        unique_ptr<HostFrameBuffer> buffer = std::move(m_data.back());
        m_data.pop_back();
        return buffer;
    }

    return nullptr;
}

unique_ptr<HostFrameBuffer> HostFrameBufferFreeList::get_or_make()
{
    std::lock_guard<std::mutex> lock(m_lock);

    unique_ptr<HostFrameBuffer> buffer;

    if (!m_data.size())
    {
        buffer = make_unique<HostFrameBuffer>();
    }
    else
    {
        buffer = std::move(m_data.back());
        m_data.pop_back();
    }

    return buffer;
}

void HostFrameBufferFreeList::submit(unique_ptr<HostFrameBuffer>&& buf)
{
    std::lock_guard<std::mutex> lock(m_lock);
    m_data.emplace_back(std::move(buf));
}

HostFrameBufferPendingList::HostFrameBufferPendingList(size_t max_size)
    : m_max_size(max_size)
{ }

unique_ptr<HostFrameBuffer> HostFrameBufferPendingList::get()
{
    std::lock_guard<std::mutex> lock(m_lock);

    if (!m_data.empty())
    {
        unique_ptr<HostFrameBuffer> buf = std::move(m_data.front());
        m_data.pop();
        return buf;
    }

    return nullptr;
}

unique_ptr<HostFrameBuffer> HostFrameBufferPendingList::submit(unique_ptr<HostFrameBuffer>&& buf)
{
    std::lock_guard<std::mutex> lock(m_lock);

    if (m_data.size() == m_max_size)
    {
        unique_ptr<HostFrameBuffer> old_buf = std::move(m_data.front());
        m_data.pop();
        m_data.push(std::move(buf));
        return old_buf;
    }

    m_data.push(std::move(buf));
    return nullptr;
}

}
