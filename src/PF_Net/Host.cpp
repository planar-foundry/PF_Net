#include <PF_Net/Host.hpp>
#include <PF_Net/Detail/Host_impl.hpp>

namespace pf::net
{

Host::Host(const HostCallbacks& cbs, HostExtendedOptions options)
    : Host(cbs, 0, std::move(options))
{ }

Host::Host(const HostCallbacks& cbs, uint16_t port, HostExtendedOptions options)
    : m_impl(detail::make_unique<detail::Host_impl>(cbs, port, std::move(options)))
{ }

Host::Host(Host&& rhs)
    : m_impl(std::move(rhs.m_impl))
{ }

Host::~Host()
{ }

bool Host::update_socket(int timeout_in_ms)
{
    return m_impl->update_socket(timeout_in_ms);
}

void Host::update_incoming()
{
    m_impl->update_incoming();
}

void Host::update_outgoing()
{
    m_impl->update_outgoing();
}

PacketId Host::send_unreliable(ConnectionId conn, std::byte* data, int len, uint8_t channel, PacketLifetime lifetime, void(*deleter)(void*))
{
    return m_impl->send_unreliable(conn, data, len, channel, lifetime, deleter);
}

ConnectionId Host::connect(const Address& remote_host)
{
    return m_impl->connect(remote_host);
}

void Host::disconnect(ConnectionId conn)
{
    m_impl->disconnect(conn);
}

}
