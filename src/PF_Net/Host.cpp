#include <PF_Net/Host.hpp>
#include <PF_Net/Detail/Assert.hpp>
#include <PF_Net/Detail/Host_impl.hpp>

namespace pf::net
{

Host::Host(HostCallbacks cbs, HostExtendedOptions options)
    : Host(cbs, 0, options)
{ }

Host::Host(HostCallbacks cbs, uint16_t port, HostExtendedOptions options)
    : m_impl(detail::make_unique<detail::Host_impl>(cbs, port, options))
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

ConnectionId Host::connect(const Address& remote_host)
{
    return m_impl->connect(remote_host);
}

void Host::disconnect(ConnectionId conn)
{
    m_impl->disconnect(conn);
}

}
