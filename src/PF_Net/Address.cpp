#include <PF_Net/Address.hpp>
#include <PF_Net/Detail/Assert.hpp>
#include <PF_Net/Detail/Socket.hpp>

#include <string.h>

namespace pf::net
{

Address::Address()
    : m_storage(std::monostate()), m_port(0)
{ }

Address::Address(uint32_t ip, uint16_t port)
    : m_port(port)
{
    detail::AddressStorageV4 storage;
    storage.addr = ip;
    m_storage = std::move(storage);
}

Address::Address(const AddressStrIPV4& ip, uint16_t port)
    : m_port(port)
{
    detail::AddressStorage storage;
    bool success = detail::address_parse(ip.addr, detail::Socket::Type::IPV4, &storage);
    m_storage = success ? std::move(storage) : std::monostate();
}

Address::Address(const uint8_t* ip_array, uint16_t port)
    : m_port(port)
{
    detail::AddressStorageV6 storage;
    memcpy(&storage.addr, ip_array, sizeof(storage.addr));
    m_storage = std::move(storage);
}

Address::Address(const AddressStrIPV6& ip, uint16_t port)
    : m_port(port)
{
    detail::AddressStorage storage;
    bool success = detail::address_parse(ip.addr, detail::Socket::Type::IPV6, &storage);
    m_storage = success ? std::move(storage) : std::monostate();
}

Address::Address(const AddressStrHostname& hostname, uint16_t port)
    : m_port(port)
{
    detail::AddressStorage storage;
    // I think this is the safest option - we can always request an IPV4 resolved hostname,
    // which IPV6 servers should provide anyway... I think?
    bool success = detail::hostname_resolve(hostname.addr, detail::Socket::Type::IPV4, &storage);
    m_storage = success ? std::move(storage) : std::monostate();
}

bool Address::is_valid() const
{
    return !std::holds_alternative<std::monostate>(m_storage);
}

bool Address::is_ipv4() const
{
    return std::holds_alternative<detail::AddressStorageV4>(m_storage);
}

bool Address::is_ipv6() const
{
    return std::holds_alternative<detail::AddressStorageV6>(m_storage);
}

bool Address::is_ipv4_on_6() const
{
    if (is_ipv6())
    {
        const uint8_t* addr = get_address_ipv6();
        // If the 11th and 12th bytes are 0xFF, this address represents an IPV4 address.
        return addr[10] == 0xFF && addr[11] == 0xFF;
    }

    return false;
}

uint32_t Address::get_address_ipv4() const
{
    if (is_ipv4_on_6())
    {
        const uint8_t* addr = get_address_ipv6();
        return addr[12] << 24 | addr[13] << 16 | addr[14] << 8 | addr[15];
    }

    return std::get<detail::AddressStorageV4>(m_storage).addr;
}

const uint8_t* Address::get_address_ipv6() const
{
    return std::get<detail::AddressStorageV6>(m_storage).addr;
}

uint16_t Address::get_port() const
{
    return m_port;
}

bool Address::write_string(char* buf, size_t buf_len) const
{
    PFNET_ASSERT(buf_len >= AddressStrBufLen);
    return detail::address_to_string(*this, buf, buf_len);
}

bool operator==(const Address& lhs, const Address& rhs)
{
    if (lhs.get_port() != rhs.get_port())
    {
        return false;
    }

    bool lhs_ipv4 = lhs.is_ipv4();
    bool lhs_ipv4on6 = lhs.is_ipv4_on_6();
    bool lhs_ipv6 = lhs.is_ipv6();

    bool rhs_ipv4 = rhs.is_ipv4();
    bool rhs_ipv4on6 = rhs.is_ipv4_on_6();
    bool rhs_ipv6 = rhs.is_ipv6();

    if ((lhs_ipv4 && rhs_ipv4) ||
        (lhs_ipv4on6 && rhs_ipv4) ||
        (lhs_ipv4 && rhs_ipv4on6) ||
        (lhs_ipv4on6 && rhs_ipv4on6))
    {
        return lhs.get_address_ipv4() == rhs.get_address_ipv4();
    }
    else if ((lhs_ipv4on6 && rhs_ipv6) || (lhs_ipv6 && rhs_ipv4on6))
    {
        return false;
    }
    else if (lhs_ipv6 && rhs_ipv6)
    {
        return memcmp(lhs.get_address_ipv6(), rhs.get_address_ipv6(), sizeof(detail::AddressStorageV6::addr)) == 0;
    }
    else if ((lhs_ipv4 && rhs_ipv6) || (lhs_ipv6 && rhs_ipv4))
    {
        return false;
    }

    PFNET_ASSERT_FAIL_MSG("Unhandled address equality case.");
    return false;
}

bool operator!=(const Address& lhs, const Address& rhs)
{
    return !(lhs == rhs);
}

}
