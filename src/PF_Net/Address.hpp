#pragma once

#include <PF_Net/Detail/Export.hpp>

#include <functional>		
#include <stdint.h>
#include <variant>

namespace pf::net
{

namespace detail
{

template <typename>
struct AddressStr
{
    // Note: this doesn't take a copy!
    explicit AddressStr(const char* _addr) : addr(_addr) {}
    const char* addr;
};

struct AddressStrHostnameTag {};
struct AddressStrIPV4Tag {};
struct AddressStrIPV6Tag {};

struct AddressStorageV4 { uint32_t addr; };
struct AddressStorageV6 { uint8_t addr[16]; };
using AddressStorage = std::variant<AddressStorageV4, AddressStorageV6, std::monostate>;

}

// Users should construct these as follows:
//
//     AddressStrIPV4("127.0.0.1")
//     AddressStrIPV6("::1")
//     AddressStrHostname("google.co.uk")

using AddressStrIPV4 = detail::AddressStr<detail::AddressStrIPV4Tag>;
using AddressStrIPV6 = detail::AddressStr<detail::AddressStrIPV6Tag>;
using AddressStrHostname = detail::AddressStr<detail::AddressStrHostnameTag>;

static constexpr size_t AddressStrBufLen = 46;

class Address
{
public:
    // Empty constructor; constructs in an invalid state.
    PFNET_API Address();

    // IPV4 constructors.
    PFNET_API Address(uint32_t ip, uint16_t port);
    PFNET_API Address(const AddressStrIPV4& ip, uint16_t port);

    // IPV6 constructors.
    PFNET_API Address(const uint8_t* ip_array, uint16_t port);
    PFNET_API Address(const AddressStrIPV6& ip, uint16_t port);

    // Hostname constructor.
    PFNET_API Address(const AddressStrHostname& hostname, uint16_t port);

    PFNET_API bool is_valid() const;

    PFNET_API bool is_ipv4() const;
    PFNET_API bool is_ipv6() const;

    // Returns true if this address is an IPV6 address that represents an IPV4 address.
    PFNET_API bool is_ipv4_on_6() const;

    PFNET_API uint32_t get_address_ipv4() const;
    PFNET_API const uint8_t* get_address_ipv6() const;

    PFNET_API uint16_t get_port() const;

    // Buf must be at least sized AddressStrBufLen.
    PFNET_API bool write_string(char* buf, size_t buf_len) const;

private:
    detail::AddressStorage m_storage;
    uint16_t m_port;
};

PFNET_API bool operator==(const Address& lhs, const Address& rhs);
PFNET_API bool operator!=(const Address& lhs, const Address& rhs);

}

namespace std
{
    template <>
    struct hash<pf::net::Address>
    {
        size_t operator()(const pf::net::Address& lhs) const
        {
            size_t hash = 0;

            if (lhs.is_ipv4())
            {
                hash = lhs.get_address_ipv4();
            }
            else if (lhs.is_ipv6())
            {
                const uint8_t* v6 = lhs.get_address_ipv6();

                for (int i = 0; i < 2; ++i)
                {
                    hash ^= (size_t)*v6++ << 0;
                    hash ^= (size_t)*v6++ << 8;
                    hash ^= (size_t)*v6++ << 16;
                    hash ^= (size_t)*v6++ << 24;
                    hash ^= (size_t)*v6++ << 32;
                    hash ^= (size_t)*v6++ << 40;
                    hash ^= (size_t)*v6++ << 48;
                    hash ^= (size_t)*v6++ << 56;
                }
            }

            return hash;
        }
    };
}
