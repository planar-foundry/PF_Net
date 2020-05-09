#include "UnitTest.hpp"
#include <PF_Net/Address.hpp>
#include <algorithm>
#include <random>
#include <vector>

using namespace pf::net;

PFNET_TEST_CREATE(Address_Equality)
{
    Address ipv4_1_port_1(AddressStrIPV4("127.0.0.1"), 1);
    Address ipv4_1_port_2(AddressStrIPV4("127.0.0.1"), 2);
    Address ipv4_2_port_1(AddressStrIPV4("127.0.0.2"), 1);
    Address ipv4_2_port_2(AddressStrIPV4("127.0.0.2"), 2);

    PFNET_TEST_EXPECT(ipv4_1_port_1 == ipv4_1_port_1);
    PFNET_TEST_EXPECT(ipv4_1_port_1 != ipv4_1_port_2);
    PFNET_TEST_EXPECT(ipv4_1_port_1 != ipv4_2_port_1);
    PFNET_TEST_EXPECT(ipv4_1_port_1 != ipv4_2_port_2);

    Address ipv4on6_1_port_1(AddressStrIPV6("::FFFF:127.0.0.1"), 1);
    Address ipv4on6_1_port_2(AddressStrIPV6("::FFFF:127.0.0.1"), 2);
    Address ipv4on6_2_port_1(AddressStrIPV6("::FFFF:255.0.255.0"), 1);
    Address ipv4on6_2_port_2(AddressStrIPV6("::FFFF:255.0.255.0"), 2);

    PFNET_TEST_EXPECT(ipv4_1_port_1 == ipv4on6_1_port_1);
    PFNET_TEST_EXPECT(ipv4_1_port_1 != ipv4on6_1_port_2);
    PFNET_TEST_EXPECT(ipv4_1_port_1 != ipv4on6_2_port_1);
    PFNET_TEST_EXPECT(ipv4_1_port_1 != ipv4on6_2_port_2);

    Address ipv6_1_port_1(AddressStrIPV6("::1"), 1);
    Address ipv6_1_port_2(AddressStrIPV6("::1"), 2);
    Address ipv6_2_port_1(AddressStrIPV6("::2"), 1);
    Address ipv6_2_port_2(AddressStrIPV6("::2"), 2);

    PFNET_TEST_EXPECT(ipv4_1_port_1 != ipv6_1_port_1);
    PFNET_TEST_EXPECT(ipv4_1_port_1 != ipv6_1_port_2);
    PFNET_TEST_EXPECT(ipv4_1_port_1 != ipv6_2_port_1);
    PFNET_TEST_EXPECT(ipv4_1_port_1 != ipv6_2_port_2);

    PFNET_TEST_EXPECT(ipv4on6_1_port_1 != ipv6_1_port_1);
}

PFNET_TEST_CREATE(Address_Types)
{
    Address ipv4(AddressStrIPV4("127.0.0.1"), 1);
    PFNET_TEST_EXPECT(ipv4.is_ipv4());
    PFNET_TEST_EXPECT(!ipv4.is_ipv4_on_6());
    PFNET_TEST_EXPECT(!ipv4.is_ipv6());

    Address ipv4_on_6(AddressStrIPV6("::FFFF:127.0.0.1"), 1);
    PFNET_TEST_EXPECT(!ipv4_on_6.is_ipv4());
    PFNET_TEST_EXPECT(ipv4_on_6.is_ipv4_on_6());
    PFNET_TEST_EXPECT(ipv4_on_6.is_ipv6());

    Address ipv6(AddressStrIPV6("::1"), 1);
    PFNET_TEST_EXPECT(!ipv6.is_ipv4());
    PFNET_TEST_EXPECT(!ipv6.is_ipv4_on_6());
    PFNET_TEST_EXPECT(ipv6.is_ipv6());
}

PFNET_TEST_CREATE(Address_Hash)
{
    Address ipv4(AddressStrIPV4("127.0.0.1"), 1);
    Address ipv4_on_6(AddressStrIPV6("::FFFF:127.0.0.1"), 1);
    Address ipv6(AddressStrIPV6("::1"), 1);

    std::unordered_map<Address, int> address_map;
    address_map[ipv4] = 0;
    address_map[ipv4_on_6] = 1;
    address_map[ipv6] = 2;

    auto maybe_ipv4 = address_map.find(ipv4);
    auto maybe_ipv4_on_6 = address_map.find(ipv4_on_6);
    auto maybe_ipv6 = address_map.find(ipv6);

    PFNET_TEST_EXPECT(maybe_ipv4 != std::end(address_map) && maybe_ipv4->first == ipv4 && maybe_ipv4->second == 0);
    PFNET_TEST_EXPECT(maybe_ipv4_on_6 != std::end(address_map) && maybe_ipv4_on_6->first == ipv4_on_6 && maybe_ipv4_on_6->second == 1);
    PFNET_TEST_EXPECT(maybe_ipv6 != std::end(address_map) && maybe_ipv6->first == ipv6 && maybe_ipv6->second == 2);
}
