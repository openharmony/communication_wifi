/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "securec.h"
#include "ipv6_address.h"

using namespace testing::ext;

namespace OHOS {
namespace Wifi {
constexpr int PREFIX_LENGTH = 256;
constexpr int PREFIX_LENGTHS = 64;
constexpr int MAX_IPV6_LENGTH = 128;

class Ipv6AddressTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {}
    virtual void TearDown()
    {}
};

HWTEST_F(Ipv6AddressTest, GetIn6Addr_Fail1, TestSize.Level1)
{
    std::string ipv6Prefix = "fe80::555b:6cea:81fa:1ff2%8";
	size_t prefixLength = PREFIX_LENGTH;
    MacAddress mac = MacAddress::Create(ipv6Prefix);
    Ipv6Address::Create(ipv6Prefix, mac, prefixLength);
}

HWTEST_F(Ipv6AddressTest, Create_Success1, TestSize.Level1)
{
    std::string ipv6Prefix = "fe80::555b:6cea:81fa:1ff2%8";
	size_t prefixLength = PREFIX_LENGTHS;
    MacAddress mac = MacAddress::Create(ipv6Prefix);
    Ipv6Address::Create(ipv6Prefix, mac, prefixLength);
}

HWTEST_F(Ipv6AddressTest, Create_Fail2, TestSize.Level1)
{
    std::string ipv6Prefix = "fe80::555b:6cea:81fa:1ff2%8";
	size_t prefixLength = PREFIX_LENGTH;
    unsigned int rndSeed = 1;
    Ipv6Address::Create(ipv6Prefix, prefixLength, rndSeed);
}

HWTEST_F(Ipv6AddressTest, Create_Success2, TestSize.Level1)
{
    std::string ipv6Prefix = "fe80::555b:6cea:81fa:1ff2%8";
	size_t prefixLength = PREFIX_LENGTHS;
    unsigned int rndSeed = 1;
    Ipv6Address::Create(ipv6Prefix, prefixLength, rndSeed);
}

HWTEST_F(Ipv6AddressTest, Create_Fail3, TestSize.Level1)
{
	struct in6_addr i6Addr;
	size_t prefixLength = PREFIX_LENGTH;
    Ipv6Address::Create(i6Addr, prefixLength);
}

HWTEST_F(Ipv6AddressTest, Create_Success3, TestSize.Level1)
{
	struct in6_addr i6Addr;
    size_t prefixLength = PREFIX_LENGTHS;
    Ipv6Address::Create(i6Addr, prefixLength);
}

HWTEST_F(Ipv6AddressTest, Create_Fail4, TestSize.Level1)
{
	std::string ipv6 = "fe80::555b:6cea:81fa:1ff2%8";
	size_t prefixLength = PREFIX_LENGTH;
    Ipv6Address::Create(ipv6, prefixLength);
}

HWTEST_F(Ipv6AddressTest, Create_Success4, TestSize.Level1)
{
	std::string ipv6 = "fe80::555b:6cea:81fa:1ff2%8";
    size_t prefixLength = PREFIX_LENGTHS;
    Ipv6Address::Create(ipv6, prefixLength);
}

HWTEST_F(Ipv6AddressTest, GetIpv6Prefix_Fail, TestSize.Level1)
{
    struct in6_addr ip6Addr;
    size_t prefixLength = PREFIX_LENGTH;
    Ipv6Address::GetIpv6Prefix(ip6Addr, prefixLength);
}

HWTEST_F(Ipv6AddressTest, GetIpv6PrefixTest, TestSize.Level1)
{
	struct in6_addr ip6Addr, addr;
    ipv6Addr.s6_addr = "555b:6cea:81fa";
    size_t prefixLength = PREFIX_LENGTHS;
    addr = Ipv6Address::GetIpv6Prefix(ip6Addr, prefixLength);
    EXPECT_TRUE(strcmp(addr.s6_addr, ipv6.s6_addr) == 0);
}

HWTEST_F(Ipv6AddressTest, GetIpv6Mask_Fail, TestSize.Level1)
{
    size_t prefixLength = PREFIX_LENGTHS;
    Ipv6Address::GetIpv6Mask(prefixLength);
}

HWTEST_F(Ipv6AddressTest, GetIpv6Mask_Fail2, TestSize.Level1)
{
    size_t prefixLength = MAX_IPV6_LENGTH;
    Ipv6Address::GetIpv6Mask(prefixLength);
}

HWTEST_F(Ipv6AddressTest, GetIpv6Mask_Success, TestSize.Level1)
{
    size_t prefixLength = PREFIX_LENGTHS;
    Ipv6Address::GetIpv6Mask(prefixLength);
}
}  // namespace Wifi
}  // namespace OHOS

