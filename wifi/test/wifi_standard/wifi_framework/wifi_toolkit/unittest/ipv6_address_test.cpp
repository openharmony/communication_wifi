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
#include <cstddef>
#include <gtest/gtest.h>
#include "ipv6_address.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_DHCP_LABEL("Ipv6AddressTest");
using namespace testing::ext;

namespace OHOS {
namespace Wifi {
constexpr int HALF_PREFIX_LENGTH = 64;
constexpr int MAX_IPV6_LENGTH = 128;
constexpr int S6_ADDR_LENGTH = 16;
constexpr int DEC_11_TOHEX = 17;
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
/**
 * @tc.name: Create_001
 * @tc.desc: Create(std::string ipv6)
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(Ipv6AddressTest, Create_001, TestSize.Level1)
{
    WIFI_LOGI("Create_001");
    std::string ipv6 = "1111:1111:1111:1111:%";
    EXPECT_TRUE(Ipv6Address::Create(ipv6) == Ipv6Address::INVALID_INET6_ADDRESS);
    ipv6 = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";
    EXPECT_TRUE(Ipv6Address::Create(ipv6) == Ipv6Address::INVALID_INET6_ADDRESS);
    ipv6 = "1111:1111:1111:1111:1111:1111:1111:1111/8";
    EXPECT_FALSE(Ipv6Address::Create(ipv6) == Ipv6Address::INVALID_INET6_ADDRESS);
}
/**
 * @tc.name: Create_002
 * @tc.desc: Create(const std::string &ipv6Prefix, MacAddress &mac, const size_t prefixLength)
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(Ipv6AddressTest, Create_002, TestSize.Level1)
{
    WIFI_LOGI("Create_002");
    std::string ipv6Prefix = "1111:1111:1111:1111:%";
    size_t prefixLength = HALF_PREFIX_LENGTH + 1;
    MacAddress mac = MacAddress::Create("aa:bb:cc:dd:ee:ff");
    EXPECT_TRUE(Ipv6Address::Create(ipv6Prefix, mac, prefixLength) == Ipv6Address::INVALID_INET6_ADDRESS);
    prefixLength = HALF_PREFIX_LENGTH;
    EXPECT_TRUE(Ipv6Address::Create(ipv6Prefix, mac, prefixLength) == Ipv6Address::INVALID_INET6_ADDRESS);
    ipv6Prefix = "1111:1111:1111:1111:1111:1111:1111:1111";
    Ipv6Address::Create(ipv6Prefix, mac, prefixLength);
}
/**
 * @tc.name: Create_003
 * @tc.desc: Create(const std::string &ipv6Prefix, const size_t prefixLength, unsigned int rndSeed)
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(Ipv6AddressTest, Create_003, TestSize.Level1)
{
    WIFI_LOGI("Create_003");
    std::string ipv6Prefix = "1111:1111:1111:1111:%";
    size_t prefixLength = MAX_IPV6_LENGTH + 1;
    unsigned int rndSeed = 1;
    EXPECT_TRUE(Ipv6Address::Create(ipv6Prefix, prefixLength, rndSeed) == Ipv6Address::INVALID_INET6_ADDRESS);
    prefixLength = MAX_IPV6_LENGTH;
    EXPECT_TRUE(Ipv6Address::Create(ipv6Prefix, prefixLength, rndSeed) == Ipv6Address::INVALID_INET6_ADDRESS);
    ipv6Prefix = "1111:1111:1111:1111:1111:1111:1111:1111";
    EXPECT_FALSE(Ipv6Address::Create(ipv6Prefix, prefixLength, rndSeed) == Ipv6Address::INVALID_INET6_ADDRESS);
    prefixLength = MAX_IPV6_LENGTH - CHAR_BIT;
    Ipv6Address::Create(ipv6Prefix, prefixLength, rndSeed);
}
/**
 * @tc.name: Create_004
 * @tc.desc: Create(const struct in6_addr &i6Addr, const size_t prefixLength)
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(Ipv6AddressTest, Create_004, TestSize.Level1)
{
    WIFI_LOGI("Create_004");
    in6_addr i6Addr;
    for (int i = 0; i < S6_ADDR_LENGTH; i++) {
        i6Addr.s6_addr[i] = 1;
    }
    size_t prefixLength = MAX_IPV6_LENGTH + 1;
    EXPECT_TRUE(Ipv6Address::Create(i6Addr, prefixLength) == Ipv6Address::INVALID_INET6_ADDRESS);
    prefixLength = MAX_IPV6_LENGTH;
    Ipv6Address::Create(i6Addr, prefixLength);
}
/**
 * @tc.name: Create_005
 * @tc.desc: Create(std::string ipv6, const size_t prefixLength)
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(Ipv6AddressTest, Create_005, TestSize.Level1)
{
    WIFI_LOGI("Create_005");
    std::string ipv6 = "1111:1111:1111:1111:%";
    size_t prefixLength = MAX_IPV6_LENGTH + 1;
    EXPECT_TRUE(Ipv6Address::Create(ipv6, prefixLength) == Ipv6Address::INVALID_INET6_ADDRESS);
    prefixLength = MAX_IPV6_LENGTH;
    EXPECT_TRUE(Ipv6Address::Create(ipv6, prefixLength) == Ipv6Address::INVALID_INET6_ADDRESS);
    ipv6 = "1111:1111:1111:1111:1111:1111:1111:1111";
    Ipv6Address::Create(ipv6, prefixLength);
}
/**
 * @tc.name: Create_006
 * @tc.desc: Create(std::string ipv6, const std::string &mask)
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(Ipv6AddressTest, Create_006, TestSize.Level1)
{
    WIFI_LOGI("Create_006");
    std::string ipv6 = "1111:1111:1111:1111:%";
    std::string mask = "ffff:ffff:ffff:ffff:0:0:0:0";
    EXPECT_TRUE(Ipv6Address::Create(ipv6, mask) == Ipv6Address::INVALID_INET6_ADDRESS);
    ipv6 = "1111:1111:1111:1111:1111:1111:1111:1111";
    Ipv6Address::Create(ipv6, mask);
}
/**
 * @tc.name: GetIn6Addr_001
 * @tc.desc: GetIn6Addr
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(Ipv6AddressTest, GetIn6Addr_001, TestSize.Level1)
{
    WIFI_LOGI("GetIn6Addr_001");
    std::string ipv6 = "1111:1111:1111:1111:1111:1111:1111:1111";
    Ipv6Address mIpv6Address = Ipv6Address::Create(ipv6);
    EXPECT_EQ(mIpv6Address.GetIn6Addr().s6_addr[0], DEC_11_TOHEX);
}
/**
 * @tc.name: GetPrefix_001
 * @tc.desc: GetPrefix
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(Ipv6AddressTest, GetPrefix_001, TestSize.Level1)
{
    WIFI_LOGI("GetPrefix_001");
    std::string ipv6 = "1111:1111:1111:1111:1111:1111:1111:1111";
    Ipv6Address mIpv6Address = Ipv6Address::Create(ipv6);
    EXPECT_EQ(mIpv6Address.GetPrefix(), ipv6);
}
/**
 * @tc.name: GetPrefixByAddr_001
 * @tc.desc: GetPrefixByAddr
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(Ipv6AddressTest, GetPrefixByAddr_001, TestSize.Level1)
{
    WIFI_LOGI("GetPrefixByAddr_001");
    size_t prefixLength = MAX_IPV6_LENGTH + 1;
    std::string ipv6 = "0101:0101:0101:0101:0101:0101:0101:0101";
    EXPECT_EQ(Ipv6Address::GetPrefixByAddr(ipv6, prefixLength), ipv6);
    prefixLength = MAX_IPV6_LENGTH - 112;
    EXPECT_EQ(Ipv6Address::GetPrefixByAddr(ipv6, prefixLength), "101::");
}
/**
 * @tc.name: GetIpv6Prefix_001
 * @tc.desc: GetIpv6Prefix(struct in6_addr &ip6Addr, size_t prefixLength)
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(Ipv6AddressTest, GetIpv6Prefix_001, TestSize.Level1)
{
    WIFI_LOGI("GetIpv6Prefix_001");
    size_t prefixLength = MAX_IPV6_LENGTH + 1;
    in6_addr ip6Addr;
    for (int i = 0; i < S6_ADDR_LENGTH; i++) {
        ip6Addr.s6_addr[i] = 1;
    }
    EXPECT_TRUE(Ipv6Address::GetIpv6Prefix(ip6Addr, prefixLength).s6_addr[0] == 0);
    prefixLength = MAX_IPV6_LENGTH;
    EXPECT_EQ(Ipv6Address::GetIpv6Prefix(ip6Addr, prefixLength).s6_addr[0], 1);
    prefixLength = MAX_IPV6_LENGTH - 1;
    EXPECT_EQ(Ipv6Address::GetIpv6Prefix(ip6Addr, prefixLength).s6_addr[0], 1);
}
/**
 * @tc.name: GetIpv6Mask_001
 * @tc.desc: GetIpv6Mask(size_t prefixLength)
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(Ipv6AddressTest, GetIpv6Mask_001, TestSize.Level1)
{
    WIFI_LOGI("GetIpv6Mask_001");
    size_t prefixLength = MAX_IPV6_LENGTH + 1;
    EXPECT_TRUE(Ipv6Address::GetIpv6Mask(prefixLength).s6_addr[0] == 0);
    prefixLength = MAX_IPV6_LENGTH;
    EXPECT_TRUE(Ipv6Address::GetIpv6Mask(prefixLength).s6_addr[0] == UCHAR_MAX);
    prefixLength = CHAR_BIT + CHAR_BIT;
    EXPECT_TRUE(Ipv6Address::GetIpv6Mask(prefixLength).s6_addr[0] == UCHAR_MAX);
}
}  // namespace Wifi
}  // namespace OHOS
