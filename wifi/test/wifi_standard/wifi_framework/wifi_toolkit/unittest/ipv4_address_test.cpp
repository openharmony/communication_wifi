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
#include "ipv4_address.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_DHCP_LABEL("Ipv4AddressTest");
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
constexpr int MAX_IPV4_PREFIX_LENGTH = 32;
constexpr unsigned int IP_TEST = 0x9003a8c0;
constexpr size_t EIGHT = 8;
class Ipv4AddressTest : public testing::Test {
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
 * @tc.desc: Create(const std::string &ipv4, size_t prefixLength)
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(Ipv4AddressTest, Create_001, TestSize.Level1)
{
    WIFI_LOGI("Create_001");
    std::string ipv4 = "192.168.15";
    size_t prefixLength = 0;
    EXPECT_TRUE(Ipv4Address::Create(ipv4, prefixLength) == Ipv4Address::invalidInetAddress);
    ipv4 = "192.168.15.23";
    prefixLength = MAX_IPV4_PREFIX_LENGTH;
    EXPECT_TRUE(Ipv4Address::Create(ipv4, prefixLength) == Ipv4Address::invalidInetAddress);
    prefixLength = MAX_IPV4_PREFIX_LENGTH - 1;
    Ipv4Address::Create(ipv4, prefixLength);
}
/**
 * @tc.name: Create_002
 * @tc.desc: Create(const std::string &ipv4, const std::string &mask)
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(Ipv4AddressTest, Create_002, TestSize.Level1)
{
    WIFI_LOGI("Create_002");
    std::string ipv4 = "192.168.15";
    std::string mask = "255.255";
    EXPECT_TRUE(Ipv4Address::Create(ipv4, mask) == Ipv4Address::invalidInetAddress);
    mask = "255.255.255.0";
    EXPECT_TRUE(Ipv4Address::Create(ipv4, mask) == Ipv4Address::invalidInetAddress);
    ipv4 = "192.168.15.23";
    Ipv4Address::Create(ipv4, mask);
}
/**
 * @tc.name: Create_003
 * @tc.desc: Create(const in_addr &ipv4, const in_addr &mask)
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(Ipv4AddressTest, Create_003, TestSize.Level1)
{
    WIFI_LOGI("Create_003");
    in_addr ipv4;
    ipv4.s_addr = IP_TEST;
    in_addr mask;
    mask.s_addr = 1;
    EXPECT_EQ(Ipv4Address::Create(ipv4, mask).GetAddressWithString(), "192.168.3.144");
}
/**
 * @tc.name: GetAddressWithInet_001
 * @tc.desc: GetAddressWithInet()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(Ipv4AddressTest, GetAddressWithInet_001, TestSize.Level1)
{
    WIFI_LOGI("GetAddressWithInet_001");
    std::string ipv4 = "192.168.3.144";
    size_t prefixLength = EIGHT;
    Ipv4Address mIpv4Address = Ipv4Address::Create(ipv4, prefixLength);
    EXPECT_TRUE(mIpv4Address.GetAddressWithInet().s_addr == IP_TEST);
}
/**
 * @tc.name: GetMaskWithString_001
 * @tc.desc: GetMaskWithString()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(Ipv4AddressTest, GetMaskWithString_001, TestSize.Level1)
{
    WIFI_LOGI("GetMaskWithString_001");
    std::string ipv4 = "192.168.3.144";
    size_t prefixLength = EIGHT;
    Ipv4Address mIpv4Address = Ipv4Address::Create(ipv4, prefixLength);
    EXPECT_TRUE(mIpv4Address.GetMaskWithString() == "255.0.0.0");
}
/**
 * @tc.name: GetNetworkAddressWithString_001
 * @tc.desc: GetNetworkAddressWithString()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(Ipv4AddressTest, GetNetworkAddressWithString_001, TestSize.Level1)
{
    WIFI_LOGI("GetNetworkAddressWithString_001");
    std::string ipv4 = "192.168.3.144";
    size_t prefixLength = EIGHT;
    Ipv4Address mIpv4Address = Ipv4Address::Create(ipv4, prefixLength);
    EXPECT_TRUE(mIpv4Address.GetNetworkAddressWithString() == "192.0.0.0");
}
/**
 * @tc.name: GetHostAddressWithString_001
 * @tc.desc: GetHostAddressWithString()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(Ipv4AddressTest, GetHostAddressWithString_001, TestSize.Level1)
{
    WIFI_LOGI("GetHostAddressWithString_001");
    std::string ipv4 = "192.168.3.144";
    size_t prefixLength = EIGHT;
    Ipv4Address mIpv4Address = Ipv4Address::Create(ipv4, prefixLength);
    EXPECT_TRUE(mIpv4Address.GetHostAddressWithString() == "0.168.3.144");
}
/**
 * @tc.name: GetNetwork_001
 * @tc.desc: GetNetwork()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(Ipv4AddressTest, GetNetwork_001, TestSize.Level1)
{
    WIFI_LOGI("GetNetwork_001");
    std::string ipv4 = "192.168.3.144";
    size_t prefixLength = EIGHT;
    Ipv4Address mIpv4Address = Ipv4Address::Create(ipv4, prefixLength);
    EXPECT_TRUE(mIpv4Address.GetNetwork() == "192.168.3.144/8");
}
}  // namespace Wifi
}  // namespace OHOS