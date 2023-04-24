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
#include "network_interface.h"
#include "wifi_logger.h"
#include "base_address.h"

DEFINE_WIFILOG_DHCP_LABEL("NetworkInterfaceTest");
using namespace testing::ext;

namespace OHOS {
namespace Wifi {
constexpr int NINE = 9;
class NetworkInterfaceTest : public testing::Test {
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

class BaseAddressTest : public BaseAddress {
public:
    BaseAddressTest(const std::string ip, BaseAddress::FamilyType familyType)
        : BaseAddress(ip, 1, familyType)
    {
        WIFI_LOGI("BaseAddressTest constructor");
    }

    bool IsValid() const override
    {
        if (GetAddressWithString().size() == NINE) {
            WIFI_LOGI("Is valid");
            return true;
        } else {
            WIFI_LOGI("Is not valid");
            return false;
        }
    }
};
/**
 * @tc.name: IsValidInterfaceNameTest
 * @tc.desc: IsValidInterfaceName(const std::string &interfaceName)
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(NetworkInterfaceTest, IsValidInterfaceNameTest, TestSize.Level1)
{
    WIFI_LOGI("IsValidInterfaceNameTest enter");
    std::string ifaceName;
    EXPECT_TRUE(NetworkInterface::IsValidInterfaceName(ifaceName) == false);
    ifaceName = "01234567890123450";
    EXPECT_TRUE(NetworkInterface::IsValidInterfaceName(ifaceName) == false);
    ifaceName = "0123456789012345";
    EXPECT_TRUE(NetworkInterface::IsValidInterfaceName(ifaceName) == true);
    ifaceName = "_123456789012345";
    EXPECT_TRUE(NetworkInterface::IsValidInterfaceName(ifaceName) == false);
    ifaceName = "012345678901234?";
    EXPECT_TRUE(NetworkInterface::IsValidInterfaceName(ifaceName) == false);
    ifaceName = "012345678901234_";
    EXPECT_TRUE(NetworkInterface::IsValidInterfaceName(ifaceName) == true);
    ifaceName = "012345678901234-";
    EXPECT_TRUE(NetworkInterface::IsValidInterfaceName(ifaceName) == true);
    ifaceName = "012345678901234:";
    EXPECT_TRUE(NetworkInterface::IsValidInterfaceName(ifaceName) == true);
}
/**
 * @tc.name: FetchInterfaceConfigTest
 * @tc.desc: FetchInterfaceConfig
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(NetworkInterfaceTest, FetchInterfaceConfigTest, TestSize.Level1)
{
    WIFI_LOGI("FetchInterfaceConfigTest enter");
    std::vector<Ipv4Address> vecIPv4;
    std::vector<Ipv6Address> vecIPv6;
    EXPECT_TRUE(NetworkInterface::FetchInterfaceConfig("wlan0", vecIPv4, vecIPv6) == true);
    NetworkInterface::Dump("wlan0");
}
/**
 * @tc.name: GetIpv4Address_001
 * @tc.desc: GetIpv4Address(const std::string &interfaceName, std::vector<Ipv4Address> &vecIPv4)
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(NetworkInterfaceTest, GetIpv4Address_001, TestSize.Level1)
{
    WIFI_LOGI("GetIpv4Address_001 enter");
    std::vector<Ipv4Address> vecIPv4;
    EXPECT_FALSE(NetworkInterface::GetIpv4Address("test", vecIPv4));
    NetworkInterface::GetIpv4Address("lo", vecIPv4);
}
/**
 * @tc.name: GetAllIpv6Address_001
 * @tc.desc: GetAllIpv6Address(const std::string &interfaceName, std::vector<Ipv6Address> &vecIPv6)
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(NetworkInterfaceTest, GetAllIpv6Address_001, TestSize.Level1)
{
    WIFI_LOGI("GetAllIpv6Address_001 enter");
    std::vector<Ipv6Address> vecIPv6;
    EXPECT_FALSE(NetworkInterface::GetAllIpv6Address("test", vecIPv6));
    EXPECT_TRUE(NetworkInterface::GetAllIpv6Address("wlan0", vecIPv6));
}
/**
 * @tc.name: IsExistAddressForInterface_001
 * @tc.desc: IsExistAddressForInterface(const std::string &interfaceName, const BaseAddress &address)
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(NetworkInterfaceTest, IsExistAddressForInterface_001, TestSize.Level1)
{
    WIFI_LOGI("IsExistAddressForInterface_001 enter");
    BaseAddressTest address1 = BaseAddressTest("192.168.1.3", BaseAddress::FamilyType::FAMILY_INET);
    EXPECT_FALSE(NetworkInterface::IsExistAddressForInterface("test", address1));
    EXPECT_FALSE(NetworkInterface::IsExistAddressForInterface("lo", address1));
    BaseAddressTest address2 = BaseAddressTest("127.0.0.1", BaseAddress::FamilyType::FAMILY_INET);
    NetworkInterface::IsExistAddressForInterface("lo", address2);
    BaseAddressTest address3 = BaseAddressTest("0:0:0:0:0:0:0:1", BaseAddress::FamilyType::FAMILY_INET6);
    NetworkInterface::IsExistAddressForInterface("lo", address3);
}
/**
 * @tc.name: AddIpAddress_001
 * @tc.desc: AddIpAddress(const std::string &interfaceName, const BaseAddress &ipAddress)
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(NetworkInterfaceTest, AddIpAddress_001, TestSize.Level1)
{
    WIFI_LOGI("AddIpAddress_001 enter");
    BaseAddressTest address1 = BaseAddressTest("192.168", BaseAddress::FamilyType::FAMILY_INET);
    EXPECT_FALSE(NetworkInterface::AddIpAddress("test", address1));
    BaseAddressTest address2 = BaseAddressTest("127.0.0.1", BaseAddress::FamilyType::FAMILY_INET6);
    EXPECT_FALSE(NetworkInterface::AddIpAddress("test", address2));
}
/**
 * @tc.name: DelIpAddress_001
 * @tc.desc: DelIpAddress(const std::string &interfaceName, const BaseAddress &ipAddress)
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(NetworkInterfaceTest, DelIpAddress_001, TestSize.Level1)
{
    WIFI_LOGI("DelIpAddress_001 enter");
    BaseAddressTest address1 = BaseAddressTest("192.168", BaseAddress::FamilyType::FAMILY_INET);
    EXPECT_FALSE(NetworkInterface::DelIpAddress("test", address1));
    BaseAddressTest address2 = BaseAddressTest("127.0.0.1", BaseAddress::FamilyType::FAMILY_INET6);
    EXPECT_TRUE(NetworkInterface::DelIpAddress("test", address2));
    NetworkInterface::DelIpAddress("lo", address2);
}
/**
 * @tc.name: ClearAllIpAddress_001
 * @tc.desc: ClearAllIpAddress(const std::string &interfaceName)
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(NetworkInterfaceTest, ClearAllIpAddress_001, TestSize.Level1)
{
    WIFI_LOGI("ClearAllIpAddress_001 enter");
    EXPECT_FALSE(NetworkInterface::ClearAllIpAddress("test"));
    NetworkInterface::ClearAllIpAddress("lo");
}
/**
 * @tc.name: IpAddressChange_001
 * @tc.desc: IpAddressChange
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(NetworkInterfaceTest, IpAddressChange_001, TestSize.Level1)
{
    WIFI_LOGI("IpAddressChange_001 enter");
    BaseAddressTest ipAddress = BaseAddressTest("192.168", BaseAddress::FamilyType::FAMILY_INET);
    EXPECT_FALSE(NetworkInterface::IpAddressChange("test", ipAddress, true, true));
}
}  // namespace Wifi
}  // namespace OHOS