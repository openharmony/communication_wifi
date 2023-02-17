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

#include "network_interface.h"
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <cstddef>
#include <cstdint>
#include "securec.h"

using ::testing::Return;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {

class WifiNetwork : public testing::Test {
public:
    static void SetUpTestCase(){};
    static void TearDownTestCase(){};
    virtual void SetUp(){};
    virtual void TearDown(){};
}; 
HWTEST_F(WifiNetwork, IsValidInterfaceNameTest, TestSize.Level1)
{
    std::string interfaceName = "IsValidInterfaceNameTest";
    NetworkInterface::IsValidInterfaceName(interfaceName);
}
HWTEST_F(WifiNetwork, DumpTest, TestSize.Level1)
{
    std::string interfaceName = "DumpTest";
    NetworkInterface::Dump(interfaceName);
}
HWTEST_F(WifiNetwork, ClearAllIpAddressTest, TestSize.Level1)
{
    std::string ifaceName = "ClearAllIpAddressTest";
    NetworkInterface::ClearAllIpAddress(ifaceName);
}
HWTEST_F(WifiNetwork, GetAllIpv6AddressTest, TestSize.Level1)
{
    std::string ifaceName = "GetAllIpv6AddressTest";
    std::vector<Ipv6Address> vecIPv6;
    NetworkInterface::GetAllIpv6Address(ifaceName, vecIPv6);
}

HWTEST_F(WifiNetwork, GetAllIpv4AddressTest, TestSize.Level1)
{
    std::string ifaceName = "GetIpv4AddressTest";
    std::vector<Ipv4Address> vecIPv4;
    NetworkInterface::GetIpv4Address(ifaceName, vecIPv4);
}
HWTEST_F(WifiNetwork, FetchInterfaceConfigTest, TestSize.Level1)
{
    std::string ifaceName = "FetchInterfaceConfigTest";
    std::vector<Ipv4Address> vecIPv4;
    std::vector<Ipv6Address> vecIPv6;
    NetworkInterface::FetchInterfaceConfig(ifaceName, vecIPv4, vecIPv6);
}
}  // namespace Wifi
}  // namespace OHOS
