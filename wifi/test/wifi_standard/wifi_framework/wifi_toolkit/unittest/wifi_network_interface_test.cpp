/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include "wifi_network_interface_test.h"
#include "network_interface.h"

using namespace testing::ext;

namespace OHOS {
namespace Wifi {
HWTEST_F(WifiNetworkInterfaceTest, IsValidInterfaceNameTest, TestSize.Level1)
{
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
}

HWTEST_F(WifiNetworkInterfaceTest, FetchInterfaceConfigTest, TestSize.Level1)
{
    std::vector<Ipv4Address> vecIPv4;
    std::vector<Ipv6Address> vecIPv6;
    EXPECT_TRUE(NetworkInterface::FetchInterfaceConfig("wlan0", vecIPv4, vecIPv6) == true);
    NetworkInterface::Dump("wlan0");
}
}  // namespace Wifi
}  // namespace OHOS