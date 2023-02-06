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
 
#include "../../../services/wifi_standard/wifi_framework/wifi_toolkit/net_helper/dhcpd_interface.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <cstddef>
#include <cstdint>
#include "securec.h"

using ::testing::Return;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
class WifiDhcpdInterfaceTest : public testing::Test{
public:
    static void SetUpTestCase(){};
    static void TearDownTestCase(){};
    virtual void SetUp(){};
    virtual void TearDown(){};

    void SetDhcpEventFuncTest()
    {
        char* ifaceName[] = nullptr;
        IDhcpResultNotify* pResultNotify = nullptr;
        DhcpdInterface.SetDhcpEventFunc(ifaceName, pResultNotify);
    }

    void AssignIpAddrTest()
    {
        bool isIpV4 = false;
        std::vector<Ipv4Address> vecIpv4Addr;
        std::vector<Ipv6Address> vecIpv6Addr;
        vecIpv4Addr.push_back("111");
        vecIpv6Addr.push_back("111");
        Ipv4Address ipv4;
        Ipv6Address ipv6;
        DhcpdInterface.AssignIpAddr(ipv4, ipv6, vecIpv4Addr, vecIpv6Addr, isIpV4);
    }

    void AssignIpAddrV6Test()
    {
        std::vector<Ipv6Address> vecIpAddr;
        vecIpAddr.push_back("111");
        vecIpAddr.push_back("111");
        vecIpAddr.push_back("111");
        DhcpdInterface.AssignIpAddrV6(vecIpAddr);
    }
};

HWTEST_F(WifiDhcpdInterfaceTest, SetDhcpEventFuncTest, TestSize.Level1)
{
    SetDhcpEventFuncTest();
}
HWTEST_F(WifiDhcpdInterfaceTest, AssignIpAddrTest, TestSize.Level1)
{
    AssignIpAddrTest();
}
HWTEST_F(WifiDhcpdInterfaceTest, AssignIpAddrV6Test, TestSize.Level1)
{
    AssignIpAddrV6Test();
}


}  // namespace Wifi
}  // namespace OHOS

