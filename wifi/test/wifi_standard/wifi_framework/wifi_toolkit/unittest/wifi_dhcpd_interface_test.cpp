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
 
#include "dhcpd_interface.h"
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
    virtual void SetUp()
    {
        pDhcpdInterface = std::make_unique<DhcpdInterface>();
    };
    virtual void TearDown()
    {
        pDhcpdInterface.reset();
    };
public:
    std::unique_ptr<DhcpdInterface> pDhcpdInterface;
};

HWTEST_F(WifiDhcpdInterfaceTest, SetDhcpEventFuncTest, TestSize.Level1)
{
    std::string ifaceName = "DHCPFUNC";
    IDhcpResultNotify* pResultNotify = nullptr;
    pDhcpdInterface->SetDhcpEventFunc(ifaceName, pResultNotify);
}
HWTEST_F(WifiDhcpdInterfaceTest, StartDhcpServerTest, TestSize.Level1)
{
    bool isIpV4 = false;
    std::string ifaceName = "StartDhcpServer";
    Ipv4Address ipv4(Ipv4Address::INVALID_INET_ADDRESS);
    Ipv6Address ipv6(Ipv6Address::INVALID_INET6_ADDRESS);
    pDhcpdInterface->StartDhcpServer(ifaceName, ipv4, ipv6, isIpV4);
}
}  // namespace Wifi
}  // namespace OHOS

