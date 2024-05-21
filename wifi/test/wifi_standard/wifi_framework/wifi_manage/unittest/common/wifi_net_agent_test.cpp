/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include "wifi_net_agent.h"
#include "wifi_log.h"
#include "wifi_logger.h"
using namespace testing;
using ::testing::_;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
class WifiNetAgentTest : public Test {
public:
    void SetUp() override
    {
    }

    void TearDown() override
    {
    }
};

HWTEST_F(WifiNetAgentTest, RegisterNetSupplier_ReturnsFalseWhenRegistrationFails, TestSize.Level1)
{
    EXPECT_FALSE(WifiNetAgent::GetInstance().RegisterNetSupplier());
}

HWTEST_F(WifiNetAgentTest, RegisterNetSupplierCallback_ReturnsFalseWhenRegistrationFails, TestSize.Level1)
{
    EXPECT_FALSE(WifiNetAgent::GetInstance().RegisterNetSupplierCallback());
}

HWTEST_F(WifiNetAgentTest, UnregisterNetSupplier_CallsUnregisterNetSupplier, TestSize.Level1)
{
    WifiNetAgent::GetInstance().UnregisterNetSupplier();
}

HWTEST_F(WifiNetAgentTest, UpdateNetSupplierInfo_CallsUpdateNetSupplierInfo, TestSize.Level1)
{
    sptr<NetManagerStandard::NetSupplierInfo> netSupplierInfo = new NetManagerStandard::NetSupplierInfo();

    WifiNetAgent::GetInstance().UpdateNetSupplierInfo(netSupplierInfo);
}

HWTEST_F(WifiNetAgentTest, UpdateNetLinkInfo_CallsUpdateNetLinkInfo, TestSize.Level1)
{
    sptr<NetManagerStandard::NetLinkInfo> netLinkInfo = new NetManagerStandard::NetLinkInfo();
    int instId = 0;
    IpInfo wifiIpInfo;
    IpV6Info wifiIpV6Info;
    WifiDeviceConfig config;
    WifiNetAgent::GetInstance().UpdateNetLinkInfo(wifiIpInfo, wifiIpV6Info, config.wifiProxyconfig, instId);
}
}
}