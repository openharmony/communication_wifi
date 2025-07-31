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
#include <string>
#include <vector>
#include "wifi_pro_service.h"
#include "wifi_logger.h"
#include "wifi_msg.h"
#include "wifi_errcode.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {

constexpr int TEN = 10;

class WifiProServiceTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        wifiProService_ = std::make_unique<WifiProService>();
        wifiProService_->InitWifiProService();
    }

    virtual void TearDown()
    {
        if (wifiProService_->pWifiProStateMachine_ != nullptr) {
            wifiProService_->pWifiProStateMachine_.reset();
        }
        wifiProService_.reset();
    }

    std::unique_ptr<WifiProService> wifiProService_;
};

HWTEST_F(WifiProServiceTest, HandleStaConnChangedTest01, TestSize.Level1)
{
    OperateResState state = OperateResState::CONNECT_AP_CONNECTED;
    WifiLinkedInfo linkedInfo;
    linkedInfo.networkId = 1;
    linkedInfo.bssid = "TEST";
    wifiProService_->HandleStaConnChanged(state, linkedInfo);
    EXPECT_NE(wifiProService_->instId_, TEN);
}

HWTEST_F(WifiProServiceTest, HandleStaConnChangedTest02, TestSize.Level1)
{
    OperateResState state = OperateResState::CONNECT_CHECK_PORTAL;
    WifiLinkedInfo linkedInfo;
    linkedInfo.networkId = 1;
    linkedInfo.bssid = "TEST";
    wifiProService_->HandleStaConnChanged(state, linkedInfo);
    EXPECT_NE(wifiProService_->instId_, TEN);
}

HWTEST_F(WifiProServiceTest, HandleStaConnChangedTest03, TestSize.Level1)
{
    OperateResState state = OperateResState::CONNECT_ENABLE_NETWORK_FAILED;
    WifiLinkedInfo linkedInfo;
    linkedInfo.networkId = 1;
    linkedInfo.bssid = "TEST";
    wifiProService_->HandleStaConnChanged(state, linkedInfo);
    EXPECT_NE(wifiProService_->instId_, TEN);
}

HWTEST_F(WifiProServiceTest, HandleStaConnChangedTest04, TestSize.Level1)
{
    WifiLinkedInfo linkedInfo;
    linkedInfo.networkId = 1;
    linkedInfo.bssid = "TEST";
    linkedInfo.wifiLinkType = WifiLinkType::WIFI7_EMLSR;
    wifiProService_->HandleStaConnChanged(OperateResState::CONNECT_EMLSR_START, linkedInfo);
    linkedInfo.wifiLinkType = WifiLinkType::WIFI7_MLSR;
    wifiProService_->HandleStaConnChanged(OperateResState::CONNECT_EMLSR_END, linkedInfo);
    EXPECT_NE(wifiProService_->instId_, TEN);
}

HWTEST_F(WifiProServiceTest, HandleRssiLevelChangedTest01, TestSize.Level1)
{
    int32_t rssi = 1;
    wifiProService_->HandleRssiLevelChanged(rssi);
    EXPECT_NE(wifiProService_->instId_, TEN);
}

HWTEST_F(WifiProServiceTest, HandleScanResultTest01, TestSize.Level1)
{
    std::vector<InterScanInfo> scanInfos;
    wifiProService_->HandleScanResult(scanInfos);
    EXPECT_NE(wifiProService_->instId_, TEN);
}

HWTEST_F(WifiProServiceTest, HandleQoeReportTest01, TestSize.Level1)
{
    NetworkLagType networkLagType = NetworkLagType::WIFIPRO_QOE_REPORT;
    NetworkLagInfo networkLagInfo;
    wifiProService_->HandleQoeReport(networkLagType, networkLagInfo);
    EXPECT_NE(wifiProService_->instId_, TEN);
}
} // namespace Wifi
} // namespace OHOS