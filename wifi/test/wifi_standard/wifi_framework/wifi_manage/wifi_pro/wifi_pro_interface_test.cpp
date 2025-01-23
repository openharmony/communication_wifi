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
#include "wifi_pro_interface.h"
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

class WifiProInterfaceTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        wifiProInterface_ = std::make_unique<WifiProInterface>();
        wifiProInterface_->InitWifiProService();
    }

    virtual void TearDown()
    {
        if (wifiProInterface_->pWifiProService_ != nullptr) {
            wifiProInterface_->pWifiProService_.reset();
        }
        wifiProInterface_.reset();
    }

    std::unique_ptr<WifiProInterface> wifiProInterface_;
};

HWTEST_F(WifiProInterfaceTest, DealStaConnChangedTest01, TestSize.Level1)
{
    OperateResState state = OperateResState::CONNECT_AP_CONNECTED;
    WifiLinkedInfo linkedInfo;
    int32_t instId = 1;
    linkedInfo.networkId = 1;
    linkedInfo.bssid = "TEST";
    wifiProInterface_->DealStaConnChanged(state, linkedInfo, instId);
    EXPECT_NE(wifiProInterface_->instId_, TEN);
}

HWTEST_F(WifiProInterfaceTest, DealRssiLevelChangedTest01, TestSize.Level1)
{
    int32_t rssi = 1;
    int32_t instId = 1;
    wifiProInterface_->DealRssiLevelChanged(rssi, instId);
    EXPECT_NE(wifiProInterface_->instId_, TEN);
}

HWTEST_F(WifiProInterfaceTest, DealScanResultTest01, TestSize.Level1)
{
    std::vector<InterScanInfo> results;
    wifiProInterface_->DealScanResult(results);
    EXPECT_NE(wifiProInterface_->instId_, TEN);
}

HWTEST_F(WifiProInterfaceTest, DealQoeReportTest01, TestSize.Level1)
{
    NetworkLagType networkLagType = NetworkLagType::WIFIPRO_QOE_REPORT;
    NetworkLagInfo networkLagInfo;
    wifiProInterface_->DealQoeReport(networkLagType, networkLagInfo);
    EXPECT_NE(wifiProInterface_->instId_, TEN);
}

HWTEST_F(WifiProInterfaceTest, GetStaCallbackTest01, TestSize.Level1)
{
    StaServiceCallback callback;
    wifiProInterface_->staCallback_ = callback;
    wifiProInterface_->GetStaCallback();
    EXPECT_NE(wifiProInterface_->instId_, TEN);
}
} // namespace Wifi
} // namespace OHOS