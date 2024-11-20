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
#include "wifi_scan_manager.h"
#include "wifi_logger.h"
#include "wifi_msg.h"
#include "wifi_errcode.h"
#include "mock_wifi_manager.h"
#include "mock_wifi_config_center.h"
#include "mock_wifi_settings.h"

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

class WifiScanManagerTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}

    static void TearDownTestCase()
    {}

    virtual void SetUp()
    {
        wifiScanManager_ = std::make_unique<WifiScanManager>();
        wifiScanManager_->InitScanCallback();
    }

    virtual void TearDown()
    {
        wifiScanManager_.reset();
    }
    std::unique_ptr<WifiScanManager> wifiScanManager_;
};

HWTEST_F(WifiScanManagerTest, GetScanCallbackTest01, TestSize.Level1)
{
    wifiScanManager_->GetScanCallback();
    EXPECT_NE(wifiScanManager_->unloadScanSaTimerId, TEN);
}

HWTEST_F(WifiScanManagerTest, GetStaCallbackTest01, TestSize.Level1)
{
    wifiScanManager_->GetStaCallback();
    EXPECT_NE(wifiScanManager_->unloadScanSaTimerId, TEN);
}

#ifndef OHOS_ARCH_LITE
HWTEST_F(WifiScanManagerTest, StopUnloadScanSaTimerTest01, TestSize.Level1)
{
    wifiScanManager_->unloadScanSaTimerId = 1;
    wifiScanManager_->StopUnloadScanSaTimer();
    EXPECT_NE(wifiScanManager_->unloadScanSaTimerId, TEN);
}
#endif

HWTEST_F(WifiScanManagerTest, TryToStartScanServiceTest01, TestSize.Level1)
{
    int instId = 1;
    EXPECT_EQ(wifiScanManager_->TryToStartScanService(instId), WIFI_OPT_FAILED);
}

HWTEST_F(WifiScanManagerTest, CheckAndStopScanServiceTest01, TestSize.Level1)
{
    int instId = 1;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScanMidState(_)).WillRepeatedly(Return(WifiOprMidState::OPENING));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetAirplaneModeState()).WillRepeatedly(Return(MODE_STATE_OPEN));
    wifiScanManager_->CheckAndStopScanService(instId);
    EXPECT_NE(wifiScanManager_->unloadScanSaTimerId, TEN);
}

HWTEST_F(WifiScanManagerTest, CloseScanServiceTest01, TestSize.Level1)
{
    int instId = 1;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScanMidState(_)).WillRepeatedly(Return(WifiOprMidState::OPENING));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiMidState(_)).WillRepeatedly(Return(WifiOprMidState::OPENING));
    wifiScanManager_->CloseScanService(instId);
    EXPECT_NE(wifiScanManager_->unloadScanSaTimerId, TEN);
}

HWTEST_F(WifiScanManagerTest, DealScanOpenResTest01, TestSize.Level1)
{
    int instId = 1;
    wifiScanManager_->DealScanOpenRes(instId);
    EXPECT_NE(wifiScanManager_->unloadScanSaTimerId, TEN);
}

HWTEST_F(WifiScanManagerTest, DealScanCloseResTest01, TestSize.Level1)
{
    int instId = 1;
    wifiScanManager_->DealScanCloseRes(instId);
    EXPECT_NE(wifiScanManager_->unloadScanSaTimerId, TEN);
}

HWTEST_F(WifiScanManagerTest, DealStoreScanInfoEventTest01, TestSize.Level1)
{
    std::vector<InterScanInfo> results;
    int instId = 1;
    wifiScanManager_->DealStoreScanInfoEvent(results, instId);
    EXPECT_NE(wifiScanManager_->unloadScanSaTimerId, TEN);
}

HWTEST_F(WifiScanManagerTest, DealStaOpenedTest01, TestSize.Level1)
{
    int instId = 1;
    wifiScanManager_->DealStaOpened(instId);
    EXPECT_NE(wifiScanManager_->unloadScanSaTimerId, TEN);
}
} // namespace Wifi
} // namespace OHOS