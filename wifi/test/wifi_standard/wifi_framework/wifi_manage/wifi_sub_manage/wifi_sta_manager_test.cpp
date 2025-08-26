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
#include "wifi_sta_manager.h"
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

class WifiStaManagerTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}

    static void TearDownTestCase()
    {}

    virtual void SetUp()
    {
        wifiStaManager_ = std::make_unique<WifiStaManager>();
        wifiStaManager_->InitStaCallback();
    }

    virtual void TearDown()
    {
        wifiStaManager_.reset();
    }
    std::unique_ptr<WifiStaManager> wifiStaManager_;
};

HWTEST_F(WifiStaManagerTest, GetStaCallbackTest01, TestSize.Level1)
{
    wifiStaManager_->GetStaCallback();
    EXPECT_NE(wifiStaManager_->unloadStaSaTimerId, TEN);
}

#ifndef OHOS_ARCH_LITE
HWTEST_F(WifiStaManagerTest, StartUnloadStaSaTimerTest01, TestSize.Level1)
{
    wifiStaManager_->unloadStaSaTimerId = 0;
    wifiStaManager_->StartUnloadStaSaTimer();
    EXPECT_NE(wifiStaManager_->unloadStaSaTimerId, TEN);
}

HWTEST_F(WifiStaManagerTest, StopUnloadStaSaTimerTest01, TestSize.Level1)
{
    wifiStaManager_->unloadStaSaTimerId = 1;
    wifiStaManager_->StopUnloadStaSaTimer();
    EXPECT_NE(wifiStaManager_->unloadStaSaTimerId, TEN);
}
#endif

HWTEST_F(WifiStaManagerTest, CloseStaServiceTest01, TestSize.Level1)
{
    int instId = 1;
    wifiStaManager_->CloseStaService(instId);
    EXPECT_NE(wifiStaManager_->unloadStaSaTimerId, TEN);
}

HWTEST_F(WifiStaManagerTest, DealStaOpenedTest01, TestSize.Level1)
{
    int instId = 1;
    wifiStaManager_->DealStaOpened(instId);
    EXPECT_NE(wifiStaManager_->unloadStaSaTimerId, TEN);
}

HWTEST_F(WifiStaManagerTest, PublishWifiOperateStateHiSysEventTest01, TestSize.Level1)
{
    OperateResState state = OperateResState::CONNECT_ASSOCIATING;
    wifiStaManager_->PublishWifiOperateStateHiSysEvent(state);
    EXPECT_NE(wifiStaManager_->unloadStaSaTimerId, TEN);
}

HWTEST_F(WifiStaManagerTest, PublishWifiOperateStateHiSysEventTest02, TestSize.Level1)
{
    OperateResState state = OperateResState::CONNECT_ASSOCIATED;
    wifiStaManager_->PublishWifiOperateStateHiSysEvent(state);
    EXPECT_NE(wifiStaManager_->unloadStaSaTimerId, TEN);
}

HWTEST_F(WifiStaManagerTest, PublishWifiOperateStateHiSysEventTest03, TestSize.Level1)
{
    OperateResState state = OperateResState::CONNECT_CONNECTION_FULL;
    wifiStaManager_->PublishWifiOperateStateHiSysEvent(state);
    EXPECT_NE(wifiStaManager_->unloadStaSaTimerId, TEN);
}

HWTEST_F(WifiStaManagerTest, PublishWifiOperateStateHiSysEventTest04, TestSize.Level1)
{
    OperateResState state = OperateResState::CONNECT_OBTAINING_IP;
    wifiStaManager_->PublishWifiOperateStateHiSysEvent(state);
    EXPECT_NE(wifiStaManager_->unloadStaSaTimerId, TEN);
}

HWTEST_F(WifiStaManagerTest, PublishWifiOperateStateHiSysEventTest05, TestSize.Level1)
{
    OperateResState state = OperateResState::DISCONNECT_DISCONNECTING;
    wifiStaManager_->PublishWifiOperateStateHiSysEvent(state);
    EXPECT_NE(wifiStaManager_->unloadStaSaTimerId, TEN);
}

HWTEST_F(WifiStaManagerTest, DealStaConnChangedTest01, TestSize.Level1)
{
    OperateResState state = OperateResState::CONNECT_AP_CONNECTED;
    WifiLinkedInfo info;
    info.connState = ConnState::AUTHENTICATING;
    int instId = 1;
    wifiStaManager_->DealStaConnChanged(state, info, instId);
    EXPECT_NE(wifiStaManager_->unloadStaSaTimerId, TEN);
}

HWTEST_F(WifiStaManagerTest, DealSignalPollReportTest01, TestSize.Level1)
{
    std::string bssid = "11:22:33:44:55:66";
    int32_t signalLevel = 2;
    int32_t instId = 0;
    wifiStaManager_->DealSignalPollReport(bssid, signalLevel, instId);
    EXPECT_NE(wifiStaManager_->unloadStaSaTimerId, TEN);
}

HWTEST_F(WifiStaManagerTest, DealAutoSelectNetworkChangedTest01, TestSize.Level1)
{
    int networkId = 1;
    int instId = 1;
    wifiStaManager_->DealAutoSelectNetworkChanged(networkId, instId);
    EXPECT_NE(wifiStaManager_->unloadStaSaTimerId, TEN);
}

#ifndef OHOS_ARCH_LITE
HWTEST_F(WifiStaManagerTest, StopSatelliteTimerTest01, TestSize.Level1)
{
    wifiStaManager_->satelliteTimerId = 1;
    wifiStaManager_->StopSatelliteTimer();
    EXPECT_NE(wifiStaManager_->unloadStaSaTimerId, TEN);
}
#endif
} // namespace Wifi
} // namespace OHOS