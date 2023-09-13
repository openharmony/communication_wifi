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
#include <gmock/gmock.h>
#include <cstddef>
#include <cstdint>
#include "securec.h"
#include "wifi_manager.h"
#include "wifi_settings.h"
#include "wifi_config_center.h"
#include "wifi_service_manager.h"
#include "wifi_logger.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Ref;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;
DEFINE_WIFILOG_LABEL("WifiManagerTest");

namespace OHOS {
namespace Wifi {
class WifiManagerTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp() {}
    virtual void TearDown() {}
public:
    WifiManager wifiManager;
};

HWTEST_F(WifiManagerTest, AutoStartStaService_001, TestSize.Level1)
{
    WIFI_LOGE("AutoStartStaService_001 enter!");
    WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::CLOSING);
    EXPECT_EQ(wifiManager.AutoStartStaService(
        AutoStartOrStopServiceReason::AUTO_START_UPON_STARTUP), WIFI_OPT_OPEN_FAIL_WHEN_CLOSING);
    WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::RUNNING);
    EXPECT_EQ(wifiManager.AutoStartStaService(
        AutoStartOrStopServiceReason::AUTO_START_UPON_STARTUP), WIFI_OPT_OPEN_SUCC_WHEN_OPENED);
}

HWTEST_F(WifiManagerTest, AutoStartStaService_002, TestSize.Level1)
{
    WIFI_LOGE("AutoStartStaService_002 enter!");
    WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::CLOSED);
    ErrCode result = wifiManager.AutoStartStaService(AutoStartOrStopServiceReason::STA_AP_EXCLUSION);
    WIFI_LOGE("AutoStartStaService_002 result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_FAILED);
}

HWTEST_F(WifiManagerTest, AutoStopStaService_001, TestSize.Level1)
{
    WIFI_LOGE("AutoStopStaService_001 enter!");
    WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::OPENING);
    EXPECT_EQ(wifiManager.AutoStopStaService(
        AutoStartOrStopServiceReason::AUTO_START_UPON_STARTUP), WIFI_OPT_CLOSE_FAIL_WHEN_OPENING);
    WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::CLOSED);
    EXPECT_EQ(wifiManager.AutoStopStaService(
        AutoStartOrStopServiceReason::AUTO_START_UPON_STARTUP), WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED);
}

HWTEST_F(WifiManagerTest, AutoStopStaService_002, TestSize.Level1)
{
    WIFI_LOGE("AutoStopStaService_002 enter!");
    WifiConfigCenter::GetInstance().SetWifiMidState(WifiOprMidState::RUNNING);
    EXPECT_EQ(wifiManager.AutoStopStaService(
        AutoStartOrStopServiceReason::AUTO_START_UPON_STARTUP), WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED);
}

HWTEST_F(WifiManagerTest, StartUnloadStaSaTimerTest, TestSize.Level1)
{
    WIFI_LOGE("StartUnloadStaSaTimerTest enter!");
    wifiManager.StartUnloadStaSaTimer();
}

HWTEST_F(WifiManagerTest, StartUnloadScanSaTimerTest, TestSize.Level1)
{
    WIFI_LOGE("StartUnloadScanSaTimerTest enter!");
    wifiManager.StartUnloadScanSaTimer();
}

HWTEST_F(WifiManagerTest, AutoStartApService_001, TestSize.Level1)
{
    WIFI_LOGE("AutoStartApService_001 enter!");
    WifiConfigCenter::GetInstance().SetApMidState(WifiOprMidState::CLOSING, 0);
    EXPECT_EQ(wifiManager.AutoStartApService(
        AutoStartOrStopServiceReason::AUTO_START_UPON_STARTUP), WIFI_OPT_OPEN_FAIL_WHEN_CLOSING);
    WifiConfigCenter::GetInstance().SetApMidState(WifiOprMidState::RUNNING, 0);
    EXPECT_EQ(wifiManager.AutoStartApService(
        AutoStartOrStopServiceReason::AUTO_START_UPON_STARTUP), WIFI_OPT_OPEN_SUCC_WHEN_OPENED);
}

HWTEST_F(WifiManagerTest, AutoStartApService_002, TestSize.Level1)
{
    WIFI_LOGE("AutoStartApService_002 enter!");
    WifiConfigCenter::GetInstance().SetApMidState(WifiOprMidState::CLOSED, 0);
    EXPECT_EQ(wifiManager.AutoStartApService(
        AutoStartOrStopServiceReason::AUTO_START_UPON_STARTUP), WIFI_OPT_FAILED);
}

HWTEST_F(WifiManagerTest, AutoStopApService_001, TestSize.Level1)
{
    WIFI_LOGE("AutoStopApService_001 enter!");
    WifiConfigCenter::GetInstance().SetApMidState(WifiOprMidState::OPENING, 0);
    EXPECT_EQ(wifiManager.AutoStopApService(
        AutoStartOrStopServiceReason::AUTO_START_UPON_STARTUP), WIFI_OPT_CLOSE_FAIL_WHEN_OPENING);
    WifiConfigCenter::GetInstance().SetApMidState(WifiOprMidState::CLOSED, 0);
    EXPECT_EQ(wifiManager.AutoStopApService(
        AutoStartOrStopServiceReason::AUTO_START_UPON_STARTUP), WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED);
}

HWTEST_F(WifiManagerTest, AutoStopApService_002, TestSize.Level1)
{
    WIFI_LOGE("AutoStopApService_002 enter!");
    WifiConfigCenter::GetInstance().SetApMidState(WifiOprMidState::RUNNING, 0);
    EXPECT_EQ(wifiManager.AutoStopApService(
        AutoStartOrStopServiceReason::AUTO_START_UPON_STARTUP), WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED);
}

HWTEST_F(WifiManagerTest, StartUnloadApSaTimerTest, TestSize.Level1)
{
    WIFI_LOGE("StartUnloadApSaTimerTest enter!");
    wifiManager.StartUnloadApSaTimer();
}

HWTEST_F(WifiManagerTest, AutoStartP2pService_001, TestSize.Level1)
{
    WIFI_LOGE("AutoStartP2pService_001 enter!");
    WifiConfigCenter::GetInstance().SetP2pMidState(WifiOprMidState::CLOSING);
    EXPECT_EQ(wifiManager.AutoStartP2pService(
        AutoStartOrStopServiceReason::AUTO_START_UPON_STARTUP), WIFI_OPT_OPEN_FAIL_WHEN_CLOSING);
    WifiConfigCenter::GetInstance().SetP2pMidState(WifiOprMidState::RUNNING);
    EXPECT_EQ(wifiManager.AutoStartP2pService(
        AutoStartOrStopServiceReason::AUTO_START_UPON_STARTUP), WIFI_OPT_OPEN_SUCC_WHEN_OPENED);
}

HWTEST_F(WifiManagerTest, AutoStartP2pService_002, TestSize.Level1)
{
    WIFI_LOGE("AutoStartP2pService_002 enter!");
    WifiConfigCenter::GetInstance().SetP2pMidState(WifiOprMidState::CLOSED);
    EXPECT_EQ(wifiManager.AutoStartP2pService(
        AutoStartOrStopServiceReason::AUTO_START_UPON_STARTUP), WIFI_OPT_FAILED);
}

HWTEST_F(WifiManagerTest, AutoStopP2pService_001, TestSize.Level1)
{
    WIFI_LOGE("AutoStopP2pService_001 enter!");
    WifiConfigCenter::GetInstance().SetP2pMidState(WifiOprMidState::OPENING);
    EXPECT_EQ(wifiManager.AutoStopP2pService(
        AutoStartOrStopServiceReason::AUTO_START_UPON_STARTUP), WIFI_OPT_CLOSE_FAIL_WHEN_OPENING);
    WifiConfigCenter::GetInstance().SetP2pMidState(WifiOprMidState::CLOSED);
    EXPECT_EQ(wifiManager.AutoStopP2pService(
        AutoStartOrStopServiceReason::AUTO_START_UPON_STARTUP), WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED);
}

HWTEST_F(WifiManagerTest, AutoStopP2pService_002, TestSize.Level1)
{
    WIFI_LOGE("AutoStopP2pService_002 enter!");
    WifiConfigCenter::GetInstance().SetP2pMidState(WifiOprMidState::RUNNING);
    EXPECT_EQ(wifiManager.AutoStopP2pService(
        AutoStartOrStopServiceReason::AUTO_START_UPON_STARTUP), WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED);
}

HWTEST_F(WifiManagerTest, StartUnloadP2PSaTimerTest, TestSize.Level1)
{
    WIFI_LOGE("StartUnloadP2PSaTimerTest enter!");
    wifiManager.StartUnloadP2PSaTimer();
}

HWTEST_F(WifiManagerTest, GetSupportedFeaturesTest, TestSize.Level1)
{
    WIFI_LOGE("GetSupportedFeaturesTest enter!");
    long features;
    int result = wifiManager.GetSupportedFeatures(features);
    WIFI_LOGE("GetSupportedFeaturesTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiManagerTest, GetAirplaneModeByDatashareTest, TestSize.Level1)
{
    WIFI_LOGE("DealOpenAirplGetAirplaneModeByDatashareTestaneModeEventTest enter!");
    wifiManager.GetAirplaneModeByDatashare();
}

HWTEST_F(WifiManagerTest, DealOpenAirplaneModeEventTest, TestSize.Level1)
{
    WIFI_LOGE("DealOpenAirplaneModeEventTest enter!");
    wifiManager.DealOpenAirplaneModeEvent();
}

HWTEST_F(WifiManagerTest, DealCloseAirplaneModeEvent_001, TestSize.Level1)
{
    WIFI_LOGE("DealCloseAirplaneModeEvent_001 enter!");
    WifiConfigCenter::GetInstance().SetOperatorWifiType(
        static_cast<int>(OperatorWifiType::USER_CLOSE_WIFI_IN_AIRPLANEMODE));
    WifiConfigCenter::GetInstance().SetStaLastRunState(false);
    wifiManager.unloadP2PSaTimerId = 0;
    WifiSettings::GetInstance().SetHotspotState(static_cast<int>(ApState::AP_STATE_CLOSED), 0);
    wifiManager.DealCloseAirplaneModeEvent();
}

HWTEST_F(WifiManagerTest, DealCloseAirplaneModeEvent_002, TestSize.Level1)
{
    WIFI_LOGE("DealCloseAirplaneModeEvent_002 enter!");
    WifiConfigCenter::GetInstance().SetOperatorWifiType(
        static_cast<int>(OperatorWifiType::CLOSE_WIFI_DUE_TO_AIRPLANEMODE_OPENED));
    WifiConfigCenter::GetInstance().SetStaLastRunState(false);
    wifiManager.DealCloseAirplaneModeEvent();
}

HWTEST_F(WifiManagerTest, GetLocationModeByDatashareTest, TestSize.Level1)
{
    WIFI_LOGE("GetLocationModeByDatashareTest enter!");
    bool result = wifiManager.GetLocationModeByDatashare(WIFI_DEVICE_ABILITY_ID);
    WIFI_LOGE("GetLocationModeByDatashareTest result(%{public}d)", result);
    EXPECT_FALSE(result);
}

HWTEST_F(WifiManagerTest, CheckAndStartScanService_001, TestSize.Level1)
{
    WIFI_LOGE("CheckAndStartScanService_001 enter!");
    WifiConfigCenter::GetInstance().SetScanMidState(WifiOprMidState::RUNNING);
    wifiManager.CheckAndStartScanService();
}

HWTEST_F(WifiManagerTest, CheckAndStartScanService_002, TestSize.Level1)
{
    WIFI_LOGE("CheckAndStartScanService_002 enter!");
    WifiConfigCenter::GetInstance().SetScanMidState(WifiOprMidState::CLOSED);
    wifiManager.CheckAndStartScanService();
}

HWTEST_F(WifiManagerTest, RegisterScreenEventTest, TestSize.Level1)
{
    WIFI_LOGE("RegisterScreenEventTest enter!");
    wifiManager.RegisterScreenEvent();
}

HWTEST_F(WifiManagerTest, UnRegisterScreenEventTest, TestSize.Level1)
{
    WIFI_LOGE("UnRegisterScreenEventTest enter!");
    wifiManager.UnRegisterScreenEvent();
}

HWTEST_F(WifiManagerTest, RegisterAirplaneModeEventTest, TestSize.Level1)
{
    WIFI_LOGE("RegisterAirplaneModeEventTest enter!");
    wifiManager.RegisterAirplaneModeEvent();
}

HWTEST_F(WifiManagerTest, UnRegisterAirplaneModeEventTest, TestSize.Level1)
{
    WIFI_LOGE("UnRegisterAirplaneModeEventTest enter!");
    wifiManager.UnRegisterAirplaneModeEvent();
}

HWTEST_F(WifiManagerTest, RegisterLocationEventTest, TestSize.Level1)
{
    WIFI_LOGE("RegisterLocationEventTest enter!");
    wifiManager.RegisterLocationEvent();
}

HWTEST_F(WifiManagerTest, UnRegisterLocationEventTest, TestSize.Level1)
{
    WIFI_LOGE("UnRegisterLocationEventTest enter!");
    wifiManager.UnRegisterLocationEvent();
}

HWTEST_F(WifiManagerTest, ExitTest, TestSize.Level1)
{
    WIFI_LOGE("ExitTest enter!");
    wifiManager.Exit();
}
}  // namespace Wifi
}  // namespace OHOS