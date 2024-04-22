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
#include "wifi_datashare_utils.h"
#include "common_event_support.h"

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
    virtual void SetUp()
    {
        wifiManager.wifiStaManager = std::make_unique<WifiStaManager>();
        wifiManager.wifiScanManager = std::make_unique<WifiScanManager>();
        wifiManager.wifiTogglerManager = std::make_unique<WifiTogglerManager>();
        wifiManager.wifiHotspotManager = std::make_unique<WifiHotspotManager>();
        wifiManager.wifiP2pManager = std::make_unique<WifiP2pManager>();
        wifiManager.wifiEventSubscriberManager = std::make_unique<WifiEventSubscriberManager>();
    }
    virtual void TearDown()
    {
        wifiManager.wifiStaManager = nullptr;
        wifiManager.wifiScanManager = nullptr;
        wifiManager.wifiTogglerManager = nullptr;
        wifiManager.wifiHotspotManager = nullptr;
        wifiManager.wifiP2pManager = nullptr;
        wifiManager.wifiEventSubscriberManager = nullptr;
    }
public:
    WifiManager wifiManager;
};

HWTEST_F(WifiManagerTest, StartUnloadStaSaTimerTest, TestSize.Level1)
{
    WIFI_LOGI("StartUnloadStaSaTimerTest enter!");
    wifiManager.wifiStaManager->StartUnloadStaSaTimer();
}

HWTEST_F(WifiManagerTest, StartUnloadScanSaTimerTest, TestSize.Level1)
{
    WIFI_LOGI("StartUnloadScanSaTimerTest enter!");
    wifiManager.wifiScanManager->StartUnloadScanSaTimer();
}

HWTEST_F(WifiManagerTest, StartUnloadApSaTimerTest, TestSize.Level1)
{
    WIFI_LOGI("StartUnloadApSaTimerTest enter!");
    wifiManager.wifiHotspotManager->StartUnloadApSaTimer();
}

HWTEST_F(WifiManagerTest, AutoStartP2pService_001, TestSize.Level1)
{
    WIFI_LOGI("AutoStartP2pService_001 enter!");
    WifiConfigCenter::GetInstance().SetP2pMidState(WifiOprMidState::CLOSING);
    EXPECT_EQ(wifiManager.wifiP2pManager->AutoStartP2pService(), WIFI_OPT_OPEN_FAIL_WHEN_CLOSING);
    WifiConfigCenter::GetInstance().SetP2pMidState(WifiOprMidState::RUNNING);
    EXPECT_EQ(wifiManager.wifiP2pManager->AutoStartP2pService(), WIFI_OPT_OPEN_SUCC_WHEN_OPENED);
}

HWTEST_F(WifiManagerTest, AutoStartP2pService_002, TestSize.Level1)
{
    WIFI_LOGI("AutoStartP2pService_002 enter!");
    WifiConfigCenter::GetInstance().SetP2pMidState(WifiOprMidState::CLOSED);
    EXPECT_EQ(wifiManager.wifiP2pManager->AutoStartP2pService(), WIFI_OPT_FAILED);
}

HWTEST_F(WifiManagerTest, AutoStopP2pService_001, TestSize.Level1)
{
    WIFI_LOGI("AutoStopP2pService_001 enter!");
    WifiConfigCenter::GetInstance().SetP2pMidState(WifiOprMidState::OPENING);
    EXPECT_EQ(wifiManager.wifiP2pManager->AutoStopP2pService(), WIFI_OPT_CLOSE_FAIL_WHEN_OPENING);
    WifiConfigCenter::GetInstance().SetP2pMidState(WifiOprMidState::CLOSED);
    EXPECT_EQ(wifiManager.wifiP2pManager->AutoStopP2pService(), WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED);
}

HWTEST_F(WifiManagerTest, AutoStopP2pService_002, TestSize.Level1)
{
    WIFI_LOGI("AutoStopP2pService_002 enter!");
    WifiConfigCenter::GetInstance().SetP2pMidState(WifiOprMidState::RUNNING);
    EXPECT_EQ(wifiManager.wifiP2pManager->AutoStopP2pService(), WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED);
}

HWTEST_F(WifiManagerTest, StartUnloadP2PSaTimerTest, TestSize.Level1)
{
    WIFI_LOGI("StartUnloadP2PSaTimerTest enter!");
    wifiManager.wifiP2pManager->StartUnloadP2PSaTimer();
}

HWTEST_F(WifiManagerTest, GetSupportedFeaturesTest, TestSize.Level1)
{
    WIFI_LOGI("GetSupportedFeaturesTest enter!");
    long features;
    int result = wifiManager.GetSupportedFeatures(features);
    WIFI_LOGI("GetSupportedFeaturesTest result(%{public}d)", result);
    EXPECT_EQ(result, WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiManagerTest, GetAirplaneModeByDatashareTest, TestSize.Level1)
{
    WIFI_LOGI("DealOpenAirplGetAirplaneModeByDatashareTestaneModeEventTest enter!");
    wifiManager.wifiEventSubscriberManager->GetAirplaneModeByDatashare();
}

HWTEST_F(WifiManagerTest, GetLocationModeByDatashareTest, TestSize.Level1)
{
    WIFI_LOGI("GetLocationModeByDatashareTest enter!");
    bool result = wifiManager.wifiEventSubscriberManager->GetLocationModeByDatashare();
    WIFI_LOGI("GetLocationModeByDatashareTest result(%{public}d)", result);
}

HWTEST_F(WifiManagerTest, GetLastStaStateByDatashareTest, TestSize.Level1)
{
    WIFI_LOGI("GetLastStaStateByDatashareTest enter!");
    wifiManager.wifiEventSubscriberManager->GetLastStaStateByDatashare();
}

HWTEST_F(WifiManagerTest, DealCloneDataChangeEventTest, TestSize.Level1)
{
    WIFI_LOGI("DealCloneDataChangeEventTest enter!");
    wifiManager.wifiEventSubscriberManager->DealCloneDataChangeEvent();
}

HWTEST_F(WifiManagerTest, CheckAndStartScanService_001, TestSize.Level1)
{
    WIFI_LOGI("CheckAndStartScanService_001 enter!");
    WifiConfigCenter::GetInstance().SetScanMidState(WifiOprMidState::RUNNING);
    wifiManager.wifiScanManager->CheckAndStartScanService();
}

HWTEST_F(WifiManagerTest, CheckAndStartScanService_002, TestSize.Level1)
{
    WIFI_LOGI("CheckAndStartScanService_002 enter!");
    WifiConfigCenter::GetInstance().SetScanMidState(WifiOprMidState::CLOSED);
    wifiManager.wifiScanManager->CheckAndStartScanService();
}

HWTEST_F(WifiManagerTest, RegisterCesEventTest, TestSize.Level1)
{
    WIFI_LOGE("RegisterCesEventTest enter!");
    wifiManager.wifiEventSubscriberManager->RegisterCesEvent();
}

HWTEST_F(WifiManagerTest, UnRegisterCesEventTest, TestSize.Level1)
{
    WIFI_LOGE("UnRegisterCesEventTest enter!");
    wifiManager.wifiEventSubscriberManager->UnRegisterCesEvent();
}

HWTEST_F(WifiManagerTest, RegisterLocationEventTest, TestSize.Level1)
{
    WIFI_LOGI("RegisterLocationEventTest enter!");
    wifiManager.wifiEventSubscriberManager->RegisterLocationEvent();
}

HWTEST_F(WifiManagerTest, UnRegisterLocationEventTest, TestSize.Level1)
{
    WIFI_LOGI("UnRegisterLocationEventTest enter!");
    wifiManager.wifiEventSubscriberManager->UnRegisterLocationEvent();
}

HWTEST_F(WifiManagerTest, RegisterPowerStateListenerTest, TestSize.Level1)
{
    WIFI_LOGI("RegisterPowerStateListenerTest enter!");
    wifiManager.wifiEventSubscriberManager->RegisterPowerStateListener();
}

HWTEST_F(WifiManagerTest, UnRegisterPowerStateListenerTest, TestSize.Level1)
{
    WIFI_LOGI("UnRegisterPowerStateListenerTest enter!");
    wifiManager.wifiEventSubscriberManager->UnRegisterPowerStateListener();
}

HWTEST_F(WifiManagerTest, ExitTest, TestSize.Level1)
{
    WIFI_LOGI("ExitTest enter!");
    wifiManager.Exit();
}

HWTEST_F(WifiManagerTest, CheckAndStopScanServiceTest, TestSize.Level1)
{
    WIFI_LOGI("ExitTest enter!");
    wifiManager.wifiScanManager->CheckAndStopScanService();
}

HWTEST_F(WifiManagerTest, AutoStartEnhanceServiceTest, TestSize.Level1)
{
    WIFI_LOGI("ExitTest enter!");
    wifiManager.AutoStartEnhanceService();
}
}  // namespace Wifi
}  // namespace OHOS