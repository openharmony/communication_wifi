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

HWTEST_F(WifiManagerTest, PushServiceCloseMsgTest, TestSize.Level1)
{
    WIFI_LOGI("ExitTest enter!");
    wifiManager.PushServiceCloseMsg(WifiCloseServiceCode::STA_SERVICE_CLOSE);
}

HWTEST_F(WifiManagerTest, CheckAndStopScanServiceTest, TestSize.Level1)
{
    WIFI_LOGI("ExitTest enter!");
    wifiManager.wifiScanManager->CheckAndStopScanService();
}

HWTEST_F(WifiManagerTest, ForceStopWifiTest, TestSize.Level1)
{
    WIFI_LOGI("ExitTest enter!");
    wifiManager.wifiStaManager->ForceStopWifi();
}

HWTEST_F(WifiManagerTest, AutoStartEnhanceServiceTest, TestSize.Level1)
{
    WIFI_LOGI("ExitTest enter!");
    wifiManager.AutoStartEnhanceService();
}

HWTEST_F(WifiManagerTest, HandleCommNetConnManagerSysChange_Add_Test, TestSize.Level1)
{
    int systemAbilityId = 1120;
    bool add = true;
    wifiManager.wifiEventSubscriberManager->HandleCommNetConnManagerSysChange(systemAbilityId, add);
    add = false;
    wifiManager.wifiEventSubscriberManager->HandleCommNetConnManagerSysChange(systemAbilityId, add);
}

HWTEST_F(WifiManagerTest, HandleCommonEventServiceChange_Add_Test, TestSize.Level1)
{
    int systemAbilityId = 1120;
    bool add = true;
    wifiManager.wifiEventSubscriberManager->HandleCommonEventServiceChange(systemAbilityId, add);
    add = false;
    wifiManager.wifiEventSubscriberManager->HandleCommonEventServiceChange(systemAbilityId, add);
}

HWTEST_F(WifiManagerTest, HandlePowerManagerServiceChange_Add_Test, TestSize.Level1)
{
    int systemAbilityId = 1120;
    bool add = true;
    wifiManager.wifiEventSubscriberManager->HandlePowerManagerServiceChange(systemAbilityId, add);
    add = false;
    wifiManager.wifiEventSubscriberManager->HandlePowerManagerServiceChange(systemAbilityId, add);
}

HWTEST_F(WifiManagerTest, HandleDistributedKvDataServiceChange_Add_Test, TestSize.Level1)
{
    bool add = true;
    wifiManager.wifiEventSubscriberManager->HandleDistributedKvDataServiceChange(add);
    add = false;
    wifiManager.wifiEventSubscriberManager->HandleDistributedKvDataServiceChange(add);
}

HWTEST_F(WifiManagerTest, OnSystemAbilityChanged_True_Add_Test, TestSize.Level1)
{
    int systemAbilityId = COMM_NET_CONN_MANAGER_SYS_ABILITY_ID;
    bool add = true;
    wifiManager.wifiEventSubscriberManager->OnSystemAbilityChanged(systemAbilityId, add);
    systemAbilityId = COMMON_EVENT_SERVICE_ID;
    wifiManager.wifiEventSubscriberManager->OnSystemAbilityChanged(systemAbilityId, add);
    systemAbilityId = POWER_MANAGER_SERVICE_ID;
    wifiManager.wifiEventSubscriberManager->OnSystemAbilityChanged(systemAbilityId, add);
    systemAbilityId = MSDP_MOVEMENT_SERVICE_ID;
    wifiManager.wifiEventSubscriberManager->OnSystemAbilityChanged(systemAbilityId, add);
    systemAbilityId = DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID;
    wifiManager.wifiEventSubscriberManager->OnSystemAbilityChanged(systemAbilityId, add);
}

HWTEST_F(WifiManagerTest, OnSystemAbilityChanged_False_Add_Test, TestSize.Level1)
{
    int systemAbilityId = COMM_NET_CONN_MANAGER_SYS_ABILITY_ID;
    bool add = false;
    wifiManager.wifiEventSubscriberManager->OnSystemAbilityChanged(systemAbilityId, add);
    systemAbilityId = COMMON_EVENT_SERVICE_ID;
    wifiManager.wifiEventSubscriberManager->OnSystemAbilityChanged(systemAbilityId, add);
    systemAbilityId = POWER_MANAGER_SERVICE_ID;
    wifiManager.wifiEventSubscriberManager->OnSystemAbilityChanged(systemAbilityId, add);
    systemAbilityId = MSDP_MOVEMENT_SERVICE_ID;
    wifiManager.wifiEventSubscriberManager->OnSystemAbilityChanged(systemAbilityId, add);
    systemAbilityId = DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID;
    wifiManager.wifiEventSubscriberManager->OnSystemAbilityChanged(systemAbilityId, add);
}

HWTEST_F(WifiManagerTest, DealLocationModeChangeEventTest, TestSize.Level1)
{
    wifiManager.wifiEventSubscriberManager->DealLocationModeChangeEvent();
}

HWTEST_F(WifiManagerTest, MdmPropChangeEvtTest, TestSize.Level1)
{
    std::string key = "persist.edm.wifi_enable";
    std::string value = "true";
    wifiManager.wifiEventSubscriberManager->MdmPropChangeEvt(key.c_str(), value.c_str(), nullptr);
    value = "false";
    wifiManager.wifiEventSubscriberManager->MdmPropChangeEvt(key.c_str(), value.c_str(), nullptr);
}

HWTEST_F(WifiManagerTest, ScreenEventSubscriberOnReceiveEventTest, TestSize.Level1)
{
    WIFI_LOGI("ScreenEventSubscriberOnReceiveEventTest enter!");
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON);
    EventFwk::CommonEventData data;
    data.SetWant(want);
    wifiManager.wifiEventSubscriberManager->cesEventSubscriber_->OnReceiveEvent(data);
}

HWTEST_F(WifiManagerTest, AirplaneModeEventSubscriberOnReceiveEventTest, TestSize.Level1)
{
    WIFI_LOGI("AirplaneModeEventSubscriberOnReceiveEventTest enter!");
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_AIRPLANE_MODE_CHANGED);
    EventFwk::CommonEventData data;
    data.SetWant(want);
    data.SetCode(1);
    wifiManager.wifiEventSubscriberManager->cesEventSubscriber_->OnReceiveEvent(data);
    data.SetCode(0);
    wifiManager.wifiEventSubscriberManager->cesEventSubscriber_->OnReceiveEvent(data);
}

HWTEST_F(WifiManagerTest, BatteryEventSubscriberOnReceiveEventTest, TestSize.Level1)
{
    WIFI_LOGI("BatteryEventSubscriberOnReceiveEventTest enter!");
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_POWER_CONNECTED);
    EventFwk::CommonEventData data;
    data.SetWant(want);
    wifiManager.wifiEventSubscriberManager->cesEventSubscriber_->OnReceiveEvent(data);
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_POWER_DISCONNECTED);
    data.SetWant(want);
    wifiManager.wifiEventSubscriberManager->cesEventSubscriber_->OnReceiveEvent(data);
}

HWTEST_F(WifiManagerTest, AppEventSubscriberOnReceiveEventTest, TestSize.Level1)
{
    WIFI_LOGI("AppEventSubscriberOnReceiveEventTest enter!");
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    EventFwk::CommonEventData data;
    data.SetWant(want);
    wifiManager.wifiEventSubscriberManager->cesEventSubscriber_->OnReceiveEvent(data);
}

HWTEST_F(WifiManagerTest, ThermalLevelSubscriberOnReceiveEventTest, TestSize.Level1)
{
    WIFI_LOGI("ThermalLevelSubscriberOnReceiveEventTest enter!");
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_THERMAL_LEVEL_CHANGED);
    EventFwk::CommonEventData data;
    data.SetWant(want);
    wifiManager.wifiEventSubscriberManager->cesEventSubscriber_->OnReceiveEvent(data);
}
}  // namespace Wifi
}  // namespace OHOS