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
#include "wifi_service_manager.h"
#include "wifi_logger.h"
#include "wifi_datashare_utils.h"
#include "common_event_support.h"
#include "wifi_msg.h"
#include "mock_wifi_config_center.h"
#include "mock_wifi_settings.h"
#include "wifi_sta_hal_interface.h"

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
static std::string g_errLog;
void MyLogCallback(const LogType type, const LogLevel level,
                   const unsigned int domain, const char *tag,
                   const char *msg)
{
    g_errLog = msg;
}
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
#ifdef FEATURE_P2P_SUPPORT
        wifiManager.wifiP2pManager = std::make_unique<WifiP2pManager>();
#endif
        wifiManager.wifiEventSubscriberManager = std::make_unique<WifiEventSubscriberManager>();
        wifiManager.wifiMultiVapManager = std::make_unique<WifiMultiVapManager>();
        LOG_SetCallback(MyLogCallback);
    }
    virtual void TearDown()
    {
        wifiManager.wifiStaManager = nullptr;
        wifiManager.wifiScanManager = nullptr;
        wifiManager.wifiTogglerManager = nullptr;
        wifiManager.wifiHotspotManager = nullptr;
#ifdef FEATURE_P2P_SUPPORT
        wifiManager.wifiP2pManager = nullptr;
#endif
        wifiManager.wifiEventSubscriberManager = nullptr;
        wifiManager.wifiMultiVapManager = nullptr;
    }
public:
    WifiManager wifiManager;
};

HWTEST_F(WifiManagerTest, StartUnloadStaSaTimerTest, TestSize.Level1)
{
    WIFI_LOGI("StartUnloadStaSaTimerTest enter!");
    wifiManager.wifiStaManager->StartUnloadStaSaTimer();
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, StaManagerDealStaOpenResTest_001, TestSize.Level1)
{
    WIFI_LOGI("StaManagerDealStaOpenResTest_001 enter!");

    std::map <int, WifiLinkedInfo> tempInfos;
    WifiLinkedInfo info1;
    info1.connState = ConnState::CONNECTED;
    tempInfos.emplace(1, info1);
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetAllWifiLinkedInfo()).WillRepeatedly(Return(tempInfos));

    wifiManager.wifiStaManager->DealStaOpened(0);
}

HWTEST_F(WifiManagerTest, DealStaCloseResTest_001, TestSize.Level1)
{
    WIFI_LOGI("DealStaCloseResTest_001 enter!");
    wifiManager.wifiStaManager->DealStaStopped(0);
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, DealStaConnChangedTest, TestSize.Level1)
{
    WIFI_LOGI("DealStaConnChangedTest enter!");

    // Add simulated wifi connection results
    WifiLinkedInfo wifiLinkedInfo;
    wifiLinkedInfo.connState = OHOS::Wifi::ConnState::CONNECTED;
    wifiLinkedInfo.bssid = "11:22:33:44:55:66";
    EXPECT_CALL(WifiSettings::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));

    WifiLinkedInfo info;
    info.connState = ConnState::AUTHENTICATING;
    wifiManager.wifiStaManager->DealStaConnChanged(OperateResState::DISCONNECT_DISCONNECTED, info);
}

HWTEST_F(WifiManagerTest, DealWpsChangedTest, TestSize.Level1)
{
    WIFI_LOGI("DealWpsChangedTest enter!");
    wifiManager.wifiStaManager->DealWpsChanged(WpsStartState::START_PBC_SUCCEED, 123456);
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, DealStreamChangedTest, TestSize.Level1)
{
    WIFI_LOGI("DealStreamChangedTest enter!");
    wifiManager.wifiStaManager->DealStreamChanged(StreamDirection::STREAM_DIRECTION_DOWN);
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, DealRssiChangedTest, TestSize.Level1)
{
    WIFI_LOGI("DealRssiChangedTest enter!");
    wifiManager.wifiStaManager->DealRssiChanged(-66);
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, StopSatelliteTimerTest, TestSize.Level1)
{
    WIFI_LOGI("StopSatelliteTimerTest enter!");
    wifiManager.wifiStaManager->StopSatelliteTimer();
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, StartSatelliteTimerTest, TestSize.Level1)
{
    WIFI_LOGI("StartSatelliteTimerTest enter!");
    wifiManager.wifiStaManager->StartSatelliteTimer();
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, StartUnloadScanSaTimerTest, TestSize.Level1)
{
    WIFI_LOGI("StartUnloadScanSaTimerTest enter!");
    wifiManager.wifiScanManager->StartUnloadScanSaTimer();
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, CheckAndStartScanService_001, TestSize.Level1)
{
    WIFI_LOGI("CheckAndStartScanService_001 enter!");
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScanMidState(_))
        .WillOnce(DoAll(Return(WifiOprMidState::RUNNING)));
    wifiManager.wifiScanManager->CheckAndStartScanService();
}

HWTEST_F(WifiManagerTest, CheckAndStartScanService_002, TestSize.Level1)
{
    WIFI_LOGI("CheckAndStartScanService_002 enter!");
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScanMidState(_))
        .WillOnce(DoAll(Return(WifiOprMidState::CLOSED)));
    wifiManager.wifiScanManager->CheckAndStartScanService();
}

HWTEST_F(WifiManagerTest, CheckAndStopScanServiceTest, TestSize.Level1)
{
    WIFI_LOGI("ExitTest enter!");
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScanMidState(_))
        .WillOnce(DoAll(Return(WifiOprMidState::CLOSED)));
    wifiManager.wifiScanManager->CheckAndStopScanService();
}

HWTEST_F(WifiManagerTest, DealScanInfoNotifyTest, TestSize.Level1)
{
    WIFI_LOGI("DealScanInfoNotifyTest enter!");
    std::vector<InterScanInfo> results;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiMidState(_))
        .WillOnce(DoAll(Return(WifiOprMidState::RUNNING)));
    wifiManager.wifiScanManager->DealScanInfoNotify(results);
}

HWTEST_F(WifiManagerTest, StartUnloadApSaTimerTest, TestSize.Level1)
{
    WIFI_LOGI("StartUnloadApSaTimerTest enter!");
    wifiManager.wifiHotspotManager->StartUnloadApSaTimer();
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, DealApStateChangedTest, TestSize.Level1)
{
    WIFI_LOGI("DealApStateChangedTest enter!");
    wifiManager.wifiHotspotManager->DealApStateChanged(ApState::AP_STATE_NONE);
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, DealApGetStaLeaveTest, TestSize.Level1)
{
    WIFI_LOGI("DealApGetStaLeaveTest enter!");
    StationInfo info;
    wifiManager.wifiHotspotManager->DealApGetStaLeave(info);
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

#ifdef FEATURE_P2P_SUPPORT
HWTEST_F(WifiManagerTest, AutoStartP2pService_001, TestSize.Level1)
{
    WIFI_LOGI("AutoStartP2pService_001 enter!");
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetP2pMidState())
        .WillOnce(DoAll(Return(WifiOprMidState::CLOSING)));
    EXPECT_EQ(wifiManager.wifiP2pManager->AutoStartP2pService(), WIFI_OPT_OPEN_FAIL_WHEN_CLOSING);

    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetP2pMidState())
        .WillOnce(DoAll(Return(WifiOprMidState::RUNNING)));
    EXPECT_EQ(wifiManager.wifiP2pManager->AutoStartP2pService(), WIFI_OPT_OPEN_SUCC_WHEN_OPENED);
}

HWTEST_F(WifiManagerTest, AutoStartP2pService_002, TestSize.Level1)
{
    WIFI_LOGI("AutoStartP2pService_002 enter!");
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetP2pMidState())
        .WillOnce(DoAll(Return(WifiOprMidState::CLOSED)));
    EXPECT_EQ(wifiManager.wifiP2pManager->AutoStartP2pService(), WIFI_OPT_FAILED);
}

HWTEST_F(WifiManagerTest, AutoStopP2pService_001, TestSize.Level1)
{
    WIFI_LOGI("AutoStopP2pService_001 enter!");
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetP2pMidState())
        .WillOnce(DoAll(Return(WifiOprMidState::OPENING)));
    EXPECT_EQ(wifiManager.wifiP2pManager->AutoStopP2pService(), WIFI_OPT_CLOSE_FAIL_WHEN_OPENING);
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetP2pMidState())
        .WillOnce(DoAll(Return(WifiOprMidState::CLOSED)));
    EXPECT_EQ(wifiManager.wifiP2pManager->AutoStopP2pService(), WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED);
}

HWTEST_F(WifiManagerTest, AutoStopP2pService_002, TestSize.Level1)
{
    WIFI_LOGI("AutoStopP2pService_002 enter!");
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetP2pMidState())
        .WillRepeatedly(DoAll(Return(WifiOprMidState::RUNNING)));
    EXPECT_EQ(wifiManager.wifiP2pManager->AutoStopP2pService(), WIFI_OPT_CLOSE_SUCC_WHEN_CLOSED);
}

HWTEST_F(WifiManagerTest, StartUnloadP2PSaTimerTest, TestSize.Level1)
{
    WIFI_LOGI("StartUnloadP2PSaTimerTest enter!");
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiMidState(_))
        .WillOnce(DoAll(Return(WifiOprMidState::CLOSED)));
    wifiManager.wifiP2pManager->StartUnloadP2PSaTimer();
}

HWTEST_F(WifiManagerTest, CloseP2pServiceTest, TestSize.Level1)
{
    WIFI_LOGI("CloseP2pServiceTest enter!");
    wifiManager.wifiP2pManager->CloseP2pService();
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, DealP2pStateChangedTest_001, TestSize.Level1)
{
    WIFI_LOGI("DealP2pStateChangedTest_001 enter!");
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiMidState(_))
        .WillRepeatedly(DoAll(Return(WifiOprMidState::CLOSED)));
    wifiManager.wifiP2pManager->DealP2pStateChanged(P2pState::P2P_STATE_STARTED);
}

HWTEST_F(WifiManagerTest, DealP2pStateChangedTest_002, TestSize.Level1)
{
    WIFI_LOGI("DealP2pStateChangedTest_002 enter!");
    wifiManager.wifiP2pManager->DealP2pStateChanged(P2pState::P2P_STATE_CLOSED);
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, DealP2pPeersChangedTest, TestSize.Level1)
{
    WIFI_LOGI("DealP2pPeersChangedTest enter!");
    std::vector<WifiP2pDevice> vPeers;
    wifiManager.wifiP2pManager->DealP2pPeersChanged(vPeers);
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, DealP2pPrivatePeersChangedTest, TestSize.Level1)
{
    WIFI_LOGI("DealP2pPrivatePeersChangedTest enter!");
    wifiManager.wifiP2pManager->DealP2pPrivatePeersChanged("test");
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, DealP2pServiceChangedTest, TestSize.Level1)
{
    WIFI_LOGI("DealP2pServiceChangedTest enter!");
    std::vector<WifiP2pServiceInfo> vServices;
    wifiManager.wifiP2pManager->DealP2pServiceChanged(vServices);
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, DealP2pConnectionChangedTest, TestSize.Level1)
{
    WIFI_LOGI("DealP2pConnectionChangedTest enter!");
    WifiP2pLinkedInfo info;
    wifiManager.wifiP2pManager->DealP2pConnectionChanged(info);
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, DealP2pThisDeviceChangedTest, TestSize.Level1)
{
    WIFI_LOGI("DealP2pThisDeviceChangedTest enter!");
    WifiP2pDevice info;
    wifiManager.wifiP2pManager->DealP2pThisDeviceChanged(info);
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, DealP2pDiscoveryChangedTest, TestSize.Level1)
{
    WIFI_LOGI("DealP2pDiscoveryChangedTest enter!");
    wifiManager.wifiP2pManager->DealP2pDiscoveryChanged(true);
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, DealP2pGroupsChangedTest, TestSize.Level1)
{
    WIFI_LOGI("DealP2pGroupsChangedTest enter!");
    wifiManager.wifiP2pManager->DealP2pGroupsChanged();
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, DealP2pActionResultTest, TestSize.Level1)
{
    WIFI_LOGI("DealP2pActionResultTest enter!");
    wifiManager.wifiP2pManager->DealP2pActionResult(P2pActionCallback::P2pConnect, WIFI_OPT_SUCCESS);
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, DealConfigChangedTest, TestSize.Level1)
{
    WIFI_LOGI("DealConfigChangedTest enter!");
    char* data = new (std::nothrow) char[6];
    wifiManager.wifiP2pManager->DealConfigChanged(CfgType::GET_SELF_CONFIG, data, 6);
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, IfaceDestoryCallbackTest, TestSize.Level1)
{
    WIFI_LOGI("IfaceDestoryCallbackTest enter!");
    std::string destoryIfaceName = "test";
    wifiManager.wifiP2pManager->IfaceDestoryCallback(destoryIfaceName, 1);
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}
#endif

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
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, GetLocationModeByDatashareTest, TestSize.Level1)
{
    WIFI_LOGI("GetLocationModeByDatashareTest enter!");
    bool result = wifiManager.wifiEventSubscriberManager->GetLocationModeByDatashare();
    WIFI_LOGI("GetLocationModeByDatashareTest result(%{public}d)", result);
    EXPECT_EQ(result, true);
}

HWTEST_F(WifiManagerTest, GetLastStaStateByDatashareTest, TestSize.Level1)
{
    WIFI_LOGI("GetLastStaStateByDatashareTest enter!");
    wifiManager.wifiEventSubscriberManager->GetLastStaStateByDatashare();
    EXPECT_EQ(wifiManager.wifiEventSubscriberManager->GetLastStaStateByDatashare(), true);
}

HWTEST_F(WifiManagerTest, RegisterCesEventTest, TestSize.Level1)
{
    WIFI_LOGE("RegisterCesEventTest enter!");
    wifiManager.wifiEventSubscriberManager->RegisterCesEvent();
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, UnRegisterCesEventTest, TestSize.Level1)
{
    WIFI_LOGE("UnRegisterCesEventTest enter!");
    wifiManager.wifiEventSubscriberManager->UnRegisterCesEvent();
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

#ifdef HAS_POWERMGR_PART
HWTEST_F(WifiManagerTest, RegisterPowermgrEventTestTest, TestSize.Level1)
{
    WIFI_LOGE("RegisterPowermgrEventTest enter!");
    wifiManager.wifiEventSubscriberManager->RegisterPowermgrEvent();
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, UnRegisterPowermgrEventTestTest, TestSize.Level1)
{
    WIFI_LOGE("UnRegisterPowermgrEventTestTest enter!");
    wifiManager.wifiEventSubscriberManager->UnRegisterPowermgrEvent();
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}
#endif

HWTEST_F(WifiManagerTest, RegisterLocationEventTest, TestSize.Level1)
{
    WIFI_LOGI("RegisterLocationEventTest enter!");
    wifiManager.wifiEventSubscriberManager->RegisterLocationEvent();
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, UnRegisterLocationEventTest, TestSize.Level1)
{
    WIFI_LOGI("UnRegisterLocationEventTest enter!");
    wifiManager.wifiEventSubscriberManager->UnRegisterLocationEvent();
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, RegisterNetworkStateChangeEventTest, TestSize.Level1)
{
    WIFI_LOGI("RegisterNetworkStateChangeEventTest enter!");
    wifiManager.wifiEventSubscriberManager->RegisterNetworkStateChangeEvent();
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, UnRegisterNetworkStateChangeEventTest, TestSize.Level1)
{
    WIFI_LOGI("UnRegisterNetworkStateChangeEventTest enter!");
    wifiManager.wifiEventSubscriberManager->UnRegisterNetworkStateChangeEvent();
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, RegisterWifiScanChangeEventTest, TestSize.Level1)
{
    WIFI_LOGI("RegisterWifiScanChangeEventTest enter!");
    wifiManager.wifiEventSubscriberManager->RegisterWifiScanChangeEvent();
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, UnRegisterWifiScanChangeEventTest, TestSize.Level1)
{
    WIFI_LOGI("UnRegisterWifiScanChangeEventTest enter!");
    wifiManager.wifiEventSubscriberManager->UnRegisterWifiScanChangeEvent();
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, ExitTest, TestSize.Level1)
{
    WIFI_LOGI("ExitTest enter!");
    wifiManager.Exit();
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, AutoStartEnhanceServiceTest, TestSize.Level1)
{
    WIFI_LOGI("ExitTest enter!");
    wifiManager.AutoStartEnhanceService();
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, CheckCanConnectDeviceTest, TestSize.Level1)
{
    EXPECT_EQ(wifiManager.wifiMultiVapManager->CheckCanConnectDevice(), true);
}

HWTEST_F(WifiManagerTest, CheckCanUseP2pTest, TestSize.Level1)
{
    wifiManager.wifiMultiVapManager->CheckCanUseP2p();
    EXPECT_EQ(wifiManager.wifiMultiVapManager->CheckCanUseP2p(), true);
}

HWTEST_F(WifiManagerTest, CheckCanUseSoftApTest, TestSize.Level1)
{
    // Add simulated wifi connection results
    WifiLinkedInfo wifiLinkedInfo;
    wifiLinkedInfo.connState = OHOS::Wifi::ConnState::CONNECTED;
    wifiLinkedInfo.bssid = "11:22:33:44:55:66";
    EXPECT_CALL(WifiSettings::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));

    wifiManager.wifiMultiVapManager->CheckCanUseSoftAp();
}

HWTEST_F(WifiManagerTest, CheckStaConnectedTest, TestSize.Level1)
{
    wifiManager.wifiMultiVapManager->CheckStaConnected();
    EXPECT_EQ(wifiManager.wifiMultiVapManager->CheckStaConnected(), false);
}

HWTEST_F(WifiManagerTest, CheckP2pConnectedTest, TestSize.Level1)
{
    wifiManager.wifiMultiVapManager->CheckP2pConnected();
    EXPECT_EQ(wifiManager.wifiMultiVapManager->CheckP2pConnected(), false);
}

HWTEST_F(WifiManagerTest, CheckSoftApStartedTest, TestSize.Level1)
{
    wifiManager.wifiMultiVapManager->CheckSoftApStarted();
    EXPECT_EQ(wifiManager.wifiMultiVapManager->CheckSoftApStarted(), false);
}

HWTEST_F(WifiManagerTest, CheckEnhanceWifiConnectedTest, TestSize.Level1)
{
    wifiManager.wifiMultiVapManager->CheckEnhanceWifiConnected();
    EXPECT_EQ(wifiManager.wifiMultiVapManager->CheckEnhanceWifiConnected(), true);
}

HWTEST_F(WifiManagerTest, VapConflictReportTest, TestSize.Level1)
{
    wifiManager.wifiMultiVapManager->VapConflictReport();
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, ForceStopSoftApTest, TestSize.Level1)
{
    wifiManager.wifiMultiVapManager->ForceStopSoftAp();
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, ShowToastTest, TestSize.Level1)
{
    wifiManager.wifiMultiVapManager->ShowToast();
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, HasAnyApRuningTest, TestSize.Level1)
{
    WIFI_LOGI("HasAnyApRuningTest enter!");
    wifiManager.wifiTogglerManager->HasAnyApRuning();
    EXPECT_EQ(wifiManager.wifiTogglerManager->HasAnyApRuning(), false);
}

HWTEST_F(WifiManagerTest, DealConcreateStartFailureTest, TestSize.Level1)
{
    WIFI_LOGI("DealConcreateStartFailureTest enter!");
    wifiManager.wifiTogglerManager->DealConcreateStartFailure(1);
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, DealSoftapStopTest, TestSize.Level1)
{
    WIFI_LOGI("DealSoftapStopTest enter!");
    wifiManager.wifiTogglerManager->DealSoftapStop(1);
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, DealSoftapStartFailureTest, TestSize.Level1)
{
    WIFI_LOGI("DealSoftapStartFailureTest enter!");
    wifiManager.wifiTogglerManager->DealSoftapStartFailure(1);
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, ForceStopWifiTest, TestSize.Level1)
{
    WIFI_LOGI("ForceStopWifiTest enter!");
    wifiManager.wifiTogglerManager->ForceStopWifi();
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, SatelliteToggledTest, TestSize.Level1)
{
    WIFI_LOGI("SatelliteToggledTest enter!");
    wifiManager.wifiTogglerManager->SatelliteToggled(3011);
    EXPECT_EQ(wifiManager.wifiTogglerManager->SatelliteToggled(3011), WIFI_OPT_SUCCESS);
    wifiManager.wifiTogglerManager->SatelliteToggled(3012);
    EXPECT_EQ(wifiManager.wifiTogglerManager->SatelliteToggled(3012), WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiManagerTest, SetSatelliteStartStateTest, TestSize.Level1)
{
    WIFI_LOGI("SetSatelliteStartStateTest enter!");
    wifiManager.wifiTogglerManager->SetSatelliteStartState(true);
    int ten = 10;
    EXPECT_NE(wifiManager.mSupportedFeatures, ten);
}

HWTEST_F(WifiManagerTest, CheckSatelliteStateTest, TestSize.Level1)
{
    WIFI_LOGI("CheckSatelliteStateTest enter!");
    wifiManager.wifiTogglerManager->CheckSatelliteState();
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, IsInterfaceUpTest, TestSize.Level1)
{
    WIFI_LOGI("IsInterfaceUpTest enter!");
    std::string iface = "wlan0";
    wifiManager.wifiTogglerManager->IsInterfaceUp(iface);
    EXPECT_EQ(wifiManager.wifiTogglerManager->IsInterfaceUp(iface), false);
}

HWTEST_F(WifiManagerTest, OnNativeProcessStatusChange_WpaDeath, TestSize.Level1)
{
    wifiManager.OnNativeProcessStatusChange(WPA_DEATH);
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiManagerTest, OnNativeProcessStatusChange_ApDeath, TestSize.Level1)
{
    wifiManager.OnNativeProcessStatusChange(AP_DEATH);
    EXPECT_TRUE(g_errLog.find("service is null") != std::string::npos);
}
}  // namespace Wifi
}  // namespace OHOS
