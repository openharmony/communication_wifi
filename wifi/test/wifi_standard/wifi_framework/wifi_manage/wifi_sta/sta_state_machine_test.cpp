/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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
#include "internal_message.h"
#include "mock_dhcp_service.h"
#include "mock_if_config.h"
#include "mock_wifi_chip_hal_interface.h"
#include "mock_wifi_manager.h"
#include "mock_wifi_config_center.h"
#include "mock_wifi_settings.h"
#include "sta_define.h"
#include "define.h"
#include "sta_state_machine.h"
#include "sta_service.h"
#include "wifi_app_state_aware.h"
#include "wifi_internal_msg.h"
#include "wifi_msg.h"
#include "mock_wifi_sta_hal_interface.h"
#include "mock_block_connect_service.h"

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
static const std::string RANDOMMAC_SSID = "testwifi";
static const std::string RANDOMMAC_PASSWORD = "testwifi";
static const std::string RANDOMMAC_BSSID = "01:23:45:67:89:a0";
constexpr int TEST_FAIL_REASON = 16;
constexpr int UMTS_AUTH_TYPE_TAG = 0xdb;
constexpr int UMTS_AUTS_TYPE_TAG = 0xdc;
constexpr int WPA3_BLACKMAP_MAX_NUM = 20;
constexpr int TWO = 2;
constexpr int INVALID_RSSI1 = -128;
constexpr int INVALID_RSSI2 = 200;
constexpr int VALID_RSSI3 = -80;
constexpr int VALID_RSSI4 = 156;
constexpr int INVALID_RSSI5 = 100;
static constexpr int MAX_STR_LENT = 127;
constexpr int CHIPSET_FEATURE_CAPABILITY_WIFI6_TEST = 127;
constexpr int CHIPSET_FEATURE_CAPABILITY_WIFI7_TEST = 255;
constexpr int TEN = 10;
static const std::string TEMP_TEST_DATA = "1234567890abcdef1234567890abcdef";
class StaStateMachineTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase()
    {
        WifiAppStateAware& wifiAppStateAware = WifiAppStateAware::GetInstance();
        wifiAppStateAware.appChangeEventHandler.reset();
        wifiAppStateAware.mAppStateObserver = nullptr;
    }
    virtual void SetUp()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveDisconnectedReason(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine.reset(new StaStateMachine());
        pStaStateMachine->InitStaStateMachine();
        pStaStateMachine->InitWifiLinkedInfo();
        pStaStateMachine->InitLastWifiLinkedInfo();
        pStaService  = std::make_unique<StaService>();
    }
    virtual void TearDown()
    {
        pStaStateMachine.reset();
        pStaService.reset();
    }
    void SleepMs(const int sleepMs)
    {
        std::unique_lock<std::mutex> lck(mMtxBlock);
        mCvTest.wait_for(lck, std::chrono::milliseconds(sleepMs));
    }
    std::unique_ptr<StaStateMachine> pStaStateMachine;
    std::unique_ptr<StaService> pStaService;
    std::mutex mMtxBlock;
    std::condition_variable mCvTest;

    void DealConnectTimeOutCmd()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).WillRepeatedly(Return(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(1));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pStaStateMachine->DealConnectTimeOutCmd(msg);
    }

    void RootStateGoInStateSuccess()
    {
        pStaStateMachine->pRootState->GoInState();
    }

    void RootStateGoOutStateSuccess()
    {
        pStaStateMachine->pRootState->GoOutState();
    }

    void RootStateExeMsgSuccess()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_SVR_CMD_UPDATE_COUNTRY_CODE);
        msg->AddStringMessageBody("CN");
        EXPECT_TRUE(pStaStateMachine->pRootState->ExecuteStateMsg(msg));
    }

    void RootStateExeMsgFail()
    {
        EXPECT_FALSE(pStaStateMachine->pRootState->ExecuteStateMsg(nullptr));
    }

    void InitStateGoInStateSuccess()
    {
        pStaStateMachine->pInitState->GoInState();
    }

    void InitStateGoOutStateSuccess()
    {
        pStaStateMachine->pInitState->GoOutState();
    }

    void InitStateExeMsgSuccess()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiState(_, _)).WillRepeatedly(Return(WIFI_HAL_OPT_OK));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaOpenRes(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), ReloadDeviceConfig()).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SetRealMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetRealMacAddress(_, _)).Times(testing::AtLeast(0));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_SVR_CMD_STA_ENABLE_STA);
        EXPECT_TRUE(pStaStateMachine->pInitState->ExecuteStateMsg(msg));
    }

    void InitStateExeMsgFail1()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_SVR_CMD_STA_DISABLE_STA);
        EXPECT_FALSE(pStaStateMachine->pInitState->ExecuteStateMsg(msg));
    }

    void InitStateExeMsgFail2()
    {
        EXPECT_FALSE(pStaStateMachine->pInitState->ExecuteStateMsg(nullptr));
    }

    void ConvertDeviceCfgSuccess()
    {
        WifiDeviceConfig config;
        config.keyMgmt = "WEP";
        EXPECT_EQ(WIFI_OPT_SUCCESS, pStaStateMachine->ConvertDeviceCfg(config));
    }

    void ConvertDeviceCfgFail1()
    {
        WifiDeviceConfig config;
        EXPECT_EQ(WIFI_OPT_SUCCESS, pStaStateMachine->ConvertDeviceCfg(config));
    }

    void ConvertDeviceCfgFail2()
    {
        WifiDeviceConfig config;
        EXPECT_EQ(WIFI_OPT_SUCCESS, pStaStateMachine->ConvertDeviceCfg(config));
    }

    void StartWifiProcessSuccess()
    {
        EXPECT_CALL(WifiManager::GetInstance(), DealStaOpenRes(_, _)).Times(testing::AtLeast(1));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), ReloadDeviceConfig()).WillRepeatedly(Return(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).WillRepeatedly(Return(WIFI_HAL_OPT_OK));
        EXPECT_CALL(WifiSettings::GetInstance(), GetRealMacAddress(_, _)).Times(testing::AtLeast(0));
        WifiDeviceConfig wifiDeviceConfig;
        std::vector<WifiDeviceConfig> results;
        wifiDeviceConfig.networkId = 1;
        results.push_back(wifiDeviceConfig);
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(results), Return(0)));
        EXPECT_CALL(WifiSettings::GetInstance(), SetRealMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiState(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->StartWifiProcess();
    }

    void StartWifiProcessFail2()
    {
        EXPECT_CALL(WifiManager::GetInstance(), DealStaOpenRes(_, _)).Times(testing::AtLeast(1));
        EXPECT_CALL(WifiSettings::GetInstance(), SetRealMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiState(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetRealMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetMacAddress(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->StartWifiProcess();
    }

    void StartWifiProcessFail1()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).WillRepeatedly(Return(WIFI_HAL_OPT_OK));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaOpenRes(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), ReloadDeviceConfig()).WillRepeatedly(Return(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetMacAddress(_, _)).Times(testing::AtLeast(0));
        WifiDeviceConfig wifiDeviceConfig;
        std::vector<WifiDeviceConfig> results;
        wifiDeviceConfig.networkId = 1;
        results.push_back(wifiDeviceConfig);
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(results), Return(0)));
        EXPECT_CALL(WifiSettings::GetInstance(), SetRealMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetRealMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiState(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->StartWifiProcess();
    }

    void WpaStartingStateExeMsgSuccess()
    {
        pStaStateMachine->pWpaStartingState->InitWpsSettings();
        pStaStateMachine->pWpaStartingState->GoInState();
        pStaStateMachine->pWpaStartingState->GoOutState();
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiState(_, _)).Times(testing::AtLeast(0));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_SVR_CMD_STA_SUP_CONNECTION_EVENT);
        EXPECT_TRUE(pStaStateMachine->pWpaStartingState->ExecuteStateMsg(msg));
    }

    void WpaStartingStateExeMsgFail1()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_SVR_CMD_STA_SUP_DISCONNECTION_EVENT);
        EXPECT_FALSE(pStaStateMachine->pWpaStartingState->ExecuteStateMsg(msg));
    }

    void WpaStartingStateExeMsgFail2()
    {
        EXPECT_FALSE(pStaStateMachine->pWpaStartingState->ExecuteStateMsg(nullptr));
    }

    void WpaStartedStateGoInStateSuccess1()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiState(_, _)).Times(testing::AtLeast(1));
        pStaStateMachine->operationalMode = STA_CONNECT_MODE;
        pStaStateMachine->pWpaStartedState->GoInState();
    }

    void WpaStartedStateGoInStateSuccess2()
    {
        pStaStateMachine->operationalMode = STA_DISABLED_MODE;
        pStaStateMachine->pWpaStartedState->GoInState();
    }

    void WpaStartedStateGoOutStateSuccess()
    {
        pStaStateMachine->pWpaStartedState->GoOutState();
    }

    void WpaStartedStateExeMsgSuccess()
    {
        EXPECT_CALL(WifiManager::GetInstance(), DealStaCloseRes(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpInfo(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(IfConfig::GetInstance(), FlushIpAddr(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpV6Info(_, _)).Times(testing::AtLeast(0));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_SVR_CMD_STA_DISABLE_STA);
        EXPECT_TRUE(pStaStateMachine->pWpaStartedState->ExecuteStateMsg(msg));
    }

    void WpaStartedStateExeMsgFail1()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_SVR_CMD_STA_ENABLE_STA);
        EXPECT_FALSE(pStaStateMachine->pWpaStartedState->ExecuteStateMsg(msg));
    }

    void WpaStartedStateExeMsgFail2()
    {
        EXPECT_FALSE(pStaStateMachine->pWpaStartedState->ExecuteStateMsg(nullptr));
    }

    void StopWifiProcessSuccess1()
    {
        pStaStateMachine->currentTpType = IPTYPE_IPV4;
        EXPECT_CALL(WifiManager::GetInstance(), DealStaCloseRes(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpV6Info(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->StopWifiProcess();
    }

    void StopWifiProcessSuccess2()
    {
        pStaStateMachine->currentTpType = IPTYPE_IPV6;
        EXPECT_CALL(WifiManager::GetInstance(), DealStaCloseRes(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpV6Info(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->StopWifiProcess();
    }

    void StopWifiProcessSuccess3()
    {
        pStaStateMachine->currentTpType = IPTYPE_IPV6;
        pStaStateMachine->linkedInfo.connState = ConnState::CONNECTED;
        EXPECT_CALL(WifiManager::GetInstance(), DealStaCloseRes(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpV6Info(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->StopWifiProcess();
    }

    void StopWifiProcessFail()
    {
        pStaStateMachine->currentTpType = IPTYPE_IPV6;
        EXPECT_CALL(WifiManager::GetInstance(), DealStaCloseRes(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpV6Info(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->StopWifiProcess();
    }

    void WpaStoppingStateGoInStateSuccess()
    {
        pStaStateMachine->pWpaStoppingState->GoInState();
    }

    void WpaStoppingStateGoOutStateSuccess()
    {
        pStaStateMachine->pWpaStoppingState->GoOutState();
    }

    void WpaStoppingStateExeMsgSuccess()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pStaStateMachine->pWpaStoppingState->ExecuteStateMsg(msg);
    }

    void WpaStoppingStateExeMsgFail()
    {
        pStaStateMachine->pWpaStoppingState->ExecuteStateMsg(nullptr);
    }

    void InitStaSMHandleMapSuccess()
    {
        EXPECT_EQ(WIFI_OPT_SUCCESS, pStaStateMachine->InitStaSMHandleMap());
    }

    void DealConnectToUserSelectedNetworkSuccess()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), EnableNetwork(_, _, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SetDeviceAfterConnect(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScanInfoList(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiState(_, _)).Times(testing::AtLeast(0));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetParam1(-1);
        msg->SetParam2(0);
        pStaStateMachine->linkedInfo.networkId = -1;
        pStaStateMachine->linkedInfo.connState = ConnState::CONNECTED;
        pStaStateMachine->DealConnectToUserSelectedNetwork(msg);
        pStaStateMachine->linkedInfo.connState = ConnState::SCANNING;
        pStaStateMachine->DealConnectToUserSelectedNetwork(msg);
    }

    void DealConnectToUserSelectedNetworkFail1()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetParam1(1);
        msg->SetParam2(0);
        pStaStateMachine->linkedInfo.networkId = 1;
        pStaStateMachine->linkedInfo.connState = ConnState::CONNECTING;
        pStaStateMachine->linkedInfo.detailedState = DetailedState::OBTAINING_IPADDR;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), EnableNetwork(_, _, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->DealConnectToUserSelectedNetwork(msg);
        pStaStateMachine->DealConnectToUserSelectedNetwork(nullptr);
    }

    void DealConnectToUserSelectedNetworkFai2()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetParam1(1);
        msg->SetParam2(0);
        pStaStateMachine->linkedInfo.networkId = 1;
        pStaStateMachine->linkedInfo.connState = ConnState::CONNECTING;
        pStaStateMachine->linkedInfo.detailedState = DetailedState::NOTWORKING;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), EnableNetwork(_, _, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->DealConnectToUserSelectedNetwork(msg);
    }

    void DealConnectTimeOutCmdSuccess()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(0));
        pStaStateMachine->DealConnectTimeOutCmd(msg);
    }

    void DealConnectTimeOutCmdFail()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->linkedInfo.connState = ConnState::CONNECTED;
        pStaStateMachine->DealConnectTimeOutCmd(nullptr);
        pStaStateMachine->DealConnectTimeOutCmd(msg);
    }

    void DealDisconnectEventSuccess1()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpInfo(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(IfConfig::GetInstance(), FlushIpAddr(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpV6Info(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->wpsState = SetupMethod::INVALID;
        pStaStateMachine->currentTpType = IPTYPE_IPV4;
        pStaStateMachine->lastLinkedInfo.detailedState = DetailedState::CONNECTING;
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        std::string bssid = "wifitest";
        msg->SetMessageObj(bssid);
        pStaStateMachine->DealDisconnectEvent(msg);
    }

    void DealDisconnectEventSuccess2()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(IfConfig::GetInstance(), FlushIpAddr(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpV6Info(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->wpsState = SetupMethod::INVALID;
        pStaStateMachine->currentTpType = IPTYPE_IPV6;
        pStaStateMachine->lastLinkedInfo.detailedState = DetailedState::CONNECTED;
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        std::string bssid = "wifitest";
        msg->SetMessageObj(bssid);
        pStaStateMachine->DealDisconnectEvent(msg);
        pStaStateMachine->wpsState = SetupMethod::LABEL;
        pStaStateMachine->DealDisconnectEvent(msg);
    }

    void DealReassociateCmdSuccess()
    {
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(0));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        std::string bssid = "wifitest";
        msg->SetMessageObj(bssid);
        pStaStateMachine->DealReassociateCmd(msg);
    }

    void DealReassociateCmdFail1()
    {
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(0));
        pStaStateMachine->DealReassociateCmd(nullptr);
    }

    void DealReassociateCmdFail2()
    {
        pStaStateMachine->DealReassociateCmd(nullptr);
    }

    void DealStartWpsCmdSuccess()
    {
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _));
        pStaStateMachine->wpsState = SetupMethod::INVALID;
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        std::string bssid = "wifitest";
        msg->SetMessageObj(bssid);
        pStaStateMachine->DealStartWpsCmd(nullptr);
        pStaStateMachine->DealStartWpsCmd(msg);
    }

    void DealStartWpsCmdFail1()
    {
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _)).Times(AtLeast(0));
        pStaStateMachine->wpsState = SetupMethod::KEYPAD;
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        std::string bssid = "wifitest";
        msg->SetMessageObj(bssid);
        msg->SetParam1(static_cast<int>(SetupMethod::INVALID));
        pStaStateMachine->DealStartWpsCmd(msg);
        pStaStateMachine->DealStartWpsCmd(msg);
        pStaStateMachine->wpsState = SetupMethod::DISPLAY;
        pStaStateMachine->DealStartWpsCmd(msg);
    }

    void StartWpsModeSuccess1()
    {
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetParam1(static_cast<int>(SetupMethod::PBC));
        pStaStateMachine->StartWpsMode(msg);
    }

    void StartWpsModeSuccess2()
    {
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetParam1(static_cast<int>(SetupMethod::DISPLAY));
        msg->AddStringMessageBody("hmwifi1");
        msg->AddStringMessageBody("hmwifi2");
        pStaStateMachine->StartWpsMode(msg);
    }

    void StartWpsModeSuccess3()
    {
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetParam1(static_cast<int>(SetupMethod::KEYPAD));
        msg->AddStringMessageBody("hmwifi1");
        msg->AddStringMessageBody("hmwifi2");
        pStaStateMachine->StartWpsMode(msg);
    }

    void StartWpsModeSuccess4()
    {
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetParam1(static_cast<int>(SetupMethod::INVALID));
        msg->AddStringMessageBody("hmwifi1");
        msg->AddStringMessageBody("hmwifi2");
        pStaStateMachine->StartWpsMode(msg);
    }

    void StartWpsModeFail1()
    {
        pStaStateMachine->StartWpsMode(nullptr);
    }

    void StartWpsModeFail2()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetParam1(static_cast<int>(SetupMethod::PBC));
        pStaStateMachine->StartWpsMode(nullptr);
    }

    void StartWpsModeFail3()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetParam1(static_cast<int>(SetupMethod::DISPLAY));
        pStaStateMachine->StartWpsMode(nullptr);
    }

    void StartWpsModeFail4()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetParam1(static_cast<int>(SetupMethod::KEYPAD));
        pStaStateMachine->StartWpsMode(nullptr);
    }

    void DealWpaBlockListClearEventSuccess()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pStaStateMachine->DealWpaBlockListClearEvent(msg);
    }

    void DealWpaBlockListClearEventFail()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pStaStateMachine->DealWpaBlockListClearEvent(msg);
    }

    void DealWpsConnectTimeOutEventSuccess()
    {
        pStaStateMachine->wpsState = SetupMethod::INVALID;
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pStaStateMachine->DealWpsConnectTimeOutEvent(msg);
    }

    void DealWpsConnectTimeOutEventFail()
    {
        pStaStateMachine->wpsState = SetupMethod::INVALID;
        pStaStateMachine->DealWpsConnectTimeOutEvent(nullptr);
    }

    void DealCancelWpsCmdSuccess1()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).WillRepeatedly(Return(-1));
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _));
        pStaStateMachine->wpsState = SetupMethod::PBC;
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pStaStateMachine->DealCancelWpsCmd(msg);
    }

    void DealCancelWpsCmdSuccess2()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).WillRepeatedly(Return(-1));
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _));
        pStaStateMachine->wpsState = SetupMethod::DISPLAY;
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pStaStateMachine->DealCancelWpsCmd(msg);
    }

    void DealCancelWpsCmdSuccess3()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).WillRepeatedly(Return(-1));
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _)).Times(AtLeast(0));
        pStaStateMachine->wpsState = SetupMethod::KEYPAD;
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pStaStateMachine->DealCancelWpsCmd(msg);
    }

    void DealCancelWpsCmdFail1()
    {
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _)).Times(AtLeast(0));
        pStaStateMachine->wpsState = SetupMethod::PBC;
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pStaStateMachine->DealCancelWpsCmd(msg);
    }

    void DealCancelWpsCmdFail2()
    {
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _)).Times(AtLeast(0));
        pStaStateMachine->wpsState = SetupMethod::DISPLAY;
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pStaStateMachine->DealCancelWpsCmd(msg);
    }

    void DealCancelWpsCmdFail3()
    {
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _)).Times(AtLeast(0));
        pStaStateMachine->wpsState = SetupMethod::KEYPAD;
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pStaStateMachine->DealCancelWpsCmd(msg);
        pStaStateMachine->DealCancelWpsCmd(nullptr);
    }

    void DealStartRoamCmdSuccess()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _));
        EXPECT_CALL(WifiSettings::GetInstance(), AddDeviceConfig(_)).WillRepeatedly(Return(WIFI_HAL_OPT_OK));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig()).WillRepeatedly(Return(WIFI_HAL_OPT_OK));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).WillRepeatedly(Return(WIFI_HAL_OPT_OK));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pStaStateMachine->DealStartRoamCmd(msg);
    }

    void DealStartRoamCmdFail1()
    {
        pStaStateMachine->DealStartRoamCmd(nullptr);
    }

    void DealStartRoamCmdFail2()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _));
        EXPECT_CALL(WifiSettings::GetInstance(), AddDeviceConfig(_)).WillRepeatedly(Return(WIFI_HAL_OPT_OK));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig()).WillRepeatedly(Return(WIFI_HAL_OPT_OK));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).WillRepeatedly(Return(WIFI_HAL_OPT_OK));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(0));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pStaStateMachine->DealStartRoamCmd(msg);
    }

    void DealStartRoamCmdFail3()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _));
        EXPECT_CALL(WifiSettings::GetInstance(), AddDeviceConfig(_)).WillRepeatedly(Return(WIFI_HAL_OPT_OK));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig()).WillRepeatedly(Return(WIFI_HAL_OPT_OK));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).WillRepeatedly(Return(WIFI_HAL_OPT_OK));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pStaStateMachine->DealStartRoamCmd(msg);
    }

    void StartConnectToNetworkSuccess()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScanInfoList(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiState(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->StartConnectToNetwork(0, "wifitest/123");
    }

    void StartConnectToNetworkFail1()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).WillRepeatedly(Return(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScanInfoList(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiState(_, _)).Times(testing::AtLeast(0));
        EXPECT_TRUE(pStaStateMachine->StartConnectToNetwork(0, "wifitest/123") == WIFI_OPT_FAILED);
    }

    void StartConnectToNetworkFail4()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).WillRepeatedly(Return(1));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScanInfoList(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiState(_, _)).Times(testing::AtLeast(0));
        EXPECT_TRUE(pStaStateMachine->StartConnectToNetwork(0, "wifitest/123") == WIFI_OPT_FAILED);
    }

    void StartConnectToNetworkFali3()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScanInfoList(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiState(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->StartConnectToNetwork(0, "wifitest/123");
    }

    void SetRandomMacSuccess1()
    {
        WifiDeviceConfig deviceConfig;
        deviceConfig.wifiPrivacySetting = WifiPrivacyConfig::DEVICEMAC;
        deviceConfig.keyMgmt = KEY_MGMT_WPA_PSK;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
            .WillRepeatedly(DoAll(SetArgReferee<1>(deviceConfig), Return(0)));
        std::string macAddress = RANDOMMAC_SSID;
        EXPECT_CALL(WifiSettings::GetInstance(), GetRealMacAddress(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(macAddress), Return(0)));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScanInfoList(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        pStaStateMachine->SetRandomMac(0, "");
    }

    void SetRandomMacFail1()
    {
        WifiDeviceConfig deviceConfig;
        deviceConfig.wifiPrivacySetting = WifiPrivacyConfig::RANDOMMAC;
        deviceConfig.keyMgmt = KEY_MGMT_SAE;
        WifiStoreRandomMac randomMacInfo;
        randomMacInfo.ssid = RANDOMMAC_SSID;
        randomMacInfo.keyMgmt = KEY_MGMT_WEP;
        randomMacInfo.preSharedKey = RANDOMMAC_PASSWORD;
        randomMacInfo.peerBssid = RANDOMMAC_BSSID;
        pStaStateMachine->MacAddressGenerate(randomMacInfo);
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
            .WillRepeatedly(DoAll(SetArgReferee<1>(deviceConfig), Return(-1)));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        pStaStateMachine->SetRandomMac(0, "");
    }

    void SetRandomMacFail2()
    {
        WifiDeviceConfig deviceConfig;
        deviceConfig.wifiPrivacySetting = WifiPrivacyConfig::RANDOMMAC;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
            .WillRepeatedly(DoAll(SetArgReferee<1>(deviceConfig), Return(0)));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScanInfoList(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        pStaStateMachine->SetRandomMac(0, "");
    }

    void StartRoamToNetworkSuccess()
    {
        pStaStateMachine->StartRoamToNetwork("a2:b1:f5:c7:d1");
    }

    void OnNetworkConnectionEventSuccess()
    {
        pStaStateMachine->OnNetworkConnectionEvent(0, "a2:b1:f5:c7:d1");
    }

    void SeparatingStateGoInStateSuccess()
    {
        pStaStateMachine->pSeparatingState->GoInState();
    }

    void SeparatingStateGoOutStateSuccess()
    {
        pStaStateMachine->pSeparatingState->GoOutState();
    }

    void SeparatingStateExeMsgSuccess()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pStaStateMachine->pSeparatingState->ExecuteStateMsg(msg);
    }

    void SeparatingStateExeMsgFail()
    {
        pStaStateMachine->pSeparatingState->ExecuteStateMsg(nullptr);
    }

    void SeparatedStateGoInStateSuccess()
    {
        pStaStateMachine->pSeparatedState->GoInState();
    }

    void SeparatedStateGoOutStateSuccess()
    {
        pStaStateMachine->pSeparatedState->GoOutState();
    }

    void SeparatedStateExeMsgSuccess1()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        std::string bssid = "wifitest";
        msg->SetMessageObj(bssid);
        msg->SetMessageName(WIFI_SVR_CMD_STA_NETWORK_DISCONNECTION_EVENT);
        EXPECT_FALSE(pStaStateMachine->pSeparatedState->ExecuteStateMsg(msg));
    }

    void SeparatedStateExeMsgSuccess2()
    {
        EXPECT_CALL(WifiManager::GetInstance(), DealStaOpenRes(_, _));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_SVR_CMD_STA_ENABLE_STA);
        EXPECT_TRUE(pStaStateMachine->pSeparatedState->ExecuteStateMsg(msg));
    }

    void SeparatedStateExeMsgFail()
    {
        EXPECT_FALSE(pStaStateMachine->pSeparatedState->ExecuteStateMsg(nullptr));
    }

    void ApLinkedStateGoInStateSuccess()
    {
        pStaStateMachine->pApLinkedState->GoInState();
    }

    void ApLinkedStateGoOutStateSuccess()
    {
        pStaStateMachine->pApLinkedState->GoOutState();
    }

    void ApLinkedStateExeMsgSuccess1()
    {
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(1));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_SVR_CMD_STA_DISCONNECT);
        EXPECT_TRUE(pStaStateMachine->pApLinkedState->ExecuteStateMsg(msg));
    }

    void ApLinkedStateExeMsgSuccess2()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        std::string bssid = "wifitest";
        msg->SetMessageObj(bssid);
        msg->SetMessageName(WIFI_SVR_CMD_STA_NETWORK_CONNECTION_EVENT);
        EXPECT_TRUE(pStaStateMachine->pApLinkedState->ExecuteStateMsg(msg));
    }

    void ApLinkedStateExeMsgFail1()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        std::string bssid = "wifitest";
        msg->SetMessageObj(bssid);
        msg->SetMessageName(WIFI_SVR_CMD_STA_BSSID_CHANGED_EVENT);
        EXPECT_TRUE(pStaStateMachine->pApLinkedState->ExecuteStateMsg(msg));
    }

    void ApLinkedStateExeMsgFai2()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        std::string bssid = "wifitest";
        msg->SetMessageObj(bssid);
        msg->SetMessageName(CMD_SIGNAL_POLL);
        EXPECT_TRUE(pStaStateMachine->pApLinkedState->ExecuteStateMsg(msg));
        EXPECT_FALSE(pStaStateMachine->pApLinkedState->ExecuteStateMsg(nullptr));
    }

    void ApLinkedStateExeMsgSuccess3()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        std::string bssid = "wifitest";
        msg->SetMessageObj(bssid);
        msg->SetMessageName(WIFI_SVR_CMD_STA_NETWORK_DISCONNECTION_EVENT);
        pStaStateMachine->pApLinkedState->ExecuteStateMsg(msg);
    }

    void ApLinkedStateExeMsgSuccess4()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        std::string bssid = "wifitest";
        msg->SetMessageObj(bssid);
        msg->SetMessageName(0);
        pStaStateMachine->pApLinkedState->ExecuteStateMsg(msg);
    }

    void ApLinkedStateExeMsgLinkSwitch()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_SVR_CMD_STA_LINK_SWITCH_EVENT);
        msg->AddStringMessageBody("wifitest");
        pStaStateMachine->pApLinkedState->ExecuteStateMsg(msg);
    }

    void DisConnectProcessSuccess()
    {
        pStaStateMachine->DisConnectProcess();
    }

    void DisConnectProcessFail()
    {
        pStaStateMachine->DisConnectProcess();
    }

    void WpsStateGoInStateSuccess()
    {
        pStaStateMachine->pWpsState->GoInState();
    }

    void WpsStateGoOutStateSuccess()
    {
        pStaStateMachine->pWpsState->GoOutState();
    }

    void WpsStateExeMsgSuccess1()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiState(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0)).WillRepeatedly(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0)).WillRepeatedly(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), AddDeviceConfig(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig()).Times(AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(AtLeast(0));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_SVR_CMD_STA_NETWORK_CONNECTION_EVENT);
        EXPECT_TRUE(pStaStateMachine->pWpsState->ExecuteStateMsg(msg));
    }

    void WpsStateExeMsgSuccess2()
    {
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_SVR_CMD_STA_STARTWPS);
        msg->SetParam1(static_cast<int>(SetupMethod::PBC));
        EXPECT_TRUE(pStaStateMachine->pWpsState->ExecuteStateMsg(msg));
    }

    void WpsStateExeMsgSuccess3()
    {
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_SVR_CMD_STA_WPS_START_EVENT);
        msg->SetParam1(static_cast<int>(SetupMethod::DISPLAY));
        EXPECT_FALSE(pStaStateMachine->pWpsState->ExecuteStateMsg(msg));
    }

    void WpsStateExeMsgSuccess4()
    {
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_SVR_CMD_STA_WPS_OVERLAP_EVENT);
        msg->SetParam1(static_cast<int>(SetupMethod::DISPLAY));
        EXPECT_TRUE(pStaStateMachine->pWpsState->ExecuteStateMsg(msg));
    }

    void WpsStateExeMsgSuccess5()
    {
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).WillRepeatedly(Return(-1));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiState(_, _)).Times(testing::AtLeast(0));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_SVR_CMD_STA_CANCELWPS);
        msg->SetParam1(static_cast<int>(SetupMethod::DISPLAY));
        EXPECT_TRUE(pStaStateMachine->pWpsState->ExecuteStateMsg(msg));
    }

    void WpsStateExeMsgFail1()
    {
        EXPECT_FALSE(pStaStateMachine->pWpsState->ExecuteStateMsg(nullptr));
    }

    void WpsStateExeMsgFail2()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_SVR_CMD_STA_WPS_START_EVENT);
        EXPECT_FALSE(pStaStateMachine->pWpsState->ExecuteStateMsg(nullptr));
    }

    void GetIpStateStateGoInStateSuccess1()
    {
        WifiDeviceConfig config;
        config.wifiProxyconfig.configureMethod = ConfigureProxyMethod::MANUALCONFIGUE;
        config.wifiIpConfig.assignMethod = AssignIpMethod::STATIC;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
            .WillRepeatedly(DoAll(SetArgReferee<1>(config), Return(0)));
        pStaStateMachine->pGetIpState->GoInState();
    }

    void GetIpStateStateGoInStateSuccess2()
    {
        pStaStateMachine->isRoam = true;
        WifiDeviceConfig config;
        config.wifiProxyconfig.configureMethod = ConfigureProxyMethod::MANUALCONFIGUE;
        config.wifiIpConfig.assignMethod = AssignIpMethod::DHCP;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDhcpIpType(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
            .WillRepeatedly(DoAll(SetArgReferee<1>(config), Return(0)));
        pStaStateMachine->enhanceService_ = nullptr;
        pStaStateMachine->pGetIpState->GoInState();
    }

    void GetIpStateStateGoInStateSuccess3()
    {
        pStaStateMachine->isRoam = false;
        WifiDeviceConfig config;
        config.wifiProxyconfig.configureMethod = ConfigureProxyMethod::MANUALCONFIGUE;
        config.wifiIpConfig.assignMethod = AssignIpMethod::DHCP;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
            .WillRepeatedly(DoAll(SetArgReferee<1>(config), Return(0)));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDhcpIpType(_)).WillRepeatedly(Return(IPTYPE_IPV4));
        pStaStateMachine->enhanceService_ = nullptr;
        pStaStateMachine->pGetIpState->GoInState();
    }

    void GetIpStateStateGoOutStateSuccess()
    {
        pStaStateMachine->pGetIpState->GoOutState();
    }

    void GetIpStateStateExeMsgSuccess()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetParam1(DHCP_RESULT);
        msg->SetParam2(0);
        msg->SetMessageName(WIFI_SVR_CMD_STA_DHCP_RESULT_NOTIFY_EVENT);
        StaStateMachine staStateMachine;
        pStaStateMachine->pGetIpState->pStaStateMachine = &staStateMachine;
                pStaStateMachine->pGetIpState->pStaStateMachine->pDhcpResultNotify->pStaStateMachine = &staStateMachine;
        pStaStateMachine->pGetIpState->ExecuteStateMsg(msg);
    }

    void GetIpStateStateExeMsgFail()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        StaStateMachine staStateMachine;
        pStaStateMachine->pGetIpState->pStaStateMachine = &staStateMachine;
        pStaStateMachine->pGetIpState->pStaStateMachine->pDhcpResultNotify->pStaStateMachine = &staStateMachine;
        msg->SetMessageName(WIFI_SVR_CMD_STA_DHCP_RESULT_NOTIFY_EVENT);
        msg->SetParam1(DHCP_JUMP);
        pStaStateMachine->pGetIpState->ExecuteStateMsg(msg);
        msg->SetParam1(DHCP_FAIL);
        pStaStateMachine->pGetIpState->ExecuteStateMsg(msg);
        msg->SetParam1(DHCP_OFFER_REPORT);
        pStaStateMachine->pGetIpState->ExecuteStateMsg(msg);
        msg->SetParam1(WIFI_SVR_CMD_STA_BSSID_CHANGED_EVENT);
        pStaStateMachine->pGetIpState->ExecuteStateMsg(msg);
        pStaStateMachine->pGetIpState->ExecuteStateMsg(nullptr);
    }

    void GetIpStateStateIsPublicESSTest()
    {
        std::vector<WifiScanInfo> scanResults;
        WifiScanInfo scanInfo;
        scanInfo.ssid = "1234";
        scanResults.push_back(scanInfo);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScanInfoList(_)).
            WillRepeatedly(DoAll(SetArgReferee<0>(scanResults), Return(0)));
        WifiLinkedInfo linkedInfo;
        linkedInfo.ssid = "1234";
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _)).
            WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
        pStaStateMachine->pGetIpState->IsPublicESS();
    }

    void ConfigStaticIpAddressSuccess1()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        pStaStateMachine->currentTpType = IPTYPE_IPV4;
        pStaStateMachine->getIpSucNum = 1;
        pStaStateMachine->isRoam = false;
        StaticIpAddress staticIpAddress;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpInfo(_, _)).Times(AtLeast(0));
        ;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(AtLeast(0));
        StaStateMachine staStateMachine;
        pStaStateMachine->pDhcpResultNotify->SetStaStateMachine(&staStateMachine);
        EXPECT_TRUE(pStaStateMachine->ConfigStaticIpAddress(staticIpAddress));
    }

    void ConfigStaticIpAddressSuccess2()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        pStaStateMachine->currentTpType = IPTYPE_IPV6;
        pStaStateMachine->getIpSucNum = 1;
        pStaStateMachine->isRoam = false;
        StaticIpAddress staticIpAddress;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(AtLeast(0));
        StaStateMachine staStateMachine;
        pStaStateMachine->pDhcpResultNotify->SetStaStateMachine(&staStateMachine);
        EXPECT_TRUE(pStaStateMachine->ConfigStaticIpAddress(staticIpAddress));
    }

    void ConfigStaticIpAddressSuccess3()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        pStaStateMachine->currentTpType = IPTYPE_MIX;
        pStaStateMachine->getIpSucNum = 1;
        pStaStateMachine->isRoam = false;
        StaticIpAddress staticIpAddress;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(AtLeast(0));
        StaStateMachine staStateMachine;
        pStaStateMachine->pDhcpResultNotify->SetStaStateMachine(&staStateMachine);
        EXPECT_TRUE(pStaStateMachine->ConfigStaticIpAddress(staticIpAddress));
    }

    void ConfigStaticIpAddressFail()
    {
        pStaStateMachine->currentTpType = IPTYPE_BUTT;
        StaticIpAddress staticIpAddress;
        pStaStateMachine->getIpSucNum = 1;
        pStaStateMachine->isRoam = false;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        StaStateMachine staStateMachine;
        pStaStateMachine->pDhcpResultNotify->SetStaStateMachine(&staStateMachine);
        EXPECT_FALSE(pStaStateMachine->ConfigStaticIpAddress(staticIpAddress));
    }

    void HandleNetCheckResultSuccess1()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(TWO);
        pStaStateMachine->linkedInfo.connState = ConnState::CONNECTED;
        pStaStateMachine->HandleNetCheckResult(SystemNetWorkState::NETWORK_IS_WORKING, "");
    }

    void HandleNetCheckResultSuccess3()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(TWO);
        pStaStateMachine->linkedInfo.connState = ConnState::CONNECTED;
        pStaStateMachine->HandleNetCheckResult(SystemNetWorkState::NETWORK_IS_PORTAL, "");
    }
    void HandleNetCheckResultSuccess4()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(TWO);
        pStaStateMachine->linkedInfo.connState = ConnState::CONNECTED;
        pStaStateMachine->HandleNetCheckResult(SystemNetWorkState::NETWORK_NOTWORKING, "");
    }

    void HandleNetCheckResultFail()
    {
        pStaStateMachine->linkedInfo.connState = ConnState::DISCONNECTED;
        pStaStateMachine->HandleNetCheckResult(SystemNetWorkState::NETWORK_NOTWORKING, "");
    }

    void TestUpdatePortalState(std::map<PortalState, PortalState> &map, SystemNetWorkState netState)
    {
        bool updatePortalAuthTime = false;
        for (auto& pair : map) {
            auto initState = pair.first;
            auto expectState = pair.second;

            pStaStateMachine->portalState = initState;
            pStaStateMachine->UpdatePortalState(netState, updatePortalAuthTime);
            EXPECT_EQ(pStaStateMachine->portalState, expectState);
        }
    }

    void LinkedStateGoOutStateSuccess()
    {
        pStaStateMachine->pLinkedState->GoOutState();
    }

    void LinkedStateExeMsgSuccess()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_SVR_CMD_STA_BSSID_CHANGED_EVENT);
        msg->AddStringMessageBody("ASSOC_COMPLETE");
        pStaStateMachine->pLinkedState->ExecuteStateMsg(msg);
    }

    void LinkedStateExeMsgFail4()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_SIGNAL_POLL);
        msg->AddStringMessageBody("hello");
        pStaStateMachine->pLinkedState->ExecuteStateMsg(msg);
    }

    void LinkedStateExeMsgFail3()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_SVR_CMD_STA_BSSID_CHANGED_EVENT);
        msg->AddStringMessageBody("ASSOC_COMPLETE");
        pStaStateMachine->pLinkedState->ExecuteStateMsg(msg);
    }

    void LinkedStateExeMsgFail2()
    {
        IpInfo ipInfo;
        IpV6Info ipv6Info;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(ipInfo), Return(0)));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpv6Info(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(ipv6Info), Return(0)));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(0);
        msg->SetParam1(DhcpReturnCode::DHCP_IP_EXPIRED);
        pStaStateMachine->pLinkedState->ExecuteStateMsg(msg);
        msg->SetMessageName(WIFI_SVR_CMD_STA_DHCP_RESULT_NOTIFY_EVENT);
        pStaStateMachine->pLinkedState->ExecuteStateMsg(msg);
        pStaStateMachine->linkedInfo.connState = ConnState::DISCONNECTED;
        msg->SetMessageName(WIFI_SVR_CMD_STA_PORTAL_BROWSE_NOTIFY_EVENT);
        pStaStateMachine->pLinkedState->ExecuteStateMsg(msg);
    }

    void LinkedStateExeMsgFail()
    {
        pStaStateMachine->pLinkedState->ExecuteStateMsg(nullptr);
    }

    void LinkedStateCheckIfRestoreWifiSuccess()
    {
        pStaStateMachine->pLinkedState->CheckIfRestoreWifi();
        EXPECT_NE(pStaStateMachine->linkedInfo.networkId, TEN);
    }
 
    void ApRoamingStateGoInStateSuccess()
    {
        pStaStateMachine->pApRoamingState->GoInState();
    }

    void ApRoamingStateGoOutStateSuccess()
    {
        pStaStateMachine->pApRoamingState->GoOutState();
    }

    void ApRoamingStateExeMsgSuccess()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiState(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).WillRepeatedly(Return(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_SVR_CMD_STA_NETWORK_CONNECTION_EVENT);
        EXPECT_TRUE(pStaStateMachine->pApRoamingState->ExecuteStateMsg(msg));
    }

    void ApRoamingStateExeMsgFail()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_SVR_CMD_STA_ERROR);
        EXPECT_FALSE(pStaStateMachine->pApRoamingState->ExecuteStateMsg(nullptr));
        EXPECT_FALSE(pStaStateMachine->pApRoamingState->ExecuteStateMsg(msg));
    }

    void ConnectToNetworkProcessSuccess()
    {
        pStaStateMachine->wpsState = SetupMethod::DISPLAY;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).WillRepeatedly(Return(-1));
        WifiHalGetDeviceConfig config;
        config.value = "hmwifi";
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig()).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiState(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        std::string bssid = "wifitest";
        pStaStateMachine->ConnectToNetworkProcess(bssid);
    }

    void ConnectToNetworkProcessSuccess1()
    {
        pStaStateMachine->wpsState = SetupMethod::PBC;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).WillRepeatedly(Return(-1));
        WifiHalGetDeviceConfig config;
        config.value = "hmwifi";
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig()).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiState(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        std::string bssid = "wifitest";
        pStaStateMachine->ConnectToNetworkProcess(bssid);
    }

    void ConnectToNetworkProcessSuccess2()
    {
        pStaStateMachine->wpsState = SetupMethod::KEYPAD;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).WillRepeatedly(Return(-1));
        WifiHalGetDeviceConfig config;
        config.value = "hmwifi";
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig()).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiState(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        std::string bssid = "wifitest";
        pStaStateMachine->ConnectToNetworkProcess(bssid);
        EXPECT_NE(pStaStateMachine->linkedInfo.networkId, TEN);
    }

    void ConnectToNetworkProcessSuccess3()
    {
        pStaStateMachine->wpsState = SetupMethod::INVALID;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).WillRepeatedly(Return(-1));
        WifiHalGetDeviceConfig config;
        config.value = "hmwifi";
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig()).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiState(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        std::string bssid = "wifitest";
        pStaStateMachine->ConnectToNetworkProcess(bssid);
    }

    void SetWifiLinkedInfoSuccess1()
    {
        pStaStateMachine->linkedInfo.networkId = INVALID_NETWORK_ID;
        pStaStateMachine->lastLinkedInfo.networkId = 0;
        pStaStateMachine->SetWifiLinkedInfo(INVALID_NETWORK_ID);
    }

    void SetWifiLinkedInfoSuccess2()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).WillRepeatedly(Return(0));
        pStaStateMachine->linkedInfo.networkId = INVALID_NETWORK_ID;
        pStaStateMachine->lastLinkedInfo.networkId = INVALID_NETWORK_ID;
        pStaStateMachine->SetWifiLinkedInfo(0);
    }

    void GetDeviceCfgInfoSuccessTest()
    {
        const std::string bssid = "wifitest";
        WifiDeviceConfig deviceConfig;
        pStaStateMachine->GetDeviceCfgInfo(bssid, deviceConfig);
    }

    void DhcpResultNotifyOnSuccessTest()
    {
        pStaStateMachine->linkedInfo.detailedState = DetailedState::CONNECTED;
        pStaStateMachine->getIpSucNum = 1;
        pStaStateMachine->isRoam = false;
        IpInfo ipInfo;
        ipInfo.ipAddress = IpTools::ConvertIpv4Address("192.168.0.2");
        ipInfo.gateway = IpTools::ConvertIpv4Address("192.168.0.1");
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(ipInfo), Return(0)));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpV6Info(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpv6Info(_, _)).Times(testing::AtLeast(0));
    }

    void DhcpResultNotifyOnSuccessTest1()
    {
        std::string ifname = "wlan0";
        DhcpResult result;
        StaStateMachine staStateMachine;
        pStaStateMachine->pDhcpResultNotify->SetStaStateMachine(&staStateMachine);
        pStaStateMachine->pDhcpResultNotify->OnSuccess(0, nullptr, &result);
        pStaStateMachine->pDhcpResultNotify->OnSuccess(0, ifname.c_str(), nullptr);
        pStaStateMachine->pDhcpResultNotify->OnSuccess(0, ifname.c_str(), &result);
    }

    void DhcpResultNotifyOnFailedTest1()
    {
        pStaStateMachine->linkedInfo.detailedState = DetailedState::CONNECTED;
        pStaStateMachine->currentTpType = IPTYPE_IPV6;
        pStaStateMachine->getIpSucNum = 0;
        pStaStateMachine->getIpFailNum = 1;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpV6Info(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpv6Info(_, _)).Times(testing::AtLeast(0));
        std::string ifname = "wlan0";
        std::string reason = "test";
        StaStateMachine staStateMachine;
        pStaStateMachine->pDhcpResultNotify->SetStaStateMachine(&staStateMachine);
        pStaStateMachine->pDhcpResultNotify->OnFailed(0, ifname.c_str(), reason.c_str());
    }

    void DhcpResultNotifyOnFailedTest2()
    {
        pStaStateMachine->linkedInfo.detailedState = DetailedState::DISCONNECTING;
        pStaStateMachine->isRoam = false;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpV6Info(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpv6Info(_, _)).Times(testing::AtLeast(0));
        std::string ifname = "wlan1";
        std::string reason = "test";
        StaStateMachine staStateMachine;
        pStaStateMachine->pDhcpResultNotify->SetStaStateMachine(&staStateMachine);
        pStaStateMachine->pDhcpResultNotify->OnFailed(DHCP_RENEW_FAILED, ifname.c_str(), reason.c_str());
    }

    void DhcpResultNotifyOnFailedTest3()
    {
        pStaStateMachine->linkedInfo.detailedState = DetailedState::DISCONNECTED;
        pStaStateMachine->isRoam = true;
        std::string ifname = "wlan1";
        std::string reason = "test";
        StaStateMachine staStateMachine;
        pStaStateMachine->pDhcpResultNotify->SetStaStateMachine(&staStateMachine);
        pStaStateMachine->pDhcpResultNotify->OnFailed(DHCP_LEASE_EXPIRED, ifname.c_str(), reason.c_str());
        EXPECT_NE(pStaStateMachine->linkedInfo.networkId, TEN);
    }

    void SaveLinkstateSuccess()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        pStaStateMachine->SaveLinkstate(ConnState::CONNECTED, DetailedState::CONNECTED);
    }

    void ConvertFreqToChannelTest()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).WillOnce(Return(1));
        pStaStateMachine->ConvertFreqToChannel();
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), AddDeviceConfig(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig()).Times(AtLeast(0));
        pStaStateMachine->linkedInfo.frequency = FREQ_2G_MIN;
        pStaStateMachine->ConvertFreqToChannel();

        pStaStateMachine->linkedInfo.frequency = FREQ_2G_MAX;
        pStaStateMachine->ConvertFreqToChannel();

        pStaStateMachine->linkedInfo.frequency = CHANNEL_14_FREQ;
        pStaStateMachine->ConvertFreqToChannel();

        pStaStateMachine->linkedInfo.frequency = FREQ_5G_MIN;
        pStaStateMachine->ConvertFreqToChannel();
    }

    void LinkStateGoInStateSuccess()
    {
        pStaStateMachine->pLinkState->GoInState();
    }

    void LinkStateGoOutStateSuccess()
    {
        pStaStateMachine->pLinkState->GoOutState();
    }

    void LinkStateExeMsgSuccess()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pStaStateMachine->pLinkState->ExecuteStateMsg(msg);
    }

    void LinkStateExeMsgFail()
    {
        EXPECT_FALSE(pStaStateMachine->pLinkState->ExecuteStateMsg(nullptr));
    }
    void OnNetManagerRestartSuccess()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiState(_)).WillRepeatedly(Return(1));
        pStaStateMachine->OnNetManagerRestart();
    }

    void OnNetManagerRestartFail()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiState(_)).WillRepeatedly(Return(1));
        pStaStateMachine->OnNetManagerRestart();
    }

    void OnBssidChangedEventSuccess()
    {
        std::string reason;
        std::string bssid;
        pStaStateMachine->OnBssidChangedEvent(reason, bssid);
    }

    void OnBssidChangedEventLinkSwitch()
    {
        std::string reason = "LINK_SWITCH";
        std::string bssid = "12:34:56:78:9A:BC";
        pStaStateMachine->OnBssidChangedEvent(reason, bssid);
    }

    void OnNetworkDisconnectEventSuccess()
    {
        int reason = 0;
        pStaStateMachine->OnNetworkDisconnectEvent(reason);
    }

    void DealReConnectCmdSuccess()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pStaStateMachine->linkedInfo.connState = ConnState::CONNECTING;
        pStaStateMachine->DealNetworkCheck(msg);
        pStaStateMachine->DealNetworkCheck(nullptr);
        EXPECT_CALL(WifiSettings::GetInstance(), SetDeviceConnFailedCount(_, _, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), IncreaseDeviceConnFailedCount(_, _, _)).Times(testing::AtLeast(0));
        pStaStateMachine->DealReConnectCmd(msg);
    }

    void DealReConnectCmdFail()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pStaStateMachine->linkedInfo.connState = ConnState::CONNECTED;
        pStaStateMachine->DealReConnectCmd(msg);
        pStaStateMachine->DealReConnectCmd(nullptr);
    }

    void DealConnectionEventSuccess()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), SetDeviceAfterConnect(_)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig()).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetUserLastSelectedNetworkId(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->wpsState = SetupMethod::INVALID;
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pStaStateMachine->DealConnectionEvent(msg);
    }

    void DealConnectionEventFail()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), SetDeviceAfterConnect(_)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig()).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetUserLastSelectedNetworkId(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->wpsState = SetupMethod::LABEL;
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pStaStateMachine->DealConnectionEvent(msg);
        pStaStateMachine->DealConnectionEvent(nullptr);
    }

    void OnConnectFailed()
    {
        int networkId = 15;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _));
        pStaStateMachine->OnConnectFailed(networkId);
    }

    void ReUpdateNetLinkInfoTest()
    {
        pStaStateMachine->linkedInfo.detailedState = DetailedState::NOTWORKING;
        pStaStateMachine->linkedInfo.connState = ConnState::CONNECTED;
        pStaStateMachine->linkedInfo.bssid = RANDOMMAC_BSSID;
        pStaStateMachine->linkedInfo.ssid = RANDOMMAC_SSID;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).WillRepeatedly(Return(0));
        WifiDeviceConfig config;
        config.bssid = RANDOMMAC_BSSID;
        config.ssid = RANDOMMAC_SSID;
        pStaStateMachine->ReUpdateNetLinkInfo(config);
    }

    void ReUpdateNetLinkInfoTest1()
    {
        pStaStateMachine->linkedInfo.detailedState = DetailedState::NOTWORKING;
        pStaStateMachine->linkedInfo.connState = ConnState::CONNECTED;
        WifiLinkedInfo linkedInfo;
        linkedInfo.connState = ConnState::CONNECTED;
        linkedInfo.ssid = "111111";
        linkedInfo.bssid = "222222";
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _)).
            WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpv6Info(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetStaIfaceName(_)).WillRepeatedly(Return("sta"));
        WifiDeviceConfig config;
        config.ssid = "111111";
        config.bssid = "222222";
        pStaStateMachine->ReUpdateNetLinkInfo(config);
    }

    void UpdateLinkInfoRssiTest()
    {
        int rssi = INVALID_RSSI1;
        int outRssi = pStaStateMachine->UpdateLinkInfoRssi(rssi);
        EXPECT_EQ(outRssi, INVALID_RSSI_VALUE);

        rssi = INVALID_RSSI2;
        outRssi = pStaStateMachine->UpdateLinkInfoRssi(rssi);
        EXPECT_EQ(outRssi, INVALID_RSSI_VALUE);

        rssi = VALID_RSSI3;
        outRssi = pStaStateMachine->UpdateLinkInfoRssi(rssi);
        EXPECT_EQ(outRssi, VALID_RSSI3);

        rssi = VALID_RSSI4;
        outRssi = pStaStateMachine->UpdateLinkInfoRssi(rssi);
        EXPECT_EQ(outRssi, (VALID_RSSI4 - SIGNAL_INFO));

        rssi = INVALID_RSSI5;
        outRssi = pStaStateMachine->UpdateLinkInfoRssi(rssi);
        EXPECT_EQ(outRssi, INVALID_RSSI_VALUE);
    }

    void UpdateLinkRssiTest()
    {
        WifiHalWpaSignalInfo signalInfo;
        signalInfo.signal = INVALID_RSSI1;
        pStaStateMachine->UpdateLinkRssi(signalInfo);

        signalInfo.signal = INVALID_RSSI2;
        pStaStateMachine->UpdateLinkRssi(signalInfo);

        signalInfo.signal = VALID_RSSI3;
        pStaStateMachine->UpdateLinkRssi(signalInfo);

        signalInfo.signal = VALID_RSSI4;
        pStaStateMachine->UpdateLinkRssi(signalInfo);
    }

    void DealSignalPollResultTest()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiLinkedStandardAndMaxSpeed(_)).Times(testing::AtLeast(0));
        pStaStateMachine->DealSignalPollResult();
        pStaStateMachine->linkedInfo.lastTxPackets = 1;
        pStaStateMachine->linkedInfo.lastRxPackets = 1;
        pStaStateMachine->linkedInfo.lastPacketDirection = 1;
        pStaStateMachine->DealSignalPacketChanged(0, 0);
    }

    void DealSignalPacketChangedTest()
    {
        pStaStateMachine->linkedInfo.lastTxPackets = -1;
        pStaStateMachine->linkedInfo.lastRxPackets = -1;
        pStaStateMachine->linkedInfo.lastPacketDirection = 1;
        pStaStateMachine->DealSignalPacketChanged(0, 0);
    }

    void GetWpa3FailCountSuccessTest()
    {
        int failreason = 0;
        std::string ssid = RANDOMMAC_SSID;
        pStaStateMachine->GetWpa3FailCount(failreason, ssid);
    }

    void GetWpa3FailCountFailTest()
    {
        int failreason = -1;
        std::string ssid = RANDOMMAC_SSID;
        pStaStateMachine->GetWpa3FailCount(failreason, ssid);
    }

    void AddWpa3FailCountSuccessTest()
    {
        int failreason = 0;
        std::string ssid = RANDOMMAC_SSID;
        pStaStateMachine->AddWpa3FailCount(failreason, ssid);
    }

    void AddWpa3FailCountFailTest()
    {
        int failreason = -1;
        std::string ssid = RANDOMMAC_SSID;
        pStaStateMachine->AddWpa3FailCount(failreason, ssid);
    }

    void AddWpa3BlackMapTest()
    {
        std::string ssid = RANDOMMAC_SSID;
        for (int i = 0; i < WPA3_BLACKMAP_MAX_NUM; i++) {
            pStaStateMachine->AddWpa3BlackMap(std::to_string(i));
        }
        pStaStateMachine->AddWpa3BlackMap(ssid);
    }

    void IsInWpa3BlackMapTest()
    {
        std::string ssid = RANDOMMAC_SSID;
        pStaStateMachine->IsInWpa3BlackMap(ssid);
    }

    void OnWifiWpa3SelfCureSuccessTest()
    {
        int failreason = TEST_FAIL_REASON;
        int networkId = 0;
        pStaStateMachine->OnWifiWpa3SelfCure(failreason, networkId);
    }

    void OnWifiWpa3SelfCureFailTest()
    {
        int failreason = 0;
        int networkId = 0;
        pStaStateMachine->OnWifiWpa3SelfCure(failreason, networkId);
    }

    void IsWpa3TransitionTest()
    {
        pStaStateMachine->IsWpa3Transition(RANDOMMAC_SSID);
    }

    void InvokeOnStaConnChanged(const OperateResState &state, WifiLinkedInfo &info)
    {
        pStaStateMachine->GetLinkedInfo(info);
        if (info.connState == ConnState::CONNECTED) {
            pStaStateMachine->InvokeOnStaConnChanged(state, info);
        }
    }

    void InvokeOnWpsChanged(const WpsStartState &state, const int code)
    {
        std::vector<StaServiceCallback> callbacks;
        callbacks.push_back(WifiManager::GetInstance().GetStaCallback());
        pStaService->InitStaService(callbacks);
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _)).Times(AtLeast(0));
        pStaStateMachine->InvokeOnWpsChanged(state, 0);
    }

    void InvokeOnStaStreamChanged(const StreamDirection &direction)
    {
        pStaStateMachine->InvokeOnStaStreamChanged(direction);
        EXPECT_NE(pStaStateMachine->linkedInfo.networkId, TEN);
    }

    void InvokeOnStaRssiLevelChanged(int level)
    {
        pStaStateMachine->InvokeOnStaRssiLevelChanged(level);
        EXPECT_NE(pStaStateMachine->linkedInfo.networkId, TEN);
    }

    void DealScreenStateChangedEventTest()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        pStaStateMachine->DealScreenStateChangedEvent(nullptr);
        msg->SetParam1(static_cast<int>(MODE_STATE_OPEN));
        pStaStateMachine->DealScreenStateChangedEvent(msg);
        msg->SetParam1(static_cast<int>(MODE_STATE_CLOSE));
        pStaStateMachine->DealScreenStateChangedEvent(msg);
    }

    void DealNetworkRemovedSuccessTest()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        WifiLinkedInfo info;
        pStaStateMachine->GetLinkedInfo(info);
        msg->SetParam1(static_cast<int>(info.networkId));
        pStaStateMachine->DealNetworkRemoved(msg);
    }

    void DealNetworkRemovedFailTest()
    {
        pStaStateMachine->DealNetworkRemoved(nullptr);
    }

    void DealHiLinkDataToWpaFailTest()
    {
        pStaStateMachine->DealHiLinkDataToWpa(nullptr);
    }

    void DealHiLinkDataToWpaSuccessTest1()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_SVR_COM_STA_ENABLE_HILINK);
        std::string cmd = "ENABLE=1 BSSID=01:23:45:67:89:a0";
        msg->SetMessageObj(cmd);
        pStaStateMachine->DealHiLinkDataToWpa(msg);
    }

    void DealHiLinkDataToWpaSuccessTest2()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_SVR_COM_STA_HILINK_DELIVER_MAC);
        std::string cmd = "HILINK_MAC=01:23:45:67:89:a0";
        msg->SetMessageObj(cmd);
        pStaStateMachine->DealHiLinkDataToWpa(msg);
    }

    void DealHiLinkDataToWpaSuccessTest3()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_SVR_COM_STA_ENABLE_HILINK);
        std::string bssid = "01:23:45:67:89:a0";
        msg->SetMessageObj(bssid);
        pStaStateMachine->DealHiLinkDataToWpa(msg);
    }

    void DealHiLinkDataToWpaSuccessTest4()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(0);
        std::string bssid = "01:23:45:67:89:a0";
        msg->SetMessageObj(bssid);
        pStaStateMachine->DealHiLinkDataToWpa(msg);
    }

    void DealHiLinkDataToWpaSuccessTest5()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_SVR_COM_STA_HILINK_TRIGGER_WPS);
        std::string bssid = "01:23:45:67:89:a0";
        msg->SetMessageObj(bssid);
        pStaStateMachine->DealHiLinkDataToWpa(msg);
    }

    void IsDisConnectReasonShouldStopTimerSuccessTest()
    {
        int event = 8;
        EXPECT_TRUE(pStaStateMachine->IsDisConnectReasonShouldStopTimer(event));
    }

    void IsDisConnectReasonShouldStopTimerFailedTest()
    {
        int event = 0;
        EXPECT_FALSE(pStaStateMachine->IsDisConnectReasonShouldStopTimer(event));
    }

    void ShouldUseFactoryMacSuccess()
    {
        WifiDeviceConfig deviceConfig;
        deviceConfig.keyMgmt = KEY_MGMT_WPA_PSK;
        deviceConfig.networkId = 1;
        pStaStateMachine->mLastConnectNetId = 0;
        pStaStateMachine->mConnectFailedCnt = 0;
        EXPECT_FALSE(pStaStateMachine->ShouldUseFactoryMac(deviceConfig));
        pStaStateMachine->mConnectFailedCnt++ ;
        EXPECT_FALSE(pStaStateMachine->ShouldUseFactoryMac(deviceConfig));
        pStaStateMachine->mConnectFailedCnt++ ;
        EXPECT_TRUE(pStaStateMachine->ShouldUseFactoryMac(deviceConfig));
    }

    void ShouldUseFactoryMacFail()
    {
        WifiDeviceConfig deviceConfig;
        deviceConfig.keyMgmt = KEY_MGMT_NONE;
        EXPECT_FALSE(pStaStateMachine->ShouldUseFactoryMac(deviceConfig));
        deviceConfig.keyMgmt = KEY_MGMT_WPA_PSK;
        deviceConfig.networkId = 1;
        pStaStateMachine->mLastConnectNetId = 0;
        pStaStateMachine->mConnectFailedCnt = 1;
        EXPECT_FALSE(pStaStateMachine->ShouldUseFactoryMac(deviceConfig));
    }

    void InitRandomMacInfoTest()
    {
        const std::string bssid = "";
        WifiDeviceConfig deviceConfig;
        deviceConfig.keyMgmt = KEY_MGMT_NONE;
        WifiStoreRandomMac randomMacInfo;
        pStaStateMachine->InitRandomMacInfo(deviceConfig, bssid, randomMacInfo);
    }

    void OnNetworkHiviewEventTest()
    {
        const int  wpaCBAssocing = 3;
        const int  wpaCBAssoced = 4;
        pStaStateMachine->OnNetworkHiviewEvent(wpaCBAssocing);
        pStaStateMachine->OnNetworkHiviewEvent(wpaCBAssoced);
    }

    void OnNetworkAssocEventTest()
    {
        const int  wpaCBAssocing = 3;
        StaStateMachine staStateMachine;
        pStaStateMachine->OnNetworkAssocEvent(-1, "a2:b1:f5:c7:d1", &staStateMachine);
    }
    void GetDataSlotIdTest()
    {
        pStaStateMachine->GetDataSlotId(0);
        pStaStateMachine->GetDataSlotId(-1);
    }
    void GetCardTypeTest()
    {
        CardType cardType;
        pStaStateMachine->GetCardType(cardType);
    }
    void GetDefaultIdTest()
    {
        pStaStateMachine->GetDefaultId(WIFI_INVALID_SIM_ID);
        pStaStateMachine->GetDefaultId(1);
    }

    void GetSimCardStateTest()
    {
        pStaStateMachine->GetSimCardState(0);
    }

    void IsValidSimIdTest()
    {
        pStaStateMachine->IsValidSimId(0);
        EXPECT_EQ(pStaStateMachine->IsValidSimId(1), true);
    }
    void IsMultiSimEnabledTest()
    {
        pStaStateMachine->IsMultiSimEnabled();
    }
    void SimAkaAuthTest()
    {
        EXPECT_EQ(pStaStateMachine->SimAkaAuth("", SIM_AUTH_EAP_SIM_TYPE), "");
    }

    void GetGsmAuthResponseWithLengthTest()
    {
        EapSimGsmAuthParam param;
        param.rands.push_back(TEMP_TEST_DATA);
        EXPECT_EQ(pStaStateMachine->GetGsmAuthResponseWithLength(param), "");
    }

    void GetGsmAuthResponseWithoutLengthTest()
    {
        EapSimGsmAuthParam param;
        param.rands.push_back(TEMP_TEST_DATA);
        EXPECT_EQ(pStaStateMachine->GetGsmAuthResponseWithoutLength(param), "");
    }

    void PreWpaEapUmtsAuthEventTest()
    {
        pStaStateMachine->PreWpaEapUmtsAuthEvent();
    }

    void FillUmtsAuthReqTest()
    {
        EapSimUmtsAuthParam param;
        param.rand = TEMP_TEST_DATA;
        param.autn = TEMP_TEST_DATA;
        EXPECT_NE(pStaStateMachine->FillUmtsAuthReq(param).size(), 0);
    }
    void ParseAndFillUmtsAuthParamTest()
    {
        std::vector<uint8_t> nonce;
        nonce.push_back(UMTS_AUTH_TYPE_TAG);
        pStaStateMachine->ParseAndFillUmtsAuthParam(nonce);
        nonce.clear();
        nonce.push_back(UMTS_AUTS_TYPE_TAG);
        pStaStateMachine->ParseAndFillUmtsAuthParam(nonce);
    }

    void GetUmtsAuthResponseTest()
    {
        EapSimUmtsAuthParam param;
        EXPECT_EQ(pStaStateMachine->GetUmtsAuthResponse(param), "");
    }

    void DealWpaEapSimAuthEventTest()
    {
        InternalMessagePtr msg = nullptr;
        pStaStateMachine->DealWpaEapSimAuthEvent(msg);
        InternalMessagePtr msg1 = std::make_shared<InternalMessage>();
        msg1->SetMessageName(WIFI_SVR_CMD_STA_WPA_EAP_SIM_AUTH_EVENT);
        EapSimGsmAuthParam param;
        param.rands.push_back(TEMP_TEST_DATA);
        msg1->SetMessageObj(param);
        pStaStateMachine->DealWpaEapSimAuthEvent(msg1);
        InternalMessagePtr msg2 = std::make_shared<InternalMessage>();
        msg2->SetMessageName(WIFI_SVR_CMD_STA_WPA_EAP_UMTS_AUTH_EVENT);
        msg2->SetMessageObj(param);
        pStaStateMachine->DealWpaEapSimAuthEvent(msg2);
    }
    void HandlePortalNetworkPorcessTests()
    {
        pStaStateMachine->HandlePortalNetworkPorcess();
    }

    void DealWpaEapUmtsAuthEventTest()
    {
        InternalMessagePtr msg = nullptr;
        pStaStateMachine->DealWpaEapUmtsAuthEvent(msg);
        InternalMessagePtr msg1 = std::make_shared<InternalMessage>();
        EapSimUmtsAuthParam param;
        msg1->SetMessageName(WIFI_SVR_CMD_STA_WPA_EAP_UMTS_AUTH_EVENT);
        msg1->SetMessageObj(param);
        pStaStateMachine->DealWpaEapUmtsAuthEvent(msg1);
        InternalMessagePtr msg2 = std::make_shared<InternalMessage>();
        msg2->SetMessageName(WIFI_SVR_CMD_STA_WPA_EAP_UMTS_AUTH_EVENT);
        param.rand = TEMP_TEST_DATA;
        param.autn = TEMP_TEST_DATA;
        msg2->SetMessageObj(param);
        WifiDeviceConfig wifiDeviceConfig;
        wifiDeviceConfig.networkId = 1;
        wifiDeviceConfig.wifiEapConfig.eapSubId = 0;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).
            WillRepeatedly(DoAll(SetArgReferee<1>(wifiDeviceConfig), Return(0)));
        pStaStateMachine->DealWpaEapUmtsAuthEvent(msg2);
    }

    void HilinkSaveConfigTest()
    {
        pStaStateMachine->HilinkSaveConfig();
    }

    void SyncDeviceEverConnectedStateTest(bool hasNet)
    {
        pStaStateMachine->SyncDeviceEverConnectedState(hasNet);
    }
 
    void IsRoamingTest()
    {
        EXPECT_EQ(pStaStateMachine->IsRoaming(), false);
    }
    void OnDhcpResultNotifyEventTest()
    {
        pStaStateMachine->OnDhcpResultNotifyEvent(DhcpReturnCode::DHCP_RENEW_FAIL);
    }

    void FillSuiteB192CfgTest()
    {
        WifiHalDeviceConfig  halDeviceConfig;
        halDeviceConfig.keyMgmt = "WPA-EAP-SUITE-B-192";
        pStaStateMachine->FillSuiteB192Cfg(halDeviceConfig);
    }

    void ReplaceEmptyDnsTest()
    {
        DhcpResult *result = nullptr;
        pStaStateMachine->ReplaceEmptyDns(result);
        DhcpResult resultO;
        std::string bssid1 = "11:22:33:44";
        std::string bssid2 = "11:22:33:44";
        strcpy_s(resultO.strOptDns1, MAX_STR_LENT, bssid1.c_str());
        strcpy_s(resultO.strOptDns2, MAX_STR_LENT, bssid2.c_str());
        pStaStateMachine->ReplaceEmptyDns(&resultO);
    }

    void SetSupportedWifiCategoryTestBssidIsEmpty()
    {
        pStaStateMachine->linkedInfo.bssid = "";
        pStaStateMachine->SetSupportedWifiCategory();
        EXPECT_EQ(pStaStateMachine->linkedInfo.supportedWifiCategory, WifiCategory::DEFAULT);
    }

    void SetSupportedWifiCategoryTestWifi6()
    {
        pStaStateMachine->linkedInfo.bssid = "123";
        EXPECT_CALL(*WifiConfigCenter::GetInstance().GetWifiScanConfig(),
            GetWifiCategoryRecord(_)).WillRepeatedly(Return(WifiCategory::WIFI6));
        pStaStateMachine->SetSupportedWifiCategory();
        EXPECT_EQ(pStaStateMachine->linkedInfo.supportedWifiCategory, WifiCategory::WIFI6);
        EXPECT_EQ(pStaStateMachine->linkedInfo.isMloConnected, false);
    }

    void SetSupportedWifiCategoryTestWifi7NotMlo()
    {
        pStaStateMachine->linkedInfo.bssid = "123";
        EXPECT_CALL(*WifiConfigCenter::GetInstance().GetWifiScanConfig(),
            GetWifiCategoryRecord(_)).WillRepeatedly(Return(WifiCategory::WIFI7));
        MockWifiStaHalInterface::GetInstance().SetChipsetFeatureCapability(CHIPSET_FEATURE_CAPABILITY_WIFI6_TEST);
        pStaStateMachine->SetSupportedWifiCategory();
        EXPECT_EQ(pStaStateMachine->linkedInfo.supportedWifiCategory, WifiCategory::WIFI7);
        EXPECT_EQ(pStaStateMachine->linkedInfo.isMloConnected, false);
    }

    void SetSupportedWifiCategoryTestWifi7IsMlo()
    {
        pStaStateMachine->linkedInfo.bssid = "123";
        EXPECT_CALL(*WifiConfigCenter::GetInstance().GetWifiScanConfig(),
            GetWifiCategoryRecord(_)).WillRepeatedly(Return(WifiCategory::WIFI7));
        MockWifiStaHalInterface::GetInstance().SetChipsetFeatureCapability(CHIPSET_FEATURE_CAPABILITY_WIFI7_TEST);
        pStaStateMachine->SetSupportedWifiCategory();
        EXPECT_EQ(pStaStateMachine->linkedInfo.supportedWifiCategory, WifiCategory::WIFI7);
        EXPECT_EQ(pStaStateMachine->linkedInfo.isMloConnected, true);
    }
};

HWTEST_F(StaStateMachineTest, ShouldUseFactoryMacSuccess, TestSize.Level1)
{
    ShouldUseFactoryMacSuccess();
}

HWTEST_F(StaStateMachineTest, ShouldUseFactoryMacFail, TestSize.Level1)
{
    ShouldUseFactoryMacFail();
}

HWTEST_F(StaStateMachineTest, IsDisConnectReasonShouldStopTimerSuccessTest, TestSize.Level1)
{
    IsDisConnectReasonShouldStopTimerSuccessTest();
}

HWTEST_F(StaStateMachineTest, IsDisConnectReasonShouldStopTimerFailedTest, TestSize.Level1)
{
    IsDisConnectReasonShouldStopTimerFailedTest();
}

HWTEST_F(StaStateMachineTest, DealConnectTimeOutCmd, TestSize.Level1)
{
    DealConnectTimeOutCmd();
}

HWTEST_F(StaStateMachineTest, RootStateGoInStateSuccess, TestSize.Level1)
{
    RootStateGoInStateSuccess();
}

HWTEST_F(StaStateMachineTest, RootStateGoOutStateSuccess, TestSize.Level1)
{
    RootStateGoOutStateSuccess();
}

HWTEST_F(StaStateMachineTest, RootStateExeMsgSuccess, TestSize.Level1)
{
    RootStateExeMsgSuccess();
}

HWTEST_F(StaStateMachineTest, RootStateExeMsgFail, TestSize.Level1)
{
    RootStateExeMsgFail();
}

HWTEST_F(StaStateMachineTest, InitStateGoInStateSuccess, TestSize.Level1)
{
    InitStateGoInStateSuccess();
}

HWTEST_F(StaStateMachineTest, InitStateGoOutStateSuccess, TestSize.Level1)
{
    InitStateGoOutStateSuccess();
}

HWTEST_F(StaStateMachineTest, InitStateExeMsgSuccess, TestSize.Level1)
{
    InitStateExeMsgSuccess();
}

HWTEST_F(StaStateMachineTest, InitStateExeMsgFail1, TestSize.Level1)
{
    InitStateExeMsgFail1();
}

HWTEST_F(StaStateMachineTest, InitStateExeMsgFail2, TestSize.Level1)
{
    InitStateExeMsgFail2();
}

HWTEST_F(StaStateMachineTest, ConvertDeviceCfgSuccess, TestSize.Level1)
{
    ConvertDeviceCfgSuccess();
}

HWTEST_F(StaStateMachineTest, ConvertDeviceCfgFail1, TestSize.Level1)
{
    ConvertDeviceCfgFail1();
}

HWTEST_F(StaStateMachineTest, ConvertDeviceCfgFail2, TestSize.Level1)
{
    ConvertDeviceCfgFail2();
}

HWTEST_F(StaStateMachineTest, StartWifiProcessSuccess, TestSize.Level1)
{
    StartWifiProcessSuccess();
}

HWTEST_F(StaStateMachineTest, StartWifiProcessFail2, TestSize.Level1)
{
    StartWifiProcessFail2();
}

HWTEST_F(StaStateMachineTest, StartWifiProcessFail1, TestSize.Level1)
{
    StartWifiProcessFail1();
}

HWTEST_F(StaStateMachineTest, WpaStartingStateExeMsgSuccess, TestSize.Level1)
{
    WpaStartingStateExeMsgSuccess();
}

HWTEST_F(StaStateMachineTest, WpaStartingStateExeMsgFail1, TestSize.Level1)
{
    WpaStartingStateExeMsgFail1();
}

HWTEST_F(StaStateMachineTest, WpaStartingStateExeMsgFail2, TestSize.Level1)
{
    WpaStartingStateExeMsgFail2();
}

HWTEST_F(StaStateMachineTest, WpaStartedStateGoInStateSuccess1, TestSize.Level1)
{
    WpaStartedStateGoInStateSuccess1();
}

HWTEST_F(StaStateMachineTest, WpaStartedStateGoInStateSuccess2, TestSize.Level1)
{
    WpaStartedStateGoInStateSuccess2();
}

HWTEST_F(StaStateMachineTest, WpaStartedStateGoOutStateSuccess, TestSize.Level1)
{
    WpaStartedStateGoOutStateSuccess();
}

HWTEST_F(StaStateMachineTest, WpaStartedStateExeMsgSuccess, TestSize.Level1)
{
    WpaStartedStateExeMsgSuccess();
}

HWTEST_F(StaStateMachineTest, WpaStartedStateExeMsgFail1, TestSize.Level1)
{
    WpaStartedStateExeMsgFail1();
}

HWTEST_F(StaStateMachineTest, WpaStartedStateExeMsgFail2, TestSize.Level1)
{
    WpaStartedStateExeMsgFail2();
}

HWTEST_F(StaStateMachineTest, StopWifiProcessSuccess1, TestSize.Level1)
{
    StopWifiProcessSuccess1();
}

HWTEST_F(StaStateMachineTest, StopWifiProcessSuccess2, TestSize.Level1)
{
    StopWifiProcessSuccess2();
}

HWTEST_F(StaStateMachineTest, StopWifiProcessSuccess3, TestSize.Level1)
{
    StopWifiProcessSuccess3();
}

HWTEST_F(StaStateMachineTest, StopWifiProcessFail, TestSize.Level1)
{
    StopWifiProcessFail();
}

HWTEST_F(StaStateMachineTest, WpaStoppingStateGoInStateSuccess, TestSize.Level1)
{
    WpaStoppingStateGoInStateSuccess();
}

HWTEST_F(StaStateMachineTest, WpaStoppingStateGoOutStateSuccess, TestSize.Level1)
{
    WpaStoppingStateGoOutStateSuccess();
}

HWTEST_F(StaStateMachineTest, WpaStoppingStateExeMsgSuccess, TestSize.Level1)
{
    WpaStoppingStateExeMsgSuccess();
}

HWTEST_F(StaStateMachineTest, WpaStoppingStateExeMsgFail, TestSize.Level1)
{
    WpaStoppingStateExeMsgFail();
}

HWTEST_F(StaStateMachineTest, LinkedStateGoOutStateSuccess, TestSize.Level1)
{
    LinkedStateGoOutStateSuccess();
}

HWTEST_F(StaStateMachineTest, LinkedStateExeMsgFail, TestSize.Level1)
{
    LinkedStateExeMsgFail();
}

HWTEST_F(StaStateMachineTest, LinkedStateExeMsgSuccess, TestSize.Level1)
{
    LinkedStateExeMsgSuccess();
}

HWTEST_F(StaStateMachineTest, LinkedStateExeMsgFail4, TestSize.Level1)
{
    LinkedStateExeMsgFail4();
}

HWTEST_F(StaStateMachineTest, LinkedStateExeMsgFail3, TestSize.Level1)
{
    LinkedStateExeMsgFail3();
}

HWTEST_F(StaStateMachineTest, LinkedStateExeMsgFail2, TestSize.Level1)
{
    LinkedStateExeMsgFail2();
}

HWTEST_F(StaStateMachineTest, LinkedStateCheckIfRestoreWifiSuccess, TestSize.Level1)
{
    LinkedStateCheckIfRestoreWifiSuccess();
}

HWTEST_F(StaStateMachineTest, InitStaSMHandleMapSuccess, TestSize.Level1)
{
    InitStaSMHandleMapSuccess();
}

HWTEST_F(StaStateMachineTest, DealConnectToUserSelectedNetworkSuccess, TestSize.Level1)
{
    DealConnectToUserSelectedNetworkSuccess();
}

/**
 * @tc.name: DealConnectToUserSelectedNetworkFai2
 * @tc.desc: DealConnectToUserSelectedNetwork()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(StaStateMachineTest, DealConnectToUserSelectedNetworkFai2, TestSize.Level1)
{
    DealConnectToUserSelectedNetworkFai2();
}
/**
 * @tc.name: DealConnectToUserSelectedNetworkFail1
 * @tc.desc: DealConnectToUserSelectedNetwork()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(StaStateMachineTest, DealConnectToUserSelectedNetworkFail1, TestSize.Level1)
{
    DealConnectToUserSelectedNetworkFail1();
}

HWTEST_F(StaStateMachineTest, DealConnectTimeOutCmdSuccess, TestSize.Level1)
{
    DealConnectTimeOutCmdSuccess();
}

HWTEST_F(StaStateMachineTest, DealConnectTimeOutCmdFail, TestSize.Level1)
{
    DealConnectTimeOutCmdFail();
}

HWTEST_F(StaStateMachineTest, DealDisconnectEventSuccess1, TestSize.Level1)
{
    DealDisconnectEventSuccess1();
}

HWTEST_F(StaStateMachineTest, DealDisconnectEventSuccess2, TestSize.Level1)
{
    DealDisconnectEventSuccess2();
}

HWTEST_F(StaStateMachineTest, DealReassociateCmdSuccess, TestSize.Level1)
{
    DealReassociateCmdSuccess();
}

HWTEST_F(StaStateMachineTest, DealReassociateCmdFail1, TestSize.Level1)
{
    DealReassociateCmdFail1();
}

HWTEST_F(StaStateMachineTest, DealReassociateCmdFail2, TestSize.Level1)
{
    DealReassociateCmdFail2();
}

HWTEST_F(StaStateMachineTest, DealStartWpsCmdSuccess, TestSize.Level1)
{
    DealStartWpsCmdSuccess();
}
/**
 * @tc.name: DealStartWpsCmdFail1
 * @tc.desc: DealStartWpsCmd()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(StaStateMachineTest, DealStartWpsCmdFail1, TestSize.Level1)
{
    DealStartWpsCmdFail1();
}

HWTEST_F(StaStateMachineTest, StartWpsModeSuccess1, TestSize.Level1)
{
    StartWpsModeSuccess1();
}

HWTEST_F(StaStateMachineTest, StartWpsModeSuccess2, TestSize.Level1)
{
    StartWpsModeSuccess2();
}

HWTEST_F(StaStateMachineTest, StartWpsModeSuccess3, TestSize.Level1)
{
    StartWpsModeSuccess3();
}

HWTEST_F(StaStateMachineTest, StartWpsModeSuccess4, TestSize.Level1)
{
    StartWpsModeSuccess4();
}

HWTEST_F(StaStateMachineTest, StartWpsModeFail1, TestSize.Level1)
{
    StartWpsModeFail1();
}

HWTEST_F(StaStateMachineTest, StartWpsModeFail2, TestSize.Level1)
{
    StartWpsModeFail2();
}

HWTEST_F(StaStateMachineTest, StartWpsModeFail3, TestSize.Level1)
{
    StartWpsModeFail3();
}

HWTEST_F(StaStateMachineTest, StartWpsModeFail4, TestSize.Level1)
{
    StartWpsModeFail4();
}

HWTEST_F(StaStateMachineTest, DealWpaBlockListClearEventSuccess, TestSize.Level1)
{
    DealWpaBlockListClearEventSuccess();
}

HWTEST_F(StaStateMachineTest, DealWpaBlockListClearEventFail, TestSize.Level1)
{
    DealWpaBlockListClearEventFail();
}

HWTEST_F(StaStateMachineTest, DealWpsConnectTimeOutEventSuccess, TestSize.Level1)
{
    DealWpsConnectTimeOutEventSuccess();
}

HWTEST_F(StaStateMachineTest, DealWpsConnectTimeOutEventFail, TestSize.Level1)
{
    DealWpsConnectTimeOutEventFail();
}

HWTEST_F(StaStateMachineTest, DealCancelWpsCmdSuccess1, TestSize.Level1)
{
    DealCancelWpsCmdSuccess1();
}

HWTEST_F(StaStateMachineTest, DealCancelWpsCmdSuccess2, TestSize.Level1)
{
    DealCancelWpsCmdSuccess2();
}

HWTEST_F(StaStateMachineTest, DealCancelWpsCmdSuccess3, TestSize.Level1)
{
    DealCancelWpsCmdSuccess3();
}

HWTEST_F(StaStateMachineTest, DealCancelWpsCmdFail1, TestSize.Level1)
{
    DealCancelWpsCmdFail1();
}

HWTEST_F(StaStateMachineTest, DealCancelWpsCmdFail2, TestSize.Level1)
{
    DealCancelWpsCmdFail2();
}

HWTEST_F(StaStateMachineTest, DealCancelWpsCmdFail3, TestSize.Level1)
{
    DealCancelWpsCmdFail3();
}

HWTEST_F(StaStateMachineTest, DealStartRoamCmdSuccess, TestSize.Level1)
{
    DealStartRoamCmdSuccess();
}

HWTEST_F(StaStateMachineTest, DealStartRoamCmdFail1, TestSize.Level1)
{
    DealStartRoamCmdFail1();
}

HWTEST_F(StaStateMachineTest, DealStartRoamCmdFail2, TestSize.Level1)
{
    DealStartRoamCmdFail2();
}

HWTEST_F(StaStateMachineTest, DealStartRoamCmdFail3, TestSize.Level1)
{
    DealStartRoamCmdFail3();
}

HWTEST_F(StaStateMachineTest, StartConnectToNetworkSuccess, TestSize.Level1)
{
    StartConnectToNetworkSuccess();
}

HWTEST_F(StaStateMachineTest, StartConnectToNetworkFail1, TestSize.Level1)
{
    StartConnectToNetworkFail1();
}

HWTEST_F(StaStateMachineTest, StartConnectToNetworkFali3, TestSize.Level1)
{
    StartConnectToNetworkFali3();
}
/**
 * @tc.name: StartConnectToNetworkFali4
 * @tc.desc: StartConnectToNetwork()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(StaStateMachineTest, StartConnectToNetworkFail4, TestSize.Level1)
{
    StartConnectToNetworkFail4();
}

HWTEST_F(StaStateMachineTest, SetRandomMacSuccess1, TestSize.Level1)
{
    SetRandomMacSuccess1();
}

HWTEST_F(StaStateMachineTest, SetRandomMacFail1, TestSize.Level1)
{
    SetRandomMacFail1();
}

HWTEST_F(StaStateMachineTest, SetRandomMacFail2, TestSize.Level1)
{
    SetRandomMacFail2();
}

HWTEST_F(StaStateMachineTest, StartRoamToNetworkSuccess, TestSize.Level1)
{
    StartRoamToNetworkSuccess();
}

HWTEST_F(StaStateMachineTest, OnNetworkConnectionEventSuccess, TestSize.Level1)
{
    OnNetworkConnectionEventSuccess();
}

HWTEST_F(StaStateMachineTest, SeparatingStateGoInStateSuccess, TestSize.Level1)
{
    SeparatingStateGoInStateSuccess();
}

HWTEST_F(StaStateMachineTest, SeparatingStateGoOutStateSuccess, TestSize.Level1)
{
    SeparatingStateGoOutStateSuccess();
}

HWTEST_F(StaStateMachineTest, SeparatingStateExeMsgSuccess, TestSize.Level1)
{
    SeparatingStateExeMsgSuccess();
}

HWTEST_F(StaStateMachineTest, SeparatingStateExeMsgFail, TestSize.Level1)
{
    SeparatingStateExeMsgFail();
}

HWTEST_F(StaStateMachineTest, SeparatedStateGoInStateSuccess, TestSize.Level1)
{
    SeparatedStateGoInStateSuccess();
}

HWTEST_F(StaStateMachineTest, SeparatedStateGoOutStateSuccess, TestSize.Level1)
{
    SeparatedStateGoOutStateSuccess();
}

HWTEST_F(StaStateMachineTest, SeparatedStateExeMsgSuccess1, TestSize.Level1)
{
    SeparatedStateExeMsgSuccess1();
}

HWTEST_F(StaStateMachineTest, SeparatedStateExeMsgSuccess2, TestSize.Level1)
{
    SeparatedStateExeMsgSuccess2();
}

HWTEST_F(StaStateMachineTest, SeparatedStateExeMsgFail, TestSize.Level1)
{
    SeparatedStateExeMsgFail();
}

HWTEST_F(StaStateMachineTest, ApLinkedStateGoInStateSuccess, TestSize.Level1)
{
    ApLinkedStateGoInStateSuccess();
}

HWTEST_F(StaStateMachineTest, ApLinkedStateGoOutStateSuccess, TestSize.Level1)
{
    ApLinkedStateGoOutStateSuccess();
}

HWTEST_F(StaStateMachineTest, ApLinkedStateExeMsgSuccess1, TestSize.Level1)
{
    ApLinkedStateExeMsgSuccess1();
}

HWTEST_F(StaStateMachineTest, ApLinkedStateExeMsgSuccess2, TestSize.Level1)
{
    ApLinkedStateExeMsgSuccess2();
}

HWTEST_F(StaStateMachineTest, ApLinkedStateExeMsgFail1, TestSize.Level1)
{
    ApLinkedStateExeMsgFail1();
}

HWTEST_F(StaStateMachineTest, ApLinkedStateExeMsgFai2, TestSize.Level1)
{
    ApLinkedStateExeMsgFai2();
}

HWTEST_F(StaStateMachineTest, DisConnectProcessSuccess, TestSize.Level1)
{
    DisConnectProcessSuccess();
}

HWTEST_F(StaStateMachineTest, DisConnectProcessFail, TestSize.Level1)
{
    DisConnectProcessFail();
}

HWTEST_F(StaStateMachineTest, WpsStateGoInStateSuccess, TestSize.Level1)
{
    WpsStateGoInStateSuccess();
}

HWTEST_F(StaStateMachineTest, WpsStateGoOutStateSuccess, TestSize.Level1)
{
    WpsStateGoOutStateSuccess();
}

HWTEST_F(StaStateMachineTest, WpsStateExeMsgSuccess1, TestSize.Level1)
{
    WpsStateExeMsgSuccess1();
}

HWTEST_F(StaStateMachineTest, WpsStateExeMsgSuccess2, TestSize.Level1)
{
    WpsStateExeMsgSuccess2();
}

HWTEST_F(StaStateMachineTest, WpsStateExeMsgSuccess3, TestSize.Level1)
{
    WpsStateExeMsgSuccess3();
}

HWTEST_F(StaStateMachineTest, WpsStateExeMsgSuccess4, TestSize.Level1)
{
    WpsStateExeMsgSuccess4();
}

HWTEST_F(StaStateMachineTest, WpsStateExeMsgSuccess5, TestSize.Level1)
{
    WpsStateExeMsgSuccess5();
}

HWTEST_F(StaStateMachineTest, WpsStateExeMsgFail1, TestSize.Level1)
{
    WpsStateExeMsgFail1();
}

HWTEST_F(StaStateMachineTest, WpsStateExeMsgFail2, TestSize.Level1)
{
    WpsStateExeMsgFail2();
}

HWTEST_F(StaStateMachineTest, GetIpStateStateGoInStateSuccess1, TestSize.Level1)
{
    GetIpStateStateGoInStateSuccess1();
}

HWTEST_F(StaStateMachineTest, GetIpStateStateGoInStateSuccess2, TestSize.Level1)
{
    GetIpStateStateGoInStateSuccess2();
}

HWTEST_F(StaStateMachineTest, GetIpStateStateGoInStateSuccess3, TestSize.Level1)
{
    GetIpStateStateGoInStateSuccess3();
}

HWTEST_F(StaStateMachineTest, GetIpStateStateGoOutStateSuccess, TestSize.Level1)
{
    GetIpStateStateGoOutStateSuccess();
}

HWTEST_F(StaStateMachineTest, GetIpStateStateExeMsgSuccess, TestSize.Level1)
{
    GetIpStateStateExeMsgSuccess();
}

HWTEST_F(StaStateMachineTest, GetIpStateStateExeMsgFail, TestSize.Level1)
{
    GetIpStateStateExeMsgFail();
}

HWTEST_F(StaStateMachineTest, GetIpStateStateIsPublicESSTest, TestSize.Level1)
{
    GetIpStateStateIsPublicESSTest();
}

HWTEST_F(StaStateMachineTest, ConfigStaticIpAddressSuccess1, TestSize.Level1)
{
    ConfigStaticIpAddressSuccess1();
}

HWTEST_F(StaStateMachineTest, ConfigStaticIpAddressSuccess2, TestSize.Level1)
{
    ConfigStaticIpAddressSuccess2();
}

HWTEST_F(StaStateMachineTest, ConfigStaticIpAddressSuccess3, TestSize.Level1)
{
    ConfigStaticIpAddressSuccess3();
}

HWTEST_F(StaStateMachineTest, ConfigStaticIpAddressFail, TestSize.Level1)
{
    ConfigStaticIpAddressFail();
}

HWTEST_F(StaStateMachineTest, HandleNetCheckResultSuccess1, TestSize.Level1)
{
    HandleNetCheckResultSuccess1();
}

HWTEST_F(StaStateMachineTest, HandleNetCheckResultSuccess3, TestSize.Level1)
{
    HandleNetCheckResultSuccess3();
}

HWTEST_F(StaStateMachineTest, HandleNetCheckResultSuccess4, TestSize.Level1)
{
    HandleNetCheckResultSuccess4();
}

HWTEST_F(StaStateMachineTest, HandleNetCheckResultFail, TestSize.Level1)
{
    HandleNetCheckResultFail();
}

HWTEST_F(StaStateMachineTest, TestUpdatePortalState1, TestSize.Level1)
{
    std::map<PortalState, PortalState> map = {
        {PortalState::UNCHECKED,   PortalState::NOT_PORTAL},
        {PortalState::NOT_PORTAL, PortalState::NOT_PORTAL},
        {PortalState::UNAUTHED,   PortalState::AUTHED},
        {PortalState::AUTHED,     PortalState::AUTHED},
        {PortalState::EXPERIED,   PortalState::AUTHED},
    };
    TestUpdatePortalState(map, SystemNetWorkState::NETWORK_IS_WORKING);
}

HWTEST_F(StaStateMachineTest, TestUpdatePortalState2, TestSize.Level1)
{
    std::map<PortalState, PortalState> map = {
        {PortalState::UNCHECKED,   PortalState::UNAUTHED},
        {PortalState::NOT_PORTAL, PortalState::EXPERIED},
        {PortalState::UNAUTHED,   PortalState::UNAUTHED},
        {PortalState::AUTHED,     PortalState::EXPERIED},
        {PortalState::EXPERIED,   PortalState::EXPERIED},
    };
    TestUpdatePortalState(map, SystemNetWorkState::NETWORK_IS_PORTAL);
}

HWTEST_F(StaStateMachineTest, ApRoamingStateGoInStateSuccess, TestSize.Level1)
{
    ApRoamingStateGoInStateSuccess();
}

HWTEST_F(StaStateMachineTest, ApRoamingStateGoOutStateSuccess, TestSize.Level1)
{
    ApRoamingStateGoOutStateSuccess();
}

HWTEST_F(StaStateMachineTest, ApRoamingStateExeMsgSuccess, TestSize.Level1)
{
    ApRoamingStateExeMsgSuccess();
}

HWTEST_F(StaStateMachineTest, ApRoamingStateExeMsgFail, TestSize.Level1)
{
    ApRoamingStateExeMsgFail();
}

/**
 * @tc.name: ConnectToNetworkProcessSuccess3
 * @tc.desc: ConnectToNetworkProcess()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(StaStateMachineTest, ConnectToNetworkProcessSuccess3, TestSize.Level1)
{
    ConnectToNetworkProcessSuccess3();
}

HWTEST_F(StaStateMachineTest, GetDeviceCfgInfoSuccessTest, TestSize.Level1)
{
    GetDeviceCfgInfoSuccessTest();
}

HWTEST_F(StaStateMachineTest, SetWifiLinkedInfoSuccess1, TestSize.Level1)
{
    SetWifiLinkedInfoSuccess1();
}

HWTEST_F(StaStateMachineTest, SetWifiLinkedInfoSuccess2, TestSize.Level1)
{
    SetWifiLinkedInfoSuccess2();
}

HWTEST_F(StaStateMachineTest, DhcpResultNotifyOnSuccessTest, TestSize.Level1)
{
    DhcpResultNotifyOnSuccessTest();
}

HWTEST_F(StaStateMachineTest, DhcpResultNotifyOnFailedTest1, TestSize.Level1)
{
    DhcpResultNotifyOnFailedTest1();
}

HWTEST_F(StaStateMachineTest, DhcpResultNotifyOnFailedTest2, TestSize.Level1)
{
    DhcpResultNotifyOnFailedTest2();
}

HWTEST_F(StaStateMachineTest, DhcpResultNotifyOnFailedTest3, TestSize.Level1)
{
    DhcpResultNotifyOnFailedTest3();
}

HWTEST_F(StaStateMachineTest, SaveLinkstateSuccess, TestSize.Level1)
{
    SaveLinkstateSuccess();
}

HWTEST_F(StaStateMachineTest, ConvertFreqToChannelTest, TestSize.Level1)
{
    ConvertFreqToChannelTest();
}

HWTEST_F(StaStateMachineTest, LinkStateGoInStateSuccess, TestSize.Level1)
{
    LinkStateGoInStateSuccess();
}

HWTEST_F(StaStateMachineTest, LinkStateGoOutStateSuccess, TestSize.Level1)
{
    LinkStateGoOutStateSuccess();
}

HWTEST_F(StaStateMachineTest, LinkStateExeMsgSuccess, TestSize.Level1)
{
    LinkStateExeMsgSuccess();
}

HWTEST_F(StaStateMachineTest, LinkStateExeMsgFail, TestSize.Level1)
{
    LinkStateExeMsgFail();
}

HWTEST_F(StaStateMachineTest, OnNetManagerRestartSuccess, TestSize.Level1)
{
    OnNetManagerRestartSuccess();
}

HWTEST_F(StaStateMachineTest, OnNetManagerRestartFail, TestSize.Level1)
{
    OnNetManagerRestartFail();
}

HWTEST_F(StaStateMachineTest, OnBssidChangedEventSuccess, TestSize.Level1)
{
    OnBssidChangedEventSuccess();
}

HWTEST_F(StaStateMachineTest, OnBssidChangedEventLinkSwitch, TestSize.Level1)
{
    OnBssidChangedEventLinkSwitch();
}

HWTEST_F(StaStateMachineTest, OnNetworkDisconnectEventSuccess, TestSize.Level1)
{
    OnNetworkDisconnectEventSuccess();
}

HWTEST_F(StaStateMachineTest, DealReConnectCmdFail, TestSize.Level1)
{
    DealReConnectCmdFail();
}

HWTEST_F(StaStateMachineTest, DealReConnectCmdSuccess, TestSize.Level1)
{
    DealReConnectCmdSuccess();
}

HWTEST_F(StaStateMachineTest, DealConnectionEventFail, TestSize.Level1)
{
    DealConnectionEventFail();
}

HWTEST_F(StaStateMachineTest, DealConnectionEventSuccess, TestSize.Level1)
{
    DealConnectionEventSuccess();
}

HWTEST_F(StaStateMachineTest, OnConnectFailedTest, TestSize.Level1)
{
    OnConnectFailed();
}

HWTEST_F(StaStateMachineTest, ReUpdateNetLinkInfoTest, TestSize.Level1)
{
    ReUpdateNetLinkInfoTest();
}
/**
 * @tc.name: ReUpdateNetLinkInfoTest1
 * @tc.desc: ReUpdateNetLinkInfo()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(StaStateMachineTest, ReUpdateNetLinkInfoTest1, TestSize.Level1)
{
    ReUpdateNetLinkInfoTest1();
}

HWTEST_F(StaStateMachineTest, UpdateLinkInfoRssiTest, TestSize.Level1)
{
    UpdateLinkInfoRssiTest();
}

HWTEST_F(StaStateMachineTest, UpdateLinkRssiTest, TestSize.Level1)
{
    UpdateLinkRssiTest();
}

/**
 * @tc.name: DealSignalPollResultTest
 * @tc.desc: DealSignalPollResult()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(StaStateMachineTest, DealSignalPollResultTest, TestSize.Level1)
{
    DealSignalPollResultTest();
}
/**
 * @tc.name: DealSignalPacketChangedTest
 * @tc.desc: DealSignalPacketChanged()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(StaStateMachineTest, DealSignalPacketChangedTest, TestSize.Level1)
{
    DealSignalPacketChangedTest();
}

HWTEST_F(StaStateMachineTest, GetWpa3FailCountSuccessTest, TestSize.Level1)
{
    GetWpa3FailCountSuccessTest();
}

HWTEST_F(StaStateMachineTest, GetWpa3FailCountFailTest, TestSize.Level1)
{
    GetWpa3FailCountFailTest();
}

HWTEST_F(StaStateMachineTest, AddWpa3FailCountSuccessTest, TestSize.Level1)
{
    AddWpa3FailCountSuccessTest();
}

HWTEST_F(StaStateMachineTest, AddWpa3FailCountFailTest, TestSize.Level1)
{
    AddWpa3FailCountFailTest();
}

HWTEST_F(StaStateMachineTest, AddWpa3BlackMapTest, TestSize.Level1)
{
    AddWpa3BlackMapTest();
}

HWTEST_F(StaStateMachineTest, IsInWpa3BlackMapTest, TestSize.Level1)
{
    IsInWpa3BlackMapTest();
}

HWTEST_F(StaStateMachineTest, OnWifiWpa3SelfCureSuccessTest, TestSize.Level1)
{
    OnWifiWpa3SelfCureSuccessTest();
}

HWTEST_F(StaStateMachineTest, OnWifiWpa3SelfCureFailTest, TestSize.Level1)
{
    OnWifiWpa3SelfCureFailTest();
}

HWTEST_F(StaStateMachineTest, IsWpa3TransitionTest, TestSize.Level1)
{
    IsWpa3TransitionTest();
}

HWTEST_F(StaStateMachineTest, InvokeOnStaConnChangedTest, TestSize.Level1)
{
    WifiLinkedInfo linkedInfo;
    InvokeOnStaConnChanged(OperateResState::OPEN_WIFI_SUCCEED, linkedInfo);
}

HWTEST_F(StaStateMachineTest, InvokeOnWpsChangedTest, TestSize.Level1)
{
    InvokeOnWpsChanged(WpsStartState::START_PBC_SUCCEED, 0);
}

HWTEST_F(StaStateMachineTest, InvokeOnStaStreamChangedTest, TestSize.Level1)
{
    InvokeOnStaStreamChanged(StreamDirection::STREAM_DIRECTION_UP);
}

HWTEST_F(StaStateMachineTest, InvokeOnStaRssiLevelChangedTest, TestSize.Level1)
{
    int rssi = -61;
    InvokeOnStaRssiLevelChanged(rssi);
}

/**
 * @tc.name: DealScreenStateChangedEventTest
 * @tc.desc: DealScreenStateChangedEvent()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(StaStateMachineTest, DealScreenStateChangedEventTest, TestSize.Level1)
{
    DealScreenStateChangedEventTest();
}

HWTEST_F(StaStateMachineTest, DealNetworkRemovedFailTest, TestSize.Level1)
{
    DealNetworkRemovedFailTest();
}

HWTEST_F(StaStateMachineTest, DealNetworkRemovedSuccessTest, TestSize.Level1)
{
    DealNetworkRemovedSuccessTest();
}

HWTEST_F(StaStateMachineTest, DealHiLinkDataToWpaFailTest, TestSize.Level1)
{
    DealHiLinkDataToWpaFailTest();
}

HWTEST_F(StaStateMachineTest, DealHiLinkDataToWpaSuccessTest1, TestSize.Level1)
{
    DealHiLinkDataToWpaSuccessTest1();
}

HWTEST_F(StaStateMachineTest, DealHiLinkDataToWpaSuccessTest2, TestSize.Level1)
{
    DealHiLinkDataToWpaSuccessTest2();
}

HWTEST_F(StaStateMachineTest, DealHiLinkDataToWpaSuccessTest3, TestSize.Level1)
{
    DealHiLinkDataToWpaSuccessTest3();
}

HWTEST_F(StaStateMachineTest, DealFillWapiCfgTest, TestSize.Level1)
{
    WifiDeviceConfig config;
    WifiHalDeviceConfig halDeviceConfig;
    config.keyMgmt = KEY_MGMT_WAPI_CERT;
    pStaStateMachine->FillWapiCfg(config, halDeviceConfig);
    EXPECT_NE(halDeviceConfig.wepKeyIdx, TEN);
}

HWTEST_F(StaStateMachineTest, InitRandomMacInfoTest, TestSize.Level1)
{
    InitRandomMacInfoTest();
}
 
HWTEST_F(StaStateMachineTest, OnNetworkHiviewEventTest, TestSize.Level1)
{
    OnNetworkHiviewEventTest();
}

HWTEST_F(StaStateMachineTest, OnNetworkAssocEventTest, TestSize.Level1)
{
    OnNetworkAssocEventTest();
}

HWTEST_F(StaStateMachineTest, GetDataSlotIdTest, TestSize.Level1)
{
    GetDataSlotIdTest();
}

HWTEST_F(StaStateMachineTest, GetCardTypeTest, TestSize.Level1)
{
    GetCardTypeTest();
}

HWTEST_F(StaStateMachineTest, GetDefaultIdTest, TestSize.Level1)
{
    GetDefaultIdTest();
}

HWTEST_F(StaStateMachineTest, GetSimCardStateTest, TestSize.Level1)
{
    GetSimCardStateTest();
}

HWTEST_F(StaStateMachineTest, IsValidSimIdTest, TestSize.Level1)
{
    IsValidSimIdTest();
}

HWTEST_F(StaStateMachineTest, IsMultiSimEnabledTest, TestSize.Level1)
{
    IsMultiSimEnabledTest();
}

HWTEST_F(StaStateMachineTest, SimAkaAuthTest, TestSize.Level1)
{
    SimAkaAuthTest();
}

HWTEST_F(StaStateMachineTest, GetGsmAuthResponseWithLengthTest, TestSize.Level1)
{
    GetGsmAuthResponseWithLengthTest();
}

HWTEST_F(StaStateMachineTest, GetGsmAuthResponseWithoutLengthTest, TestSize.Level1)
{
    GetGsmAuthResponseWithoutLengthTest();
}

HWTEST_F(StaStateMachineTest, PreWpaEapUmtsAuthEventTest, TestSize.Level1)
{
    PreWpaEapUmtsAuthEventTest();
}

HWTEST_F(StaStateMachineTest, FillUmtsAuthReqTest, TestSize.Level1)
{
    FillUmtsAuthReqTest();
}

HWTEST_F(StaStateMachineTest, ParseAndFillUmtsAuthParamTest, TestSize.Level1)
{
    ParseAndFillUmtsAuthParamTest();
}

HWTEST_F(StaStateMachineTest, GetUmtsAuthResponseTest, TestSize.Level1)
{
    GetUmtsAuthResponseTest();
}

HWTEST_F(StaStateMachineTest, DealWpaEapSimAuthEventTest, TestSize.Level1)
{
    DealWpaEapSimAuthEventTest();
}

HWTEST_F(StaStateMachineTest, HandlePortalNetworkPorcessTests, TestSize.Level1)
{
    HandlePortalNetworkPorcessTests();
}

HWTEST_F(StaStateMachineTest, DealWpaEapUmtsAuthEventTest, TestSize.Level1)
{
    DealWpaEapUmtsAuthEventTest();
}

HWTEST_F(StaStateMachineTest, HilinkSaveConfigTest, TestSize.Level1)
{
    HilinkSaveConfigTest();
}

HWTEST_F(StaStateMachineTest, SyncDeviceEverConnectedStateTest, TestSize.Level1)
{
    bool hasNet = false;
    SyncDeviceEverConnectedStateTest(hasNet);
}

HWTEST_F(StaStateMachineTest, ReplaceEmptyDnsTest, TestSize.Level1)
{
    ReplaceEmptyDnsTest();
}

HWTEST_F(StaStateMachineTest, IsRoamingTest, TestSize.Level1)
{
    IsRoamingTest();
}
 
HWTEST_F(StaStateMachineTest, ApLinkedStateExeMsgSuccess3, TestSize.Level1)
{
    ApLinkedStateExeMsgSuccess3();
}
 
HWTEST_F(StaStateMachineTest, ApLinkedStateExeMsgSuccess4, TestSize.Level1)
{
    ApLinkedStateExeMsgSuccess4();
}

HWTEST_F(StaStateMachineTest, ApLinkedStateExeMsgLinkSwitch, TestSize.Level1)
{
    ApLinkedStateExeMsgLinkSwitch();
}
 
HWTEST_F(StaStateMachineTest, DealHiLinkDataToWpaSuccessTest4, TestSize.Level1)
{
    DealHiLinkDataToWpaSuccessTest4();
}
 
HWTEST_F(StaStateMachineTest, DealHiLinkDataToWpaSuccessTest5, TestSize.Level1)
{
    DealHiLinkDataToWpaSuccessTest5();
}

HWTEST_F(StaStateMachineTest, SetSupportedWifiCategoryTestBssidIsEmpty, TestSize.Level1)
{
    SetSupportedWifiCategoryTestBssidIsEmpty();
}

HWTEST_F(StaStateMachineTest, SetSupportedWifiCategoryTestWifi6, TestSize.Level1)
{
    SetSupportedWifiCategoryTestWifi6();
}

HWTEST_F(StaStateMachineTest, SetSupportedWifiCategoryTestWifi7NotMlo, TestSize.Level1)
{
    SetSupportedWifiCategoryTestWifi7NotMlo();
}

HWTEST_F(StaStateMachineTest, SetSupportedWifiCategoryTestWifi7IsMlo, TestSize.Level1)
{
    SetSupportedWifiCategoryTestWifi7IsMlo();
}
} // namespace Wifi
} // namespace OHOS
