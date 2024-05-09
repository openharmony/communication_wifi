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
#include "mock_wifi_settings.h"
#include "mock_wifi_sta_interface.h"
#include "sta_define.h"
#include "define.h"
#include "sta_state_machine.h"
#include "wifi_internal_msg.h"
#include "wifi_msg.h"

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

class StaStateMachineTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetLinkedInfo(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetPortalUri(_)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveDisconnectedReason(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine.reset(new StaStateMachine());
        pStaStateMachine->InitStaStateMachine();
        pStaStateMachine->InitWifiLinkedInfo();
        pStaStateMachine->InitLastWifiLinkedInfo();
    }
    virtual void TearDown()
    {
        pStaStateMachine.reset();
    }
    void SleepMs(const int sleepMs)
    {
        std::unique_lock<std::mutex> lck(mMtxBlock);
        mCvTest.wait_for(lck, std::chrono::milliseconds(sleepMs));
    }
    std::unique_ptr<StaStateMachine> pStaStateMachine;

    std::mutex mMtxBlock;
    std::condition_variable mCvTest;

    void DealConnectTimeOutCmd()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).WillRepeatedly(Return(0));
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.disableNetwork = false;
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(1));
        InternalMessage msg;
        pStaStateMachine->DealConnectTimeOutCmd(&msg);
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
        InternalMessage msg;
        msg.SetMessageName(WIFI_SVR_CMD_UPDATE_COUNTRY_CODE);
        msg.AddStringMessageBody("CN");
        EXPECT_TRUE(pStaStateMachine->pRootState->ExecuteStateMsg(&msg));
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
        EXPECT_CALL(WifiSettings::GetInstance(), SetWifiState(_, _)).WillRepeatedly(Return(WIFI_IDL_OPT_OK));
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.startWifi = true;
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.wpaAutoConnect = true;
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.clearDevice = true;
        EXPECT_CALL(WifiManager::GetInstance(), DealStaOpenRes(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), ReloadDeviceConfig()).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SetMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SetRealMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetRealMacAddress(_, _)).Times(testing::AtLeast(0));
        InternalMessage msg;
        msg.SetMessageName(WIFI_SVR_CMD_STA_ENABLE_WIFI);
        EXPECT_TRUE(pStaStateMachine->pInitState->ExecuteStateMsg(&msg));
    }

    void InitStateExeMsgFail1()
    {
        InternalMessage msg;
        msg.SetMessageName(WIFI_SVR_CMD_STA_DISABLE_WIFI);
        EXPECT_FALSE(pStaStateMachine->pInitState->ExecuteStateMsg(&msg));
    }

    void InitStateExeMsgFail2()
    {
        EXPECT_FALSE(pStaStateMachine->pInitState->ExecuteStateMsg(nullptr));
    }

    void ConvertDeviceCfgSuccess()
    {
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.setDeviceConfig = true;
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.saveDeviceConfig = true;
        WifiDeviceConfig config;
        EXPECT_EQ(WIFI_OPT_SUCCESS, pStaStateMachine->ConvertDeviceCfg(config));
    }

    void ConvertDeviceCfgFail1()
    {
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.setDeviceConfig = false;
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.saveDeviceConfig = true;
        WifiDeviceConfig config;
        EXPECT_EQ(WIFI_OPT_FAILED, pStaStateMachine->ConvertDeviceCfg(config));
    }

    void ConvertDeviceCfgFail2()
    {
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.setDeviceConfig = false;
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.saveDeviceConfig = false;
        WifiDeviceConfig config;
        EXPECT_EQ(WIFI_OPT_FAILED, pStaStateMachine->ConvertDeviceCfg(config));
    }

    void StartWifiProcessSuccess()
    {
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.startWifi = true;
        EXPECT_CALL(WifiManager::GetInstance(), DealStaOpenRes(_, _)).Times(testing::AtLeast(1));
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.wpaAutoConnect = true;
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.clearDevice = true;
        EXPECT_CALL(WifiSettings::GetInstance(), SetMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), ReloadDeviceConfig()).WillRepeatedly(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).WillRepeatedly(Return(WIFI_IDL_OPT_OK));
        EXPECT_CALL(WifiSettings::GetInstance(), GetRealMacAddress(_, _)).Times(testing::AtLeast(0));
        WifiDeviceConfig wifiDeviceConfig;
        std::vector<WifiDeviceConfig> results;
        wifiDeviceConfig.networkId = 1;
        results.push_back(wifiDeviceConfig);
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.getNextNetworkId = false;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_))
            .WillRepeatedly(DoAll(SetArgReferee<0>(results), Return(0)));
        EXPECT_CALL(WifiSettings::GetInstance(), SetRealMacAddress(_, _)).Times(testing::AtLeast(0));
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.setDeviceConfig = true;
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.saveDeviceConfig = true;
        EXPECT_CALL(WifiSettings::GetInstance(), SetWifiState(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->StartWifiProcess();
    }

    void StartWifiProcessFail2()
    {
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.startWifi = true;
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.wpaAutoConnect = false;
        EXPECT_CALL(WifiManager::GetInstance(), DealStaOpenRes(_, _)).Times(testing::AtLeast(1));
        EXPECT_CALL(WifiSettings::GetInstance(), SetRealMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SetWifiState(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetRealMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SetMacAddress(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->StartWifiProcess();
    }

    void StartWifiProcessFail1()
    {
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.startWifi = false;
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).WillRepeatedly(Return(WIFI_IDL_OPT_OK));
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.wpaAutoConnect = true;
        EXPECT_CALL(WifiManager::GetInstance(), DealStaOpenRes(_, _)).Times(testing::AtLeast(0));
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.clearDevice = true;
        EXPECT_CALL(WifiSettings::GetInstance(), ReloadDeviceConfig()).WillRepeatedly(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SetMacAddress(_, _)).Times(testing::AtLeast(0));
        WifiDeviceConfig wifiDeviceConfig;
        std::vector<WifiDeviceConfig> results;
        wifiDeviceConfig.networkId = 1;
        results.push_back(wifiDeviceConfig);
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_))
            .WillRepeatedly(DoAll(SetArgReferee<0>(results), Return(0)));
        EXPECT_CALL(WifiSettings::GetInstance(), SetRealMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetRealMacAddress(_, _)).Times(testing::AtLeast(0));
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.setDeviceConfig = true;
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.saveDeviceConfig = true;
        EXPECT_CALL(WifiSettings::GetInstance(), SetWifiState(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->StartWifiProcess();
    }

    void WpaStartingStateExeMsgSuccess()
    {
        pStaStateMachine->pWpaStartingState->InitWpsSettings();
        pStaStateMachine->pWpaStartingState->GoInState();
        pStaStateMachine->pWpaStartingState->GoOutState();
        EXPECT_CALL(WifiSettings::GetInstance(), SetWifiState(_, _)).Times(testing::AtLeast(0));
        InternalMessage msg;
        msg.SetMessageName(WIFI_SVR_CMD_STA_SUP_CONNECTION_EVENT);
        EXPECT_TRUE(pStaStateMachine->pWpaStartingState->ExecuteStateMsg(&msg));
    }

    void WpaStartingStateExeMsgFail1()
    {
        InternalMessage msg;
        msg.SetMessageName(WIFI_SVR_CMD_STA_SUP_DISCONNECTION_EVENT);
        EXPECT_FALSE(pStaStateMachine->pWpaStartingState->ExecuteStateMsg(&msg));
    }

    void WpaStartingStateExeMsgFail2()
    {
        EXPECT_FALSE(pStaStateMachine->pWpaStartingState->ExecuteStateMsg(nullptr));
    }

    void WpaStartedStateGoInStateSuccess1()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), SetWifiState(_, _)).Times(testing::AtLeast(1));
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
        EXPECT_CALL(WifiSettings::GetInstance(), SetMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveIpInfo(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(IfConfig::GetInstance(), FlushIpAddr(_, _)).Times(AtLeast(0));
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.stopWifi = true;
        EXPECT_CALL(WifiSettings::GetInstance(), SaveIpV6Info(_, _)).Times(testing::AtLeast(0));
        InternalMessage msg;
        msg.SetMessageName(WIFI_SVR_CMD_STA_DISABLE_WIFI);
        EXPECT_TRUE(pStaStateMachine->pWpaStartedState->ExecuteStateMsg(&msg));
    }

    void WpaStartedStateExeMsgFail1()
    {
        InternalMessage msg;
        msg.SetMessageName(WIFI_SVR_CMD_STA_ENABLE_WIFI);
        EXPECT_FALSE(pStaStateMachine->pWpaStartedState->ExecuteStateMsg(&msg));
    }

    void WpaStartedStateExeMsgFail2()
    {
        EXPECT_FALSE(pStaStateMachine->pWpaStartedState->ExecuteStateMsg(nullptr));
    }

    void StopWifiProcessSuccess1()
    {
        pStaStateMachine->currentTpType = IPTYPE_IPV4;
        EXPECT_CALL(WifiManager::GetInstance(), DealStaCloseRes(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SetMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveIpInfo(_, _));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.stopWifi = true;
        EXPECT_CALL(WifiSettings::GetInstance(), SaveIpV6Info(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->StopWifiProcess();
    }

    void StopWifiProcessSuccess2()
    {
        pStaStateMachine->currentTpType = IPTYPE_IPV6;
        EXPECT_CALL(WifiManager::GetInstance(), DealStaCloseRes(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SetMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveIpInfo(_, _));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.stopWifi = true;
        EXPECT_CALL(WifiSettings::GetInstance(), SaveIpV6Info(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->StopWifiProcess();
    }

    void StopWifiProcessSuccess3()
    {
        pStaStateMachine->currentTpType = IPTYPE_IPV6;
        pStaStateMachine->linkedInfo.connState = ConnState::CONNECTED;
        EXPECT_CALL(WifiManager::GetInstance(), DealStaCloseRes(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SetMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveIpInfo(_, _));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.stopWifi = true;
        EXPECT_CALL(WifiSettings::GetInstance(), SaveIpV6Info(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->StopWifiProcess();
    }

    void StopWifiProcessFail()
    {
        pStaStateMachine->currentTpType = IPTYPE_IPV6;
        EXPECT_CALL(WifiManager::GetInstance(), DealStaCloseRes(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SetMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveIpInfo(_, _));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.stopWifi = false;
        EXPECT_CALL(WifiSettings::GetInstance(), SaveIpV6Info(_, _)).Times(testing::AtLeast(0));
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
        InternalMessage msg;
        pStaStateMachine->pWpaStoppingState->ExecuteStateMsg(&msg);
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
        EXPECT_CALL(WifiSettings::GetInstance(), EnableNetwork(_, _, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SetDeviceState(_, _, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SetDeviceAfterConnect(_)).Times(AtLeast(0));
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.enableNetwork = true;
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.connect = true;
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.saveDeviceConfig = true;
        EXPECT_CALL(WifiSettings::GetInstance(), GetScanInfoList(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SetWifiState(_, _)).Times(testing::AtLeast(0));
        InternalMessage msg;
        msg.SetParam1(-1);
        msg.SetParam2(0);
        pStaStateMachine->linkedInfo.networkId = -1;
        pStaStateMachine->linkedInfo.connState = ConnState::CONNECTED;
        pStaStateMachine->DealConnectToUserSelectedNetwork(&msg);
        pStaStateMachine->linkedInfo.connState = ConnState::SCANNING;
        pStaStateMachine->DealConnectToUserSelectedNetwork(&msg);
    }

    void DealConnectToUserSelectedNetworkFail1()
    {
        InternalMessage msg;
        msg.SetParam1(1);
        msg.SetParam2(0);
        pStaStateMachine->linkedInfo.networkId = 1;
        pStaStateMachine->linkedInfo.connState = ConnState::CONNECTING;
        pStaStateMachine->linkedInfo.detailedState = DetailedState::OBTAINING_IPADDR;
        EXPECT_CALL(WifiSettings::GetInstance(), EnableNetwork(_, _, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SetDeviceState(_, _, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->DealConnectToUserSelectedNetwork(&msg);
        pStaStateMachine->DealConnectToUserSelectedNetwork(nullptr);
    }

    void DealConnectToUserSelectedNetworkFail()
    {
        InternalMessage msg;
        msg.SetParam1(1);
        msg.SetParam2(1);
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _))
            .WillOnce(Return(1))
            .WillRepeatedly(Return(0));
        pStaStateMachine->linkedInfo.networkId = 0;
        pStaStateMachine->DealConnectToUserSelectedNetwork(&msg);
        pStaStateMachine->DealConnectToUserSelectedNetwork(&msg);
    }

    void DealConnectToUserSelectedNetworkFai2()
    {
        InternalMessage msg;
        msg.SetParam1(1);
        msg.SetParam2(0);
        pStaStateMachine->linkedInfo.networkId = 1;
        pStaStateMachine->linkedInfo.connState = ConnState::CONNECTING;
        pStaStateMachine->linkedInfo.detailedState = DetailedState::NOTWORKING;
        EXPECT_CALL(WifiSettings::GetInstance(), EnableNetwork(_, _, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SetDeviceState(_, _, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->DealConnectToUserSelectedNetwork(&msg);
    }

    void DealConnectTimeOutCmdSuccess()
    {
        InternalMessage msg;
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.disableNetwork = false;
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(0));
        pStaStateMachine->DealConnectTimeOutCmd(&msg);
    }

    void DealConnectTimeOutCmdFail()
    {
        InternalMessage msg;
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->linkedInfo.connState = ConnState::CONNECTED;
        pStaStateMachine->DealConnectTimeOutCmd(nullptr);
        pStaStateMachine->DealConnectTimeOutCmd(&msg);
    }

    void DealDisconnectEventSuccess1()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), SetMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveIpInfo(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(IfConfig::GetInstance(), FlushIpAddr(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveIpV6Info(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->wpsState = SetupMethod::INVALID;
        pStaStateMachine->currentTpType = IPTYPE_IPV4;
        pStaStateMachine->lastLinkedInfo.detailedState = DetailedState::CONNECTING;
        InternalMessage msg;
        std::string bssid = "wifitest";
        msg.SetMessageObj(bssid);
        pStaStateMachine->DealDisconnectEvent(&msg);
    }

    void DealDisconnectEventSuccess2()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), SetMacAddress(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveIpInfo(_, _));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _));
        EXPECT_CALL(IfConfig::GetInstance(), FlushIpAddr(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveIpV6Info(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->wpsState = SetupMethod::INVALID;
        pStaStateMachine->currentTpType = IPTYPE_IPV6;
        pStaStateMachine->lastLinkedInfo.detailedState = DetailedState::CONNECTED;
        InternalMessage msg;
        std::string bssid = "wifitest";
        msg.SetMessageObj(bssid);
        pStaStateMachine->DealDisconnectEvent(&msg);
        pStaStateMachine->wpsState = SetupMethod::LABEL;
        pStaStateMachine->DealDisconnectEvent(&msg);
    }

    void DealWpaWrongPskEventFail1()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(0));
        InternalMessage msg;
        msg.SetMessageName(WIFI_SVR_CMD_STA_WPA_PASSWD_WRONG_EVENT);
        pStaStateMachine->DealWpaLinkFailEvent(&msg);
        pStaStateMachine->DealWpaLinkFailEvent(nullptr);
    }

    void DealWpaWrongPskEventFail2()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(0));
        InternalMessage msg;
        msg.SetMessageName(WIFI_SVR_CMD_STA_WPA_FULL_CONNECT_EVENT);
        pStaStateMachine->DealWpaLinkFailEvent(&msg);
    }

    void DealWpaWrongPskEventSuccess()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(0));
        InternalMessage msg;
        msg.SetMessageName(WIFI_SVR_CMD_STA_WPA_ASSOC_REJECT_EVENT);
        pStaStateMachine->DealWpaLinkFailEvent(&msg);
    }

    void DealReassociateCmdSuccess()
    {
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.reassociate = true;
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(0));
        InternalMessage msg;
        pStaStateMachine->DealReassociateCmd(&msg);
    }

    void DealReassociateCmdFail1()
    {
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.reassociate = false;
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(0));
        pStaStateMachine->DealReassociateCmd(nullptr);
    }

    void DealReassociateCmdFail2()
    {
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.reassociate = false;
        pStaStateMachine->DealReassociateCmd(nullptr);
    }

    void DealStartWpsCmdSuccess()
    {
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _));
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.clearDevice = true;
        pStaStateMachine->wpsState = SetupMethod::INVALID;
        InternalMessage msg;
        pStaStateMachine->DealStartWpsCmd(nullptr);
        pStaStateMachine->DealStartWpsCmd(&msg);
    }

    void DealStartWpsCmdFail1()
    {
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.clearDevice = false;
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _)).Times(AtLeast(0));
        pStaStateMachine->wpsState = SetupMethod::KEYPAD;
        InternalMessage msg;
        msg.SetParam1(static_cast<int>(SetupMethod::INVALID));
        pStaStateMachine->DealStartWpsCmd(&msg);
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.clearDevice = true;
        pStaStateMachine->DealStartWpsCmd(&msg);
        pStaStateMachine->wpsState = SetupMethod::DISPLAY;
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.clearDevice = true;
        pStaStateMachine->DealStartWpsCmd(&msg);
    }

    void StartWpsModeSuccess1()
    {
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.startWpsPbcMode = true;
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _));
        InternalMessage msg;
        msg.SetParam1(static_cast<int>(SetupMethod::PBC));
        pStaStateMachine->StartWpsMode(&msg);
    }

    void StartWpsModeSuccess2()
    {
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.startWpsPinMode = true;
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _));
        InternalMessage msg;
        msg.SetParam1(static_cast<int>(SetupMethod::DISPLAY));
        msg.AddStringMessageBody("hmwifi1");
        msg.AddStringMessageBody("hmwifi2");
        pStaStateMachine->StartWpsMode(&msg);
    }

    void StartWpsModeSuccess3()
    {
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.startWpsPinMode = true;
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _));
        InternalMessage msg;
        msg.SetParam1(static_cast<int>(SetupMethod::KEYPAD));
        msg.AddStringMessageBody("hmwifi1");
        msg.AddStringMessageBody("hmwifi2");
        pStaStateMachine->StartWpsMode(&msg);
    }

    void StartWpsModeSuccess4()
    {
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _));
        InternalMessage msg;
        msg.SetParam1(static_cast<int>(SetupMethod::INVALID));
        msg.AddStringMessageBody("hmwifi1");
        msg.AddStringMessageBody("hmwifi2");
        pStaStateMachine->StartWpsMode(&msg);
    }

    void StartWpsModeFail1()
    {
        pStaStateMachine->StartWpsMode(nullptr);
    }

    void StartWpsModeFail2()
    {
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.startWpsPbcMode = false;
        InternalMessage msg;
        msg.SetParam1(static_cast<int>(SetupMethod::PBC));
        pStaStateMachine->StartWpsMode(nullptr);
    }

    void StartWpsModeFail3()
    {
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.startWpsPinMode = false;
        InternalMessage msg;
        msg.SetParam1(static_cast<int>(SetupMethod::DISPLAY));
        pStaStateMachine->StartWpsMode(nullptr);
    }

    void StartWpsModeFail4()
    {
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.startWpsPinMode = false;
        InternalMessage msg;
        msg.SetParam1(static_cast<int>(SetupMethod::KEYPAD));
        pStaStateMachine->StartWpsMode(nullptr);
    }

    void DealWpaBlockListClearEventSuccess()
    {
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.wpaBlocklist = true;
        InternalMessage msg;
        pStaStateMachine->DealWpaBlockListClearEvent(&msg);
    }

    void DealWpaBlockListClearEventFail()
    {
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.wpaBlocklist = false;
        InternalMessage msg;
        pStaStateMachine->DealWpaBlockListClearEvent(&msg);
    }

    void DealWpsConnectTimeOutEventSuccess()
    {
        pStaStateMachine->wpsState = SetupMethod::INVALID;
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.stopWps = false;
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _));
        InternalMessage msg;
        pStaStateMachine->DealWpsConnectTimeOutEvent(&msg);
    }

    void DealWpsConnectTimeOutEventFail()
    {
        pStaStateMachine->wpsState = SetupMethod::INVALID;
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.stopWps = false;
        pStaStateMachine->DealWpsConnectTimeOutEvent(nullptr);
    }

    void DealCancelWpsCmdSuccess1()
    {
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.stopWps = true;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_)).WillRepeatedly(Return(-1));
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.enableNetwork = true;
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.saveDeviceConfig = true;
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _));
        pStaStateMachine->wpsState = SetupMethod::PBC;
        InternalMessage msg;
        pStaStateMachine->DealCancelWpsCmd(&msg);
    }

    void DealCancelWpsCmdSuccess2()
    {
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.stopWps = true;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_)).WillRepeatedly(Return(-1));
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.enableNetwork = true;
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.saveDeviceConfig = false;
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _));
        pStaStateMachine->wpsState = SetupMethod::DISPLAY;
        InternalMessage msg;
        pStaStateMachine->DealCancelWpsCmd(&msg);
    }

    void DealCancelWpsCmdSuccess3()
    {
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.stopWps = true;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_)).WillRepeatedly(Return(-1));
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.enableNetwork = true;
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.saveDeviceConfig = false;
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _)).Times(AtLeast(0));
        pStaStateMachine->wpsState = SetupMethod::KEYPAD;
        InternalMessage msg;
        pStaStateMachine->DealCancelWpsCmd(&msg);
    }

    void DealCancelWpsCmdFail1()
    {
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.stopWps = false;
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _)).Times(AtLeast(0));
        pStaStateMachine->wpsState = SetupMethod::PBC;
        InternalMessage msg;
        pStaStateMachine->DealCancelWpsCmd(&msg);
    }

    void DealCancelWpsCmdFail2()
    {
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.stopWps = false;
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _)).Times(AtLeast(0));
        pStaStateMachine->wpsState = SetupMethod::DISPLAY;
        InternalMessage msg;
        pStaStateMachine->DealCancelWpsCmd(&msg);
    }

    void DealCancelWpsCmdFail3()
    {
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.stopWps = false;
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _)).Times(AtLeast(0));
        pStaStateMachine->wpsState = SetupMethod::KEYPAD;
        InternalMessage msg;
        pStaStateMachine->DealCancelWpsCmd(&msg);
        pStaStateMachine->DealCancelWpsCmd(nullptr);
    }

    void DealStartRoamCmdSuccess()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _));
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.setDeviceConfig = true;
        EXPECT_CALL(WifiSettings::GetInstance(), AddDeviceConfig(_)).WillRepeatedly(Return(WIFI_IDL_OPT_OK));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig()).WillRepeatedly(Return(WIFI_IDL_OPT_OK));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).WillRepeatedly(Return(WIFI_IDL_OPT_OK));
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.reassociate = true;
        InternalMessage msg;
        pStaStateMachine->DealStartRoamCmd(&msg);
    }

    void DealStartRoamCmdFail1()
    {
        pStaStateMachine->DealStartRoamCmd(nullptr);
    }

    void DealStartRoamCmdFail2()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _));
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.setDeviceConfig = false;
        EXPECT_CALL(WifiSettings::GetInstance(), AddDeviceConfig(_)).WillRepeatedly(Return(WIFI_IDL_OPT_OK));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig()).WillRepeatedly(Return(WIFI_IDL_OPT_OK));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).WillRepeatedly(Return(WIFI_IDL_OPT_OK));
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.reassociate = true;
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(0));
        InternalMessage msg;
        pStaStateMachine->DealStartRoamCmd(&msg);
    }

    void DealStartRoamCmdFail3()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _));
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.setDeviceConfig = true;
        EXPECT_CALL(WifiSettings::GetInstance(), AddDeviceConfig(_)).WillRepeatedly(Return(WIFI_IDL_OPT_OK));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig()).WillRepeatedly(Return(WIFI_IDL_OPT_OK));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).WillRepeatedly(Return(WIFI_IDL_OPT_OK));
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.reassociate = false;
        InternalMessage msg;
        pStaStateMachine->DealStartRoamCmd(&msg);
    }

    void StartConnectToNetworkSuccess()
    {
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.enableNetwork = true;
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.connect = true;
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.saveDeviceConfig = true;
        EXPECT_CALL(WifiSettings::GetInstance(), GetScanInfoList(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SetWifiState(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->StartConnectToNetwork(0, "wifitest/123");
    }

    void StartConnectToNetworkFail1()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).WillRepeatedly(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetScanInfoList(_)).Times(AtLeast(0));
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.enableNetwork = false;
        EXPECT_CALL(WifiSettings::GetInstance(), SetWifiState(_, _)).Times(testing::AtLeast(0));
        EXPECT_TRUE(pStaStateMachine->StartConnectToNetwork(0, "wifitest/123") == WIFI_OPT_FAILED);
    }

    void StartConnectToNetworkFail4()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).WillRepeatedly(Return(1));
        EXPECT_CALL(WifiSettings::GetInstance(), GetScanInfoList(_)).Times(AtLeast(0));
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.enableNetwork = false;
        EXPECT_CALL(WifiSettings::GetInstance(), SetWifiState(_, _)).Times(testing::AtLeast(0));
        EXPECT_TRUE(pStaStateMachine->StartConnectToNetwork(0, "wifitest/123") == WIFI_OPT_FAILED);
    }

    void StartConnectToNetworkFail2()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetScanInfoList(_)).Times(AtLeast(0));
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.enableNetwork = true;
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.connect = false;
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SetWifiState(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->StartConnectToNetwork(0, "wifitest/123");
    }

    void StartConnectToNetworkFali3()
    {
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.enableNetwork = true;
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.enableNetwork = true;
        EXPECT_CALL(WifiSettings::GetInstance(), GetScanInfoList(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0));
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.connect = true;
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.saveDeviceConfig = false;
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SetWifiState(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->StartConnectToNetwork(0, "wifitest/123");
    }

    void SetRandomMacSuccess1()
    {
        WifiDeviceConfig deviceConfig;
        deviceConfig.wifiPrivacySetting = WifiPrivacyConfig::RANDOMMAC;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<1>(deviceConfig), Return(0)));
        EXPECT_CALL(WifiSettings::GetInstance(), GetScanInfoList(_)).Times(AtLeast(0));
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.getDeviceAddress = true;
        EXPECT_CALL(WifiSettings::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.setConnectMac = true;
        pStaStateMachine->SetRandomMac(0, "");
    }

    void SetRandomMacFail1()
    {
        WifiDeviceConfig deviceConfig;
        deviceConfig.wifiPrivacySetting = WifiPrivacyConfig::RANDOMMAC;
        WifiStoreRandomMac randomMacInfo;
        randomMacInfo.ssid = RANDOMMAC_SSID;
        randomMacInfo.keyMgmt = KEY_MGMT_WEP;
        randomMacInfo.preSharedKey = RANDOMMAC_PASSWORD;
        randomMacInfo.peerBssid = RANDOMMAC_BSSID;
        pStaStateMachine->MacAddressGenerate(randomMacInfo);
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<1>(deviceConfig), Return(-1)));
        EXPECT_CALL(WifiSettings::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        pStaStateMachine->SetRandomMac(0, "");
    }

    void SetRandomMacFail2()
    {
        WifiDeviceConfig deviceConfig;
        deviceConfig.wifiPrivacySetting = WifiPrivacyConfig::RANDOMMAC;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<1>(deviceConfig), Return(0)));
        EXPECT_CALL(WifiSettings::GetInstance(), GetScanInfoList(_)).Times(AtLeast(0));
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.getDeviceAddress = false;
        EXPECT_CALL(WifiSettings::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
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
        InternalMessage msg;
        pStaStateMachine->pSeparatingState->ExecuteStateMsg(&msg);
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
        InternalMessage msg;
        std::string bssid = "wifitest";
        msg.SetMessageObj(bssid);
        msg.SetMessageName(WIFI_SVR_CMD_STA_NETWORK_DISCONNECTION_EVENT);
        EXPECT_FALSE(pStaStateMachine->pSeparatedState->ExecuteStateMsg(&msg));
    }

    void SeparatedStateExeMsgSuccess2()
    {
        EXPECT_CALL(WifiManager::GetInstance(), DealStaOpenRes(_, _));
        InternalMessage msg;
        msg.SetMessageName(WIFI_SVR_CMD_STA_ENABLE_WIFI);
        EXPECT_TRUE(pStaStateMachine->pSeparatedState->ExecuteStateMsg(&msg));
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
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.disconnect = false;
        InternalMessage msg;
        msg.SetMessageName(WIFI_SVR_CMD_STA_DISCONNECT);
        EXPECT_TRUE(pStaStateMachine->pApLinkedState->ExecuteStateMsg(&msg));
    }

    void ApLinkedStateExeMsgSuccess2()
    {
        InternalMessage msg;
        std::string bssid = "wifitest";
        msg.SetMessageObj(bssid);
        msg.SetMessageName(WIFI_SVR_CMD_STA_NETWORK_CONNECTION_EVENT);
        EXPECT_TRUE(pStaStateMachine->pApLinkedState->ExecuteStateMsg(&msg));
    }

    void ApLinkedStateExeMsgFail1()
    {
        InternalMessage msg;
        std::string bssid = "wifitest";
        msg.SetMessageObj(bssid);
        msg.SetMessageName(WIFI_SVR_CMD_STA_NETWORK_DISCONNECTION_EVENT);
        EXPECT_FALSE(pStaStateMachine->pApLinkedState->ExecuteStateMsg(&msg));
    }

    void ApLinkedStateExeMsgFai2()
    {
        EXPECT_FALSE(pStaStateMachine->pApLinkedState->ExecuteStateMsg(nullptr));
    }

    void DisConnectProcessSuccess()
    {
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.disconnect = true;
        pStaStateMachine->DisConnectProcess();
    }

    void DisConnectProcessFail()
    {
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.disconnect = false;
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
        EXPECT_CALL(WifiSettings::GetInstance(), SetWifiState(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0)).WillRepeatedly(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_)).Times(AtLeast(0)).WillRepeatedly(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), AddDeviceConfig(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig()).Times(AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SetDeviceState(_, _, _)).Times(AtLeast(0));
        InternalMessage msg;
        msg.SetMessageName(WIFI_SVR_CMD_STA_NETWORK_CONNECTION_EVENT);
        EXPECT_TRUE(pStaStateMachine->pWpsState->ExecuteStateMsg(&msg));
    }

    void WpsStateExeMsgSuccess2()
    {
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _));
        InternalMessage msg;
        msg.SetMessageName(WIFI_SVR_CMD_STA_STARTWPS);
        msg.SetParam1(static_cast<int>(SetupMethod::PBC));
        EXPECT_TRUE(pStaStateMachine->pWpsState->ExecuteStateMsg(&msg));
    }

    void WpsStateExeMsgSuccess3()
    {
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _));
        InternalMessage msg;
        msg.SetMessageName(WIFI_SVR_CMD_STA_STARTWPS);
        msg.SetParam1(static_cast<int>(SetupMethod::DISPLAY));
        EXPECT_TRUE(pStaStateMachine->pWpsState->ExecuteStateMsg(&msg));
    }

    void WpsStateExeMsgSuccess4()
    {
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _));
        InternalMessage msg;
        msg.SetMessageName(WIFI_SVR_CMD_STA_WPS_OVERLAP_EVENT);
        msg.SetParam1(static_cast<int>(SetupMethod::DISPLAY));
        EXPECT_TRUE(pStaStateMachine->pWpsState->ExecuteStateMsg(&msg));
    }

    void WpsStateExeMsgSuccess5()
    {
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_)).WillRepeatedly(Return(-1));
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.stopWps = false;
        EXPECT_CALL(WifiSettings::GetInstance(), SetWifiState(_, _)).Times(testing::AtLeast(0));
        InternalMessage msg;
        msg.SetMessageName(WIFI_SVR_CMD_STA_WPS_OVERLAP_EVENT);
        msg.SetParam1(static_cast<int>(SetupMethod::DISPLAY));
        EXPECT_TRUE(pStaStateMachine->pWpsState->ExecuteStateMsg(&msg));
    }

    void WpsStateExeMsgFail1()
    {
        EXPECT_FALSE(pStaStateMachine->pWpsState->ExecuteStateMsg(nullptr));
    }

    void WpsStateExeMsgFail2()
    {
        InternalMessage msg;
        msg.SetMessageName(WIFI_SVR_CMD_STA_WPS_START_EVENT);
        EXPECT_FALSE(pStaStateMachine->pWpsState->ExecuteStateMsg(nullptr));
    }

    void GetIpStateStateGoInStateSuccess1()
    {
        WifiDeviceConfig config;
        config.wifiProxyconfig.configureMethod = ConfigureProxyMethod::MANUALCONFIGUE;
        config.wifiIpConfig.assignMethod = AssignIpMethod::STATIC;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<1>(config), Return(0)));
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.disconnect = false;
        pStaStateMachine->pGetIpState->GoInState();
    }

    void GetIpStateStateGoInStateSuccess2()
    {
        pStaStateMachine->isRoam = true;
        WifiDeviceConfig config;
        config.wifiProxyconfig.configureMethod = ConfigureProxyMethod::MANUALCONFIGUE;
        config.wifiIpConfig.assignMethod = AssignIpMethod::DHCP;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDhcpIpType(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<1>(config), Return(0)));
        pStaStateMachine->pGetIpState->GoInState();
    }

    void GetIpStateStateGoInStateSuccess3()
    {
        pStaStateMachine->isRoam = false;
        WifiDeviceConfig config;
        config.wifiProxyconfig.configureMethod = ConfigureProxyMethod::MANUALCONFIGUE;
        config.wifiIpConfig.assignMethod = AssignIpMethod::DHCP;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<1>(config), Return(0)));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDhcpIpType(_)).WillRepeatedly(Return(IPTYPE_IPV4));
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.disconnect = false;
        pStaStateMachine->pGetIpState->GoInState();
    }

    void GetIpStateStateGoOutStateSuccess()
    {
        pStaStateMachine->pGetIpState->GoOutState();
    }

    void GetIpStateStateExeMsgSuccess()
    {
        InternalMessage msg;
        msg.SetParam1(1);
        msg.SetParam2(0);
        msg.SetMessageName(WIFI_SVR_CMD_STA_DHCP_RESULT_NOTIFY_EVENT);
        pStaStateMachine->pGetIpState->ExecuteStateMsg(&msg);
    }

    void GetIpStateStateExeMsgFail()
    {
        InternalMessage msg;
        pStaStateMachine->pGetIpState->ExecuteStateMsg(&msg);
        pStaStateMachine->pGetIpState->ExecuteStateMsg(nullptr);
    }

    void ConfigStaticIpAddressSuccess1()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        pStaStateMachine->currentTpType = IPTYPE_IPV4;
        pStaStateMachine->getIpSucNum = 1;
        pStaStateMachine->isRoam = false;
        StaticIpAddress staticIpAddress;
        EXPECT_CALL(WifiSettings::GetInstance(), SaveIpInfo(_, _)).Times(AtLeast(0));
        ;
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(AtLeast(0));
        pStaStateMachine->pDhcpResultNotify->pStaStateMachine = nullptr;
        EXPECT_TRUE(pStaStateMachine->ConfigStaticIpAddress(staticIpAddress));
    }

    void ConfigStaticIpAddressSuccess2()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        pStaStateMachine->currentTpType = IPTYPE_IPV6;
        pStaStateMachine->getIpSucNum = 1;
        pStaStateMachine->isRoam = false;
        StaticIpAddress staticIpAddress;
        EXPECT_CALL(WifiSettings::GetInstance(), SaveIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(AtLeast(0));
        pStaStateMachine->pDhcpResultNotify->pStaStateMachine = nullptr;
        EXPECT_TRUE(pStaStateMachine->ConfigStaticIpAddress(staticIpAddress));
    }

    void ConfigStaticIpAddressSuccess3()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        pStaStateMachine->currentTpType = IPTYPE_MIX;
        pStaStateMachine->getIpSucNum = 1;
        pStaStateMachine->isRoam = false;
        StaticIpAddress staticIpAddress;
        EXPECT_CALL(WifiSettings::GetInstance(), SaveIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiManager::GetInstance(), DealStaConnChanged(_, _, _)).Times(AtLeast(0));
        pStaStateMachine->pDhcpResultNotify->pStaStateMachine = nullptr;
        EXPECT_TRUE(pStaStateMachine->ConfigStaticIpAddress(staticIpAddress));
    }

    void ConfigStaticIpAddressFail()
    {
        pStaStateMachine->currentTpType = IPTYPE_BUTT;
        StaticIpAddress staticIpAddress;
        pStaStateMachine->getIpSucNum = 1;
        pStaStateMachine->isRoam = false;
        EXPECT_CALL(WifiSettings::GetInstance(), SaveIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_FALSE(pStaStateMachine->ConfigStaticIpAddress(staticIpAddress));
    }

    void HandleNetCheckResultSuccess1()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _));
        pStaStateMachine->linkedInfo.connState = ConnState::CONNECTED;
        pStaStateMachine->HandleNetCheckResult(SystemNetWorkState::NETWORK_IS_WORKING, "");
    }

    void HandleNetCheckResultSuccess3()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _));
        pStaStateMachine->linkedInfo.connState = ConnState::CONNECTED;
        pStaStateMachine->HandleNetCheckResult(SystemNetWorkState::NETWORK_IS_PORTAL, "");
    }
    void HandleNetCheckResultSuccess4()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _));
        pStaStateMachine->linkedInfo.connState = ConnState::CONNECTED;
        pStaStateMachine->HandleNetCheckResult(SystemNetWorkState::NETWORK_NOTWORKING, "");
    }

    void HandleNetCheckResultFail()
    {
        pStaStateMachine->linkedInfo.connState = ConnState::DISCONNECTED;
        pStaStateMachine->HandleNetCheckResult(SystemNetWorkState::NETWORK_NOTWORKING, "");
    }

    void LinkedStateGoInStateSuccess()
    {
        pStaStateMachine->pLinkedState->GoInState();
    }

    void LinkedStateGoOutStateSuccess()
    {
        pStaStateMachine->pLinkedState->GoOutState();
    }

    void LinkedStateExeMsgSuccess()
    {
        InternalMessage msg;
        msg.SetMessageName(WIFI_SVR_CMD_STA_BSSID_CHANGED_EVENT);
        msg.AddStringMessageBody("ASSOC_COMPLETE");
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.setBssid = true;
        pStaStateMachine->pLinkedState->ExecuteStateMsg(&msg);
    }

    void LinkedStateExeMsgFail4()
    {
        InternalMessage msg;
        msg.SetMessageName(WIFI_SVR_CMD_STA_BSSID_CHANGED_EVENT);
        msg.AddStringMessageBody("hello");
        pStaStateMachine->pLinkedState->ExecuteStateMsg(&msg);
    }

    void LinkedStateExeMsgFail3()
    {
        InternalMessage msg;
        msg.SetMessageName(WIFI_SVR_CMD_STA_BSSID_CHANGED_EVENT);
        msg.AddStringMessageBody("ASSOC_COMPLETE");
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.setBssid = false;
        pStaStateMachine->pLinkedState->ExecuteStateMsg(&msg);
    }

    void LinkedStateExeMsgFail2()
    {
        InternalMessage msg;
        pStaStateMachine->pLinkedState->ExecuteStateMsg(&msg);
    }

    void LinkedStateExeMsgFail()
    {
        pStaStateMachine->pLinkedState->ExecuteStateMsg(nullptr);
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
        EXPECT_CALL(WifiSettings::GetInstance(), SetWifiState(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).WillRepeatedly(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        InternalMessage msg;
        msg.SetMessageName(WIFI_SVR_CMD_STA_NETWORK_CONNECTION_EVENT);
        EXPECT_TRUE(pStaStateMachine->pApRoamingState->ExecuteStateMsg(&msg));
    }

    void ApRoamingStateExeMsgFail()
    {
        InternalMessage msg;
        msg.SetMessageName(WIFI_SVR_CMD_STA_ERROR);
        EXPECT_FALSE(pStaStateMachine->pApRoamingState->ExecuteStateMsg(nullptr));
        EXPECT_FALSE(pStaStateMachine->pApRoamingState->ExecuteStateMsg(&msg));
    }

    void ConnectToNetworkProcessSuccess()
    {
        pStaStateMachine->wpsState = SetupMethod::DISPLAY;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).WillRepeatedly(Return(-1));
        WifiIdlGetDeviceConfig config;
        config.value = "hmwifi";
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.getDeviceConfig = false;
        EXPECT_CALL(WifiSettings::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig());
        EXPECT_CALL(WifiSettings::GetInstance(), SetWifiState(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        std::string bssid = "wifitest";
        pStaStateMachine->ConnectToNetworkProcess(bssid);
    }

    void ConnectToNetworkProcessSuccess1()
    {
        pStaStateMachine->wpsState = SetupMethod::PBC;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).WillRepeatedly(Return(-1));
        WifiIdlGetDeviceConfig config;
        config.value = "hmwifi";
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.getDeviceConfig = false;
        EXPECT_CALL(WifiSettings::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig());
        EXPECT_CALL(WifiSettings::GetInstance(), SetWifiState(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        std::string bssid = "wifitest";
        pStaStateMachine->ConnectToNetworkProcess(bssid);
    }

    void ConnectToNetworkProcessSuccess2()
    {
        pStaStateMachine->wpsState = SetupMethod::KEYPAD;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).WillRepeatedly(Return(-1));
        WifiIdlGetDeviceConfig config;
        config.value = "hmwifi";
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.getDeviceConfig = true;
        EXPECT_CALL(WifiSettings::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig());
        EXPECT_CALL(WifiSettings::GetInstance(), SetWifiState(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        std::string bssid = "wifitest";
        pStaStateMachine->ConnectToNetworkProcess(bssid);
    }

    void ConnectToNetworkProcessSuccess3()
    {
        pStaStateMachine->wpsState = SetupMethod::INVALID;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).WillRepeatedly(Return(-1));
        WifiIdlGetDeviceConfig config;
        config.value = "hmwifi";
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.getDeviceConfig = false;
        EXPECT_CALL(WifiSettings::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig());
        EXPECT_CALL(WifiSettings::GetInstance(), SetWifiState(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
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
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).WillRepeatedly(Return(0));
        pStaStateMachine->linkedInfo.networkId = INVALID_NETWORK_ID;
        pStaStateMachine->lastLinkedInfo.networkId = INVALID_NETWORK_ID;
        pStaStateMachine->SetWifiLinkedInfo(0);
    }

    void DhcpResultNotifyOnSuccessTest()
    {
        pStaStateMachine->linkedInfo.detailedState = DetailedState::CONNECTED;
        pStaStateMachine->getIpSucNum = 1;
        pStaStateMachine->isRoam = false;
        IpInfo ipInfo;
        ipInfo.ipAddress = IpTools::ConvertIpv4Address("192.168.0.2");
        ipInfo.gateway = IpTools::ConvertIpv4Address("192.168.0.1");
        EXPECT_CALL(WifiSettings::GetInstance(), GetIpInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(ipInfo), Return(0)));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetStrDnsBak(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveIpV6Info(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetIpv6Info(_, _)).Times(testing::AtLeast(0));
    }

    void DhcpResultNotifyOnSuccessTest1()
    {
        std::string ifname = "wlan0";
        DhcpResult result;
        pStaStateMachine->pDhcpResultNotify->OnSuccess(0, nullptr, &result);
        pStaStateMachine->pDhcpResultNotify->OnSuccess(0, ifname.c_str(), nullptr);
        pStaStateMachine->pDhcpResultNotify->pStaStateMachine = nullptr;
        pStaStateMachine->pDhcpResultNotify->OnSuccess(0, ifname.c_str(), &result);
    }

    void DhcpResultNotifyOnFailedTest1()
    {
        pStaStateMachine->linkedInfo.detailedState = DetailedState::CONNECTED;
        pStaStateMachine->currentTpType = IPTYPE_IPV6;
        pStaStateMachine->getIpSucNum = 0;
        pStaStateMachine->getIpFailNum = 1;
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.disconnect = false;
        EXPECT_CALL(WifiSettings::GetInstance(), SaveIpV6Info(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetIpv6Info(_, _)).Times(testing::AtLeast(0));
        std::string ifname = "wlan0";
        std::string reason = "test";
        pStaStateMachine->pDhcpResultNotify->OnFailed(0, ifname.c_str(), reason.c_str());
    }

    void DhcpResultNotifyOnFailedTest2()
    {
        pStaStateMachine->linkedInfo.detailedState = DetailedState::DISCONNECTING;
        pStaStateMachine->isRoam = false;
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.disconnect = false;
        EXPECT_CALL(WifiSettings::GetInstance(), SaveIpV6Info(_, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetIpv6Info(_, _)).Times(testing::AtLeast(0));
        std::string ifname = "wlan1";
        std::string reason = "test";
        pStaStateMachine->pDhcpResultNotify->OnFailed(0, ifname.c_str(), reason.c_str());
    }

    void DhcpResultNotifyOnFailedTest3()
    {
        pStaStateMachine->linkedInfo.detailedState = DetailedState::DISCONNECTED;
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.disconnect = false;
        pStaStateMachine->isRoam = true;
        std::string ifname = "wlan1";
        std::string reason = "test";
        pStaStateMachine->pDhcpResultNotify->OnFailed(0, ifname.c_str(), reason.c_str());
    }

    void SaveLinkstateSuccess()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _));
        pStaStateMachine->SaveLinkstate(ConnState::CONNECTED, DetailedState::CONNECTED);
    }

    void ConvertFreqToChannelTest()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).WillOnce(Return(1));
        pStaStateMachine->ConvertFreqToChannel();
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0));
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
        InternalMessage msg;
        pStaStateMachine->pLinkState->ExecuteStateMsg(&msg);
    }

    void LinkStateExeMsgFail()
    {
        EXPECT_FALSE(pStaStateMachine->pLinkState->ExecuteStateMsg(nullptr));
    }
    void OnNetManagerRestartSuccess()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetWifiState(_)).WillRepeatedly(Return(1));
        pStaStateMachine->OnNetManagerRestart();
    }

    void OnNetManagerRestartFail()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetWifiState(_)).WillRepeatedly(Return(1));
        pStaStateMachine->OnNetManagerRestart();
    }

    void ReUpdateNetSupplierInfoSuccess()
    {
        sptr<NetManagerStandard::NetSupplierInfo> supplierInfo;
        pStaStateMachine->linkedInfo.detailedState = DetailedState::NOTWORKING;
        pStaStateMachine->linkedInfo.connState = ConnState::CONNECTED;
        pStaStateMachine->ReUpdateNetSupplierInfo(supplierInfo);
    }

    void ReUpdateNetSupplierInfoFail()
    {
        sptr<NetManagerStandard::NetSupplierInfo> supplierInfo;
        pStaStateMachine->ReUpdateNetSupplierInfo(supplierInfo);
    }

    void OnBssidChangedEventSuccess()
    {
        std::string reason;
        std::string bssid;
        pStaStateMachine->OnBssidChangedEvent(reason, bssid);
    }

    void OnNetworkDisconnectEventSuccess()
    {
        int reason = 0;
        pStaStateMachine->OnNetworkDisconnectEvent(reason);
    }

    void DealReConnectCmdSuccess()
    {
        InternalMessage msg;
        pStaStateMachine->linkedInfo.connState = ConnState::CONNECTING;
        pStaStateMachine->DealNetworkCheck(&msg);
        pStaStateMachine->DealNetworkCheck(nullptr);
        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.reconnect = true;
        EXPECT_CALL(WifiSettings::GetInstance(), SetDeviceConnFailedCount(_, _, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), IncreaseDeviceConnFailedCount(_, _, _)).Times(testing::AtLeast(0));
        pStaStateMachine->DealReConnectCmd(&msg);

        MockWifiStaInterface::GetInstance().pWifiStaHalInfo.reconnect = false;
        pStaStateMachine->DealReConnectCmd(&msg);
    }

    void DealReConnectCmdFail()
    {
        InternalMessage msg;
        pStaStateMachine->linkedInfo.connState = ConnState::CONNECTED;
        pStaStateMachine->DealReConnectCmd(&msg);
        pStaStateMachine->DealReConnectCmd(nullptr);
    }

    void DealConnectionEventSuccess()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), SetDeviceAfterConnect(_)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SetDeviceState(_, _, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig()).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _));
        EXPECT_CALL(WifiSettings::GetInstance(), SetUserLastSelectedNetworkId(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->wpsState = SetupMethod::INVALID;
        InternalMessage msg;
        pStaStateMachine->DealConnectionEvent(&msg);
    }

    void DealConnectionEventFail()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), SetDeviceAfterConnect(_)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SetDeviceState(_, _, _)).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig()).Times(testing::AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _));
        EXPECT_CALL(WifiSettings::GetInstance(), SetUserLastSelectedNetworkId(_, _)).Times(testing::AtLeast(0));
        pStaStateMachine->wpsState = SetupMethod::LABEL;
        InternalMessage msg;
        pStaStateMachine->DealConnectionEvent(&msg);
        pStaStateMachine->DealConnectionEvent(nullptr);
    }

    void OnConnectFailed()
    {
        int networkId = 15;
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _));
        pStaStateMachine->OnConnectFailed(networkId);
    }
    void ComparedKeymgmtTest()
    {
        std::string scanInfoKeymgmt;
        std::string deviceKeymgmt;
        pStaStateMachine->ComparedKeymgmt(scanInfoKeymgmt, deviceKeymgmt);
        deviceKeymgmt = "WPA-PSK";
        pStaStateMachine->ComparedKeymgmt(scanInfoKeymgmt, deviceKeymgmt);
        deviceKeymgmt = "WPA-EAP";
        pStaStateMachine->ComparedKeymgmt(scanInfoKeymgmt, deviceKeymgmt);
        deviceKeymgmt = "SAE";
        pStaStateMachine->ComparedKeymgmt(scanInfoKeymgmt, deviceKeymgmt);
        deviceKeymgmt = "NONE";
        pStaStateMachine->ComparedKeymgmt(scanInfoKeymgmt, deviceKeymgmt);
    }

    void ReUpdateNetLinkInfoTest()
    {
        pStaStateMachine->linkedInfo.detailedState = DetailedState::NOTWORKING;
        pStaStateMachine->linkedInfo.connState = ConnState::CONNECTED;
        pStaStateMachine->linkedInfo.bssid = RANDOMMAC_BSSID;
        pStaStateMachine->linkedInfo.ssid = RANDOMMAC_SSID;
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).WillRepeatedly(Return(0));
        WifiDeviceConfig config;
        config.bssid = RANDOMMAC_BSSID;
        config.ssid = RANDOMMAC_SSID;
        pStaStateMachine->ReUpdateNetLinkInfo(config);
    }

    void ReUpdateNetLinkInfoTest1()
    {
        pStaStateMachine->linkedInfo.detailedState = DetailedState::NOTWORKING;
        pStaStateMachine->linkedInfo.connState = ConnState::CONNECTED;
        EXPECT_CALL(WifiSettings::GetInstance(), SaveLinkedInfo(_, _)).WillRepeatedly(Return(0));
        WifiDeviceConfig config;
        pStaStateMachine->ReUpdateNetLinkInfo(config);
    }

    void DealSignalPollResultTest()
    {
        InternalMessage msg;
        EXPECT_CALL(WifiSettings::GetInstance(), SetWifiLinkedStandardAndMaxSpeed(_)).Times(testing::AtLeast(0));
        pStaStateMachine->DealSignalPollResult(nullptr);
        pStaStateMachine->DealSignalPollResult(&msg);
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

    void InvokeOnStaOpenRes(const OperateResState &state)
    {
        EXPECT_CALL(WifiManager::GetInstance(), DealStaOpenRes(_, _)).Times(AtLeast(0));
        pStaStateMachine->InvokeOnStaOpenRes(state);
    }

    void InvokeOnStaCloseRes(const OperateResState &state)
    {
        pStaStateMachine->InvokeOnStaCloseRes(state);
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
        EXPECT_CALL(WifiManager::GetInstance(), DealWpsChanged(_, _, _)).Times(AtLeast(0));
        pStaStateMachine->InvokeOnWpsChanged(state, 0);
    }

    void InvokeOnStaStreamChanged(const StreamDirection &direction)
    {
        pStaStateMachine->InvokeOnStaStreamChanged(direction);
    }

    void InvokeOnStaRssiLevelChanged(int level)
    {
        pStaStateMachine->InvokeOnStaRssiLevelChanged(level);
    }

    void DealScreenStateChangedEventTest()
    {
        InternalMessage msg;
        pStaStateMachine->DealScreenStateChangedEvent(nullptr);
        msg.SetParam1(static_cast<int>(MODE_STATE_OPEN));
        pStaStateMachine->DealScreenStateChangedEvent(&msg);
        msg.SetParam1(static_cast<int>(MODE_STATE_CLOSE));
        pStaStateMachine->DealScreenStateChangedEvent(&msg);
    }
};

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

HWTEST_F(StaStateMachineTest, LinkedStateGoInStateSuccess, TestSize.Level1)
{
    LinkedStateGoInStateSuccess();
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

HWTEST_F(StaStateMachineTest, InitStaSMHandleMapSuccess, TestSize.Level1)
{
    InitStaSMHandleMapSuccess();
}

HWTEST_F(StaStateMachineTest, DealConnectToUserSelectedNetworkSuccess, TestSize.Level1)
{
    DealConnectToUserSelectedNetworkSuccess();
}

HWTEST_F(StaStateMachineTest, DealConnectToUserSelectedNetworkFail, TestSize.Level1)
{
    DealConnectToUserSelectedNetworkFail();
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

HWTEST_F(StaStateMachineTest, DealWpaWrongPskEventFail1, TestSize.Level1)
{
    DealWpaWrongPskEventFail1();
}
/**
 * @tc.name: DealWpaWrongPskEventFail2
 * @tc.desc: DealWpaWrongPskEvent()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(StaStateMachineTest, DealWpaWrongPskEventFail2, TestSize.Level1)
{
    DealWpaWrongPskEventFail2();
}

HWTEST_F(StaStateMachineTest, DealWpaWrongPskEventSuccess, TestSize.Level1)
{
    DealWpaWrongPskEventSuccess();
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

HWTEST_F(StaStateMachineTest, StartConnectToNetworkFail2, TestSize.Level1)
{
    StartConnectToNetworkFail2();
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

HWTEST_F(StaStateMachineTest, ConnectToNetworkProcessSuccess, TestSize.Level1)
{
}
/**
 * @tc.name: ConnectToNetworkProcessSuccess1
 * @tc.desc: ConnectToNetworkProcess()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(StaStateMachineTest, ConnectToNetworkProcessSuccess1, TestSize.Level1)
{
}
/**
 * @tc.name: ConnectToNetworkProcessSuccess2
 * @tc.desc: ConnectToNetworkProcess()
 * @tc.type: FUNC
 * @tc.require: issue
*/
HWTEST_F(StaStateMachineTest, ConnectToNetworkProcessSuccess2, TestSize.Level1)
{
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
    DhcpResultNotifyOnSuccessTest1();
}

HWTEST_F(StaStateMachineTest, DhcpResultNotifyOnFailedTest1, TestSize.Level1)
{
}

HWTEST_F(StaStateMachineTest, DhcpResultNotifyOnFailedTest2, TestSize.Level1)
{
}

HWTEST_F(StaStateMachineTest, DhcpResultNotifyOnFailedTest3, TestSize.Level1)
{
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

HWTEST_F(StaStateMachineTest, ReUpdateNetSupplierInfoSuccess, TestSize.Level1)
{
    ReUpdateNetSupplierInfoSuccess();
}

HWTEST_F(StaStateMachineTest, ReUpdateNetSupplierInfoFail, TestSize.Level1)
{
    ReUpdateNetSupplierInfoFail();
}

HWTEST_F(StaStateMachineTest, OnBssidChangedEventSuccess, TestSize.Level1)
{
    OnBssidChangedEventSuccess();
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

HWTEST_F(StaStateMachineTest, ComparedKeymgmtTest, TestSize.Level1)
{
    ComparedKeymgmtTest();
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

HWTEST_F(StaStateMachineTest, InvokeOnStaOpenResTest, TestSize.Level1)
{
    InvokeOnStaOpenRes(OperateResState::OPEN_WIFI_SUCCEED);
}

HWTEST_F(StaStateMachineTest, InvokeOnStaCloseResTest, TestSize.Level1)
{
    InvokeOnStaCloseRes(OperateResState::OPEN_WIFI_SUCCEED);
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
}
} // namespace Wifi
} // namespace OHOS
