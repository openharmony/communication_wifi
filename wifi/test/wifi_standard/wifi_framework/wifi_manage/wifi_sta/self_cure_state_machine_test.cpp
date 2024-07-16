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
#include "mock_wifi_config_center.h"
#include "mock_wifi_settings.h"
#include "internal_message.h"
#include "define.h"
#include "self_cure_common.h"
#include "self_cure_state_machine.h"
#include "wifi_internal_msg.h"
#include "wifi_msg.h"
#include "wifi_logger.h"
#include "wifi_scan_msg.h"
#include "self_cure_msg.h"
#include "mock_sta_service.h"

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
static const int32_t SELFCURE_FAILED_CNT = 5;
static const int32_t CONNECT_NETWORK_RETRY_CNT = 2;
static const int64_t TIME_MILLS = 1615153293123;
static const std::string CURR_BSSID = "11:22:33:ef:ac:0e";
static const std::string REAL_MAC = "fa:22:33:ef:ac:0e";
static const std::string GATEWAY = "192.168.0.1";
static const std::string CURRENT_ADDR = "192.168.0.100";
static const std::vector<std::string> TESTED_ADDR = {"192.168.0.101", "192.168.0.102", "192.168.0.103"};

class SelfCureStateMachineTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiSelfcureReset(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        pSelfCureStateMachine = std::make_unique<SelfCureStateMachine>();
        pSelfCureStateMachine->Initialize();
        pMockStaService = std::make_unique<MockWifiStaService>();
    }

    virtual void TearDown()
    {
        pSelfCureStateMachine.reset();
    }

    std::unique_ptr<SelfCureStateMachine> pSelfCureStateMachine;
    std::unique_ptr<MockWifiStaService> pMockStaService;

    void DefaultStateGoInStateSuccess()
    {
        LOGI("Enter DefaultStateGoInStateSuccess");
        pSelfCureStateMachine->pDefaultState->GoInState();
    }

    void DefaultStateGoOutStateSuccess()
    {
        LOGI("Enter DefaultStateGoOutStateSuccess");
        pSelfCureStateMachine->pDefaultState->GoOutState();
    }

    void DefaultStateExeMsgFail()
    {
        LOGI("Enter DefaultStateExeMsgFail");
        EXPECT_FALSE(pSelfCureStateMachine->pDefaultState->ExecuteStateMsg(nullptr));
    }

    void DefaultStateExeMsgSuccess1()
    {
        LOGI("Enter DefaultStateExeMsgSuccess1");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(1);
        EXPECT_FALSE(pSelfCureStateMachine->pDefaultState->ExecuteStateMsg(msg));
        msg->SetMessageName(0);
        EXPECT_TRUE(pSelfCureStateMachine->pDefaultState->ExecuteStateMsg(msg));
    }

    void ConnectedMonitorStateGoInStateSuccess()
    {
        LOGI("Enter ConnectedMonitorStateGoInStateSuccess");
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiSelfcureReset()).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetStaIfaceName()).WillRepeatedly(Return("sta"));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetLastNetworkId(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), AddDeviceConfig(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig()).Times(AtLeast(0));
        pSelfCureStateMachine->pConnectedMonitorState->GoInState();
    }

    void ConnectedMonitorStateGoOutStateSuccess()
    {
        LOGI("Enter ConnectedMonitorStateGoOutStateSuccess");
        pSelfCureStateMachine->pConnectedMonitorState->GoOutState();
    }

    void ConnectedMonitorStateExeMsgFail()
    {
        LOGI("Enter ConnectedMonitorStateExeMsgFail");
        EXPECT_FALSE(pSelfCureStateMachine->pConnectedMonitorState->ExecuteStateMsg(nullptr));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(0);
        pSelfCureStateMachine->pConnectedMonitorState->ExecuteStateMsg(msg);
    }

    void ConnectedMonitorStateExeMsgSuccess1()
    {
        LOGI("Enter ConnectedMonitorStateExeMsgSuccess1");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_PERIODIC_ARP_DETECTED);
        pSelfCureStateMachine->pConnectedMonitorState->ExecuteStateMsg(msg);
    }

    void InitSelfCureCmsHandleMapTest()
    {
        LOGI("Enter InitSelfCureCmsHandleMapTest");
        pSelfCureStateMachine->pConnectedMonitorState->InitSelfCureCmsHandleMap();
    }

    void TransitionToSelfCureStateTest()
    {
        LOGI("Enter TransitionToSelfCureStateTest");
        int reason = 0;
        pSelfCureStateMachine->pConnectedMonitorState->mobileHotspot = false;
        pSelfCureStateMachine->pConnectedMonitorState->TransitionToSelfCureState(reason);

        pSelfCureStateMachine->pConnectedMonitorState->mobileHotspot = true;
        reason = WIFI_CURE_INTERNET_FAILED_TYPE_ROAMING;
        pSelfCureStateMachine->pConnectedMonitorState->TransitionToSelfCureState(reason);

        reason = WIFI_CURE_INTERNET_FAILED_TYPE_TCP;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpv6Info(_, _)).Times(AtLeast(0));
        pSelfCureStateMachine->pConnectedMonitorState->TransitionToSelfCureState(reason);

        IpInfo ipInfo;
        IpV6Info ipv6Info;
        ipInfo.primaryDns = 0;
        ipInfo.secondDns = 0;
        ipInfo.gateway = 0;
        ipv6Info.gateway = "";
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(ipInfo), Return(0)));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpv6Info(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(ipv6Info), Return(0)));
        pSelfCureStateMachine->pConnectedMonitorState->TransitionToSelfCureState(reason);

        ipInfo.secondDns = 1;
        ipInfo.gateway = 1;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(ipInfo), Return(0)));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpv6Info(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(ipv6Info), Return(0)));
        pSelfCureStateMachine->pConnectedMonitorState->TransitionToSelfCureState(reason);
    }

    void HandleResetupSelfCureTest()
    {
        LOGI("Enter TransitionToSelfCureStateTest");
        pSelfCureStateMachine->pConnectedMonitorState->HandleResetupSelfCure(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_RESETUP_SELF_CURE_MONITOR);
        pSelfCureStateMachine->pConnectedMonitorState->HandleResetupSelfCure(msg);
    }

    void HandlePeriodicArpDetectionTest()
    {
        LOGI("Enter HandlePeriodicArpDetectionTest");
        pSelfCureStateMachine->pConnectedMonitorState->HandlePeriodicArpDetection(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_PERIODIC_ARP_DETECTED);
        pSelfCureStateMachine->pConnectedMonitorState->HandlePeriodicArpDetection(msg);
    }

    void HandleNetworkConnectTest()
    {
        LOGI("Enter HandleNetworkConnectTest");
        pSelfCureStateMachine->pConnectedMonitorState->HandleNetworkConnect(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_NOTIFY_NETWORK_CONNECTED_RCVD);
        pSelfCureStateMachine->pConnectedMonitorState->HandleNetworkConnect(msg);
    }

    void HandleNetworkDisconnectTest()
    {
        LOGI("Enter HandleNetworkDisconnectTest");
        pSelfCureStateMachine->pConnectedMonitorState->HandleNetworkDisconnect(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_NOTIFY_NETWORK_DISCONNECTED_RCVD);
        pSelfCureStateMachine->pConnectedMonitorState->HandleNetworkDisconnect(msg);
    }

    void HandleRssiLevelChangeTest()
    {
        LOGI("Enter HandleRssiLevelChangeTest");
        pSelfCureStateMachine->pConnectedMonitorState->HandleRssiLevelChange(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_NOTIFY_RSSI_LEVEL_CHANGED_EVENT);
        pSelfCureStateMachine->pConnectedMonitorState->HandleRssiLevelChange(msg);
    }

    void HandleArpDetectionFailedTest()
    {
        LOGI("Enter HandleArpDetectionFailedTest");
        pSelfCureStateMachine->pConnectedMonitorState->HandleArpDetectionFailed(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_ARP_FAILED_DETECTED);
        pSelfCureStateMachine->pConnectedMonitorState->HandleArpDetectionFailed(msg);
    }

    void SetupSelfCureMonitorTest()
    {
        LOGI("Enter SetupSelfCureMonitorTest");
        pSelfCureStateMachine->pConnectedMonitorState->SetupSelfCureMonitor();
        IpInfo ipInfo;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _))
            .WillOnce(DoAll(SetArgReferee<0>(ipInfo), Return(0)));
            ipInfo.ipAddress = 0x0100007F;
        pSelfCureStateMachine->pConnectedMonitorState->SetupSelfCureMonitor();
    }

    void IsGatewayChangedTest()
    {
        LOGI("Enter IsGatewayChangedTest");
        pSelfCureStateMachine->pConnectedMonitorState->IsGatewayChanged();
    }

    void HandleGatewayChangedTest()
    {
        LOGI("enter HandleGatewayChangedTest");
        pSelfCureStateMachine->pConnectedMonitorState->HandleGatewayChanged(nullptr);

        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_GATEWAY_CHANGED_DETECT);
        pSelfCureStateMachine->pConnectedMonitorState->HandleGatewayChanged(msg);
        pSelfCureStateMachine->pConnectedMonitorState->hasInternetRecently = true;
        pSelfCureStateMachine->pConnectedMonitorState->configAuthType = KEY_MGMT_WPA_PSK;
        pSelfCureStateMachine->pConnectedMonitorState->HandleGatewayChanged(msg);

        pSelfCureStateMachine->pConnectedMonitorState->hasInternetRecently = false;
        pSelfCureStateMachine->pConnectedMonitorState->HandleGatewayChanged(msg);
    }

    void RequestReassocWithFactoryMacTest()
    {
        LOGI("Enter RequestReassocWithFactoryMacTest");
        pSelfCureStateMachine->pConnectedMonitorState->RequestReassocWithFactoryMac();
    }

    void HandleInvalidIpTest()
    {
        LOGI("Enter HandleInvalidIpTest");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_INVALID_IP_CONFIRM);
        pSelfCureStateMachine->mIsHttpReachable = true;
        pSelfCureStateMachine->pConnectedMonitorState->HandleInvalidIp(msg);
        pSelfCureStateMachine->mIsHttpReachable = false;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpv6Info(_, _)).Times(AtLeast(0));
        pSelfCureStateMachine->pConnectedMonitorState->HandleInvalidIp(msg);
    }

    void HandleInternetFailedDetectedTest()
    {
        LOGI("Enter HandleInternetFailedDetectedTest");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_INTERNET_FAILURE_DETECTED);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpv6Info(_, _)).Times(AtLeast(0));
        pSelfCureStateMachine->pConnectedMonitorState->mobileHotspot = false;
        pSelfCureStateMachine->pConnectedMonitorState->HandleInternetFailedDetected(msg);

        pSelfCureStateMachine->pConnectedMonitorState->mobileHotspot = true;
        std::string currConnectedBssid = CURR_BSSID;
        WifiLinkedInfo wifiLinkedInfo;
        wifiLinkedInfo.supportedWifiCategory = WifiCategory::WIFI6;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));
        pSelfCureStateMachine->pConnectedMonitorState->HandleInternetFailedDetected(msg);

        wifiLinkedInfo.supportedWifiCategory = WifiCategory::DEFAULT;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));
        pSelfCureStateMachine->pConnectedMonitorState->HandleInternetFailedDetected(msg);
        
        pSelfCureStateMachine->mIsHttpReachable = true;
        pSelfCureStateMachine->pConnectedMonitorState->HandleInternetFailedDetected(msg);

        pSelfCureStateMachine->mIsHttpReachable = false;
        pSelfCureStateMachine->pConnectedMonitorState->HandleInternetFailedDetected(msg);
    }

    void HandleTcpQualityQueryTest()
    {
        LOGI("Enter HandleTcpQualityQueryTest");
        pSelfCureStateMachine->pConnectedMonitorState->HandleTcpQualityQuery(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_INTERNET_STATUS_DETECT_INTERVAL);
        pSelfCureStateMachine->pConnectedMonitorState->HandleTcpQualityQuery(msg);
    }

    void DisconnectedMonitorGoInStateSuccess()
    {
        LOGI("Enter DisconnectedMonitorGoInStateSuccess");
        pSelfCureStateMachine->pDisconnectedMonitorState->GoInState();
    }

    void DisconnectedMonitorGoOutStateSuccess()
    {
        LOGI("Enter DisconnectedMonitorGoOutStateSuccess");
        pSelfCureStateMachine->pDisconnectedMonitorState->GoOutState();
    }

    void DisconnectedMonitorExeMsgFail()
    {
        LOGI("Enter DisconnectedMonitorExeMsgFail");
        EXPECT_FALSE(pSelfCureStateMachine->pDisconnectedMonitorState->ExecuteStateMsg(nullptr));
    }

    void DisconnectedMonitorExeMsgSuccess1()
    {
        LOGI("Enter DisconnectedMonitorExeMsgSuccess1");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(1);
        EXPECT_FALSE(pSelfCureStateMachine->pDisconnectedMonitorState->ExecuteStateMsg(msg));
    }

    void DisconnectedMonitorExeMsgSuccess2()
    {
        LOGI("Enter DisconnectedMonitorExeMsgSuccess2");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_NOTIFY_NETWORK_CONNECTED_RCVD);
        EXPECT_TRUE(pSelfCureStateMachine->pDisconnectedMonitorState->ExecuteStateMsg(msg));
    }

    void DisconnectedMonitorExeMsgSuccess3()
    {
        LOGI("Enter DisconnectedMonitorExeMsgSuccess3");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_OPEN_WIFI_SUCCEED_RESET);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScreenState()).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLastNetworkId()).Times(AtLeast(0));
        EXPECT_TRUE(pSelfCureStateMachine->pDisconnectedMonitorState->ExecuteStateMsg(msg));
    }

    void DisconnectedMonitorExeMsgSuccess4()
    {
        LOGI("Enter DisconnectedMonitorExeMsgSuccess4");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_CONN_FAILED_TIMEOUT);
        pSelfCureStateMachine->useWithRandMacAddress = 0;
        pSelfCureStateMachine->selfCureOnGoing = false;
        EXPECT_TRUE(pSelfCureStateMachine->pDisconnectedMonitorState->ExecuteStateMsg(msg));
    }
    
    void HandleConnectFailedTest()
    {
        LOGI("Enter HandleConnectFailedTest");
        pSelfCureStateMachine->pDisconnectedMonitorState->HandleConnectFailed(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_CONN_FAILED_TIMEOUT);
        pSelfCureStateMachine->useWithRandMacAddress = 0;
        pSelfCureStateMachine->selfCureOnGoing = true;
        pSelfCureStateMachine->pDisconnectedMonitorState->HandleConnectFailed(msg);

        pSelfCureStateMachine->useWithRandMacAddress = 1;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLastNetworkId()).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), AddDeviceConfig(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig()).Times(AtLeast(0));
        pSelfCureStateMachine->pDisconnectedMonitorState->HandleConnectFailed(msg);
    }

    void ConnectionSelfCureGoInStateSuccess()
    {
        LOGI("Enter ConnectionSelfCureGoInStateSuccess");
        pSelfCureStateMachine->pConnectionSelfCureState->GoInState();
    }

    void ConnectionSelfCureGoOutStateSuccess()
    {
        LOGI("Enter ConnectionSelfCureGoOutStateSuccess");
        pSelfCureStateMachine->pConnectionSelfCureState->GoOutState();
    }

    void ConnectionSelfCureExeMsgFail()
    {
        LOGI("Enter ConnectionSelfCureExeMsgFail");
        EXPECT_FALSE(pSelfCureStateMachine->pConnectionSelfCureState->ExecuteStateMsg(nullptr));
    }

    void ConnectionSelfCureExeMsgSuccess1()
    {
        LOGI("Enter ConnectionSelfCureExeMsgSuccess1");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(1);
        EXPECT_FALSE(pSelfCureStateMachine->pConnectionSelfCureState->ExecuteStateMsg(msg));
        msg->SetMessageName(0);
        EXPECT_TRUE(pSelfCureStateMachine->pConnectionSelfCureState->ExecuteStateMsg(msg));
    }

    void InternetSelfCureGoInStateSuccess()
    {
        LOGI("Enter InternetSelfCureGoInStateSuccess");
        pSelfCureStateMachine->pInternetSelfCureState->GoInState();
    }

    void InternetSelfCureGoOutStateSuccess()
    {
        LOGI("Enter InternetSelfCureGoOutStateSuccess");
        pSelfCureStateMachine->pInternetSelfCureState->GoOutState();
    }

    void InternetSelfCureExeMsgFail()
    {
        LOGI("Enter InternetSelfCureExeMsgFail");
        EXPECT_FALSE(pSelfCureStateMachine->pInternetSelfCureState->ExecuteStateMsg(nullptr));
    }

    void InternetSelfCureExeMsgSuccess1()
    {
        LOGI("Enter InternetSelfCureExeMsgSuccess1");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_INTERNET_FAILED_SELF_CURE);
        pSelfCureStateMachine->pInternetSelfCureState->ExecuteStateMsg(msg);
        msg->SetMessageName(0);
        pSelfCureStateMachine->pInternetSelfCureState->ExecuteStateMsg(msg);
    }

    void InitSelfCureIssHandleMapTest()
    {
        LOGI("Enter InitSelfCureIssHandleMapTest");
        pSelfCureStateMachine->pInternetSelfCureState->InitSelfCureIssHandleMap();
    }

    void HandleRandMacSelfCureCompleteTest()
    {
        LOGI("Enter HandleRandMacSelfCureCompleteTest");
        pSelfCureStateMachine->pInternetSelfCureState->HandleRandMacSelfCureComplete(nullptr);

        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_RAND_MAC_SELFCURE_COMPLETE);
        pSelfCureStateMachine->pInternetSelfCureState->HandleRandMacSelfCureComplete(msg);

        pSelfCureStateMachine->mIsHttpReachable = false;
        pSelfCureStateMachine->pInternetSelfCureState->HandleRandMacSelfCureComplete(msg);

        pSelfCureStateMachine->mIsHttpReachable = true;
        std::string MacAddress = CURR_BSSID;
        std::string RealMacAddress = REAL_MAC;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).
            WillRepeatedly(DoAll(SetArgReferee<0>(MacAddress), Return(0)));
        EXPECT_CALL(WifiSettings::GetInstance(), GetRealMacAddress(_, _)).
            WillRepeatedly(DoAll(SetArgReferee<0>(RealMacAddress), Return(0)));
        pSelfCureStateMachine->pInternetSelfCureState->HandleRandMacSelfCureComplete(msg);

        MacAddress = CURR_BSSID;
        RealMacAddress = CURR_BSSID;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).
            WillRepeatedly(DoAll(SetArgReferee<0>(MacAddress), Return(0)));
        EXPECT_CALL(WifiSettings::GetInstance(), GetRealMacAddress(_, _)).
            WillRepeatedly(DoAll(SetArgReferee<0>(RealMacAddress), Return(0)));
        pSelfCureStateMachine->pInternetSelfCureState->HandleRandMacSelfCureComplete(msg);
    }

    void HandleInternetFailedSelfCureTest()
    {
        LOGI("Enter HandleInternetFailedSelfCureTest");
        pSelfCureStateMachine->pInternetSelfCureState->HandleInternetFailedSelfCure(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_INTERNET_FAILED_SELF_CURE);
        pSelfCureStateMachine->pInternetSelfCureState->HandleInternetFailedSelfCure(msg);

        WifiLinkedInfo wifiLinkedInfo;
        wifiLinkedInfo.connState = ConnState::CONNECTED;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));
        pSelfCureStateMachine->pInternetSelfCureState->HandleInternetFailedSelfCure(msg);
    }

    void HandleSelfCureWifiLinkTest()
    {
        LOGI("Enter HandleSelfCureWifiLinkTest");
        pSelfCureStateMachine->pInternetSelfCureState->HandleSelfCureWifiLink(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_SELF_CURE_WIFI_LINK);
        pSelfCureStateMachine->pInternetSelfCureState->HandleSelfCureWifiLink(msg);

        WifiLinkedInfo wifiLinkedInfo;
        wifiLinkedInfo.connState = ConnState::CONNECTED;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));
        pSelfCureStateMachine->pInternetSelfCureState->HandleSelfCureWifiLink(msg);
    }

    void HandleNetworkDisconnectedTest()
    {
        LOGI("Enter HandleNetworkDisconnectedTest");
        pSelfCureStateMachine->pInternetSelfCureState->HandleNetworkDisconnected(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_NOTIFY_NETWORK_DISCONNECTED_RCVD);
        pSelfCureStateMachine->pInternetSelfCureState->HandleNetworkDisconnected(msg);
    }

    void HandleInternetRecoveryTest()
    {
        LOGI("Enter HandleInternetRecoveryTest");
        pSelfCureStateMachine->pInternetSelfCureState->HandleInternetRecovery(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_INTERNET_RECOVERY_CONFIRM);
        pSelfCureStateMachine->pInternetSelfCureState->HandleInternetRecovery(msg);

        pSelfCureStateMachine->selfCureOnGoing = true;
        pSelfCureStateMachine->pInternetSelfCureState->HandleInternetRecovery(msg);
    }

    void HandleRssiChangedEventTest()
    {
        LOGI("Enter HandleRssiChangedEventTest");
        pSelfCureStateMachine->pInternetSelfCureState->HandleRssiChangedEvent(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_NOTIFY_RSSI_LEVEL_CHANGED_EVENT);
        pSelfCureStateMachine->pInternetSelfCureState->HandleRssiChangedEvent(msg);
    }

    void HandleP2pDisconnectedTest()
    {
        LOGI("Enter HandleP2pDisconnectedTest");
        pSelfCureStateMachine->pInternetSelfCureState->HandleP2pDisconnected(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_P2P_DISCONNECTED_EVENT);
        pSelfCureStateMachine->pInternetSelfCureState->HandleP2pDisconnected(msg);
    }

    void HandlePeriodicArpDetecteTest()
    {
        LOGI("Enter HandlePeriodicArpDetecteTest");
        pSelfCureStateMachine->pInternetSelfCureState->HandlePeriodicArpDetecte(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_PERIODIC_ARP_DETECTED);
        pSelfCureStateMachine->pInternetSelfCureState->HandlePeriodicArpDetecte(msg);
    }

    void HandleHttpReachableRecvTest()
    {
        LOGI("Enter HandleHttpReachableRecvTest");
        pSelfCureStateMachine->pInternetSelfCureState->HandleHttpReachableRecv(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_HTTP_REACHABLE_RCV);
        pSelfCureStateMachine->pInternetSelfCureState->HandleHttpReachableRecv(msg);
    }

    void HandleArpFailedDetectedTest()
    {
        LOGI("Enter HandleArpFailedDetectedTest");
        pSelfCureStateMachine->pInternetSelfCureState->HandleArpFailedDetected(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_ARP_FAILED_DETECTED);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifi6BlackListCache(_)).Times(AtLeast(0)).WillOnce(Return(0));
        WifiLinkedInfo wifiLinkedInfo;
        wifiLinkedInfo.supportedWifiCategory = WifiCategory::WIFI6;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));
        pSelfCureStateMachine->pInternetSelfCureState->HandleArpFailedDetected(msg);

        pSelfCureStateMachine->selfCureOnGoing = false;
        pSelfCureStateMachine->pInternetSelfCureState->HandleArpFailedDetected(msg);

        pSelfCureStateMachine->selfCureOnGoing = true;
        pSelfCureStateMachine->pInternetSelfCureState->HandleArpFailedDetected(msg);

        pSelfCureStateMachine->mIsHttpReachable = false;
        pSelfCureStateMachine->pInternetSelfCureState->HandleArpFailedDetected(msg);
        
        pSelfCureStateMachine->mIsHttpReachable = true;
        pSelfCureStateMachine->pInternetSelfCureState->HandleArpFailedDetected(msg);
    }

    void SelectSelfCureByFailedReasonTest()
    {
        LOGI("Enter SelectSelfCureByFailedReasonTest");
        int internetFailedType = WIFI_CURE_INTERNET_FAILED_TYPE_DNS;
        pSelfCureStateMachine->pInternetSelfCureState->userSetStaticIpConfig = true;
        pSelfCureStateMachine->pInternetSelfCureState->SelectSelfCureByFailedReason(internetFailedType);

        internetFailedType = WIFI_CURE_INTERNET_FAILED_TYPE_GATEWAY;
        pSelfCureStateMachine->pInternetSelfCureState->SelectSelfCureByFailedReason(internetFailedType);

        internetFailedType = WIFI_CURE_INTERNET_FAILED_TYPE_ROAMING;
        pSelfCureStateMachine->pInternetSelfCureState->SelectSelfCureByFailedReason(internetFailedType);

        internetFailedType = 0;
        pSelfCureStateMachine->pInternetSelfCureState->SelectSelfCureByFailedReason(internetFailedType);

        pSelfCureStateMachine->pInternetSelfCureState->userSetStaticIpConfig = false;
        internetFailedType = WIFI_CURE_INTERNET_FAILED_TYPE_DNS;
        pSelfCureStateMachine->pInternetSelfCureState->SelectSelfCureByFailedReason(internetFailedType);

        internetFailedType = WIFI_CURE_INTERNET_FAILED_TYPE_ROAMING;
        pSelfCureStateMachine->pInternetSelfCureState->SelectSelfCureByFailedReason(internetFailedType);

        internetFailedType = WIFI_CURE_INTERNET_FAILED_TYPE_TCP;
        pSelfCureStateMachine->pInternetSelfCureState->SelectSelfCureByFailedReason(internetFailedType);
        
        pSelfCureStateMachine->pInternetSelfCureState->selfCureHistoryInfo.resetSelfCureFailedCnt =
            SELFCURE_FAILED_CNT;
        pSelfCureStateMachine->UpdateSelfCureHistoryInfo(pSelfCureStateMachine->pInternetSelfCureState->
            selfCureHistoryInfo, WIFI_CURE_RESET_LEVEL_HIGH_RESET, false);
        pSelfCureStateMachine->pInternetSelfCureState->SelectSelfCureByFailedReason(internetFailedType);
    }

    void SelectBestSelfCureSolutionTest()
    {
        LOGI("Enter SelectBestSelfCureSolutionTest");
        int internetFailedType = WIFI_CURE_INTERNET_FAILED_TYPE_GATEWAY;
        pSelfCureStateMachine->pInternetSelfCureState->SelectBestSelfCureSolution(internetFailedType);
        pSelfCureStateMachine->pInternetSelfCureState->configAuthType = KEY_MGMT_WPA_PSK;
        pSelfCureStateMachine->pInternetSelfCureState->SelectBestSelfCureSolution(internetFailedType);
        pSelfCureStateMachine->connectedTime = 0;
        pSelfCureStateMachine->pInternetSelfCureState->lastHasInetTime = static_cast<int64_t>(time(nullptr));
        pSelfCureStateMachine->pInternetSelfCureState->SelectBestSelfCureSolution(internetFailedType);
    }

    void SelectBestSelfCureSolutionExtTest()
    {
        LOGI("Enter SelectBestSelfCureSolutionExtTest");
        int internetFailedType = WIFI_CURE_INTERNET_FAILED_INVALID_IP;
        pSelfCureStateMachine->pInternetSelfCureState->SelectBestSelfCureSolutionExt(internetFailedType);
        internetFailedType = WIFI_CURE_INTERNET_FAILED_TYPE_ROAMING;
        pSelfCureStateMachine->pInternetSelfCureState->SelectBestSelfCureSolutionExt(internetFailedType);
        internetFailedType = WIFI_CURE_INTERNET_FAILED_TYPE_DNS;
        pSelfCureStateMachine->pInternetSelfCureState->SelectBestSelfCureSolutionExt(internetFailedType);
        internetFailedType = WIFI_CURE_INTERNET_FAILED_RAND_MAC;
        pSelfCureStateMachine->pInternetSelfCureState->SelectBestSelfCureSolutionExt(internetFailedType);
        internetFailedType = WIFI_CURE_INTERNET_FAILED_TYPE_TCP;
        pSelfCureStateMachine->pInternetSelfCureState->SelectBestSelfCureSolutionExt(internetFailedType);
    }

    void GetNextTestDhcpResultsTest()
    {
        LOGI("Enter GetNextTestDhcpResultsTest");
        pSelfCureStateMachine->pInternetSelfCureState->GetNextTestDhcpResults();
    }

    void GetRecordDhcpResultsTest()
    {
        LOGI("Enter GetRecordDhcpResultsTest");
        pSelfCureStateMachine->pInternetSelfCureState->GetRecordDhcpResults();
    }

    void SelfCureWifiLinkTest()
    {
        LOGI("Enter SelfCureWifiLinkTest");
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetLastNetworkId(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiSelfcureReset(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiToggledState(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), AddDeviceConfig(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig()).Times(AtLeast(0));
        int requestCureLevel = 0;
        pSelfCureStateMachine->pInternetSelfCureState->SelfCureWifiLink(requestCureLevel);
        requestCureLevel = WIFI_CURE_RESET_LEVEL_LOW_2_RENEW_DHCP;
        pSelfCureStateMachine->pInternetSelfCureState->SelfCureWifiLink(requestCureLevel);
        requestCureLevel = WIFI_CURE_RESET_LEVEL_LOW_3_STATIC_IP;
        pSelfCureStateMachine->pInternetSelfCureState->SelfCureWifiLink(requestCureLevel);
        requestCureLevel = WIFI_CURE_RESET_LEVEL_RECONNECT_4_INVALID_IP;
        pSelfCureStateMachine->pInternetSelfCureState->SelfCureWifiLink(requestCureLevel);
        requestCureLevel = WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC;
        pSelfCureStateMachine->pInternetSelfCureState->SelfCureWifiLink(requestCureLevel);
        requestCureLevel = WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC;
        pSelfCureStateMachine->pInternetSelfCureState->SelfCureWifiLink(requestCureLevel);
        requestCureLevel = WIFI_CURE_RESET_LEVEL_HIGH_RESET;
        pSelfCureStateMachine->pInternetSelfCureState->SelfCureWifiLink(requestCureLevel);
    }

    void SelfCureForStaticIpTest()
    {
        LOGI("Enter SelfCureForStaticIpTest");
        int requestCureLevel = WIFI_CURE_RESET_LEVEL_LOW_3_STATIC_IP;
        pSelfCureStateMachine->pInternetSelfCureState->configStaticIp4MultiDhcpServer = true;
        pSelfCureStateMachine->pInternetSelfCureState->SelfCureForStaticIp(requestCureLevel);
        pSelfCureStateMachine->pInternetSelfCureState->configStaticIp4MultiDhcpServer = false;
        pSelfCureStateMachine->pInternetSelfCureState->SelfCureForStaticIp(requestCureLevel);
    }

    void RequestUseStaticIpConfigTest()
    {
        LOGI("Enter RequestUseStaticIpConfigTest");
        IpInfo dhcpResult;
        dhcpResult.ipAddress = IpTools::ConvertIpv4Address("192.168.101.39");
        dhcpResult.gateway = IpTools::ConvertIpv4Address("192.168.101.1");
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetStaIfaceName()).WillRepeatedly(Return("wlan0"));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        pSelfCureStateMachine->pInternetSelfCureState->RequestUseStaticIpConfig(dhcpResult);
    }

    void SelfCureForInvalidIpTest()
    {
        LOGI("Enter SelfCureForInvalidIpTest");
        pSelfCureStateMachine->pInternetSelfCureState->selfCureForInvalidIpCnt = 0;
        pSelfCureStateMachine->pInternetSelfCureState->SelfCureForInvalidIp();

        pSelfCureStateMachine->pInternetSelfCureState->selfCureForInvalidIpCnt = MAX_SELF_CURE_CNT_INVALID_IP + 1;
        pSelfCureStateMachine->pInternetSelfCureState->SelfCureForInvalidIp();

        pSelfCureStateMachine->pInternetSelfCureState->selfCureForInvalidIpCnt = 0;
        EXPECT_CALL(*pMockStaService, Disconnect()).WillRepeatedly(Return(WIFI_OPT_FAILED));
        pSelfCureStateMachine->pInternetSelfCureState->SelfCureForInvalidIp();

        EXPECT_CALL(*pMockStaService, Disconnect()).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
        pSelfCureStateMachine->pInternetSelfCureState->SelfCureForInvalidIp();
    }

    void SelfCureForReassocTest()
    {
        LOGI("Enter SelfCureForReassocTest");
        int requestCureLevel = WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC;
        pSelfCureStateMachine->pInternetSelfCureState->currentRssi = MIN_VAL_LEVEL_2_24G;
        pSelfCureStateMachine->pInternetSelfCureState->SelfCureForReassoc(requestCureLevel);

        WifiP2pLinkedInfo linkedInfo;
        linkedInfo.SetConnectState(P2pConnectedState::P2P_CONNECTED);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetP2pInfo(_))
            .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
        pSelfCureStateMachine->pInternetSelfCureState->SelfCureForReassoc(requestCureLevel);

        linkedInfo.SetConnectState(P2pConnectedState::P2P_DISCONNECTED);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetP2pInfo(_))
            .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
        pSelfCureStateMachine->pInternetSelfCureState->SelfCureForReassoc(requestCureLevel);

        pSelfCureStateMachine->pInternetSelfCureState->currentRssi = MIN_VAL_LEVEL_4;
        pSelfCureStateMachine->pInternetSelfCureState->SelfCureForReassoc(requestCureLevel);

        EXPECT_CALL(*pMockStaService, ReAssociate()).WillRepeatedly(Return(WIFI_OPT_FAILED));
        pSelfCureStateMachine->pInternetSelfCureState->SelfCureForReassoc(requestCureLevel);

        EXPECT_CALL(*pMockStaService, ReAssociate()).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
        pSelfCureStateMachine->pInternetSelfCureState->SelfCureForReassoc(requestCureLevel);
    }

    void IsNeedMultiGatewaySelfcureTest()
    {
        LOGI("Enter IsNeedMultiGatewaySelfcureTest");
        pSelfCureStateMachine->pInternetSelfCureState->IsNeedMultiGatewaySelfcure();
        pSelfCureStateMachine->pInternetSelfCureState->usedMultiGwSelfcure = true;
        pSelfCureStateMachine->pInternetSelfCureState->IsNeedMultiGatewaySelfcure();
    }

    void SelfcureForMultiGatewayTest()
    {
        LOGI("Enter SelfcureForMultiGatewayTest");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_MULTI_GATEWAY);
        WifiLinkedInfo linkedInfo;
        linkedInfo.connState = ConnState::DISCONNECTED;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
        pSelfCureStateMachine->pInternetSelfCureState->SelfcureForMultiGateway(msg);

        linkedInfo.connState = ConnState::CONNECTED;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
        pSelfCureStateMachine->pInternetSelfCureState->SelfcureForMultiGateway(msg);
    }

    void SelfCureForRandMacReassocTest()
    {
        LOGI("Enter SelfCureForRandMacReassocTest");
        int requestCureLevel = WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetLastNetworkId(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), AddDeviceConfig(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig()).Times(AtLeast(0));
        pSelfCureStateMachine->pInternetSelfCureState->SelfCureForRandMacReassoc(requestCureLevel);

        pSelfCureStateMachine->pInternetSelfCureState->currentRssi = MIN_VAL_LEVEL_2_24G;
        pSelfCureStateMachine->pInternetSelfCureState->SelfCureForRandMacReassoc(requestCureLevel);

        WifiP2pLinkedInfo linkedInfo;
        linkedInfo.SetConnectState(P2pConnectedState::P2P_CONNECTED);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetP2pInfo(_))
            .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
        pSelfCureStateMachine->pInternetSelfCureState->SelfCureForRandMacReassoc(requestCureLevel);

        linkedInfo.SetConnectState(P2pConnectedState::P2P_DISCONNECTED);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetP2pInfo(_))
            .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
        pSelfCureStateMachine->pInternetSelfCureState->SelfCureForRandMacReassoc(requestCureLevel);

        pSelfCureStateMachine->pInternetSelfCureState->currentRssi = MIN_VAL_LEVEL_4;
        pSelfCureStateMachine->pInternetSelfCureState->SelfCureForRandMacReassoc(requestCureLevel);

        EXPECT_CALL(*pMockStaService, ConnectToNetwork(_)).WillRepeatedly(Return(WIFI_OPT_FAILED));
        pSelfCureStateMachine->pInternetSelfCureState->SelfCureForRandMacReassoc(requestCureLevel);

        EXPECT_CALL(*pMockStaService, ConnectToNetwork(_)).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
        pSelfCureStateMachine->pInternetSelfCureState->SelfCureForRandMacReassoc(requestCureLevel);
    }

    void SelectedSelfCureAcceptableTest()
    {
        LOGI("Enter SelectedSelfCureAcceptableTest");
        pSelfCureStateMachine->pInternetSelfCureState->currentAbnormalType = WIFI_CURE_INTERNET_FAILED_TYPE_DNS;
        pSelfCureStateMachine->pInternetSelfCureState->SelectedSelfCureAcceptable();

        pSelfCureStateMachine->pInternetSelfCureState->currentAbnormalType = WIFI_CURE_INTERNET_FAILED_TYPE_GATEWAY;
        pSelfCureStateMachine->pInternetSelfCureState->SelectedSelfCureAcceptable();
        
        pSelfCureStateMachine->pInternetSelfCureState->selfCureHistoryInfo.dnsSelfCureFailedCnt =
            SELFCURE_FAILED_CNT;
        pSelfCureStateMachine->UpdateSelfCureHistoryInfo(pSelfCureStateMachine->pInternetSelfCureState->
            selfCureHistoryInfo, WIFI_CURE_RESET_LEVEL_LOW_1_DNS, false);
        pSelfCureStateMachine->pInternetSelfCureState->SelectedSelfCureAcceptable();

        pSelfCureStateMachine->pInternetSelfCureState->currentAbnormalType = WIFI_CURE_INTERNET_FAILED_TYPE_TCP;
        pSelfCureStateMachine->pInternetSelfCureState->SelectedSelfCureAcceptable();

        pSelfCureStateMachine->pInternetSelfCureState->selfCureHistoryInfo.reassocSelfCureFailedCnt =
            SELFCURE_FAILED_CNT;
        pSelfCureStateMachine->UpdateSelfCureHistoryInfo(pSelfCureStateMachine->pInternetSelfCureState->
            selfCureHistoryInfo, WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC, false);
        pSelfCureStateMachine->pInternetSelfCureState->SelectedSelfCureAcceptable();

        pSelfCureStateMachine->pInternetSelfCureState->currentAbnormalType = 0;
        pSelfCureStateMachine->pInternetSelfCureState->SelectedSelfCureAcceptable();
    }

    void HandleInternetFailedAndUserSetStaticIpTest()
    {
        LOGI("Enter HandleInternetFailedAndUserSetStaticIpTest");
        int internetFailedType = WIFI_CURE_INTERNET_FAILED_TYPE_DNS;
        pSelfCureStateMachine->pInternetSelfCureState->hasInternetRecently = true;
        pSelfCureStateMachine->pInternetSelfCureState->HandleInternetFailedAndUserSetStaticIp(internetFailedType);

        internetFailedType = WIFI_CURE_INTERNET_FAILED_TYPE_ROAMING;
        pSelfCureStateMachine->pInternetSelfCureState->HandleInternetFailedAndUserSetStaticIp(internetFailedType);

        internetFailedType = WIFI_CURE_INTERNET_FAILED_TYPE_GATEWAY;
        pSelfCureStateMachine->pInternetSelfCureState->HandleInternetFailedAndUserSetStaticIp(internetFailedType);

        pSelfCureStateMachine->pInternetSelfCureState->selfCureHistoryInfo.resetSelfCureFailedCnt =
            SELFCURE_FAILED_CNT;
        pSelfCureStateMachine->UpdateSelfCureHistoryInfo(pSelfCureStateMachine->pInternetSelfCureState->
            selfCureHistoryInfo, WIFI_CURE_RESET_LEVEL_HIGH_RESET, false);
        pSelfCureStateMachine->pInternetSelfCureState->HandleInternetFailedAndUserSetStaticIp(internetFailedType);

        pSelfCureStateMachine->pInternetSelfCureState->hasInternetRecently = false;
        pSelfCureStateMachine->internetUnknown = true;
        pSelfCureStateMachine->pInternetSelfCureState->HandleInternetFailedAndUserSetStaticIp(internetFailedType);

        pSelfCureStateMachine->internetUnknown = false;
        pSelfCureStateMachine->pInternetSelfCureState->HandleInternetFailedAndUserSetStaticIp(internetFailedType);
    }

    void HandleIpConfigTimeoutTest()
    {
        LOGI("Enter HandleIpConfigTimeoutTest");
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScanInfoList(_)).Times(AtLeast(0));
        pSelfCureStateMachine->pInternetSelfCureState->HandleIpConfigTimeout();

        pSelfCureStateMachine->pInternetSelfCureState->currentAbnormalType = WIFI_CURE_INTERNET_FAILED_TYPE_ROAMING;
        pSelfCureStateMachine->pInternetSelfCureState->configAuthType = KEY_MGMT_WPA_PSK;
        pSelfCureStateMachine->pInternetSelfCureState->finalSelfCureUsed = false;
        pSelfCureStateMachine->pInternetSelfCureState->HandleIpConfigTimeout();

        pSelfCureStateMachine->pInternetSelfCureState->currentAbnormalType = 0;
        pSelfCureStateMachine->pInternetSelfCureState->HandleIpConfigTimeout();
    }

    void HandleIpConfigCompletedTest()
    {
        LOGI("Enter HandleIpConfigCompletedTest");
        pSelfCureStateMachine->pInternetSelfCureState->HandleIpConfigCompleted();
    }

    void HandleIpConfigCompletedAfterRenewDhcpTest()
    {
        LOGI("Enter HandleIpConfigCompletedAfterRenewDhcpTest");
        pSelfCureStateMachine->pInternetSelfCureState->HandleIpConfigCompletedAfterRenewDhcp();
    }

    void HandleInternetRecoveryConfirmTest()
    {
        LOGI("Enter HandleInternetRecoveryConfirmTest");
        pSelfCureStateMachine->pInternetSelfCureState->HandleInternetRecoveryConfirm();
        pSelfCureStateMachine->pInternetSelfCureState->currentSelfCureLevel = WIFI_CURE_RESET_LEVEL_IDLE;
        pSelfCureStateMachine->pInternetSelfCureState->HandleInternetRecoveryConfirm();

        pSelfCureStateMachine->pInternetSelfCureState->currentSelfCureLevel = WIFI_CURE_RESET_LEVEL_LOW_1_DNS;
        pSelfCureStateMachine->mIsHttpReachable = true;
        pSelfCureStateMachine->internetUnknown = true;
        pSelfCureStateMachine->pInternetSelfCureState->HandleInternetRecoveryConfirm();
    }

    void ConfirmInternetSelfCureTest()
    {
        LOGI("Enter ConfirmInternetSelfCureTest");
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetRealMacAddress(_, _)).Times(testing::AtLeast(0));
        int currentCureLevel = WIFI_CURE_RESET_LEVEL_IDLE;
        pSelfCureStateMachine->pInternetSelfCureState->ConfirmInternetSelfCure(currentCureLevel);
        
        pSelfCureStateMachine->mIsHttpReachable = true;
        pSelfCureStateMachine->pInternetSelfCureState->currentSelfCureLevel = WIFI_CURE_RESET_LEVEL_LOW_1_DNS;
        pSelfCureStateMachine->internetUnknown = true;

        currentCureLevel = WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC;
        pSelfCureStateMachine->useWithRandMacAddress = FAC_MAC_REASSOC;
        pSelfCureStateMachine->pInternetSelfCureState->ConfirmInternetSelfCure(currentCureLevel);
        
        pSelfCureStateMachine->useWithRandMacAddress = RAND_MAC_REASSOC;
        pSelfCureStateMachine->pInternetSelfCureState->ConfirmInternetSelfCure(currentCureLevel);
        
        pSelfCureStateMachine->mIsHttpReachable = false;
        pSelfCureStateMachine->internetUnknown = true;
        pSelfCureStateMachine->pInternetSelfCureState->ConfirmInternetSelfCure(currentCureLevel);
        pSelfCureStateMachine->internetUnknown = false;
        pSelfCureStateMachine->pInternetSelfCureState->ConfirmInternetSelfCure(currentCureLevel);

        pSelfCureStateMachine->pInternetSelfCureState->finalSelfCureUsed = true;
        pSelfCureStateMachine->pInternetSelfCureState->ConfirmInternetSelfCure(currentCureLevel);

        pSelfCureStateMachine->pInternetSelfCureState->finalSelfCureUsed = false;
        pSelfCureStateMachine->pInternetSelfCureState->ConfirmInternetSelfCure(currentCureLevel);
    }

    void HandleConfirmInternetSelfCureFailedTest()
    {
        LOGI("Enter ConfirmInternetSelfCureFailedTest");
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetRealMacAddress(_, _)).Times(AtLeast(0));
        int currentCureLevel = WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC;
        pSelfCureStateMachine->internetUnknown = true;
        pSelfCureStateMachine->pInternetSelfCureState->HandleConfirmInternetSelfCureFailed(currentCureLevel);
        pSelfCureStateMachine->internetUnknown = false;
        pSelfCureStateMachine->pInternetSelfCureState->HandleConfirmInternetSelfCureFailed(currentCureLevel);
        pSelfCureStateMachine->pInternetSelfCureState->finalSelfCureUsed = true;
        pSelfCureStateMachine->pInternetSelfCureState->HandleConfirmInternetSelfCureFailed(currentCureLevel);
        pSelfCureStateMachine->pInternetSelfCureState->finalSelfCureUsed = false;
        pSelfCureStateMachine->pInternetSelfCureState->HandleConfirmInternetSelfCureFailed(currentCureLevel);
        currentCureLevel = WIFI_CURE_RESET_LEVEL_LOW_3_STATIC_IP;
        pSelfCureStateMachine->pInternetSelfCureState->HandleConfirmInternetSelfCureFailed(currentCureLevel);
    }

    void HandleSelfCureFailedForRandMacReassocTest()
    {
        LOGI("Enter HandleSelfCureFailedForRandMacReassocTest");
        std::string MacAddress = CURR_BSSID;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetLastNetworkId(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).
            WillRepeatedly(DoAll(SetArgReferee<0>(MacAddress), Return(0)));
        EXPECT_CALL(WifiSettings::GetInstance(), GetRealMacAddress(_, _)).
            WillRepeatedly(DoAll(SetArgReferee<0>(MacAddress), Return(0)));
        pSelfCureStateMachine->useWithRandMacAddress = RAND_MAC_REASSOC;
        pSelfCureStateMachine->pInternetSelfCureState->HandleSelfCureFailedForRandMacReassoc();
        pSelfCureStateMachine->useWithRandMacAddress = FAC_MAC_REASSOC;
        pSelfCureStateMachine->pInternetSelfCureState->HandleSelfCureFailedForRandMacReassoc();

        EXPECT_CALL(*pMockStaService, ConnectToNetwork(_)).WillRepeatedly(Return(WIFI_OPT_FAILED));
        pSelfCureStateMachine->pInternetSelfCureState->HandleSelfCureFailedForRandMacReassoc();

        EXPECT_CALL(*pMockStaService, ConnectToNetwork(_)).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
        pSelfCureStateMachine->pInternetSelfCureState->HandleSelfCureFailedForRandMacReassoc();

        pSelfCureStateMachine->useWithRandMacAddress = RAND_MAC_REASSOC;
        pSelfCureStateMachine->pInternetSelfCureState->HandleSelfCureFailedForRandMacReassoc();
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetRealMacAddress(_, _)).Times(AtLeast(0));
    }

    void HandleHttpReachableAfterSelfCureTest()
    {
        LOGI("Enter HandleHttpReachableAfterSelfCureTest");
        pSelfCureStateMachine->pInternetSelfCureState->setStaticIp4InvalidIp = true;
        int currentCureLevel = 1;
        pSelfCureStateMachine->pInternetSelfCureState->HandleHttpReachableAfterSelfCure(currentCureLevel);

        pSelfCureStateMachine->pInternetSelfCureState->setStaticIp4InvalidIp = false;
        pSelfCureStateMachine->pInternetSelfCureState->HandleHttpReachableAfterSelfCure(currentCureLevel);

        currentCureLevel = WIFI_CURE_RESET_LEVEL_LOW_3_STATIC_IP;
        pSelfCureStateMachine->pInternetSelfCureState->HandleHttpReachableAfterSelfCure(currentCureLevel);

        pSelfCureStateMachine->pInternetSelfCureState->setStaticIp4InvalidIp = true;
        pSelfCureStateMachine->pInternetSelfCureState->HandleHttpReachableAfterSelfCure(currentCureLevel);
    }

    void HandleHttpUnreachableFinallyTest()
    {
        LOGI("Enter HandleHttpUnreachableFinallyTest");
        pSelfCureStateMachine->pInternetSelfCureState->HandleHttpUnreachableFinally();
    }

    void HasBeenTestedTest()
    {
        LOGI("Enter HasBeenTestedTest");
        int cureLevel = 1;
        pSelfCureStateMachine->pInternetSelfCureState->testedSelfCureLevel = {0, 1};
        EXPECT_TRUE(pSelfCureStateMachine->pInternetSelfCureState->HasBeenTested(cureLevel));
        cureLevel = WIFI_CURE_RESET_LEVEL_HIGH_RESET;
        EXPECT_FALSE(pSelfCureStateMachine->pInternetSelfCureState->HasBeenTested(cureLevel));
    }

    void HandleRssiChangedTest()
    {
        LOGI("Enter HandleRssiChangedTest");
        pSelfCureStateMachine->pInternetSelfCureState->currentRssi = MIN_VAL_LEVEL_2_5G;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScreenState()).Times(AtLeast(0));
        WifiP2pLinkedInfo linkedInfo;
        linkedInfo.SetConnectState(P2pConnectedState::P2P_DISCONNECTED);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetP2pInfo(_))
            .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
        pSelfCureStateMachine->notAllowSelfcure = false;
        pSelfCureStateMachine->pInternetSelfCureState->HandleRssiChanged();

        pSelfCureStateMachine->notAllowSelfcure = true;
        pSelfCureStateMachine->pInternetSelfCureState->HandleRssiChanged();

        linkedInfo.SetConnectState(P2pConnectedState::P2P_CONNECTED);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetP2pInfo(_))
            .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
        pSelfCureStateMachine->pInternetSelfCureState->HandleRssiChanged();

        pSelfCureStateMachine->pInternetSelfCureState->currentRssi = MIN_VAL_LEVEL_4;
        pSelfCureStateMachine->pInternetSelfCureState->delayedResetSelfCure = true;
        pSelfCureStateMachine->pInternetSelfCureState->HandleRssiChanged();
        pSelfCureStateMachine->pInternetSelfCureState->delayedResetSelfCure = false;
        pSelfCureStateMachine->pInternetSelfCureState->HandleRssiChanged();

        pSelfCureStateMachine->selfCureOnGoing = false;
        pSelfCureStateMachine->pInternetSelfCureState->delayedReassocSelfCure = true;
        pSelfCureStateMachine->pInternetSelfCureState->delayedRandMacReassocSelfCure = true;
        pSelfCureStateMachine->mIsHttpReachable = true;
        pSelfCureStateMachine->pInternetSelfCureState->HandleRssiChanged();

        pSelfCureStateMachine->mIsHttpReachable = false;
        pSelfCureStateMachine->pInternetSelfCureState->HandleRssiChanged();

        pSelfCureStateMachine->pInternetSelfCureState->delayedReassocSelfCure = true;
        pSelfCureStateMachine->pInternetSelfCureState->delayedRandMacReassocSelfCure = false;
        pSelfCureStateMachine->pInternetSelfCureState->HandleRssiChanged();

        pSelfCureStateMachine->pInternetSelfCureState->delayedReassocSelfCure = false;
        pSelfCureStateMachine->pInternetSelfCureState->delayedRandMacReassocSelfCure = true;
        pSelfCureStateMachine->pInternetSelfCureState->HandleRssiChanged();
    }

    void HandleDelayedResetSelfCureTest()
    {
        LOGI("Enter HandleDelayedResetSelfCureTest");
        pSelfCureStateMachine->mIsHttpReachable = false;
        pSelfCureStateMachine->pInternetSelfCureState->HandleDelayedResetSelfCure();
        pSelfCureStateMachine->mIsHttpReachable = true;
        pSelfCureStateMachine->pInternetSelfCureState->HandleDelayedResetSelfCure();
    }

    void Wifi6SelfCureStateGoInStateSuccess()
    {
        LOGI("Enter Wifi6SelfCureStateGoInStateSuccess");
        pSelfCureStateMachine->pWifi6SelfCureState->GoInState();
    }

    void Wifi6SelfCureStateGoOutStateSuccess()
    {
        LOGI("Enter Wifi6SelfCureStateGoOutStateSuccess");
        pSelfCureStateMachine->pWifi6SelfCureState->GoOutState();
    }

    void InitExeMsgFail()
    {
        LOGI("Enter InitExeMsgFail");
        EXPECT_FALSE(pSelfCureStateMachine->pWifi6SelfCureState->ExecuteStateMsg(nullptr));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(0);
        EXPECT_FALSE(pSelfCureStateMachine->pWifi6SelfCureState->ExecuteStateMsg(msg));
    }

    void InitExeMsgSuccess1()
    {
        LOGI("Enter InitExeMsgSuccess1");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_WIFI6_SELFCURE);
        EXPECT_TRUE(pSelfCureStateMachine->pWifi6SelfCureState->ExecuteStateMsg(msg));
    }

    void InitExeMsgSuccess2()
    {
        LOGI("Enter InitExeMsgSuccess2");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_WIFI6_BACKOFF_SELFCURE);
        EXPECT_TRUE(pSelfCureStateMachine->pWifi6SelfCureState->ExecuteStateMsg(msg));
    }

    void CanArpReachableFailedTest()
    {
        LOGI("Enter CanArpReachableFailedTest");
        IpInfo ipInfo;
        ipInfo.gateway = 0;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(ipInfo), Return(0)));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetStaIfaceName()).WillRepeatedly(Return("sta"));
        EXPECT_FALSE(pSelfCureStateMachine->CanArpReachable());
    }

    void CanArpReachableTest()
    {
        LOGI("Enter CanArpReachableTest");
        IpInfo ipInfo;
        ipInfo.gateway = 1;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(ipInfo), Return(0)));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetStaIfaceName()).WillRepeatedly(Return("sta"));
        EXPECT_FALSE(pSelfCureStateMachine->CanArpReachable());
    }

    void InitExeMsgSuccess3()
    {
        LOGI("Enter InitExeMsgSuccess3");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_WIFI6_WITH_HTC_PERIODIC_ARP_DETECTED);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiSelfcureReset(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetStaIfaceName()).WillRepeatedly(Return("sta"));
        EXPECT_TRUE(pSelfCureStateMachine->pWifi6SelfCureState->ExecuteStateMsg(msg));
    }

    void InitExeMsgSuccess4()
    {
        LOGI("Enter InitExeMsgSuccess4");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_WIFI6_WITHOUT_HTC_PERIODIC_ARP_DETECTED);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiSelfcureReset(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetStaIfaceName()).WillRepeatedly(Return("sta"));
        EXPECT_TRUE(pSelfCureStateMachine->pWifi6SelfCureState->ExecuteStateMsg(msg));
    }

    void InitExeMsgSuccess5()
    {
        LOGI("Enter InitExeMsgSuccess5");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_WIFI6_WITH_HTC_ARP_FAILED_DETECTED);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), InsertWifi6BlackListCache(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), RemoveWifi6BlackListCache(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifi6BlackListCache(_)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_TRUE(pSelfCureStateMachine->pWifi6SelfCureState->ExecuteStateMsg(msg));
    }

    void InitExeMsgSuccess6()
    {
        LOGI("Enter InitExeMsgSuccess6");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_WIFI6_WITHOUT_HTC_ARP_FAILED_DETECTED);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), InsertWifi6BlackListCache(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), RemoveWifi6BlackListCache(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifi6BlackListCache(_)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_TRUE(pSelfCureStateMachine->pWifi6SelfCureState->ExecuteStateMsg(msg));
    }

    void PeriodicWifi6WithHtcArpDetectTest()
    {
        LOGI("Enter PeriodicWifi6WithHtcArpDetectTest");
        pSelfCureStateMachine->pWifi6SelfCureState->PeriodicWifi6WithHtcArpDetect(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_WIFI6_WITH_HTC_PERIODIC_ARP_DETECTED);
        pSelfCureStateMachine->pWifi6SelfCureState->PeriodicWifi6WithHtcArpDetect(msg);

        IpInfo ipInfo;
        ipInfo.gateway = 0;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(ipInfo), Return(0)));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetStaIfaceName()).WillRepeatedly(Return("sta"));
        pSelfCureStateMachine->pWifi6SelfCureState->PeriodicWifi6WithHtcArpDetect(msg);

        pSelfCureStateMachine->pWifi6SelfCureState->wifi6HtcArpDetectionFailedCnt = ARP_DETECTED_FAILED_COUNT - 1;
        pSelfCureStateMachine->pWifi6SelfCureState->PeriodicWifi6WithHtcArpDetect(msg);
    }

    void PeriodicWifi6WithoutHtcArpDetectTest()
    {
        LOGI("Enter PeriodicWifi6WithoutHtcArpDetectTest");
        pSelfCureStateMachine->pWifi6SelfCureState->PeriodicWifi6WithoutHtcArpDetect(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_WIFI6_WITHOUT_HTC_PERIODIC_ARP_DETECTED);
        pSelfCureStateMachine->pWifi6SelfCureState->PeriodicWifi6WithoutHtcArpDetect(msg);

        IpInfo ipInfo;
        ipInfo.gateway = 0;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(ipInfo), Return(0)));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetStaIfaceName()).WillRepeatedly(Return("sta"));
        pSelfCureStateMachine->pWifi6SelfCureState->PeriodicWifi6WithoutHtcArpDetect(msg);

        pSelfCureStateMachine->pWifi6SelfCureState->wifi6ArpDetectionFailedCnt = ARP_DETECTED_FAILED_COUNT - 1;
        pSelfCureStateMachine->pWifi6SelfCureState->PeriodicWifi6WithoutHtcArpDetect(msg);
    }

    void HandleWifi6WithHtcArpFailTest()
    {
        LOGI("Enter HandleWifi6WithHtcArpFailTest");
        pSelfCureStateMachine->pWifi6SelfCureState->HandleWifi6WithHtcArpFail(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_WIFI6_WITH_HTC_ARP_FAILED_DETECTED);
        pSelfCureStateMachine->pWifi6SelfCureState->HandleWifi6WithHtcArpFail(msg);

        WifiDeviceConfig config;
        config.bssid = CURR_BSSID;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<1>(config), Return(0)));
        pSelfCureStateMachine->pWifi6SelfCureState->HandleWifi6WithHtcArpFail(msg);
    }

    void HandleWifi6WithoutHtcArpFailTest()
    {
        LOGI("Enter HandleWifi6WithoutHtcArpFailTest");
        pSelfCureStateMachine->pWifi6SelfCureState->HandleWifi6WithoutHtcArpFail(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_WIFI6_WITHOUT_HTC_ARP_FAILED_DETECTED);
        pSelfCureStateMachine->pWifi6SelfCureState->HandleWifi6WithoutHtcArpFail(msg);
    }

    void GetNowMilliSecondsTest()
    {
        LOGI("Enter GetNowMilliSecondsTest");
        pSelfCureStateMachine->GetNowMilliSeconds();
    }

    void SendBlaListToDriverTest()
    {
        LOGI("Enter SendBlaListToDriverTest");
        std::map<std::string, Wifi6BlackListInfo> wifi6BlackListCache = {};
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifi6BlackListCache(_))
            .WillRepeatedly(DoAll(SetArgReferee<0>(wifi6BlackListCache), Return(0)));
        pSelfCureStateMachine->SendBlaListToDriver();
    }

    void SendBlaListToDriverTest2()
    {
        LOGI("Enter SendBlaListToDriverTest2");
        std::map<std::string, Wifi6BlackListInfo> wifi6BlackListCache;
        std::string currentBssid = CURR_BSSID;
        Wifi6BlackListInfo wifi6BlackListInfo(1, TIME_MILLS);
        wifi6BlackListCache.emplace(std::make_pair(currentBssid, wifi6BlackListInfo));

        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifi6BlackListCache(_))
            .WillRepeatedly(DoAll(SetArgReferee<0>(wifi6BlackListCache), Return(0)));
        pSelfCureStateMachine->SendBlaListToDriver();
    }

    void BlackListToStringTest()
    {
        LOGI("Enter BlackListToStringTest");
        std::map<std::string, Wifi6BlackListInfo> wifi6BlackListCache = {};
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifi6BlackListCache(_))
            .WillRepeatedly(DoAll(SetArgReferee<0>(wifi6BlackListCache), Return(0)));
        pSelfCureStateMachine->BlackListToString(wifi6BlackListCache);
    }

    void BlackListToStringTest2()
    {
        LOGI("Enter BlackListToStringTest2");
        std::map<std::string, Wifi6BlackListInfo> wifi6BlackListCache;
        std::string currentBssid = CURR_BSSID;
        Wifi6BlackListInfo wifi6BlackListInfo(1, TIME_MILLS);
        wifi6BlackListCache.emplace(std::make_pair(currentBssid, wifi6BlackListInfo));

        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifi6BlackListCache(_))
            .WillRepeatedly(DoAll(SetArgReferee<0>(wifi6BlackListCache), Return(0)));
        pSelfCureStateMachine->BlackListToString(wifi6BlackListCache);
    }

    void ParseWifi6BlackListInfoTest()
    {
        LOGI("Enter ParseWifi6BlackListInfoTest");
        std::string currentBssid = CURR_BSSID;
        Wifi6BlackListInfo wifi6BlackListInfo(1, TIME_MILLS);
        std::pair<std::string, Wifi6BlackListInfo> iter = std::make_pair(CURR_BSSID, wifi6BlackListInfo);
        pSelfCureStateMachine->ParseWifi6BlackListInfo(iter);

        iter = std::make_pair("", wifi6BlackListInfo);
        pSelfCureStateMachine->ParseWifi6BlackListInfo(iter);
    }

    void AgeOutWifi6BlackTest()
    {
        LOGI("Enter AgeOutWifi6BlackTest");
        std::map<std::string, Wifi6BlackListInfo> wifi6BlackListCache;
        std::string currentBssid = CURR_BSSID;
        Wifi6BlackListInfo wifi6BlackListInfo(1, TIME_MILLS);
        wifi6BlackListCache.emplace(std::make_pair(currentBssid, wifi6BlackListInfo));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), RemoveWifi6BlackListCache(_)).Times(AtLeast(0));
        pSelfCureStateMachine->AgeOutWifi6Black(wifi6BlackListCache);

        wifi6BlackListCache.emplace(std::make_pair("1", wifi6BlackListInfo));
        wifi6BlackListCache.emplace(std::make_pair("2", wifi6BlackListInfo));
        wifi6BlackListCache.emplace(std::make_pair("3", wifi6BlackListInfo));
        wifi6BlackListCache.emplace(std::make_pair("4", wifi6BlackListInfo));
        wifi6BlackListCache.emplace(std::make_pair("5", wifi6BlackListInfo));
        wifi6BlackListCache.emplace(std::make_pair("6", wifi6BlackListInfo));
        wifi6BlackListCache.emplace(std::make_pair("7", wifi6BlackListInfo));
        wifi6BlackListCache.emplace(std::make_pair("8", wifi6BlackListInfo));
        wifi6BlackListCache.emplace(std::make_pair("9", wifi6BlackListInfo));
        wifi6BlackListCache.emplace(std::make_pair("10", wifi6BlackListInfo));
        wifi6BlackListCache.emplace(std::make_pair("11", wifi6BlackListInfo));
        wifi6BlackListCache.emplace(std::make_pair("12", wifi6BlackListInfo));
        wifi6BlackListCache.emplace(std::make_pair("13", wifi6BlackListInfo));
        wifi6BlackListCache.emplace(std::make_pair("14", wifi6BlackListInfo));
        wifi6BlackListCache.emplace(std::make_pair("15", wifi6BlackListInfo));
        wifi6BlackListCache.emplace(std::make_pair("16", wifi6BlackListInfo));
        pSelfCureStateMachine->AgeOutWifi6Black(wifi6BlackListCache);
    }

    void ShouldTransToWifi6SelfCureTest()
    {
        LOGI("Enter ShouldTransToWifi6SelfCureTest");
        std::string currConnectedBssid = "";
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(1);
        EXPECT_FALSE(pSelfCureStateMachine->ShouldTransToWifi6SelfCure(msg, currConnectedBssid));
    }

    void ShouldTransToWifi6SelfCureTest2()
    {
        LOGI("Enter ShouldTransToWifi6SelfCureTest2");
        std::string currConnectedBssid = CURR_BSSID;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScanInfoList(_)).Times(AtLeast(0));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(1);
        EXPECT_FALSE(pSelfCureStateMachine->ShouldTransToWifi6SelfCure(msg, currConnectedBssid));

        currConnectedBssid = CURR_BSSID;
        WifiLinkedInfo wifiLinkedInfo;
        wifiLinkedInfo.supportedWifiCategory = WifiCategory::DEFAULT;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));
        pSelfCureStateMachine->ShouldTransToWifi6SelfCure(msg, currConnectedBssid);

        pSelfCureStateMachine->isWifi6ArpSuccess = true;
        pSelfCureStateMachine->ShouldTransToWifi6SelfCure(msg, currConnectedBssid);

        wifiLinkedInfo.rssi = MIN_VAL_LEVEL_2_5G;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));
        pSelfCureStateMachine->ShouldTransToWifi6SelfCure(msg, currConnectedBssid);
    }

    void GetCurrentBssidTest()
    {
        LOGI("Enter GetCurrentBssidTest");
        std::string currConnectedBssid = "";
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        pSelfCureStateMachine->GetCurrentBssid();
    }

    void IsWifi6NetworkTest()
    {
        LOGI("Enter IsWifi6NetworkTest");
        std::string currConnectedBssid = "";
        EXPECT_FALSE(pSelfCureStateMachine->IsWifi6Network(currConnectedBssid));
    }

    void IsWifi6NetworkTest2()
    {
        LOGI("Enter IsWifi6NetworkTest2");
        std::string currConnectedBssid = CURR_BSSID;
        WifiLinkedInfo wifiLinkedInfo;
        wifiLinkedInfo.supportedWifiCategory = WifiCategory::DEFAULT;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));
        EXPECT_FALSE(pSelfCureStateMachine->IsWifi6Network(currConnectedBssid));
    }

    void IsWifi6NetworkTest3()
    {
        LOGI("Enter IsWifi6NetworkTest3");
        std::string currConnectedBssid = CURR_BSSID;
        WifiLinkedInfo wifiLinkedInfo;
        wifiLinkedInfo.supportedWifiCategory = WifiCategory::WIFI6;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));
        EXPECT_TRUE(pSelfCureStateMachine->IsWifi6Network(currConnectedBssid));
    }

    void DisconnectedExeMsgSuccess0()
    {
        LOGI("Enter DisconnectedExeMsgSuccess0");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_OPEN_WIFI_SUCCEED_RESET);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiSelfcureReset()).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScreenState()).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLastNetworkId()).Times(AtLeast(0));
        EXPECT_TRUE(pSelfCureStateMachine->pDisconnectedMonitorState->ExecuteStateMsg(msg));
    }

    void HandleResetConnectNetworkTest()
    {
        LOGI("Enter HandleResetConnectNetworkTest");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_OPEN_WIFI_SUCCEED_RESET);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiSelfcureReset()).Times(AtLeast(0)).WillOnce(Return(false));
        pSelfCureStateMachine->pDisconnectedMonitorState->HandleResetConnectNetwork(msg);

        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiSelfcureReset()).Times(AtLeast(0)).WillOnce(Return(true));
        pSelfCureStateMachine->connectNetworkRetryCnt = 0;
        pSelfCureStateMachine->pDisconnectedMonitorState->HandleResetConnectNetwork(msg);

        pSelfCureStateMachine->connectNetworkRetryCnt = CONNECT_NETWORK_RETRY_CNT;
        pSelfCureStateMachine->pDisconnectedMonitorState->HandleResetConnectNetwork(msg);

        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScreenState()).Times(AtLeast(0)).WillOnce(
            Return(MODE_STATE_OPEN));
        pSelfCureStateMachine->pDisconnectedMonitorState->HandleResetConnectNetwork(msg);

        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScreenState()).Times(AtLeast(0)).WillOnce(
            Return(MODE_STATE_CLOSE));
        pSelfCureStateMachine->pDisconnectedMonitorState->HandleResetConnectNetwork(msg);

        EXPECT_CALL(*pMockStaService, ConnectToNetwork(_)).WillRepeatedly(Return(WIFI_OPT_FAILED));
        pSelfCureStateMachine->pDisconnectedMonitorState->HandleResetConnectNetwork(msg);

        EXPECT_CALL(*pMockStaService, ConnectToNetwork(_)).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
        pSelfCureStateMachine->pDisconnectedMonitorState->HandleResetConnectNetwork(msg);
    }

    void HandleResetConnectNetworkTest2()
    {
        LOGI("Enter HandleResetConnectNetworkTest2");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_OPEN_WIFI_SUCCEED_RESET);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiSelfcureReset()).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScreenState()).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLastNetworkId()).Times(AtLeast(0));
        pSelfCureStateMachine->pDisconnectedMonitorState->HandleResetConnectNetwork(msg);
    }

    void HandleResetConnectNetworkTest3()
    {
        LOGI("Enter HandleResetConnectNetworkTest3");
        pSelfCureStateMachine->pDisconnectedMonitorState->HandleResetConnectNetwork(nullptr);
    }

    void SelfCureForResetTest()
    {
        LOGI("Enter SelfCureForResetTest");
        int requestCureLevel = WIFI_CURE_RESET_LEVEL_HIGH_RESET;
        pSelfCureStateMachine->internetUnknown = true;
        pSelfCureStateMachine->pInternetSelfCureState->SelfCureForReset(requestCureLevel);
    }

    void SelfCureForResetTest2()
    {
        LOGI("Enter SelfCureForResetTest2");
        int requestCureLevel = WIFI_CURE_RESET_LEVEL_HIGH_RESET;
        pSelfCureStateMachine->internetUnknown = false;
        pSelfCureStateMachine->pInternetSelfCureState->hasInternetRecently = false;
        pSelfCureStateMachine->pInternetSelfCureState->SelfCureForReset(requestCureLevel);
    }

    void SelfCureForResetTest3()
    {
        LOGI("Enter SelfCureForResetTest3");
        int requestCureLevel = WIFI_CURE_RESET_LEVEL_HIGH_RESET;
        pSelfCureStateMachine->internetUnknown = false;
        pSelfCureStateMachine->pInternetSelfCureState->hasInternetRecently = true;
        pSelfCureStateMachine->pInternetSelfCureState->currentRssi = MIN_VAL_LEVEL_2_5G;
        pSelfCureStateMachine->pInternetSelfCureState->SelfCureForReset(requestCureLevel);
    }

    void SelfCureForResetTest4()
    {
        LOGI("Enter SelfCureForResetTest4");
        int requestCureLevel = WIFI_CURE_RESET_LEVEL_HIGH_RESET;
        pSelfCureStateMachine->internetUnknown = false;
        pSelfCureStateMachine->pInternetSelfCureState->hasInternetRecently = true;
        pSelfCureStateMachine->pInternetSelfCureState->currentRssi = MIN_VAL_LEVEL_4;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScreenState()).Times(AtLeast(0));
        WifiP2pLinkedInfo linkedInfo;
        linkedInfo.SetConnectState(P2pConnectedState::P2P_CONNECTED);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetP2pInfo(_))
            .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
        pSelfCureStateMachine->pInternetSelfCureState->SelfCureForReset(requestCureLevel);
    }

    void SelfCureForResetTest5()
    {
        LOGI("Enter SelfCureForResetTest5");
        int requestCureLevel = WIFI_CURE_RESET_LEVEL_HIGH_RESET;
        pSelfCureStateMachine->internetUnknown = false;
        pSelfCureStateMachine->pInternetSelfCureState->hasInternetRecently = true;
        pSelfCureStateMachine->pInternetSelfCureState->currentRssi = MIN_VAL_LEVEL_4;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScreenState()).Times(AtLeast(0));
        WifiP2pLinkedInfo linkedInfo;
        linkedInfo.SetConnectState(P2pConnectedState::P2P_DISCONNECTED);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetP2pInfo(_))
            .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
        pSelfCureStateMachine->notAllowSelfcure = true;
        pSelfCureStateMachine->pInternetSelfCureState->SelfCureForReset(requestCureLevel);
    }

    void SelfCureForResetTest6()
    {
        LOGI("Enter SelfCureForResetTest6");
        int requestCureLevel = WIFI_CURE_RESET_LEVEL_HIGH_RESET;
        pSelfCureStateMachine->internetUnknown = false;
        pSelfCureStateMachine->pInternetSelfCureState->hasInternetRecently = true;
        pSelfCureStateMachine->pInternetSelfCureState->currentRssi = MIN_VAL_LEVEL_4;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScreenState()).Times(AtLeast(0));
        WifiP2pLinkedInfo linkedInfo;
        linkedInfo.SetConnectState(P2pConnectedState::P2P_DISCONNECTED);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetP2pInfo(_))
            .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
        pSelfCureStateMachine->notAllowSelfcure = false;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetLastNetworkId(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiSelfcureReset(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiToggledState(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), AddDeviceConfig(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig()).Times(AtLeast(0));
        pSelfCureStateMachine->pInternetSelfCureState->SelfCureForReset(requestCureLevel);
    }

    void IsSettingsPageTest()
    {
        LOGI("Enter IsSettingsPageTest");
        pSelfCureStateMachine->IsSettingsPage();
    }

    void NoInternetStateGoInStateSuccess()
    {
        LOGI("Enter NoInternetStateGoInStateSuccess");
        pSelfCureStateMachine->pNoInternetState->GoInState();
    }

    void NoInternetStateGoOutStateSuccess()
    {
        LOGI("Enter NoInternetStateGoOutStateSuccess");
        pSelfCureStateMachine->pNoInternetState->GoOutState();
    }

    void NoInternetStateExeMsgFail()
    {
        LOGI("Enter NoInternetStateExeMsgFail");
        EXPECT_FALSE(pSelfCureStateMachine->pNoInternetState->ExecuteStateMsg(nullptr));
    }

    void NoInternetStateExeMsgSuccess1()
    {
        LOGI("Enter NoInternetStateExeMsgSuccess1");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(1);
        EXPECT_FALSE(pSelfCureStateMachine->pNoInternetState->ExecuteStateMsg(msg));
    }

    void NoInternetStateExeMsgSuccess2()
    {
        LOGI("Enter NoInternetStateExeMsgSuccess1");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_INTERNET_STATUS_DETECT_INTERVAL);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScreenState()).WillRepeatedly(Return(MODE_STATE_OPEN));
        EXPECT_TRUE(pSelfCureStateMachine->pNoInternetState->ExecuteStateMsg(msg));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScreenState()).WillRepeatedly(Return(MODE_STATE_CLOSE));
        EXPECT_TRUE(pSelfCureStateMachine->pNoInternetState->ExecuteStateMsg(msg));
    }

    void NoInternetStateExeMsgSuccess3()
    {
        LOGI("Enter NoInternetStateExeMsgSuccess1");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_HTTP_REACHABLE_RCV);
        EXPECT_TRUE(pSelfCureStateMachine->pNoInternetState->ExecuteStateMsg(msg));
    }

    void IsHttpReachableTest()
    {
        LOGI("Enter IsHttpReachableTest");
        pSelfCureStateMachine->IsHttpReachable();
        pSelfCureStateMachine->mNetWorkDetect = nullptr;
        EXPECT_TRUE(pSelfCureStateMachine->IsHttpReachable() == false);
    }
};

HWTEST_F(SelfCureStateMachineTest, DefaultStateGoInStateSuccess, TestSize.Level1)
{
    DefaultStateGoInStateSuccess();
}

HWTEST_F(SelfCureStateMachineTest, DefaultStateGoOutStateSuccess, TestSize.Level1)
{
    DefaultStateGoOutStateSuccess();
}

HWTEST_F(SelfCureStateMachineTest, DefaultStateExeMsgFail, TestSize.Level1)
{
    DefaultStateExeMsgFail();
}

HWTEST_F(SelfCureStateMachineTest, DefaultStateExeMsgSuccess1, TestSize.Level1)
{
    DefaultStateExeMsgSuccess1();
}

HWTEST_F(SelfCureStateMachineTest, ConnectedMonitorStateGoInStateSuccess, TestSize.Level1)
{
    ConnectedMonitorStateGoInStateSuccess();
}

HWTEST_F(SelfCureStateMachineTest, ConnectedMonitorStateGoOutStateSuccess, TestSize.Level1)
{
    ConnectedMonitorStateGoOutStateSuccess();
}

HWTEST_F(SelfCureStateMachineTest, ConnectedMonitorStateExeMsgFail, TestSize.Level1)
{
    ConnectedMonitorStateExeMsgFail();
}

HWTEST_F(SelfCureStateMachineTest, ConnectedMonitorStateExeMsgSuccess1, TestSize.Level1)
{
    ConnectedMonitorStateExeMsgSuccess1();
}

HWTEST_F(SelfCureStateMachineTest, InitSelfCureCmsHandleMapTest, TestSize.Level1)
{
    InitSelfCureCmsHandleMapTest();
}

HWTEST_F(SelfCureStateMachineTest, TransitionToSelfCureStateTest, TestSize.Level1)
{
    TransitionToSelfCureStateTest();
}

HWTEST_F(SelfCureStateMachineTest, HandleResetupSelfCureTest, TestSize.Level1)
{
    HandleResetupSelfCureTest();
}

HWTEST_F(SelfCureStateMachineTest, HandlePeriodicArpDetectionTest, TestSize.Level1)
{
    HandlePeriodicArpDetectionTest();
}

HWTEST_F(SelfCureStateMachineTest, HandleNetworkConnectTest, TestSize.Level1)
{
    HandleNetworkConnectTest();
}

HWTEST_F(SelfCureStateMachineTest, HandleNetworkDisconnectTest, TestSize.Level1)
{
    HandleNetworkDisconnectTest();
}

HWTEST_F(SelfCureStateMachineTest, HandleRssiLevelChangeTest, TestSize.Level1)
{
    HandleRssiLevelChangeTest();
}

HWTEST_F(SelfCureStateMachineTest, HandleArpDetectionFailedTest, TestSize.Level1)
{
    HandleArpDetectionFailedTest();
}

HWTEST_F(SelfCureStateMachineTest, SetupSelfCureMonitorTest, TestSize.Level1)
{
    SetupSelfCureMonitorTest();
}

HWTEST_F(SelfCureStateMachineTest, RequestReassocWithFactoryMacTest, TestSize.Level1)
{
    RequestReassocWithFactoryMacTest();
}

HWTEST_F(SelfCureStateMachineTest, IsGatewayChangedTest, TestSize.Level1)
{
    IsGatewayChangedTest();
}

HWTEST_F(SelfCureStateMachineTest, HandleGatewayChangedTest, TestSize.Level1)
{
    HandleGatewayChangedTest();
}

HWTEST_F(SelfCureStateMachineTest, HandleInvalidIpTest, TestSize.Level1)
{
    HandleInvalidIpTest();
}

HWTEST_F(SelfCureStateMachineTest, HandleInternetFailedDetectedTest, TestSize.Level1)
{
    HandleInternetFailedDetectedTest();
}

HWTEST_F(SelfCureStateMachineTest, HandleTcpQualityQueryTest, TestSize.Level1)
{
    HandleTcpQualityQueryTest();
}

HWTEST_F(SelfCureStateMachineTest, DisconnectedMonitorGoInStateSuccess, TestSize.Level1)
{
    DisconnectedMonitorGoInStateSuccess();
}

HWTEST_F(SelfCureStateMachineTest, DisconnectedMonitorGoOutStateSuccess, TestSize.Level1)
{
    DisconnectedMonitorGoOutStateSuccess();
}

HWTEST_F(SelfCureStateMachineTest, DisconnectedMonitorExeMsgFail, TestSize.Level1)
{
    DisconnectedMonitorExeMsgFail();
}

HWTEST_F(SelfCureStateMachineTest, DisconnectedMonitorExeMsgSuccess1, TestSize.Level1)
{
    DisconnectedMonitorExeMsgSuccess1();
}

HWTEST_F(SelfCureStateMachineTest, DisconnectedMonitorExeMsgSuccess2, TestSize.Level1)
{
    DisconnectedMonitorExeMsgSuccess2();
}

HWTEST_F(SelfCureStateMachineTest, DisconnectedMonitorExeMsgSuccess3, TestSize.Level1)
{
    DisconnectedMonitorExeMsgSuccess3();
}

HWTEST_F(SelfCureStateMachineTest, DisconnectedMonitorExeMsgSuccess4, TestSize.Level1)
{
    DisconnectedMonitorExeMsgSuccess4();
}

HWTEST_F(SelfCureStateMachineTest, HandleConnectFailedTest, TestSize.Level1)
{
    HandleConnectFailedTest();
}

HWTEST_F(SelfCureStateMachineTest, ConnectionSelfCureGoInStateSuccess, TestSize.Level1)
{
    ConnectionSelfCureGoInStateSuccess();
}

HWTEST_F(SelfCureStateMachineTest, ConnectionSelfCureGoOutStateSuccess, TestSize.Level1)
{
    ConnectionSelfCureGoOutStateSuccess();
}

HWTEST_F(SelfCureStateMachineTest, ConnectionSelfCureExeMsgFail, TestSize.Level1)
{
    ConnectionSelfCureExeMsgFail();
}

HWTEST_F(SelfCureStateMachineTest, ConnectionSelfCureExeMsgSuccess1, TestSize.Level1)
{
    ConnectionSelfCureExeMsgSuccess1();
}

HWTEST_F(SelfCureStateMachineTest, InternetSelfCureGoInStateSuccess, TestSize.Level1)
{
    InternetSelfCureGoInStateSuccess();
}

HWTEST_F(SelfCureStateMachineTest, InternetSelfCureGoOutStateSuccess, TestSize.Level1)
{
    InternetSelfCureGoOutStateSuccess();
}

HWTEST_F(SelfCureStateMachineTest, InternetSelfCureExeMsgFail, TestSize.Level1)
{
    InternetSelfCureExeMsgFail();
}

HWTEST_F(SelfCureStateMachineTest, InternetSelfCureExeMsgSuccess1, TestSize.Level1)
{
    InternetSelfCureExeMsgSuccess1();
}

HWTEST_F(SelfCureStateMachineTest, InitSelfCureIssHandleMapTest, TestSize.Level1)
{
    InitSelfCureIssHandleMapTest();
}

HWTEST_F(SelfCureStateMachineTest, HandleRandMacSelfCureCompleteTest, TestSize.Level1)
{
    HandleRandMacSelfCureCompleteTest();
}

HWTEST_F(SelfCureStateMachineTest, HandleInternetFailedSelfCureTest, TestSize.Level1)
{
    HandleInternetFailedSelfCureTest();
}

HWTEST_F(SelfCureStateMachineTest, HandleSelfCureWifiLinkTest, TestSize.Level1)
{
    HandleSelfCureWifiLinkTest();
}

HWTEST_F(SelfCureStateMachineTest, HandleNetworkDisconnectedTest, TestSize.Level1)
{
    HandleNetworkDisconnectedTest();
}

HWTEST_F(SelfCureStateMachineTest, HandleInternetRecoveryTest, TestSize.Level1)
{
    HandleInternetRecoveryTest();
}

HWTEST_F(SelfCureStateMachineTest, HandleRssiChangedEventTest, TestSize.Level1)
{
    HandleRssiChangedEventTest();
}

HWTEST_F(SelfCureStateMachineTest, HandleP2pDisconnectedTest, TestSize.Level1)
{
    HandleP2pDisconnectedTest();
}

HWTEST_F(SelfCureStateMachineTest, HandlePeriodicArpDetecteTest, TestSize.Level1)
{
    HandlePeriodicArpDetecteTest();
}

HWTEST_F(SelfCureStateMachineTest, HandleHttpReachableRecvTest, TestSize.Level1)
{
    HandleHttpReachableRecvTest();
}

HWTEST_F(SelfCureStateMachineTest, HandleArpFailedDetectedTest, TestSize.Level1)
{
    HandleArpFailedDetectedTest();
}

HWTEST_F(SelfCureStateMachineTest, SelectSelfCureByFailedReasonTest, TestSize.Level1)
{
    SelectSelfCureByFailedReasonTest();
}

HWTEST_F(SelfCureStateMachineTest, SelectBestSelfCureSolutionTest, TestSize.Level1)
{
    SelectBestSelfCureSolutionTest();
}

HWTEST_F(SelfCureStateMachineTest, SelectBestSelfCureSolutionExtTest, TestSize.Level1)
{
    SelectBestSelfCureSolutionExtTest();
}

HWTEST_F(SelfCureStateMachineTest, GetNextTestDhcpResultsTest, TestSize.Level1)
{
    GetNextTestDhcpResultsTest();
}

HWTEST_F(SelfCureStateMachineTest, GetRecordDhcpResultsTest, TestSize.Level1)
{
    GetRecordDhcpResultsTest();
}

HWTEST_F(SelfCureStateMachineTest, SelfCureWifiLinkTest, TestSize.Level1)
{
    SelfCureWifiLinkTest();
}

HWTEST_F(SelfCureStateMachineTest, SelfCureForStaticIpTest, TestSize.Level1)
{
    SelfCureForStaticIpTest();
}

HWTEST_F(SelfCureStateMachineTest, RequestUseStaticIpConfigTest, TestSize.Level1)
{
    RequestUseStaticIpConfigTest();
}

HWTEST_F(SelfCureStateMachineTest, SelfCureForInvalidIpTest, TestSize.Level1)
{
    SelfCureForInvalidIpTest();
}

HWTEST_F(SelfCureStateMachineTest, SelfCureForReassocTest, TestSize.Level1)
{
    SelfCureForReassocTest();
}

HWTEST_F(SelfCureStateMachineTest, IsNeedMultiGatewaySelfcureTest, TestSize.Level1)
{
    IsNeedMultiGatewaySelfcureTest();
}

HWTEST_F(SelfCureStateMachineTest, SelfcureForMultiGatewayTest, TestSize.Level1)
{
    SelfcureForMultiGatewayTest();
}

HWTEST_F(SelfCureStateMachineTest, SelfCureForRandMacReassocTest, TestSize.Level1)
{
    SelfCureForRandMacReassocTest();
}

HWTEST_F(SelfCureStateMachineTest, SelectedSelfCureAcceptableTest, TestSize.Level1)
{
    SelectedSelfCureAcceptableTest();
}

HWTEST_F(SelfCureStateMachineTest, HandleInternetFailedAndUserSetStaticIpTest, TestSize.Level1)
{
    HandleInternetFailedAndUserSetStaticIpTest();
}

HWTEST_F(SelfCureStateMachineTest, HandleIpConfigTimeoutTest, TestSize.Level1)
{
    HandleIpConfigTimeoutTest();
}

HWTEST_F(SelfCureStateMachineTest, HandleIpConfigCompletedTest, TestSize.Level1)
{
    HandleIpConfigCompletedTest();
}

HWTEST_F(SelfCureStateMachineTest, HandleIpConfigCompletedAfterRenewDhcpTest, TestSize.Level1)
{
    HandleIpConfigCompletedAfterRenewDhcpTest();
}

HWTEST_F(SelfCureStateMachineTest, HandleInternetRecoveryConfirmTest, TestSize.Level1)
{
    HandleInternetRecoveryConfirmTest();
}

HWTEST_F(SelfCureStateMachineTest, ConfirmInternetSelfCureTest, TestSize.Level1)
{
    ConfirmInternetSelfCureTest();
}

HWTEST_F(SelfCureStateMachineTest, HandleConfirmInternetSelfCureFailedTest, TestSize.Level1)
{
    HandleConfirmInternetSelfCureFailedTest();
}

HWTEST_F(SelfCureStateMachineTest, HandleSelfCureFailedForRandMacReassocTest, TestSize.Level1)
{
    HandleSelfCureFailedForRandMacReassocTest();
}

HWTEST_F(SelfCureStateMachineTest, HandleHttpReachableAfterSelfCureTest, TestSize.Level1)
{
    HandleHttpReachableAfterSelfCureTest();
}

HWTEST_F(SelfCureStateMachineTest, HandleHttpUnreachableFinallyTest, TestSize.Level1)
{
    HandleHttpUnreachableFinallyTest();
}

HWTEST_F(SelfCureStateMachineTest, HasBeenTestedTest, TestSize.Level1)
{
    HasBeenTestedTest();
}

HWTEST_F(SelfCureStateMachineTest, HandleRssiChangedTest, TestSize.Level1)
{
    HandleRssiChangedTest();
}

HWTEST_F(SelfCureStateMachineTest, HandleDelayedResetSelfCureTest, TestSize.Level1)
{
    HandleDelayedResetSelfCureTest();
}

HWTEST_F(SelfCureStateMachineTest, Wifi6SelfCureStateGoInStateSuccess, TestSize.Level1)
{
    Wifi6SelfCureStateGoInStateSuccess();
}

HWTEST_F(SelfCureStateMachineTest, Wifi6SelfCureStateGoOutStateSuccess, TestSize.Level1)
{
    Wifi6SelfCureStateGoOutStateSuccess();
}

HWTEST_F(SelfCureStateMachineTest, InitExeMsgFail, TestSize.Level1)
{
    InitExeMsgFail();
}

HWTEST_F(SelfCureStateMachineTest, InitExeMsgSuccess1, TestSize.Level1)
{
    InitExeMsgSuccess1();
}

HWTEST_F(SelfCureStateMachineTest, InitExeMsgSuccess2, TestSize.Level1)
{
    InitExeMsgSuccess2();
}

HWTEST_F(SelfCureStateMachineTest, CanArpReachableFailedTest, TestSize.Level1)
{
    CanArpReachableFailedTest();
}

HWTEST_F(SelfCureStateMachineTest, CanArpReachableTest, TestSize.Level1)
{
    CanArpReachableTest();
}

HWTEST_F(SelfCureStateMachineTest, InitExeMsgSuccess3, TestSize.Level1)
{
    InitExeMsgSuccess3();
}

HWTEST_F(SelfCureStateMachineTest, InitExeMsgSuccess4, TestSize.Level1)
{
    InitExeMsgSuccess4();
}

HWTEST_F(SelfCureStateMachineTest, InitExeMsgSuccess5, TestSize.Level1)
{
    InitExeMsgSuccess5();
}

HWTEST_F(SelfCureStateMachineTest, InitExeMsgSuccess6, TestSize.Level1)
{
    InitExeMsgSuccess6();
}

HWTEST_F(SelfCureStateMachineTest, PeriodicWifi6WithHtcArpDetectTest, TestSize.Level1)
{
    PeriodicWifi6WithHtcArpDetectTest();
}

HWTEST_F(SelfCureStateMachineTest, PeriodicWifi6WithoutHtcArpDetectTest, TestSize.Level1)
{
    PeriodicWifi6WithoutHtcArpDetectTest();
}

HWTEST_F(SelfCureStateMachineTest, HandleWifi6WithHtcArpFailTest, TestSize.Level1)
{
    HandleWifi6WithHtcArpFailTest();
}

HWTEST_F(SelfCureStateMachineTest, HandleWifi6WithoutHtcArpFailTest, TestSize.Level1)
{
    HandleWifi6WithoutHtcArpFailTest();
}

HWTEST_F(SelfCureStateMachineTest, GetNowMilliSecondsTest, TestSize.Level1)
{
    GetNowMilliSecondsTest();
}

HWTEST_F(SelfCureStateMachineTest, SendBlaListToDriverTest, TestSize.Level1)
{
    SendBlaListToDriverTest();
}

HWTEST_F(SelfCureStateMachineTest, SendBlaListToDriverTest2, TestSize.Level1)
{
    SendBlaListToDriverTest2();
}

HWTEST_F(SelfCureStateMachineTest, BlackListToStringTest, TestSize.Level1)
{
    BlackListToStringTest();
}

HWTEST_F(SelfCureStateMachineTest, BlackListToStringTest2, TestSize.Level1)
{
    BlackListToStringTest2();
}

HWTEST_F(SelfCureStateMachineTest, ParseWifi6BlackListInfoTest, TestSize.Level1)
{
    ParseWifi6BlackListInfoTest();
}

HWTEST_F(SelfCureStateMachineTest, AgeOutWifi6BlackTest, TestSize.Level1)
{
    AgeOutWifi6BlackTest();
}

HWTEST_F(SelfCureStateMachineTest, ShouldTransToWifi6SelfCureTest, TestSize.Level1)
{
    ShouldTransToWifi6SelfCureTest();
}

HWTEST_F(SelfCureStateMachineTest, ShouldTransToWifi6SelfCureTest2, TestSize.Level1)
{
    ShouldTransToWifi6SelfCureTest2();
}

HWTEST_F(SelfCureStateMachineTest, GetCurrentBssidTest, TestSize.Level1)
{
    GetCurrentBssidTest();
}

HWTEST_F(SelfCureStateMachineTest, IsWifi6NetworkTest, TestSize.Level1)
{
    IsWifi6NetworkTest();
}

HWTEST_F(SelfCureStateMachineTest, IsWifi6NetworkTest2, TestSize.Level1)
{
    IsWifi6NetworkTest2();
}

HWTEST_F(SelfCureStateMachineTest, IsWifi6NetworkTest3, TestSize.Level1)
{
    IsWifi6NetworkTest3();
}

HWTEST_F(SelfCureStateMachineTest, DisconnectedExeMsgSuccess0, TestSize.Level1)
{
    DisconnectedExeMsgSuccess0();
}

HWTEST_F(SelfCureStateMachineTest, HandleResetConnectNetworkTest, TestSize.Level1)
{
    HandleResetConnectNetworkTest();
}

HWTEST_F(SelfCureStateMachineTest, HandleResetConnectNetworkTest2, TestSize.Level1)
{
    HandleResetConnectNetworkTest2();
}

HWTEST_F(SelfCureStateMachineTest, HandleResetConnectNetworkTest3, TestSize.Level1)
{
    HandleResetConnectNetworkTest3();
}

HWTEST_F(SelfCureStateMachineTest, SelfCureForResetTest, TestSize.Level1)
{
    SelfCureForResetTest();
}

HWTEST_F(SelfCureStateMachineTest, SelfCureForResetTest2, TestSize.Level1)
{
    SelfCureForResetTest2();
}

HWTEST_F(SelfCureStateMachineTest, SelfCureForResetTest3, TestSize.Level1)
{
    SelfCureForResetTest3();
}

HWTEST_F(SelfCureStateMachineTest, SelfCureForResetTest4, TestSize.Level1)
{
    SelfCureForResetTest4();
}

HWTEST_F(SelfCureStateMachineTest, SelfCureForResetTest5, TestSize.Level1)
{
    SelfCureForResetTest5();
}

HWTEST_F(SelfCureStateMachineTest, SelfCureForResetTest6, TestSize.Level1)
{
    SelfCureForResetTest6();
}

HWTEST_F(SelfCureStateMachineTest, IsSettingsPageTest, TestSize.Level1)
{
    IsSettingsPageTest();
}

HWTEST_F(SelfCureStateMachineTest, NoInternetStateGoInStateSuccess, TestSize.Level1)
{
    NoInternetStateGoInStateSuccess();
}

HWTEST_F(SelfCureStateMachineTest, NoInternetStateGoOutStateSuccess, TestSize.Level1)
{
    NoInternetStateGoOutStateSuccess();
}

HWTEST_F(SelfCureStateMachineTest, NoInternetStateExeMsgFail, TestSize.Level1)
{
    NoInternetStateExeMsgFail();
}

HWTEST_F(SelfCureStateMachineTest, NoInternetStateExeMsgSuccess1, TestSize.Level1)
{
    NoInternetStateExeMsgSuccess1();
}

HWTEST_F(SelfCureStateMachineTest, NoInternetStateExeMsgSuccess2, TestSize.Level1)
{
    NoInternetStateExeMsgSuccess2();
}

HWTEST_F(SelfCureStateMachineTest, NoInternetStateExeMsgSuccess3, TestSize.Level1)
{
    NoInternetStateExeMsgSuccess3();
}

HWTEST_F(SelfCureStateMachineTest, TransIpAddressToVec, TestSize.Level1)
{
    std::string addr = "";
    pSelfCureStateMachine->TransIpAddressToVec(addr);

    addr = CURR_BSSID;
    pSelfCureStateMachine->TransIpAddressToVec(addr);

    addr = "00:aa:bb:cc:dd:ee:ff";
    pSelfCureStateMachine->TransIpAddressToVec(addr);
}

HWTEST_F(SelfCureStateMachineTest, TransVecToIpAddress, TestSize.Level1)
{
    std::vector<uint32_t> vec = {1, 2, 3, 4};
    pSelfCureStateMachine->TransVecToIpAddress(vec);
    
    vec = {0, 0, 0, 0};
    pSelfCureStateMachine->TransVecToIpAddress(vec);
    
    vec = {};
    pSelfCureStateMachine->TransVecToIpAddress(vec);
}

HWTEST_F(SelfCureStateMachineTest, GetLegalIpConfigurationTest, TestSize.Level1)
{
    IpInfo dhcpResults;
    dhcpResults.gateway = 0;
    pSelfCureStateMachine->GetLegalIpConfiguration(dhcpResults);

    dhcpResults.ipAddress = 0;
    pSelfCureStateMachine->GetLegalIpConfiguration(dhcpResults);

    dhcpResults.ipAddress = 1;
    pSelfCureStateMachine->GetLegalIpConfiguration(dhcpResults);
}

HWTEST_F(SelfCureStateMachineTest, GetLegalIpConfigurationTest1, TestSize.Level1)
{
    IpInfo dhcpResults;
    int result = pSelfCureStateMachine->GetLegalIpConfiguration(dhcpResults);
    EXPECT_EQ(result, -1);
}

HWTEST_F(SelfCureStateMachineTest, GetLegalIpConfigurationTest2, TestSize.Level1)
{
    IpInfo dhcpResults;
    dhcpResults.gateway = 19216801;
    dhcpResults.ipAddress = 19216801;
    int result = pSelfCureStateMachine->GetLegalIpConfiguration(dhcpResults);
    EXPECT_EQ(result, 0);
}

HWTEST_F(SelfCureStateMachineTest, DoArpTest_Test, TestSize.Level1)
{
    std::string gateway = GATEWAY;
    std::string ipAddress = CURRENT_ADDR;
    pSelfCureStateMachine->DoArpTest(ipAddress, gateway);
}

HWTEST_F(SelfCureStateMachineTest, GetNextIpAddr_WhenGatewayAndCurrentAddrAreEmpty_ReturnEmptyString, TestSize.Level1)
{
    std::string gateway = "";
    std::string currentAddr = "";
    std::vector<std::string> testedAddr = {};
    std::string nextIpAddr = pSelfCureStateMachine->GetNextIpAddr(gateway, currentAddr, testedAddr);
    EXPECT_EQ(nextIpAddr, "");
}

HWTEST_F(SelfCureStateMachineTest, GetNextIpAddr_WhenGatewayIsEmpty_ReturnEmptyString, TestSize.Level1)
{
    std::string gateway = "";
    std::string currentAddr = CURRENT_ADDR;
    std::vector<std::string> testedAddr = TESTED_ADDR;
    std::string nextIpAddr = pSelfCureStateMachine->GetNextIpAddr(gateway, currentAddr, testedAddr);
    EXPECT_EQ(nextIpAddr, "");
}

HWTEST_F(SelfCureStateMachineTest, GetNextIpAddr_WhenCurrentAddrIsEmpty_ReturnEmptyString, TestSize.Level1)
{
    std::string gateway = GATEWAY;
    std::string currentAddr = "";
    std::vector<std::string> testedAddr = TESTED_ADDR;
    std::string nextIpAddr = pSelfCureStateMachine->GetNextIpAddr(gateway, currentAddr, testedAddr);
    EXPECT_EQ(nextIpAddr, "");
}

HWTEST_F(SelfCureStateMachineTest, GetNextIpAddr_WhenTestedAddrIsEmpty_ReturnEmptyString, TestSize.Level1)
{
    std::string gateway = GATEWAY;
    std::string currentAddr = CURRENT_ADDR;
    std::vector<std::string> testedAddr = {};
    std::string nextIpAddr = pSelfCureStateMachine->GetNextIpAddr(gateway, currentAddr, testedAddr);
    EXPECT_EQ(nextIpAddr, "");
}

HWTEST_F(SelfCureStateMachineTest, GetNextIpAddr_WhenGatewayAndCurrentAddrAreValid_ReturnNextIpAddr, TestSize.Level1)
{
    std::string gateway = GATEWAY;
    std::string currentAddr = CURRENT_ADDR;
    std::vector<std::string> testedAddr = TESTED_ADDR;
    pSelfCureStateMachine->GetNextIpAddr(gateway, currentAddr, testedAddr);
}

HWTEST_F(SelfCureStateMachineTest, IsIpAddressInvalidTest1, TestSize.Level1)
{
    IpInfo dhcpInfo;
    dhcpInfo.ipAddress = 0;
    dhcpInfo.netmask = 0;
    dhcpInfo.gateway = 0;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _))
        .WillOnce(DoAll(SetArgReferee<0>(dhcpInfo), Return(0)));
    EXPECT_FALSE(pSelfCureStateMachine->IsIpAddressInvalid());
}

HWTEST_F(SelfCureStateMachineTest, IsIpAddressInvalidTest2, TestSize.Level1)
{
    IpInfo dhcpInfo;
    dhcpInfo.ipAddress = 0x0100007F; // 127.0.0.1
    dhcpInfo.netmask = 0x00FFFFFF;
    dhcpInfo.gateway = 0x0100007F; // 127.0.0.1
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _))
        .WillOnce(DoAll(SetArgReferee<0>(dhcpInfo), Return(0)));
    EXPECT_TRUE(pSelfCureStateMachine->IsIpAddressInvalid());
}

HWTEST_F(SelfCureStateMachineTest, IsIpAddressInvalidTest3, TestSize.Level1)
{
    IpInfo dhcpInfo;
    dhcpInfo.ipAddress = 0x0500007F; // 127.0.0.5
    dhcpInfo.netmask = 0x00FFFFFF;
    dhcpInfo.gateway = 0x0100007F; // 127.0.0.1
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _))
        .WillOnce(DoAll(SetArgReferee<0>(dhcpInfo), Return(0)));
    EXPECT_FALSE(pSelfCureStateMachine->IsIpAddressInvalid());
}

HWTEST_F(SelfCureStateMachineTest, IsIpAddressInvalidTest4, TestSize.Level1)
{
    IpInfo dhcpInfo;
    dhcpInfo.ipAddress = 0x0000007F; // 127.0.0.0
    dhcpInfo.netmask = 0x00FFFFFF;
    dhcpInfo.gateway = 0x0100007F; // 127.0.0.1
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _))
        .WillOnce(DoAll(SetArgReferee<0>(dhcpInfo), Return(0)));
    EXPECT_FALSE(pSelfCureStateMachine->IsIpAddressInvalid());
}

HWTEST_F(SelfCureStateMachineTest, IsIpAddressInvalidTest5, TestSize.Level1)
{
    IpInfo dhcpInfo;
    dhcpInfo.ipAddress = 0xFF00007F; // 127.0.0.255
    dhcpInfo.netmask = 0x00FFFFFF;
    dhcpInfo.gateway = 0x0100007F; // 127.0.0.1
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _))
        .WillOnce(DoAll(SetArgReferee<0>(dhcpInfo), Return(0)));
    EXPECT_FALSE(pSelfCureStateMachine->IsIpAddressInvalid());
}

HWTEST_F(SelfCureStateMachineTest, TransStrToVecTest, TestSize.Level1)
{
    std::string str = "0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0";
    char c = '|';
    pSelfCureStateMachine->TransStrToVec(str, c);
    c = '/';
    pSelfCureStateMachine->TransStrToVec(str, c);
}

HWTEST_F(SelfCureStateMachineTest, IsUseFactoryMacTest, TestSize.Level1)
{
    std::string MacAddress = CURR_BSSID;
    std::string RealMacAddress = REAL_MAC;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).
        WillRepeatedly(DoAll(SetArgReferee<0>(MacAddress), Return(0)));
    EXPECT_CALL(WifiSettings::GetInstance(), GetRealMacAddress(_, _)).
        WillRepeatedly(DoAll(SetArgReferee<0>(RealMacAddress), Return(0)));
    pSelfCureStateMachine->IsUseFactoryMac();

    MacAddress = CURR_BSSID;
    RealMacAddress = CURR_BSSID;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).
        WillRepeatedly(DoAll(SetArgReferee<0>(MacAddress), Return(0)));
    EXPECT_CALL(WifiSettings::GetInstance(), GetRealMacAddress(_, _)).
        WillRepeatedly(DoAll(SetArgReferee<0>(RealMacAddress), Return(0)));
    pSelfCureStateMachine->IsUseFactoryMac();

    MacAddress = "";
    RealMacAddress = REAL_MAC;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).
        WillRepeatedly(DoAll(SetArgReferee<0>(MacAddress), Return(0)));
    EXPECT_CALL(WifiSettings::GetInstance(), GetRealMacAddress(_, _)).
        WillRepeatedly(DoAll(SetArgReferee<0>(RealMacAddress), Return(0)));
    pSelfCureStateMachine->IsUseFactoryMac();

    MacAddress = CURR_BSSID;
    RealMacAddress = "";
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).
        WillRepeatedly(DoAll(SetArgReferee<0>(MacAddress), Return(0)));
    EXPECT_CALL(WifiSettings::GetInstance(), GetRealMacAddress(_, _)).
        WillRepeatedly(DoAll(SetArgReferee<0>(RealMacAddress), Return(0)));
    pSelfCureStateMachine->IsUseFactoryMac();
}

HWTEST_F(SelfCureStateMachineTest, IsSameEncryptTypeTest, TestSize.Level1)
{
    std::string deviceKeymgmt = "WPA-PSK";
    std::string scanInfoKeymgmt = "WPA-PSK";
    bool result = pSelfCureStateMachine->IsSameEncryptType(scanInfoKeymgmt, deviceKeymgmt);
    EXPECT_TRUE(result);

    deviceKeymgmt = "WPA-EAP";
    scanInfoKeymgmt = "WPA-EAP";
    result = pSelfCureStateMachine->IsSameEncryptType(scanInfoKeymgmt, deviceKeymgmt);
    EXPECT_TRUE(result);

    deviceKeymgmt = "SAE";
    scanInfoKeymgmt = "SAE";
    result = pSelfCureStateMachine->IsSameEncryptType(scanInfoKeymgmt, deviceKeymgmt);
    EXPECT_TRUE(result);

    deviceKeymgmt = "SAE";
    scanInfoKeymgmt = "WPA2-PSK";
    result = pSelfCureStateMachine->IsSameEncryptType(scanInfoKeymgmt, deviceKeymgmt);
    EXPECT_FALSE(result);

    deviceKeymgmt = "NONE";
    scanInfoKeymgmt = "NONE";
    result = pSelfCureStateMachine->IsSameEncryptType(scanInfoKeymgmt, deviceKeymgmt);
    EXPECT_TRUE(result);

    deviceKeymgmt = "NONE";
    scanInfoKeymgmt = "WPA-PSK";
    result = pSelfCureStateMachine->IsSameEncryptType(scanInfoKeymgmt, deviceKeymgmt);
    EXPECT_FALSE(result);

    deviceKeymgmt = "Invalid";
    scanInfoKeymgmt = "WPA-PSK";
    result = pSelfCureStateMachine->IsSameEncryptType(scanInfoKeymgmt, deviceKeymgmt);
    EXPECT_FALSE(result);
}

HWTEST_F(SelfCureStateMachineTest, GetBssidCounterTest, TestSize.Level1)
{
    std::vector<WifiScanInfo> scanResults = {};
    int counter = pSelfCureStateMachine->GetBssidCounter(scanResults);
    EXPECT_EQ(counter, 0);
    
    WifiScanInfo info;
    info.bssid = "";
    info.ssid = "ssid";
    info.bssidType = 0;
    scanResults = {info};
    pSelfCureStateMachine->GetBssidCounter(scanResults);

    WifiDeviceConfig config;
    config.keyMgmt = "";
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(config), Return(0)));
    pSelfCureStateMachine->GetBssidCounter(scanResults);

    info.bssid = CURR_BSSID;
    scanResults = {info};
    pSelfCureStateMachine->GetBssidCounter(scanResults);

    config.keyMgmt = "WPA_PSK";
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(config), Return(0)));
    pSelfCureStateMachine->GetBssidCounter(scanResults);
}

HWTEST_F(SelfCureStateMachineTest, IsNeedWifiReassocUseDeviceMac_Test1, TestSize.Level1)
{
    std::string selfCureHistory = "";
    pSelfCureStateMachine->SetSelfCureHistoryInfo(selfCureHistory);
    EXPECT_FALSE(pSelfCureStateMachine->IsNeedWifiReassocUseDeviceMac());
}

HWTEST_F(SelfCureStateMachineTest, IsNeedWifiReassocUseDeviceMac_Test2, TestSize.Level1)
{
    WifiDeviceConfig config;
    config.internetSelfCureHistory = "0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0";
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(config), Return(0)));
    EXPECT_FALSE(pSelfCureStateMachine->IsNeedWifiReassocUseDeviceMac());
}

HWTEST_F(SelfCureStateMachineTest, IsNeedWifiReassocUseDeviceMac_Test3, TestSize.Level1)
{
    WifiDeviceConfig config;
    config.internetSelfCureHistory = "0|0|0|1|2|1|0|0|0|0|0|0|0|0|0|0|0|0";
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(config), Return(0)));
    EXPECT_FALSE(pSelfCureStateMachine->IsNeedWifiReassocUseDeviceMac());
}

HWTEST_F(SelfCureStateMachineTest, SetSelfCureFailInfo_Test, TestSize.Level1)
{
    WifiSelfCureHistoryInfo info;
    std::vector<std::string> histories = {"1", "1615153293123", "2", "1615153293124", "3", "1615153293125",
                                          "4", "1615153293126", "5", "1615153293127", "6", "1615153293128"};
    int cnt = SELFCURE_FAIL_LENGTH;
    pSelfCureStateMachine->SetSelfCureFailInfo(info, histories, cnt);
}

HWTEST_F(SelfCureStateMachineTest, SetSelfCureFailInfoTest_InvalidHistories, TestSize.Level1)
{
    WifiSelfCureHistoryInfo info;
    std::vector<std::string> histories = {"1", "1615153293123", "2", "1615153293124", "3", "1615153293125",
                                          "4", "1615153293126", "5", "1615153293127"};
    int cnt = 6;
    int result = pSelfCureStateMachine->SetSelfCureFailInfo(info, histories, cnt);
    EXPECT_EQ(result, -1);
}

HWTEST_F(SelfCureStateMachineTest, SetSelfCureFailInfoTest_InvalidCnt, TestSize.Level1)
{
    WifiSelfCureHistoryInfo info;
    std::vector<std::string> histories = {"1", "1615153293123", "2", "1615153293124", "3", "1615153293125",
                                          "4", "1615153293126", "5", "1615153293127", "6", "1615153293128"};
    int cnt = 5;
    int result = pSelfCureStateMachine->SetSelfCureFailInfo(info, histories, cnt);
    EXPECT_EQ(result, -1);
}

HWTEST_F(SelfCureStateMachineTest, SetSelfCureFailInfoTest, TestSize.Level1)
{
    WifiSelfCureHistoryInfo info;
    std::vector<std::string> histories = {"1", "2", "3", "4", "5", "6", "7",
        "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18"};
    int cnt = SELFCURE_FAIL_LENGTH;
    int result = pSelfCureStateMachine->SetSelfCureFailInfo(info, histories, cnt);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(info.dnsSelfCureFailedCnt, 1);
    EXPECT_EQ(info.lastDnsSelfCureFailedTs, 2);
    EXPECT_EQ(info.renewDhcpSelfCureFailedCnt, 3);
    EXPECT_EQ(info.lastRenewDhcpSelfCureFailedTs, 4);
    EXPECT_EQ(info.staticIpSelfCureFailedCnt, 5);
    EXPECT_EQ(info.lastStaticIpSelfCureFailedTs, 6);
    EXPECT_EQ(info.reassocSelfCureFailedCnt, 7);
    EXPECT_EQ(info.lastReassocSelfCureFailedTs, 8);
    EXPECT_EQ(info.randMacSelfCureFailedCnt, 9);
    EXPECT_EQ(info.lastRandMacSelfCureFailedCntTs, 10);
    EXPECT_EQ(info.resetSelfCureFailedCnt, 11);
    EXPECT_EQ(info.lastResetSelfCureFailedTs, 12);
}

HWTEST_F(SelfCureStateMachineTest, SetSelfCureFailInfoEmptyHistoriesTest, TestSize.Level1)
{
    WifiSelfCureHistoryInfo info;
    std::vector<std::string> histories;
    int cnt = 0;
    int result = pSelfCureStateMachine->SetSelfCureFailInfo(info, histories, cnt);
    EXPECT_EQ(result, -1);
}

HWTEST_F(SelfCureStateMachineTest, SetSelfCureFailInfoInvalidHistoriesSizeTest, TestSize.Level1)
{
    WifiSelfCureHistoryInfo info;
    std::vector<std::string> histories = {"1", "2", "3", "4", "5", "6", "7",
        "8", "9", "10", "11", "12", "13", "14", "15", "16", "17"};
    int cnt = SELFCURE_FAIL_LENGTH;
    int result = pSelfCureStateMachine->SetSelfCureFailInfo(info, histories, cnt);
    EXPECT_EQ(result, -1);
}

HWTEST_F(SelfCureStateMachineTest, SetSelfCureConnectFailInfoTest, TestSize.Level1)
{
    WifiSelfCureHistoryInfo info;
    std::vector<std::string> histories = {"0", "0", "0", "0", "0", "0", "0",
        "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"};
    int cnt = SELFCURE_FAIL_LENGTH;
    int result = pSelfCureStateMachine->SetSelfCureConnectFailInfo(info, histories, cnt);
    EXPECT_EQ(result, 0);
    EXPECT_EQ(info.reassocSelfCureConnectFailedCnt, 0);
    EXPECT_EQ(info.lastReassocSelfCureConnectFailedTs, 0);
    EXPECT_EQ(info.randMacSelfCureConnectFailedCnt, 0);
    EXPECT_EQ(info.lastRandMacSelfCureConnectFailedCntTs, 0);
    EXPECT_EQ(info.resetSelfCureConnectFailedCnt, 0);
    EXPECT_EQ(info.lastResetSelfCureConnectFailedTs, 0);
}

HWTEST_F(SelfCureStateMachineTest, SetSelfCureConnectFailInfoInvalidHistoriesTest, TestSize.Level1)
{
    WifiSelfCureHistoryInfo info;
    std::vector<std::string> histories = {"0", "0", "0", "0", "0", "0", "0",
        "0", "0", "0", "0", "0", "0", "0", "0", "0"};
    int cnt = 1;
    int result = pSelfCureStateMachine->SetSelfCureConnectFailInfo(info, histories, cnt);
    EXPECT_EQ(result, -1);
}

HWTEST_F(SelfCureStateMachineTest, SetSelfCureConnectFailInfoInvalidCntTest, TestSize.Level1)
{
    WifiSelfCureHistoryInfo info;
    std::vector<std::string> histories = {"0", "0", "0", "0", "0", "0", "0",
        "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"};
    int cnt = 2;
    int result = pSelfCureStateMachine->SetSelfCureConnectFailInfo(info, histories, cnt);
    EXPECT_EQ(result, -1);
}

HWTEST_F(SelfCureStateMachineTest, IsSuppOnCompletedStateTest, TestSize.Level1)
{
    WifiLinkedInfo linkedInfo;
    linkedInfo.connState = ConnState::CONNECTED;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
    pSelfCureStateMachine->IsSuppOnCompletedState();

    linkedInfo.connState = ConnState::DISCONNECTED;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
    pSelfCureStateMachine->IsSuppOnCompletedState();
}

HWTEST_F(SelfCureStateMachineTest, IfPeriodicArpDetectionTest, TestSize.Level1)
{
    EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).WillRepeatedly(Return(4));
    pSelfCureStateMachine->IfPeriodicArpDetection();

    WifiLinkedInfo linkedInfo;
    linkedInfo.connState = ConnState::CONNECTED;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScreenState()).WillRepeatedly(Return(1));
    pSelfCureStateMachine->IfPeriodicArpDetection();
}

HWTEST_F(SelfCureStateMachineTest, PeriodicArpDetection_WhenMsgIsNullptr_ReturnsFalse, TestSize.Level1)
{
    pSelfCureStateMachine->PeriodicArpDetection();

    EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).WillRepeatedly(Return(4));
    pSelfCureStateMachine->PeriodicArpDetection();

    WifiLinkedInfo linkedInfo;
    linkedInfo.connState = ConnState::CONNECTED;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScreenState()).WillRepeatedly(Return(1));
    pSelfCureStateMachine->PeriodicArpDetection();
}

HWTEST_F(SelfCureStateMachineTest, IfP2pConnectedTest, TestSize.Level1)
{
    bool expectedResult = false;
    WifiP2pLinkedInfo linkedInfo;
    linkedInfo.SetConnectState(P2pConnectedState::P2P_DISCONNECTED);
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetP2pInfo(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
    EXPECT_EQ(expectedResult, pSelfCureStateMachine->IfP2pConnected());

    linkedInfo.SetConnectState(P2pConnectedState::P2P_CONNECTED);
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetP2pInfo(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
    expectedResult = true;
    EXPECT_EQ(expectedResult, pSelfCureStateMachine->IfP2pConnected());
}

HWTEST_F(SelfCureStateMachineTest, GetIpAssignmentTest, TestSize.Level1)
{
    AssignIpMethod ipAssignment;
    int result = pSelfCureStateMachine->GetIpAssignment(ipAssignment);
    EXPECT_EQ(result, 0);

    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0)).WillOnce(Return(-1));
    pSelfCureStateMachine->GetIpAssignment(ipAssignment);
}

HWTEST_F(SelfCureStateMachineTest, GetAuthTypeTest, TestSize.Level1)
{
    pSelfCureStateMachine->GetAuthType();

    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0)).WillOnce(Return(-1));
    pSelfCureStateMachine->GetAuthType();
}

HWTEST_F(SelfCureStateMachineTest, GetLastHasInternetTimeTest, TestSize.Level1)
{
    pSelfCureStateMachine->GetLastHasInternetTime();

    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0)).WillOnce(Return(-1));
    pSelfCureStateMachine->GetLastHasInternetTime();
}

HWTEST_F(SelfCureStateMachineTest, GetNetworkStatusHistoryTest, TestSize.Level1)
{
    pSelfCureStateMachine->GetNetworkStatusHistory();

    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0)).WillOnce(Return(-1));
    pSelfCureStateMachine->GetNetworkStatusHistory();
}

HWTEST_F(SelfCureStateMachineTest, SetSelfCureHistoryInfoTest, TestSize.Level1)
{
    std::string selfCureHistory = "1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18";
    int result = pSelfCureStateMachine->SetSelfCureHistoryInfo(selfCureHistory);
    EXPECT_EQ(result, 0);

    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0)).WillOnce(Return(-1));
    pSelfCureStateMachine->SetSelfCureHistoryInfo(selfCureHistory);
}

HWTEST_F(SelfCureStateMachineTest, GetSelfCureHistoryInfoTest, TestSize.Level1)
{
    pSelfCureStateMachine->GetSelfCureHistoryInfo();

    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0)).WillOnce(Return(-1));
    pSelfCureStateMachine->GetSelfCureHistoryInfo();
}

HWTEST_F(SelfCureStateMachineTest, SetSelfCureHistoryInfoZeroTest, TestSize.Level1)
{
    std::string selfCureHistory = "0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0";
    int result = pSelfCureStateMachine->SetSelfCureHistoryInfo(selfCureHistory);
    EXPECT_EQ(result, 0);

    selfCureHistory = "";
    result = pSelfCureStateMachine->SetSelfCureHistoryInfo(selfCureHistory);
    EXPECT_EQ(result, -1);
}

HWTEST_F(SelfCureStateMachineTest, SetIsReassocWithFactoryMacAddress_Test1, TestSize.Level1)
{
    int isReassocWithFactoryMacAddress = 1;
    int result = pSelfCureStateMachine->SetIsReassocWithFactoryMacAddress(isReassocWithFactoryMacAddress);
    EXPECT_EQ(result, 0);
}

HWTEST_F(SelfCureStateMachineTest, SetIsReassocWithFactoryMacAddress_Test2, TestSize.Level1)
{
    int isReassocWithFactoryMacAddress = 0;
    int result = pSelfCureStateMachine->SetIsReassocWithFactoryMacAddress(isReassocWithFactoryMacAddress);
    EXPECT_EQ(result, 0);
}

HWTEST_F(SelfCureStateMachineTest, SetIsReassocWithFactoryMacAddress_Test3, TestSize.Level1)
{
    int isReassocWithFactoryMacAddress = -1;
    int result = pSelfCureStateMachine->SetIsReassocWithFactoryMacAddress(isReassocWithFactoryMacAddress);
    EXPECT_EQ(result, 0);

    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0)).WillOnce(Return(-1));
    pSelfCureStateMachine->SetIsReassocWithFactoryMacAddress(isReassocWithFactoryMacAddress);
}

HWTEST_F(SelfCureStateMachineTest, GetCurrentWifiDeviceConfigTest, TestSize.Level1)
{
    WifiDeviceConfig config;
    pSelfCureStateMachine->GetCurrentWifiDeviceConfig(config);

    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0)).WillOnce(Return(-1));
    pSelfCureStateMachine->GetCurrentWifiDeviceConfig(config);

    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _)).Times(AtLeast(0)).WillOnce(Return(-1));
    pSelfCureStateMachine->GetCurrentWifiDeviceConfig(config);
}

HWTEST_F(SelfCureStateMachineTest, SelfCureAcceptable_Dns_ReturnsTrue, TestSize.Level1)
{
    WifiSelfCureHistoryInfo historyInfo;
    historyInfo.dnsSelfCureFailedCnt = 0;
    int requestCureLevel = WIFI_CURE_RESET_LEVEL_LOW_1_DNS;
    bool result = pSelfCureStateMachine->SelfCureAcceptable(historyInfo, requestCureLevel);
    ASSERT_TRUE(result);
}

HWTEST_F(SelfCureStateMachineTest, SelfCureAcceptable_RenewDhcp_ReturnsTrue, TestSize.Level1)
{
    WifiSelfCureHistoryInfo historyInfo;
    historyInfo.renewDhcpSelfCureFailedCnt = 0;
    int requestCureLevel = WIFI_CURE_RESET_LEVEL_LOW_2_RENEW_DHCP;
    bool result = pSelfCureStateMachine->SelfCureAcceptable(historyInfo, requestCureLevel);
    ASSERT_TRUE(result);
}

HWTEST_F(SelfCureStateMachineTest, SelfCureAcceptable_StaticIp_ReturnsTrue, TestSize.Level1)
{
    WifiSelfCureHistoryInfo historyInfo;
    historyInfo.staticIpSelfCureFailedCnt = 0;
    int requestCureLevel = WIFI_CURE_RESET_LEVEL_LOW_3_STATIC_IP;
    bool result = pSelfCureStateMachine->SelfCureAcceptable(historyInfo, requestCureLevel);
    ASSERT_TRUE(result);
}

HWTEST_F(SelfCureStateMachineTest, SelfCureAcceptable_MiddleReassoc_ReturnsTrue, TestSize.Level1)
{
    WifiSelfCureHistoryInfo historyInfo;
    historyInfo.reassocSelfCureFailedCnt = 0;
    int requestCureLevel = WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC;
    bool result = pSelfCureStateMachine->SelfCureAcceptable(historyInfo, requestCureLevel);
    ASSERT_TRUE(result);
}

HWTEST_F(SelfCureStateMachineTest, SelfCureAcceptable_RandMacReassoc_ReturnsTrue, TestSize.Level1)
{
    WifiSelfCureHistoryInfo historyInfo;
    historyInfo.randMacSelfCureFailedCnt = 0;
    int requestCureLevel = WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC;
    bool result = pSelfCureStateMachine->SelfCureAcceptable(historyInfo, requestCureLevel);
    ASSERT_TRUE(result);
}

HWTEST_F(SelfCureStateMachineTest, SelfCureAcceptable_HighReset_ReturnsTrue, TestSize.Level1)
{
    WifiSelfCureHistoryInfo historyInfo;
    historyInfo.resetSelfCureFailedCnt = 0;
    int requestCureLevel = WIFI_CURE_RESET_LEVEL_HIGH_RESET;
    bool result = pSelfCureStateMachine->SelfCureAcceptable(historyInfo, requestCureLevel);
    ASSERT_TRUE(result);
}

HWTEST_F(SelfCureStateMachineTest, HandleNetworkConnectedTest, TestSize.Level1)
{
    pSelfCureStateMachine->HandleNetworkConnected();
}

HWTEST_F(SelfCureStateMachineTest, GetCurrentGatewayTest, TestSize.Level1)
{
    IpInfo ipInfo;
    ipInfo.gateway = 1;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _))
        .WillOnce(DoAll(SetArgReferee<0>(ipInfo), Return(0)));
    pSelfCureStateMachine->GetCurrentGateway();
}

HWTEST_F(SelfCureStateMachineTest, UpdateSelfCureConnectHistoryInfo_Success_Reassoc, TestSize.Level1)
{
    WifiSelfCureHistoryInfo historyInfo;
    int requestCureLevel = WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC;
    bool success = true;
    pSelfCureStateMachine->UpdateSelfCureConnectHistoryInfo(historyInfo, requestCureLevel, success);
    ASSERT_EQ(historyInfo.reassocSelfCureConnectFailedCnt, 0);
    ASSERT_EQ(historyInfo.lastReassocSelfCureConnectFailedTs, 0);
}

HWTEST_F(SelfCureStateMachineTest, UpdateSelfCureConnectHistoryInfo_Failure_Reassoc, TestSize.Level1)
{
    WifiSelfCureHistoryInfo historyInfo;
    int requestCureLevel = WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC;
    bool success = false;
    pSelfCureStateMachine->UpdateSelfCureConnectHistoryInfo(historyInfo, requestCureLevel, success);
    ASSERT_EQ(historyInfo.reassocSelfCureConnectFailedCnt, 1);
}

HWTEST_F(SelfCureStateMachineTest, UpdateSelfCureConnectHistoryInfo_Success_RandMacReassoc, TestSize.Level1)
{
    WifiSelfCureHistoryInfo historyInfo;
    int requestCureLevel = WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC;
    bool success = true;
    pSelfCureStateMachine->UpdateSelfCureConnectHistoryInfo(historyInfo, requestCureLevel, success);
    ASSERT_EQ(historyInfo.randMacSelfCureConnectFailedCnt, 0);
    ASSERT_EQ(historyInfo.lastRandMacSelfCureConnectFailedCntTs, 0);
}

HWTEST_F(SelfCureStateMachineTest, UpdateSelfCureConnectHistoryInfo_Failure_RandMacReassoc, TestSize.Level1)
{
    WifiSelfCureHistoryInfo historyInfo;
    int requestCureLevel = WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC;
    bool success = false;
    pSelfCureStateMachine->UpdateSelfCureConnectHistoryInfo(historyInfo, requestCureLevel, success);
    ASSERT_EQ(historyInfo.randMacSelfCureConnectFailedCnt, 1);
}

HWTEST_F(SelfCureStateMachineTest, UpdateSelfCureConnectHistoryInfo_Success_Reset, TestSize.Level1)
{
    WifiSelfCureHistoryInfo historyInfo;
    int requestCureLevel = WIFI_CURE_RESET_LEVEL_HIGH_RESET;
    bool success = true;
    pSelfCureStateMachine->UpdateSelfCureConnectHistoryInfo(historyInfo, requestCureLevel, success);
    ASSERT_EQ(historyInfo.resetSelfCureConnectFailedCnt, 0);
    ASSERT_EQ(historyInfo.lastResetSelfCureConnectFailedTs, 0);
}

HWTEST_F(SelfCureStateMachineTest, UpdateSelfCureConnectHistoryInfo_Failure_Reset, TestSize.Level1)
{
    WifiSelfCureHistoryInfo historyInfo;
    int requestCureLevel = WIFI_CURE_RESET_LEVEL_HIGH_RESET;
    bool success = false;
    pSelfCureStateMachine->UpdateSelfCureConnectHistoryInfo(historyInfo, requestCureLevel, success);
    ASSERT_EQ(historyInfo.resetSelfCureConnectFailedCnt, 1);
}


HWTEST_F(SelfCureStateMachineTest, UpdateSelfCureHistoryInfo_Success_DnsSelfCureFailedCntZero, TestSize.Level1)
{
    WifiSelfCureHistoryInfo historyInfo;
    historyInfo.dnsSelfCureFailedCnt = 1;
    historyInfo.lastDnsSelfCureFailedTs = 1234567890;
    int requestCureLevel = WIFI_CURE_RESET_LEVEL_LOW_1_DNS;
    bool success = true;
    pSelfCureStateMachine->UpdateSelfCureHistoryInfo(historyInfo, requestCureLevel, success);
    EXPECT_EQ(historyInfo.dnsSelfCureFailedCnt, 0);
    EXPECT_EQ(historyInfo.lastDnsSelfCureFailedTs, 0);
}

HWTEST_F(SelfCureStateMachineTest, UpdateSelfCureHistoryInfo_Failure_DnsSelfCureFailedCntIncremented, TestSize.Level1)
{
    WifiSelfCureHistoryInfo historyInfo;
    historyInfo.dnsSelfCureFailedCnt = 1;
    historyInfo.lastDnsSelfCureFailedTs = 1234567890;
    int requestCureLevel = WIFI_CURE_RESET_LEVEL_LOW_1_DNS;
    bool success = false;
    pSelfCureStateMachine->UpdateSelfCureHistoryInfo(historyInfo, requestCureLevel, success);
    EXPECT_EQ(historyInfo.dnsSelfCureFailedCnt, 2);
    EXPECT_NE(historyInfo.lastDnsSelfCureFailedTs, 0);
}

HWTEST_F(SelfCureStateMachineTest, UpdateReassocAndResetHistoryInfo_SuccessfulReassoc, TestSize.Level1)
{
    WifiSelfCureHistoryInfo historyInfo;
    int requestCureLevel = WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC;
    bool success = true;

    pSelfCureStateMachine->UpdateReassocAndResetHistoryInfo(historyInfo, requestCureLevel, success);

    EXPECT_EQ(historyInfo.reassocSelfCureFailedCnt, 0);
    EXPECT_EQ(historyInfo.lastReassocSelfCureFailedTs, 0);
}

HWTEST_F(SelfCureStateMachineTest, UpdateReassocAndResetHistoryInfo_FailedReassoc, TestSize.Level1)
{
    WifiSelfCureHistoryInfo historyInfo;
    int requestCureLevel = WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC;
    bool success = false;

    pSelfCureStateMachine->UpdateReassocAndResetHistoryInfo(historyInfo, requestCureLevel, success);

    EXPECT_EQ(historyInfo.reassocSelfCureFailedCnt, 1);
    EXPECT_NE(historyInfo.lastReassocSelfCureFailedTs, 0);
}

HWTEST_F(SelfCureStateMachineTest, UpdateReassocAndResetHistoryInfo_SuccessfulRandMacReassoc, TestSize.Level1)
{
    WifiSelfCureHistoryInfo historyInfo;
    int requestCureLevel = WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC;
    bool success = true;

    pSelfCureStateMachine->UpdateReassocAndResetHistoryInfo(historyInfo, requestCureLevel, success);

    EXPECT_EQ(historyInfo.randMacSelfCureFailedCnt, 0);
    EXPECT_EQ(historyInfo.lastRandMacSelfCureFailedCntTs, 0);
}

HWTEST_F(SelfCureStateMachineTest, UpdateReassocAndResetHistoryInfo_FailedRandMacReassoc, TestSize.Level1)
{
    WifiSelfCureHistoryInfo historyInfo;
    int requestCureLevel = WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC;
    bool success = false;

    pSelfCureStateMachine->UpdateReassocAndResetHistoryInfo(historyInfo, requestCureLevel, success);

    EXPECT_EQ(historyInfo.randMacSelfCureFailedCnt, 1);
    EXPECT_NE(historyInfo.lastRandMacSelfCureFailedCntTs, 0);
}

HWTEST_F(SelfCureStateMachineTest, UpdateReassocAndResetHistoryInfo_SuccessfulHighReset, TestSize.Level1)
{
    WifiSelfCureHistoryInfo historyInfo;
    int requestCureLevel = WIFI_CURE_RESET_LEVEL_HIGH_RESET;
    bool success = true;

    pSelfCureStateMachine->UpdateReassocAndResetHistoryInfo(historyInfo, requestCureLevel, success);

    EXPECT_EQ(historyInfo.resetSelfCureFailedCnt, 0);
    EXPECT_EQ(historyInfo.lastResetSelfCureFailedTs, 0);
}

HWTEST_F(SelfCureStateMachineTest, UpdateReassocAndResetHistoryInfo_FailedHighReset, TestSize.Level1)
{
    WifiSelfCureHistoryInfo historyInfo;
    int requestCureLevel = WIFI_CURE_RESET_LEVEL_HIGH_RESET;
    bool success = false;

    pSelfCureStateMachine->UpdateReassocAndResetHistoryInfo(historyInfo, requestCureLevel, success);

    EXPECT_EQ(historyInfo.resetSelfCureFailedCnt, 1);
    EXPECT_NE(historyInfo.lastResetSelfCureFailedTs, 0);
}

HWTEST_F(SelfCureStateMachineTest, HandleP2pConnChanged_P2pConnectedState_SetP2pConnectedFlag, TestSize.Level1)
{
    WifiP2pLinkedInfo info;
    info.SetConnectState(P2pConnectedState::P2P_CONNECTED);
    pSelfCureStateMachine->HandleP2pConnChanged(info);
    EXPECT_TRUE(pSelfCureStateMachine->p2pConnected);
}

HWTEST_F(SelfCureStateMachineTest, HandleP2pConnChanged_P2pDisconnectedState_ClearP2pConnectedFlag, TestSize.Level1)
{
    WifiP2pLinkedInfo info;
    info.SetConnectState(P2pConnectedState::P2P_DISCONNECTED);
    pSelfCureStateMachine->HandleP2pConnChanged(info);
    EXPECT_FALSE(pSelfCureStateMachine->p2pConnected);
}

HWTEST_F(SelfCureStateMachineTest, IfMultiGateway_Test, TestSize.Level1)
{
    pSelfCureStateMachine->IfMultiGateway();
}

HWTEST_F(SelfCureStateMachineTest, IsSelfCureOnGoing_Test, TestSize.Level1)
{
    pSelfCureStateMachine->IsSelfCureOnGoing();
}

HWTEST_F(SelfCureStateMachineTest, SetHttpMonitorStatusTest, TestSize.Level1)
{
    bool isHttpReachable = true;
    pSelfCureStateMachine->SetHttpMonitorStatus(isHttpReachable);
}

HWTEST_F(SelfCureStateMachineTest, GetCurrentRssiTest, TestSize.Level1)
{
    pSelfCureStateMachine->GetCurrentRssi();
}

HWTEST_F(SelfCureStateMachineTest, GetIsReassocWithFactoryMacAddressTest, TestSize.Level1)
{
    pSelfCureStateMachine->GetIsReassocWithFactoryMacAddress();
}

HWTEST_F(SelfCureStateMachineTest, IsEncryptedAuthTypeTest, TestSize.Level1)
{
    std::string authType = "";
    pSelfCureStateMachine->IsEncryptedAuthType(authType);

    authType = "KEY_MGMT_WPA_PSK";
    pSelfCureStateMachine->IsEncryptedAuthType(authType);

    authType = KEY_MGMT_WAPI_PSK;
    pSelfCureStateMachine->IsEncryptedAuthType(authType);

    authType = "KEY_MGMT_SAE";
    pSelfCureStateMachine->IsEncryptedAuthType(authType);
}

HWTEST_F(SelfCureStateMachineTest, IsHttpReachableTest, TestSize.Level1)
{
    IsHttpReachableTest();
}
} // namespace Wifi
} // namespace OHOS
