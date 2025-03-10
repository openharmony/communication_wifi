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
#include "wifi_country_code_manager.h"
#include "self_cure_utils.h"

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
constexpr int TEN = 10;

static std::string g_errLog;
void SelfCureStateMachineCallBack(const LogType type, const LogLevel level,
                                  const unsigned int domain,
                                  const char *tag, const char *msg)
{
    g_errLog = msg;
}
class SelfCureStateMachineTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        LOG_SetCallback(SelfCureStateMachineCallBack);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiSelfcureReset(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        pSelfCureStateMachine_ = std::make_unique<SelfCureStateMachine>();
        pSelfCureStateMachine_->Initialize();
        pMockStaService = std::make_unique<MockWifiStaService>();
    }

    virtual void TearDown()
    {
        pSelfCureStateMachine_.reset();
    }

    std::unique_ptr<SelfCureStateMachine> pSelfCureStateMachine_;
    std::unique_ptr<MockWifiStaService> pMockStaService;

    void DefaultStateGoInStateSuccess()
    {
        LOGI("Enter DefaultStateGoInStateSuccess");
        pSelfCureStateMachine_->pDefaultState_->GoInState();
    }

    void DefaultStateGoOutStateSuccess()
    {
        LOGI("Enter DefaultStateGoOutStateSuccess");
        pSelfCureStateMachine_->pDefaultState_->GoOutState();
    }

    void DefaultStateExeMsgFail()
    {
        LOGI("Enter DefaultStateExeMsgFail");
        EXPECT_FALSE(pSelfCureStateMachine_->pDefaultState_->ExecuteStateMsg(nullptr));
    }

    void DefaultStateExeMsgSuccess1()
    {
        LOGI("Enter DefaultStateExeMsgSuccess1");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(1);
        EXPECT_FALSE(pSelfCureStateMachine_->pDefaultState_->ExecuteStateMsg(msg));
        msg->SetMessageName(0);
        EXPECT_FALSE(pSelfCureStateMachine_->pDefaultState_->ExecuteStateMsg(msg));
    }

    void ConnectedMonitorStateGoInStateSuccess()
    {
        LOGI("Enter ConnectedMonitorStateGoInStateSuccess");
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiSelfcureReset()).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetStaIfaceName(_)).WillRepeatedly(Return("sta"));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetLastNetworkId(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), AddDeviceConfig(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig()).Times(AtLeast(0));
        pSelfCureStateMachine_->pConnectedMonitorState_->GoInState();
    }

    void ConnectedMonitorStateGoOutStateSuccess()
    {
        LOGI("Enter ConnectedMonitorStateGoOutStateSuccess");
        pSelfCureStateMachine_->pConnectedMonitorState_->GoOutState();
    }

    void ConnectedMonitorStateExeMsgFail()
    {
        LOGI("Enter ConnectedMonitorStateExeMsgFail");
        EXPECT_FALSE(pSelfCureStateMachine_->pConnectedMonitorState_->ExecuteStateMsg(nullptr));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(0);
        pSelfCureStateMachine_->pConnectedMonitorState_->ExecuteStateMsg(msg);
    }

    void ConnectedMonitorStateExeMsgSuccess1()
    {
        LOGI("Enter ConnectedMonitorStateExeMsgSuccess1");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_PERIODIC_ARP_DETECTED);
        pSelfCureStateMachine_->pConnectedMonitorState_->ExecuteStateMsg(msg);
    }

    void InitSelfCureCmsHandleMapTest()
    {
        LOGI("Enter InitSelfCureCmsHandleMapTest");
        EXPECT_EQ(pSelfCureStateMachine_->pConnectedMonitorState_->InitSelfCureCmsHandleMap(), 0);
    }

    void TransitionToSelfCureStateTest()
    {
        LOGI("Enter TransitionToSelfCureStateTest");
        int reason = 0;
        pSelfCureStateMachine_->pConnectedMonitorState_->isMobileHotspot_ = false;
        pSelfCureStateMachine_->pConnectedMonitorState_->TransitionToSelfCureState(reason);

        pSelfCureStateMachine_->pConnectedMonitorState_->isMobileHotspot_ = true;
        reason = WIFI_CURE_INTERNET_FAILED_TYPE_TCP;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpv6Info(_, _)).Times(AtLeast(0));
        pSelfCureStateMachine_->pConnectedMonitorState_->TransitionToSelfCureState(reason);

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
        pSelfCureStateMachine_->pConnectedMonitorState_->TransitionToSelfCureState(reason);

        ipInfo.secondDns = 1;
        ipInfo.gateway = 1;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(ipInfo), Return(0)));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpv6Info(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(ipv6Info), Return(0)));
        pSelfCureStateMachine_->pConnectedMonitorState_->TransitionToSelfCureState(reason);
    }

    void HandleResetupSelfCureTest()
    {
        LOGI("Enter TransitionToSelfCureStateTest");
        pSelfCureStateMachine_->pConnectedMonitorState_->HandleResetupSelfCure(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_RESETUP_SELF_CURE_MONITOR);
        pSelfCureStateMachine_->pConnectedMonitorState_->HandleResetupSelfCure(msg);
        EXPECT_NE(pSelfCureStateMachine_->instId_, TEN);
    }

    void HandlePeriodicArpDetectionTest()
    {
        LOGI("Enter HandlePeriodicArpDetectionTest");
        pSelfCureStateMachine_->pConnectedMonitorState_->HandlePeriodicArpDetection(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_PERIODIC_ARP_DETECTED);
        pSelfCureStateMachine_->pConnectedMonitorState_->HandlePeriodicArpDetection(msg);
        EXPECT_NE(pSelfCureStateMachine_->instId_, TEN);
    }

    void HandleNetworkConnectTest()
    {
        LOGI("Enter HandleNetworkConnectTest");
        pSelfCureStateMachine_->pConnectedMonitorState_->HandleNetworkConnect(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_NOTIFY_NETWORK_CONNECTED_RCVD);
        pSelfCureStateMachine_->pConnectedMonitorState_->HandleNetworkConnect(msg);
        EXPECT_NE(pSelfCureStateMachine_->instId_, TEN);
    }

    void HandleNetworkDisconnectTest()
    {
        LOGI("Enter HandleNetworkDisconnectTest");
        pSelfCureStateMachine_->pConnectedMonitorState_->HandleNetworkDisconnect(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_NOTIFY_NETWORK_DISCONNECTED_RCVD);
        pSelfCureStateMachine_->pConnectedMonitorState_->HandleNetworkDisconnect(msg);
        EXPECT_NE(pSelfCureStateMachine_->instId_, TEN);
    }

    void HandleRssiLevelChangeTest()
    {
        LOGI("Enter HandleRssiLevelChangeTest");
        pSelfCureStateMachine_->pConnectedMonitorState_->HandleRssiLevelChange(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_NOTIFY_RSSI_LEVEL_CHANGED_EVENT);
        pSelfCureStateMachine_->pConnectedMonitorState_->HandleRssiLevelChange(msg);
        EXPECT_NE(pSelfCureStateMachine_->instId_, TEN);
    }

    void HandleArpDetectionFailedTest()
    {
        LOGI("Enter HandleArpDetectionFailedTest");
        pSelfCureStateMachine_->pConnectedMonitorState_->HandleArpDetectionFailed(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_ARP_FAILED_DETECTED);
        pSelfCureStateMachine_->pConnectedMonitorState_->HandleArpDetectionFailed(msg);
    }

    void SetupSelfCureMonitorTest()
    {
        LOGI("Enter SetupSelfCureMonitorTest");
        pSelfCureStateMachine_->pConnectedMonitorState_->SetupSelfCureMonitor();
        IpInfo ipInfo;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _))
            .WillOnce(DoAll(SetArgReferee<0>(ipInfo), Return(0)));
            ipInfo.ipAddress = 0x0100007F;
        pSelfCureStateMachine_->pConnectedMonitorState_->SetupSelfCureMonitor();
    }

    void IsGatewayChangedTest()
    {
        LOGI("Enter IsGatewayChangedTest");
        pSelfCureStateMachine_->pConnectedMonitorState_->IsGatewayChanged();
    }

    void HandleGatewayChangedTest()
    {
        LOGI("enter HandleGatewayChangedTest");
        pSelfCureStateMachine_->pConnectedMonitorState_->HandleGatewayChanged(nullptr);

        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_GATEWAY_CHANGED_DETECT);
        pSelfCureStateMachine_->pConnectedMonitorState_->HandleGatewayChanged(msg);
        pSelfCureStateMachine_->pConnectedMonitorState_->isHasInternetRecently_ = true;
        pSelfCureStateMachine_->pConnectedMonitorState_->configAuthType_ = KEY_MGMT_WPA_PSK;
        pSelfCureStateMachine_->pConnectedMonitorState_->HandleGatewayChanged(msg);

        pSelfCureStateMachine_->pConnectedMonitorState_->isHasInternetRecently_ = false;
        pSelfCureStateMachine_->pConnectedMonitorState_->HandleGatewayChanged(msg);
        EXPECT_NE(pSelfCureStateMachine_->instId_, TEN);
    }

    void RequestReassocWithFactoryMacTest()
    {
        LOGI("Enter RequestReassocWithFactoryMacTest");
        pSelfCureStateMachine_->pConnectedMonitorState_->RequestReassocWithFactoryMac();
        EXPECT_NE(pSelfCureStateMachine_->instId_, TEN);
    }

    void IsCustNetworkSelfCureTest()
    {
        LOGI("Enter IsCustNetworkSelfCureTest");
        pSelfCureStateMachine_->IsCustNetworkSelfCure();
    }

    void HandleInvalidIpTest()
    {
        LOGI("Enter HandleInvalidIpTest");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_INVALID_IP_CONFIRM);
        pSelfCureStateMachine_->isHttpReachable_ = true;
        pSelfCureStateMachine_->pConnectedMonitorState_->HandleInvalidIp(msg);
        pSelfCureStateMachine_->isHttpReachable_ = false;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpv6Info(_, _)).Times(AtLeast(0));
        pSelfCureStateMachine_->pConnectedMonitorState_->HandleInvalidIp(msg);
    }

    void HandleInternetFailedDetectedTest()
    {
        LOGI("Enter HandleInternetFailedDetectedTest");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_INTERNET_FAILURE_DETECTED);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpv6Info(_, _)).Times(AtLeast(0));
        pSelfCureStateMachine_->pConnectedMonitorState_->isMobileHotspot_ = false;
        pSelfCureStateMachine_->pConnectedMonitorState_->HandleInternetFailedDetected(msg);

        pSelfCureStateMachine_->pConnectedMonitorState_->isMobileHotspot_ = true;
        std::string currConnectedBssid = CURR_BSSID;
        WifiLinkedInfo wifiLinkedInfo;
        wifiLinkedInfo.supportedWifiCategory = WifiCategory::WIFI6;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));
        pSelfCureStateMachine_->pConnectedMonitorState_->HandleInternetFailedDetected(msg);

        wifiLinkedInfo.supportedWifiCategory = WifiCategory::DEFAULT;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));
        pSelfCureStateMachine_->pConnectedMonitorState_->HandleInternetFailedDetected(msg);
        
        pSelfCureStateMachine_->isHttpReachable_ = true;
        pSelfCureStateMachine_->pConnectedMonitorState_->HandleInternetFailedDetected(msg);

        pSelfCureStateMachine_->isHttpReachable_ = false;
        pSelfCureStateMachine_->pConnectedMonitorState_->HandleInternetFailedDetected(msg);
    }

    void HandleTcpQualityQueryTest()
    {
        LOGI("Enter HandleTcpQualityQueryTest");
        pSelfCureStateMachine_->pConnectedMonitorState_->HandleTcpQualityQuery(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_INTERNET_STATUS_DETECT_INTERVAL);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScreenState()).WillRepeatedly(Return(MODE_STATE_OPEN));
        pSelfCureStateMachine_->pConnectedMonitorState_->HandleTcpQualityQuery(msg);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScreenState()).WillRepeatedly(Return(MODE_STATE_CLOSE));
        pSelfCureStateMachine_->pConnectedMonitorState_->HandleTcpQualityQuery(msg);
    }

    void DisconnectedMonitorGoInStateSuccess()
    {
        LOGI("Enter DisconnectedMonitorGoInStateSuccess");
        pSelfCureStateMachine_->pDisconnectedMonitorState_->GoInState();
    }

    void DisconnectedMonitorGoOutStateSuccess()
    {
        LOGI("Enter DisconnectedMonitorGoOutStateSuccess");
        pSelfCureStateMachine_->pDisconnectedMonitorState_->GoOutState();
    }

    void DisconnectedMonitorExeMsgFail()
    {
        LOGI("Enter DisconnectedMonitorExeMsgFail");
        EXPECT_FALSE(pSelfCureStateMachine_->pDisconnectedMonitorState_->ExecuteStateMsg(nullptr));
    }

    void DisconnectedMonitorExeMsgSuccess1()
    {
        LOGI("Enter DisconnectedMonitorExeMsgSuccess1");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(1);
        EXPECT_FALSE(pSelfCureStateMachine_->pDisconnectedMonitorState_->ExecuteStateMsg(msg));
    }

    void DisconnectedMonitorExeMsgSuccess2()
    {
        LOGI("Enter DisconnectedMonitorExeMsgSuccess2");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_NOTIFY_NETWORK_CONNECTED_RCVD);
        EXPECT_TRUE(pSelfCureStateMachine_->pDisconnectedMonitorState_->ExecuteStateMsg(msg));
    }

    void ConnectionSelfCureGoInStateSuccess()
    {
        LOGI("Enter ConnectionSelfCureGoInStateSuccess");
        pSelfCureStateMachine_->pConnectionSelfCureState_->GoInState();
    }

    void ConnectionSelfCureGoOutStateSuccess()
    {
        LOGI("Enter ConnectionSelfCureGoOutStateSuccess");
        pSelfCureStateMachine_->pConnectionSelfCureState_->GoOutState();
    }

    void ConnectionSelfCureExeMsgFail()
    {
        LOGI("Enter ConnectionSelfCureExeMsgFail");
        EXPECT_FALSE(pSelfCureStateMachine_->pConnectionSelfCureState_->ExecuteStateMsg(nullptr));
    }

    void ConnectionSelfCureExeMsgSuccess1()
    {
        LOGI("Enter ConnectionSelfCureExeMsgSuccess1");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(1);
        EXPECT_FALSE(pSelfCureStateMachine_->pConnectionSelfCureState_->ExecuteStateMsg(msg));
        msg->SetMessageName(0);
        EXPECT_TRUE(pSelfCureStateMachine_->pConnectionSelfCureState_->ExecuteStateMsg(msg));
    }

    void InternetSelfCureGoInStateSuccess()
    {
        LOGI("Enter InternetSelfCureGoInStateSuccess");
        pSelfCureStateMachine_->pInternetSelfCureState_->GoInState();
    }

    void InternetSelfCureGoOutStateSuccess()
    {
        LOGI("Enter InternetSelfCureGoOutStateSuccess");
        pSelfCureStateMachine_->pInternetSelfCureState_->GoOutState();
        EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
    }

    void InternetSelfCureExeMsgFail()
    {
        LOGI("Enter InternetSelfCureExeMsgFail");
        EXPECT_FALSE(pSelfCureStateMachine_->pInternetSelfCureState_->ExecuteStateMsg(nullptr));
    }

    void InternetSelfCureExeMsgSuccess1()
    {
        LOGI("Enter InternetSelfCureExeMsgSuccess1");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_INTERNET_FAILED_SELF_CURE);
        pSelfCureStateMachine_->pInternetSelfCureState_->ExecuteStateMsg(msg);
        msg->SetMessageName(0);
        pSelfCureStateMachine_->pInternetSelfCureState_->ExecuteStateMsg(msg);
    }

    void InitSelfCureIssHandleMapTest()
    {
        LOGI("Enter InitSelfCureIssHandleMapTest");
        EXPECT_EQ(pSelfCureStateMachine_->pInternetSelfCureState_->InitSelfCureIssHandleMap(), 0);
    }

    void HandleInternetFailedSelfCureTest()
    {
        LOGI("Enter HandleInternetFailedSelfCureTest");
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleInternetFailedSelfCure(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_INTERNET_FAILED_SELF_CURE);
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleInternetFailedSelfCure(msg);

        WifiLinkedInfo wifiLinkedInfo;
        wifiLinkedInfo.connState = ConnState::CONNECTED;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleInternetFailedSelfCure(msg);
    }

    void HandleSelfCureWifiLinkTest()
    {
        LOGI("Enter HandleSelfCureWifiLinkTest");
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleSelfCureWifiLink(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_SELF_CURE_WIFI_LINK);
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleSelfCureWifiLink(msg);

        WifiLinkedInfo wifiLinkedInfo;
        wifiLinkedInfo.connState = ConnState::CONNECTED;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleSelfCureWifiLink(msg);
    }

    void HandleNetworkDisconnectedTest()
    {
        LOGI("Enter HandleNetworkDisconnectedTest");
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleNetworkDisconnected(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_NOTIFY_NETWORK_DISCONNECTED_RCVD);
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleNetworkDisconnected(msg);
        EXPECT_NE(pSelfCureStateMachine_->instId_, TEN);
    }

    void HandleInternetRecoveryTest()
    {
        LOGI("Enter HandleInternetRecoveryTest");
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleInternetRecoveryConfirm(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_INTERNET_RECOVERY_CONFIRM);
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleInternetRecoveryConfirm(msg);

        pSelfCureStateMachine_->isSelfCureOnGoing_ = true;
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleInternetRecoveryConfirm(msg);
        EXPECT_NE(pSelfCureStateMachine_->instId_, TEN);
    }

    void HandleRssiChangedEventTest()
    {
        LOGI("Enter HandleRssiChangedEventTest");
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleRssiChangedEvent(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_NOTIFY_RSSI_LEVEL_CHANGED_EVENT);
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleRssiChangedEvent(msg);
        EXPECT_NE(pSelfCureStateMachine_->pInternetSelfCureState_->currentRssi_, TEN);
    }

    void HandleP2pDisconnectedTest()
    {
        LOGI("Enter HandleP2pDisconnectedTest");
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleP2pDisconnected(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_P2P_DISCONNECTED_EVENT);
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleP2pDisconnected(msg);
        EXPECT_NE(pSelfCureStateMachine_->instId_, TEN);
    }

    void HandlePeriodicArpDetecteTest()
    {
        LOGI("Enter HandlePeriodicArpDetecteTest");
        pSelfCureStateMachine_->pInternetSelfCureState_->HandlePeriodicArpDetecte(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_PERIODIC_ARP_DETECTED);
        pSelfCureStateMachine_->pInternetSelfCureState_->HandlePeriodicArpDetecte(msg);
        EXPECT_NE(pSelfCureStateMachine_->instId_, TEN);
    }

    void HandleHttpReachableRecvTest()
    {
        LOGI("Enter HandleHttpReachableRecvTest");
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleHttpReachableRecv(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_HTTP_REACHABLE_RCV);
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleHttpReachableRecv(msg);
        EXPECT_NE(pSelfCureStateMachine_->useWithRandMacAddress_, TEN);
    }

    void HandleArpFailedDetectedTest()
    {
        LOGI("Enter HandleArpFailedDetectedTest");
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleArpFailedDetected(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_ARP_FAILED_DETECTED);
        EXPECT_CALL(WifiConfigCenter::GetInstance(),
            GetWifiCategoryBlackListCache(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        WifiLinkedInfo wifiLinkedInfo;
        wifiLinkedInfo.supportedWifiCategory = WifiCategory::WIFI6;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleArpFailedDetected(msg);

        pSelfCureStateMachine_->isSelfCureOnGoing_ = false;
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleArpFailedDetected(msg);

        pSelfCureStateMachine_->isSelfCureOnGoing_ = true;
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleArpFailedDetected(msg);

        pSelfCureStateMachine_->isHttpReachable_ = false;
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleArpFailedDetected(msg);
        
        pSelfCureStateMachine_->isHttpReachable_ = true;
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleArpFailedDetected(msg);
    }

    void SelectSelfCureByFailedReasonTest()
    {
        LOGI("Enter SelectSelfCureByFailedReasonTest");
        int internetFailedType = WIFI_CURE_INTERNET_FAILED_TYPE_DNS;
        pSelfCureStateMachine_->pInternetSelfCureState_->isUserSetStaticIpConfig_ = true;
        pSelfCureStateMachine_->pInternetSelfCureState_->SelectSelfCureByFailedReason(internetFailedType);

        internetFailedType = WIFI_CURE_INTERNET_FAILED_TYPE_GATEWAY;
        pSelfCureStateMachine_->pInternetSelfCureState_->SelectSelfCureByFailedReason(internetFailedType);
        internetFailedType = 0;
        pSelfCureStateMachine_->pInternetSelfCureState_->SelectSelfCureByFailedReason(internetFailedType);

        pSelfCureStateMachine_->pInternetSelfCureState_->isUserSetStaticIpConfig_ = false;
        internetFailedType = WIFI_CURE_INTERNET_FAILED_TYPE_DNS;
        pSelfCureStateMachine_->pInternetSelfCureState_->SelectSelfCureByFailedReason(internetFailedType);
        internetFailedType = WIFI_CURE_INTERNET_FAILED_TYPE_TCP;
        pSelfCureStateMachine_->pInternetSelfCureState_->SelectSelfCureByFailedReason(internetFailedType);
        
        pSelfCureStateMachine_->pInternetSelfCureState_->selfCureHistoryInfo_.resetSelfCureFailedCnt =
            SELFCURE_FAILED_CNT;
        SelfCureUtils::GetInstance().UpdateSelfCureHistoryInfo(pSelfCureStateMachine_->pInternetSelfCureState_->
            selfCureHistoryInfo_, WIFI_CURE_RESET_LEVEL_HIGH_RESET, false);
        pSelfCureStateMachine_->pInternetSelfCureState_->SelectSelfCureByFailedReason(internetFailedType);
    }

    void SelectBestSelfCureSolutionTest()
    {
        LOGI("Enter SelectBestSelfCureSolutionTest");
        int internetFailedType = WIFI_CURE_INTERNET_FAILED_TYPE_GATEWAY;
        pSelfCureStateMachine_->pInternetSelfCureState_->SelectBestSelfCureSolution(internetFailedType);
        pSelfCureStateMachine_->pInternetSelfCureState_->configAuthType_ = KEY_MGMT_WPA_PSK;
        pSelfCureStateMachine_->pInternetSelfCureState_->SelectBestSelfCureSolution(internetFailedType);
        pSelfCureStateMachine_->connectedTime_ = 0;
        pSelfCureStateMachine_->pInternetSelfCureState_->lastHasInetTime_ = static_cast<int64_t>(time(nullptr));
        pSelfCureStateMachine_->pInternetSelfCureState_->SelectBestSelfCureSolution(internetFailedType);
    }

    void SelectBestSelfCureSolutionExtTest()
    {
        LOGI("Enter SelectBestSelfCureSolutionExtTest");
        int internetFailedType = WIFI_CURE_INTERNET_FAILED_INVALID_IP;
        pSelfCureStateMachine_->pInternetSelfCureState_->SelectBestSelfCureSolutionExt(internetFailedType);
        internetFailedType = WIFI_CURE_INTERNET_FAILED_TYPE_DNS;
        pSelfCureStateMachine_->pInternetSelfCureState_->SelectBestSelfCureSolutionExt(internetFailedType);
        internetFailedType = WIFI_CURE_INTERNET_FAILED_RAND_MAC;
        pSelfCureStateMachine_->pInternetSelfCureState_->SelectBestSelfCureSolutionExt(internetFailedType);
        internetFailedType = WIFI_CURE_INTERNET_FAILED_TYPE_TCP;
        pSelfCureStateMachine_->pInternetSelfCureState_->SelectBestSelfCureSolutionExt(internetFailedType);
    }

    void GetNextTestDhcpResultsTest()
    {
        LOGI("Enter GetNextTestDhcpResultsTest");
        pSelfCureStateMachine_->pInternetSelfCureState_->GetNextTestDhcpResults();
    }

    void GetRecordDhcpResultsTest()
    {
        LOGI("Enter GetRecordDhcpResultsTest");
        pSelfCureStateMachine_->pInternetSelfCureState_->GetRecordDhcpResults();
    }

    void SelfCureWifiLinkTest()
    {
        LOGI("Enter SelfCureWifiLinkTest");
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetLastNetworkId(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiSelfcureReset(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiToggledState(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), AddDeviceConfig(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig()).Times(AtLeast(0));
        int requestCureLevel = 0;
        pSelfCureStateMachine_->pInternetSelfCureState_->SelfCureWifiLink(requestCureLevel);
        requestCureLevel = WIFI_CURE_RESET_LEVEL_LOW_3_STATIC_IP;
        pSelfCureStateMachine_->pInternetSelfCureState_->SelfCureWifiLink(requestCureLevel);
        requestCureLevel = WIFI_CURE_RESET_LEVEL_RECONNECT_4_INVALID_IP;
        pSelfCureStateMachine_->pInternetSelfCureState_->SelfCureWifiLink(requestCureLevel);
        requestCureLevel = WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC;
        pSelfCureStateMachine_->pInternetSelfCureState_->SelfCureWifiLink(requestCureLevel);
        requestCureLevel = WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC;
        pSelfCureStateMachine_->pInternetSelfCureState_->SelfCureWifiLink(requestCureLevel);
        requestCureLevel = WIFI_CURE_RESET_LEVEL_HIGH_RESET;
        pSelfCureStateMachine_->pInternetSelfCureState_->SelfCureWifiLink(requestCureLevel);
    }

    void SelfCureForStaticIpTest()
    {
        LOGI("Enter SelfCureForStaticIpTest");
        int requestCureLevel = WIFI_CURE_RESET_LEVEL_LOW_3_STATIC_IP;
        pSelfCureStateMachine_->pInternetSelfCureState_->isConfigStaticIp4MultiDhcpServer_ = true;
        pSelfCureStateMachine_->pInternetSelfCureState_->SelfCureForStaticIp(requestCureLevel);
        pSelfCureStateMachine_->pInternetSelfCureState_->isConfigStaticIp4MultiDhcpServer_ = false;
        pSelfCureStateMachine_->pInternetSelfCureState_->SelfCureForStaticIp(requestCureLevel);
        EXPECT_NE(pSelfCureStateMachine_->useWithRandMacAddress_, TEN);
    }

    void RequestUseStaticIpConfigTest()
    {
        LOGI("Enter RequestUseStaticIpConfigTest");
        IpInfo dhcpResult;
        dhcpResult.ipAddress = IpTools::ConvertIpv4Address("192.168.101.39");
        dhcpResult.gateway = IpTools::ConvertIpv4Address("192.168.101.1");
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetStaIfaceName(_)).WillRepeatedly(Return("wlan0"));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SaveLinkedInfo(_, _)).Times(AtLeast(0));
        pSelfCureStateMachine_->pInternetSelfCureState_->RequestUseStaticIpConfig(dhcpResult);
    }

    void SelfCureForInvalidIpTest()
    {
        LOGI("Enter SelfCureForInvalidIpTest");
        pSelfCureStateMachine_->pInternetSelfCureState_->selfCureForInvalidIpCnt_ = 0;
        pSelfCureStateMachine_->pInternetSelfCureState_->SelfCureForInvalidIp();

        pSelfCureStateMachine_->pInternetSelfCureState_->selfCureForInvalidIpCnt_ = MAX_SELF_CURE_CNT_INVALID_IP + 1;
        pSelfCureStateMachine_->pInternetSelfCureState_->SelfCureForInvalidIp();

        pSelfCureStateMachine_->pInternetSelfCureState_->selfCureForInvalidIpCnt_ = 0;
        EXPECT_CALL(*pMockStaService, Disconnect()).WillRepeatedly(Return(WIFI_OPT_FAILED));
        pSelfCureStateMachine_->pInternetSelfCureState_->SelfCureForInvalidIp();

        EXPECT_CALL(*pMockStaService, Disconnect()).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
        pSelfCureStateMachine_->pInternetSelfCureState_->SelfCureForInvalidIp();
    }

    void SelfCureForReassocTest()
    {
        LOGI("Enter SelfCureForReassocTest");
        int requestCureLevel = WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC;
        pSelfCureStateMachine_->pInternetSelfCureState_->currentRssi_ = MIN_VAL_LEVEL_2_24G;
        pSelfCureStateMachine_->pInternetSelfCureState_->SelfCureForReassoc(requestCureLevel);

        WifiP2pLinkedInfo linkedInfo;
        linkedInfo.SetConnectState(P2pConnectedState::P2P_CONNECTED);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetP2pInfo(_))
            .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
        pSelfCureStateMachine_->pInternetSelfCureState_->SelfCureForReassoc(requestCureLevel);

        linkedInfo.SetConnectState(P2pConnectedState::P2P_DISCONNECTED);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetP2pInfo(_))
            .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
        pSelfCureStateMachine_->pInternetSelfCureState_->SelfCureForReassoc(requestCureLevel);

        pSelfCureStateMachine_->pInternetSelfCureState_->currentRssi_ = MIN_VAL_LEVEL_4;
        pSelfCureStateMachine_->pInternetSelfCureState_->SelfCureForReassoc(requestCureLevel);

        EXPECT_CALL(*pMockStaService, ReAssociate()).WillRepeatedly(Return(WIFI_OPT_FAILED));
        pSelfCureStateMachine_->pInternetSelfCureState_->SelfCureForReassoc(requestCureLevel);

        EXPECT_CALL(*pMockStaService, ReAssociate()).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
        pSelfCureStateMachine_->pInternetSelfCureState_->SelfCureForReassoc(requestCureLevel);
    }

    void IsNeedMultiGatewaySelfcureTest()
    {
        LOGI("Enter IsNeedMultiGatewaySelfcureTest");
        pSelfCureStateMachine_->pInternetSelfCureState_->IsNeedMultiGatewaySelfcure();
        pSelfCureStateMachine_->pInternetSelfCureState_->isUsedMultiGwSelfcure_ = true;
        EXPECT_EQ(pSelfCureStateMachine_->pInternetSelfCureState_->IsNeedMultiGatewaySelfcure(), false);
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
        pSelfCureStateMachine_->pInternetSelfCureState_->SelfcureForMultiGateway(msg);

        linkedInfo.connState = ConnState::CONNECTED;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
        pSelfCureStateMachine_->pInternetSelfCureState_->SelfcureForMultiGateway(msg);
    }

    void SelfCureForRandMacReassocTest()
    {
        LOGI("Enter SelfCureForRandMacReassocTest");
        int requestCureLevel = WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetLastNetworkId(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), AddDeviceConfig(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig()).Times(AtLeast(0));
        pSelfCureStateMachine_->pInternetSelfCureState_->SelfCureForRandMacReassoc(requestCureLevel);

        pSelfCureStateMachine_->pInternetSelfCureState_->currentRssi_ = MIN_VAL_LEVEL_2_24G;
        pSelfCureStateMachine_->pInternetSelfCureState_->SelfCureForRandMacReassoc(requestCureLevel);

        WifiP2pLinkedInfo linkedInfo;
        linkedInfo.SetConnectState(P2pConnectedState::P2P_CONNECTED);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetP2pInfo(_))
            .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
        pSelfCureStateMachine_->pInternetSelfCureState_->SelfCureForRandMacReassoc(requestCureLevel);

        linkedInfo.SetConnectState(P2pConnectedState::P2P_DISCONNECTED);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetP2pInfo(_))
            .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
        pSelfCureStateMachine_->pInternetSelfCureState_->SelfCureForRandMacReassoc(requestCureLevel);

        pSelfCureStateMachine_->pInternetSelfCureState_->currentRssi_ = MIN_VAL_LEVEL_4;
        pSelfCureStateMachine_->pInternetSelfCureState_->SelfCureForRandMacReassoc(requestCureLevel);

        EXPECT_CALL(*pMockStaService, ConnectToNetwork(_, _)).WillRepeatedly(Return(WIFI_OPT_FAILED));
        pSelfCureStateMachine_->pInternetSelfCureState_->SelfCureForRandMacReassoc(requestCureLevel);

        EXPECT_CALL(*pMockStaService, ConnectToNetwork(_, _)).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
        pSelfCureStateMachine_->pInternetSelfCureState_->SelfCureForRandMacReassoc(requestCureLevel);
    }

    void SelectedSelfCureAcceptableTest()
    {
        LOGI("Enter SelectedSelfCureAcceptableTest");
        pSelfCureStateMachine_->pInternetSelfCureState_->currentAbnormalType_ = WIFI_CURE_INTERNET_FAILED_TYPE_DNS;
        pSelfCureStateMachine_->pInternetSelfCureState_->SelectedSelfCureAcceptable();

        pSelfCureStateMachine_->pInternetSelfCureState_->currentAbnormalType_ = WIFI_CURE_INTERNET_FAILED_TYPE_GATEWAY;
        pSelfCureStateMachine_->pInternetSelfCureState_->SelectedSelfCureAcceptable();
        
        pSelfCureStateMachine_->pInternetSelfCureState_->selfCureHistoryInfo_.resetSelfCureFailedCnt =
            SELFCURE_FAILED_CNT;

        pSelfCureStateMachine_->pInternetSelfCureState_->currentAbnormalType_ = WIFI_CURE_INTERNET_FAILED_TYPE_TCP;
        pSelfCureStateMachine_->pInternetSelfCureState_->SelectedSelfCureAcceptable();

        pSelfCureStateMachine_->pInternetSelfCureState_->selfCureHistoryInfo_.reassocSelfCureFailedCnt =
            SELFCURE_FAILED_CNT;
        SelfCureUtils::GetInstance().UpdateSelfCureHistoryInfo(pSelfCureStateMachine_->pInternetSelfCureState_->
            selfCureHistoryInfo_, WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC, false);
        pSelfCureStateMachine_->pInternetSelfCureState_->SelectedSelfCureAcceptable();

        pSelfCureStateMachine_->pInternetSelfCureState_->currentAbnormalType_ = 0;
        pSelfCureStateMachine_->pInternetSelfCureState_->SelectedSelfCureAcceptable();
    }

    void HandleInternetFailedAndUserSetStaticIpTest()
    {
        LOGI("Enter HandleInternetFailedAndUserSetStaticIpTest");
        int internetFailedType = WIFI_CURE_INTERNET_FAILED_TYPE_DNS;
        pSelfCureStateMachine_->pInternetSelfCureState_->isHasInternetRecently_ = true;
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleInternetFailedAndUserSetStaticIp(internetFailedType);
        internetFailedType = WIFI_CURE_INTERNET_FAILED_TYPE_GATEWAY;
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleInternetFailedAndUserSetStaticIp(internetFailedType);

        pSelfCureStateMachine_->pInternetSelfCureState_->selfCureHistoryInfo_.resetSelfCureFailedCnt =
            SELFCURE_FAILED_CNT;
        SelfCureUtils::GetInstance().UpdateSelfCureHistoryInfo(pSelfCureStateMachine_->pInternetSelfCureState_->
            selfCureHistoryInfo_, WIFI_CURE_RESET_LEVEL_HIGH_RESET, false);
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleInternetFailedAndUserSetStaticIp(internetFailedType);

        pSelfCureStateMachine_->pInternetSelfCureState_->isHasInternetRecently_ = false;
        pSelfCureStateMachine_->isInternetUnknown_ = true;
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleInternetFailedAndUserSetStaticIp(internetFailedType);

        pSelfCureStateMachine_->isInternetUnknown_ = false;
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleInternetFailedAndUserSetStaticIp(internetFailedType);
    }

    void ConfirmInternetSelfCureTest()
    {
        LOGI("Enter ConfirmInternetSelfCureTest");
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetRealMacAddress(_, _)).Times(testing::AtLeast(0));
        int currentCureLevel = WIFI_CURE_RESET_LEVEL_IDLE;
        pSelfCureStateMachine_->pInternetSelfCureState_->ConfirmInternetSelfCure(currentCureLevel);
        
        pSelfCureStateMachine_->isHttpReachable_ = true;
        pSelfCureStateMachine_->isInternetUnknown_ = true;

        currentCureLevel = WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC;
        pSelfCureStateMachine_->useWithRandMacAddress_ = FAC_MAC_REASSOC;
        pSelfCureStateMachine_->pInternetSelfCureState_->ConfirmInternetSelfCure(currentCureLevel);
        
        pSelfCureStateMachine_->useWithRandMacAddress_ = RAND_MAC_REASSOC;
        pSelfCureStateMachine_->pInternetSelfCureState_->ConfirmInternetSelfCure(currentCureLevel);
        
        pSelfCureStateMachine_->isHttpReachable_ = false;
        pSelfCureStateMachine_->isInternetUnknown_ = true;
        pSelfCureStateMachine_->pInternetSelfCureState_->ConfirmInternetSelfCure(currentCureLevel);
        pSelfCureStateMachine_->isInternetUnknown_ = false;
        pSelfCureStateMachine_->pInternetSelfCureState_->ConfirmInternetSelfCure(currentCureLevel);

        pSelfCureStateMachine_->pInternetSelfCureState_->isFinalSelfCureUsed_ = true;
        pSelfCureStateMachine_->pInternetSelfCureState_->ConfirmInternetSelfCure(currentCureLevel);

        pSelfCureStateMachine_->pInternetSelfCureState_->isFinalSelfCureUsed_ = false;
        pSelfCureStateMachine_->pInternetSelfCureState_->ConfirmInternetSelfCure(currentCureLevel);
    }

    void HandleConfirmInternetSelfCureFailedTest()
    {
        LOGI("Enter ConfirmInternetSelfCureFailedTest");
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetRealMacAddress(_, _)).Times(AtLeast(0));
        int currentCureLevel = WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC;
        pSelfCureStateMachine_->isInternetUnknown_ = true;
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleConfirmInternetSelfCureFailed(currentCureLevel);
        pSelfCureStateMachine_->isInternetUnknown_ = false;
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleConfirmInternetSelfCureFailed(currentCureLevel);
        pSelfCureStateMachine_->pInternetSelfCureState_->isFinalSelfCureUsed_ = true;
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleConfirmInternetSelfCureFailed(currentCureLevel);
        pSelfCureStateMachine_->pInternetSelfCureState_->isFinalSelfCureUsed_ = false;
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleConfirmInternetSelfCureFailed(currentCureLevel);
        currentCureLevel = WIFI_CURE_RESET_LEVEL_LOW_3_STATIC_IP;
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleConfirmInternetSelfCureFailed(currentCureLevel);
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
        pSelfCureStateMachine_->useWithRandMacAddress_ = RAND_MAC_REASSOC;
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleSelfCureFailedForRandMacReassoc();
        pSelfCureStateMachine_->useWithRandMacAddress_ = FAC_MAC_REASSOC;
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleSelfCureFailedForRandMacReassoc();

        EXPECT_CALL(*pMockStaService, ConnectToNetwork(_, _)).WillRepeatedly(Return(WIFI_OPT_FAILED));
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleSelfCureFailedForRandMacReassoc();

        EXPECT_CALL(*pMockStaService, ConnectToNetwork(_, _)).WillRepeatedly(Return(WIFI_OPT_SUCCESS));
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleSelfCureFailedForRandMacReassoc();

        pSelfCureStateMachine_->useWithRandMacAddress_ = RAND_MAC_REASSOC;
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleSelfCureFailedForRandMacReassoc();
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetRealMacAddress(_, _)).Times(AtLeast(0));
    }

    void HandleHttpReachableAfterSelfCureTest()
    {
        LOGI("Enter HandleHttpReachableAfterSelfCureTest");
        pSelfCureStateMachine_->pInternetSelfCureState_->isSetStaticIp4InvalidIp_ = true;
        int currentCureLevel = 1;
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleHttpReachableAfterSelfCure(currentCureLevel);

        pSelfCureStateMachine_->pInternetSelfCureState_->isSetStaticIp4InvalidIp_ = false;
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleHttpReachableAfterSelfCure(currentCureLevel);

        currentCureLevel = WIFI_CURE_RESET_LEVEL_LOW_3_STATIC_IP;
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleHttpReachableAfterSelfCure(currentCureLevel);

        pSelfCureStateMachine_->pInternetSelfCureState_->isSetStaticIp4InvalidIp_ = true;
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleHttpReachableAfterSelfCure(currentCureLevel);

        currentCureLevel = WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC;
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleHttpReachableAfterSelfCure(currentCureLevel);
        currentCureLevel = WIFI_CURE_RESET_LEVEL_HIGH_RESET;
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleHttpReachableAfterSelfCure(currentCureLevel);
        currentCureLevel = WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC;
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleHttpReachableAfterSelfCure(currentCureLevel);
        EXPECT_NE(pSelfCureStateMachine_->useWithRandMacAddress_, TEN);
    }

    void HandleHttpUnreachableFinallyTest()
    {
        LOGI("Enter HandleHttpUnreachableFinallyTest");
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleHttpUnreachableFinally();
        EXPECT_NE(pSelfCureStateMachine_->useWithRandMacAddress_, TEN);
    }

    void HasBeenTestedTest()
    {
        LOGI("Enter HasBeenTestedTest");
        int cureLevel = 1;
        pSelfCureStateMachine_->pInternetSelfCureState_->testedSelfCureLevel_ = {0, 1};
        EXPECT_TRUE(pSelfCureStateMachine_->pInternetSelfCureState_->HasBeenTested(cureLevel));
        cureLevel = WIFI_CURE_RESET_LEVEL_HIGH_RESET;
        EXPECT_FALSE(pSelfCureStateMachine_->pInternetSelfCureState_->HasBeenTested(cureLevel));
    }

    void HandleRssiChangedTest()
    {
        LOGI("Enter HandleRssiChangedTest");
        pSelfCureStateMachine_->pInternetSelfCureState_->currentRssi_ = MIN_VAL_LEVEL_2_5G;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScreenState()).Times(AtLeast(0));
        WifiP2pLinkedInfo linkedInfo;
        linkedInfo.SetConnectState(P2pConnectedState::P2P_DISCONNECTED);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetP2pInfo(_))
            .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
        pSelfCureStateMachine_->isNotAllowSelfcure_ = false;
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleRssiChanged();

        pSelfCureStateMachine_->isNotAllowSelfcure_ = true;
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleRssiChanged();

        linkedInfo.SetConnectState(P2pConnectedState::P2P_CONNECTED);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetP2pInfo(_))
            .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleRssiChanged();

        pSelfCureStateMachine_->pInternetSelfCureState_->currentRssi_ = MIN_VAL_LEVEL_4;
        pSelfCureStateMachine_->pInternetSelfCureState_->isDelayedResetSelfCure_ = true;
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleRssiChanged();
        pSelfCureStateMachine_->pInternetSelfCureState_->isDelayedResetSelfCure_ = false;
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleRssiChanged();

        pSelfCureStateMachine_->isSelfCureOnGoing_ = false;
        pSelfCureStateMachine_->pInternetSelfCureState_->isDelayedReassocSelfCure_ = true;
        pSelfCureStateMachine_->pInternetSelfCureState_->isDelayedRandMacReassocSelfCure_ = true;
        pSelfCureStateMachine_->isHttpReachable_ = true;
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleRssiChanged();

        pSelfCureStateMachine_->isHttpReachable_ = false;
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleRssiChanged();

        pSelfCureStateMachine_->pInternetSelfCureState_->isDelayedReassocSelfCure_ = true;
        pSelfCureStateMachine_->pInternetSelfCureState_->isDelayedRandMacReassocSelfCure_ = false;
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleRssiChanged();

        pSelfCureStateMachine_->pInternetSelfCureState_->isDelayedReassocSelfCure_ = false;
        pSelfCureStateMachine_->pInternetSelfCureState_->isDelayedRandMacReassocSelfCure_ = true;
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleRssiChanged();
    }

    void HandleDelayedResetSelfCureTest()
    {
        LOGI("Enter HandleDelayedResetSelfCureTest");
        pSelfCureStateMachine_->isHttpReachable_ = false;
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleDelayedResetSelfCure();
        pSelfCureStateMachine_->isHttpReachable_ = true;
        pSelfCureStateMachine_->pInternetSelfCureState_->HandleDelayedResetSelfCure();
        EXPECT_NE(pSelfCureStateMachine_->useWithRandMacAddress_, TEN);
    }

    void Wifi6SelfCureStateGoInStateSuccess()
    {
        LOGI("Enter Wifi6SelfCureStateGoInStateSuccess");
        pSelfCureStateMachine_->pWifi6SelfCureState_->GoInState();
    }

    void Wifi6SelfCureStateGoOutStateSuccess()
    {
        LOGI("Enter Wifi6SelfCureStateGoOutStateSuccess");
        pSelfCureStateMachine_->pWifi6SelfCureState_->GoOutState();
    }

    void InitExeMsgFail()
    {
        LOGI("Enter InitExeMsgFail");
        EXPECT_FALSE(pSelfCureStateMachine_->pWifi6SelfCureState_->ExecuteStateMsg(nullptr));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(0);
        EXPECT_FALSE(pSelfCureStateMachine_->pWifi6SelfCureState_->ExecuteStateMsg(msg));
    }

    void InitExeMsgSuccess1()
    {
        LOGI("Enter InitExeMsgSuccess1");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_WIFI6_SELFCURE);
        EXPECT_TRUE(pSelfCureStateMachine_->pWifi6SelfCureState_->ExecuteStateMsg(msg));
    }

    void InitExeMsgSuccess2()
    {
        LOGI("Enter InitExeMsgSuccess2");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_WIFI6_BACKOFF_SELFCURE);
        EXPECT_TRUE(pSelfCureStateMachine_->pWifi6SelfCureState_->ExecuteStateMsg(msg));
    }

    void CanArpReachableFailedTest()
    {
        LOGI("Enter CanArpReachableFailedTest");
        IpInfo ipInfo;
        ipInfo.gateway = 0;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(ipInfo), Return(0)));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetStaIfaceName(_)).WillRepeatedly(Return("sta"));
        EXPECT_FALSE(pSelfCureStateMachine_->CanArpReachable());
    }

    void CanArpReachableTest()
    {
        LOGI("Enter CanArpReachableTest");
        IpInfo ipInfo;
        ipInfo.gateway = 1;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(ipInfo), Return(0)));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetStaIfaceName(_)).WillRepeatedly(Return("sta"));
        EXPECT_FALSE(pSelfCureStateMachine_->CanArpReachable());
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
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetStaIfaceName(_)).WillRepeatedly(Return("sta"));
        EXPECT_TRUE(pSelfCureStateMachine_->pWifi6SelfCureState_->ExecuteStateMsg(msg));
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
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetStaIfaceName(_)).WillRepeatedly(Return("sta"));
        EXPECT_TRUE(pSelfCureStateMachine_->pWifi6SelfCureState_->ExecuteStateMsg(msg));
    }

    void InitExeMsgSuccess5()
    {
        LOGI("Enter InitExeMsgSuccess5");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_WIFI6_WITH_HTC_ARP_FAILED_DETECTED);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), InsertWifiCategoryBlackListCache(_, _, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), RemoveWifiCategoryBlackListCache(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(),
            GetWifiCategoryBlackListCache(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_TRUE(pSelfCureStateMachine_->pWifi6SelfCureState_->ExecuteStateMsg(msg));
    }

    void InitExeMsgSuccess6()
    {
        LOGI("Enter InitExeMsgSuccess6");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_WIFI6_WITHOUT_HTC_ARP_FAILED_DETECTED);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), InsertWifiCategoryBlackListCache(_, _, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), RemoveWifiCategoryBlackListCache(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(),
            GetWifiCategoryBlackListCache(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_TRUE(pSelfCureStateMachine_->pWifi6SelfCureState_->ExecuteStateMsg(msg));
    }

    void InitExeMsgSuccess7()
    {
        LOGI("Enter InitExeMsgSuccess7");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        WifiLinkedInfo info;
        info.bssid = CURR_BSSID;
        msg->SetMessageName(WIFI_CURE_CMD_WIFI7_DISCONNECT_COUNT);
        msg->SetMessageObj(info);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), UpdateWifiConnectFailListCache(_, _, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), RemoveWifiConnectFailListCache(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(),
            GetWifiConnectFailListCache(_)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_TRUE(pSelfCureStateMachine_->pDisconnectedMonitorState_->ExecuteStateMsg(msg));
    }

    void InitExeMsgSuccess8()
    {
        LOGI("Enter InitExeMsgSuccess8");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        WifiLinkedInfo info;
        info.bssid = CURR_BSSID;
        msg->SetMessageName(WIFI_CURE_CMD_WIFI7_MLD_BACKOFF);
        msg->SetMessageObj(info);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), InsertWifiCategoryBlackListCache(_, _, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), RemoveWifiCategoryBlackListCache(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(),
            GetWifiCategoryBlackListCache(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_TRUE(pSelfCureStateMachine_->pDisconnectedMonitorState_->ExecuteStateMsg(msg));
    }

        void InitExeMsgSuccess9()
    {
        LOGI("Enter InitExeMsgSuccess9");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        WifiLinkedInfo info;
        info.bssid = CURR_BSSID;
        msg->SetMessageName(WIFI_CURE_CMD_WIFI7_NON_MLD_BACKOFF);
        msg->SetMessageObj(info);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), InsertWifiCategoryBlackListCache(_, _, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), RemoveWifiCategoryBlackListCache(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(),
            GetWifiCategoryBlackListCache(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_TRUE(pSelfCureStateMachine_->pDisconnectedMonitorState_->ExecuteStateMsg(msg));
    }

    void InitExeMsgSuccess10()
    {
        LOGI("Enter InitExeMsgSuccess10");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        WifiLinkedInfo info;
        info.bssid = CURR_BSSID;
        msg->SetMessageName(WIFI_CURE_CMD_WIFI7_BACKOFF_RECOVER);
        msg->SetMessageObj(info);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), RemoveWifiCategoryBlackListCache(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(),
            GetWifiCategoryBlackListCache(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_TRUE(pSelfCureStateMachine_->pDisconnectedMonitorState_->ExecuteStateMsg(msg));
    }

    void PeriodicWifi6WithHtcArpDetectTest()
    {
        LOGI("Enter PeriodicWifi6WithHtcArpDetectTest");
        pSelfCureStateMachine_->pWifi6SelfCureState_->PeriodicWifi6WithHtcArpDetect(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_WIFI6_WITH_HTC_PERIODIC_ARP_DETECTED);
        pSelfCureStateMachine_->pWifi6SelfCureState_->PeriodicWifi6WithHtcArpDetect(msg);

        IpInfo ipInfo;
        ipInfo.gateway = 0;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(ipInfo), Return(0)));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetStaIfaceName(_)).WillRepeatedly(Return("sta"));
        pSelfCureStateMachine_->pWifi6SelfCureState_->PeriodicWifi6WithHtcArpDetect(msg);

        pSelfCureStateMachine_->pWifi6SelfCureState_->wifi6HtcArpDetectionFailedCnt_ = ARP_DETECTED_FAILED_COUNT - 1;
        pSelfCureStateMachine_->pWifi6SelfCureState_->PeriodicWifi6WithHtcArpDetect(msg);
    }

    void PeriodicWifi6WithoutHtcArpDetectTest()
    {
        LOGI("Enter PeriodicWifi6WithoutHtcArpDetectTest");
        pSelfCureStateMachine_->pWifi6SelfCureState_->PeriodicWifi6WithoutHtcArpDetect(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_WIFI6_WITHOUT_HTC_PERIODIC_ARP_DETECTED);
        pSelfCureStateMachine_->pWifi6SelfCureState_->PeriodicWifi6WithoutHtcArpDetect(msg);

        IpInfo ipInfo;
        ipInfo.gateway = 0;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(ipInfo), Return(0)));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetStaIfaceName(_)).WillRepeatedly(Return("sta"));
        pSelfCureStateMachine_->pWifi6SelfCureState_->PeriodicWifi6WithoutHtcArpDetect(msg);

        pSelfCureStateMachine_->pWifi6SelfCureState_->wifi6ArpDetectionFailedCnt_ = ARP_DETECTED_FAILED_COUNT - 1;
        pSelfCureStateMachine_->pWifi6SelfCureState_->PeriodicWifi6WithoutHtcArpDetect(msg);
    }

    void HandleWifi6WithHtcArpFailTest()
    {
        LOGI("Enter HandleWifi6WithHtcArpFailTest");
        pSelfCureStateMachine_->pWifi6SelfCureState_->HandleWifi6WithHtcArpFail(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_WIFI6_WITH_HTC_ARP_FAILED_DETECTED);
        pSelfCureStateMachine_->pWifi6SelfCureState_->HandleWifi6WithHtcArpFail(msg);

        WifiDeviceConfig config;
        config.bssid = CURR_BSSID;
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
            .WillRepeatedly(DoAll(SetArgReferee<1>(config), Return(0)));
        pSelfCureStateMachine_->pWifi6SelfCureState_->HandleWifi6WithHtcArpFail(msg);
    }

    void HandleWifi6WithoutHtcArpFailTest()
    {
        LOGI("Enter HandleWifi6WithoutHtcArpFailTest");
        pSelfCureStateMachine_->pWifi6SelfCureState_->HandleWifi6WithoutHtcArpFail(nullptr);
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_WIFI6_WITHOUT_HTC_ARP_FAILED_DETECTED);
        pSelfCureStateMachine_->pWifi6SelfCureState_->HandleWifi6WithoutHtcArpFail(msg);
    }

    void GetNowMilliSecondsTest()
    {
        LOGI("Enter GetNowMilliSecondsTest");
        EXPECT_NE(pSelfCureStateMachine_->GetNowMilliSeconds(), 0);
    }

    void SendBlaListToDriverTest()
    {
        LOGI("Enter SendBlaListToDriverTest");
        int blaListType = EVENT_AX_BLA_LIST;
        std::map<std::string, WifiCategoryBlackListInfo> wifiBlackListCache = {};
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiCategoryBlackListCache(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<1>(wifiBlackListCache), Return(0)));
        pSelfCureStateMachine_->SendBlaListToDriver(EVENT_AX_BLA_LIST);
    }

    void SendBlaListToDriverTest2()
    {
        LOGI("Enter SendBlaListToDriverTest2");
        int blaListType = EVENT_AX_BLA_LIST;
        std::map<int, std::map<std::string, WifiCategoryBlackListInfo>> wifiCategoryBlackListCache;
        std::map<std::string, WifiCategoryBlackListInfo> wifiBlackListCache;
        std::string currentBssid_ = CURR_BSSID;
        WifiCategoryBlackListInfo wifiBlackListInfo(1, TIME_MILLS);
        wifiBlackListCache.emplace(std::make_pair(currentBssid_, wifiBlackListInfo));
        wifiCategoryBlackListCache.emplace(blaListType, wifiBlackListCache);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiCategoryBlackListCache(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<1>(wifiBlackListCache), Return(0)));
        pSelfCureStateMachine_->SendBlaListToDriver(EVENT_AX_BLA_LIST);
    }

    void BlackListToStringTest()
    {
        LOGI("Enter BlackListToStringTest");
        std::map<std::string, WifiCategoryBlackListInfo> wifi6BlackListCache = {};
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiCategoryBlackListCache(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<1>(wifi6BlackListCache), Return(0)));
        pSelfCureStateMachine_->BlackListToString(wifi6BlackListCache);
    }

    void BlackListToStringTest2()
    {
        LOGI("Enter BlackListToStringTest2");
        std::map<std::string, WifiCategoryBlackListInfo> wifi6BlackListCache;
        std::string currentBssid_ = CURR_BSSID;
        WifiCategoryBlackListInfo wifi6BlackListInfo(1, TIME_MILLS);
        wifi6BlackListCache.emplace(std::make_pair(currentBssid_, wifi6BlackListInfo));

        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiCategoryBlackListCache(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<1>(wifi6BlackListCache), Return(0)));
        pSelfCureStateMachine_->BlackListToString(wifi6BlackListCache);
    }

    void ParseWifi6BlackListInfoTest()
    {
        LOGI("Enter ParseWifi6BlackListInfoTest");
        std::string currentBssid_ = CURR_BSSID;
        WifiCategoryBlackListInfo wifi6BlackListInfo(1, TIME_MILLS);
        std::pair<std::string, WifiCategoryBlackListInfo> iter = std::make_pair(CURR_BSSID, wifi6BlackListInfo);
        pSelfCureStateMachine_->ParseWifiCategoryBlackListInfo(iter);

        iter = std::make_pair("", wifi6BlackListInfo);
        EXPECT_NE(pSelfCureStateMachine_->ParseWifiCategoryBlackListInfo(iter), "AUIS");
    }

    void AgeOutWifi6BlackTest()
    {
        LOGI("Enter AgeOutWifi6BlackTest");
        std::map<std::string, WifiCategoryBlackListInfo> wifi6BlackListCache;
        std::string currentBssid_ = CURR_BSSID;
        WifiCategoryBlackListInfo wifi6BlackListInfo(1, TIME_MILLS);
        wifi6BlackListCache.emplace(std::make_pair(currentBssid_, wifi6BlackListInfo));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), RemoveWifiCategoryBlackListCache(_, _)).Times(AtLeast(0));
        pSelfCureStateMachine_->AgeOutWifiCategoryBlack(EVENT_AX_BLA_LIST, wifi6BlackListCache);

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
        pSelfCureStateMachine_->AgeOutWifiCategoryBlack(EVENT_AX_BLA_LIST, wifi6BlackListCache);
    }

    void AgeOutWifiConnectFailTest()
    {
        LOGI("Enter AgeOutWifiConnectFailTest");
        std::map<std::string, WifiCategoryConnectFailInfo> connectFailListCache;
        std::string currentBssid_ = CURR_BSSID;
        WifiCategoryConnectFailInfo connectFailListInfo(1, 1, TIME_MILLS);
        connectFailListCache.emplace(std::make_pair(currentBssid_, connectFailListInfo));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), RemoveWifiConnectFailListCache(_)).Times(AtLeast(0));
        pSelfCureStateMachine_->AgeOutWifiConnectFailList();

        connectFailListCache.emplace(std::make_pair("1", connectFailListInfo));
        connectFailListCache.emplace(std::make_pair("2", connectFailListInfo));
        connectFailListCache.emplace(std::make_pair("3", connectFailListInfo));
        connectFailListCache.emplace(std::make_pair("4", connectFailListInfo));
        connectFailListCache.emplace(std::make_pair("5", connectFailListInfo));
        connectFailListCache.emplace(std::make_pair("6", connectFailListInfo));
        connectFailListCache.emplace(std::make_pair("7", connectFailListInfo));
        connectFailListCache.emplace(std::make_pair("8", connectFailListInfo));
        connectFailListCache.emplace(std::make_pair("9", connectFailListInfo));
        connectFailListCache.emplace(std::make_pair("10", connectFailListInfo));
        connectFailListCache.emplace(std::make_pair("11", connectFailListInfo));
        connectFailListCache.emplace(std::make_pair("12", connectFailListInfo));
        connectFailListCache.emplace(std::make_pair("13", connectFailListInfo));
        connectFailListCache.emplace(std::make_pair("14", connectFailListInfo));
        connectFailListCache.emplace(std::make_pair("15", connectFailListInfo));
        connectFailListCache.emplace(std::make_pair("16", connectFailListInfo));
        pSelfCureStateMachine_->AgeOutWifiConnectFailList();
    }

    void ShouldTransToWifi6SelfCureTest()
    {
        LOGI("Enter ShouldTransToWifi6SelfCureTest");
        std::string currConnectedBssid = "";
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(1);
        EXPECT_FALSE(pSelfCureStateMachine_->ShouldTransToWifi6SelfCure(msg, currConnectedBssid));
    }

    void ShouldTransToWifi6SelfCureTest2()
    {
        LOGI("Enter ShouldTransToWifi6SelfCureTest2");
        std::string currConnectedBssid = CURR_BSSID;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScanInfoList(_)).Times(AtLeast(0));
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(1);
        EXPECT_FALSE(pSelfCureStateMachine_->ShouldTransToWifi6SelfCure(msg, currConnectedBssid));

        currConnectedBssid = CURR_BSSID;
        WifiLinkedInfo wifiLinkedInfo;
        wifiLinkedInfo.supportedWifiCategory = WifiCategory::DEFAULT;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));
        pSelfCureStateMachine_->ShouldTransToWifi6SelfCure(msg, currConnectedBssid);

        pSelfCureStateMachine_->isWifi6ArpSuccess_ = true;
        pSelfCureStateMachine_->ShouldTransToWifi6SelfCure(msg, currConnectedBssid);

        wifiLinkedInfo.rssi = MIN_VAL_LEVEL_2_5G;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));
        pSelfCureStateMachine_->ShouldTransToWifi6SelfCure(msg, currConnectedBssid);
    }

    void GetScanRssiTest()
    {
        LOGI("Enter GetScanRssiTest");
        std::vector<WifiScanInfo> scanResult = {};
        int counter = pSelfCureStateMachine_->GetBssidCounter(scanResult);
        EXPECT_EQ(counter, 0);

        WifiScanInfo info;
        info.bssid = CURR_BSSID;
        info.ssid = "ssid";
        info.bssidType = 0;
        info.rssi  = 0;
        scanResult = {info};
        int rssi = pSelfCureStateMachine_->GetScanRssi(CURR_BSSID, scanResult);
        EXPECT_EQ(rssi, 0);
    }
    
    void GetWifi7SelfCureTypeTest()
    {
        LOGI("Enter GetWifi7SelfCureTypeTest");
        int type;
        int connectFailTimes = 1;
        WifiLinkedInfo info;
        info.supportedWifiCategory = WifiCategory::WIFI7;
        type = pSelfCureStateMachine_->GetWifi7SelfCureType(connectFailTimes, info);
        EXPECT_EQ(type, 0);

        connectFailTimes = SELF_CURE_WIFI7_CONNECT_FAIL_MAX_COUNT;
        info.rssi = MIN_VAL_LEVEL_4;
        type = pSelfCureStateMachine_->GetWifi7SelfCureType(connectFailTimes, info);
        EXPECT_EQ(type, 1);
    }

    void ShouldTransToWifi7SelfCureTest()
    {
        LOGI("Enter ShouldTransToWifi7SelfCureTest");
        WifiLinkedInfo info;
        info.supportedWifiCategory = WifiCategory::WIFI7;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(info), Return(0)));
        pSelfCureStateMachine_->ShouldTransToWifi7SelfCure(info);
    
        info.rssi = MIN_VAL_LEVEL_2_5G;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(info), Return(0)));
        pSelfCureStateMachine_->ShouldTransToWifi7SelfCure(info);
    }

    void HandleWifiBlackListUpdateMsgTest()
    {
        WifiCategoryBlackListInfo wifiBlackListInfo(1, TIME_MILLS);
        wifiBlackListCache.emplace(std::make_pair(currentBssid_, wifiBlackListInfo));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiCategoryBlackListCache(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<1>(wifiBlackListCache), Return(0)));
        pSelfCureStateMachine_->HandleWifiBlackListUpdateMsg();
    }

    void GetCurrentBssidTest()
    {
        LOGI("Enter GetCurrentBssidTest");
        std::string currConnectedBssid = "";
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).Times(AtLeast(0)).WillOnce(Return(0));
        pSelfCureStateMachine_->GetCurrentBssid();
    }

    void IsWifi6NetworkTest()
    {
        LOGI("Enter IsWifi6NetworkTest");
        std::string currConnectedBssid = "";
        EXPECT_FALSE(pSelfCureStateMachine_->IsWifi6Network(currConnectedBssid));
    }

    void IsWifi6NetworkTest2()
    {
        LOGI("Enter IsWifi6NetworkTest2");
        std::string currConnectedBssid = CURR_BSSID;
        WifiLinkedInfo wifiLinkedInfo;
        wifiLinkedInfo.supportedWifiCategory = WifiCategory::DEFAULT;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));
        EXPECT_FALSE(pSelfCureStateMachine_->IsWifi6Network(currConnectedBssid));
    }

    void IsWifi6NetworkTest3()
    {
        LOGI("Enter IsWifi6NetworkTest3");
        std::string currConnectedBssid = CURR_BSSID;
        WifiLinkedInfo wifiLinkedInfo;
        wifiLinkedInfo.supportedWifiCategory = WifiCategory::WIFI6;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));
        EXPECT_TRUE(pSelfCureStateMachine_->IsWifi6Network(currConnectedBssid));
    }

    void IsWifi6NetworkTest4()
    {
        LOGI("Enter IsWifi6NetworkTest4");
        std::string currConnectedBssid = CURR_BSSID;
        WifiLinkedInfo wifiLinkedInfo;
        wifiLinkedInfo.supportedWifiCategory = WifiCategory::WIFI7;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));
        EXPECT_TRUE(pSelfCureStateMachine_->IsWifi6Network(currConnectedBssid));
    }

    void SelfCureForResetTest()
    {
        LOGI("Enter SelfCureForResetTest");
        int requestCureLevel = WIFI_CURE_RESET_LEVEL_HIGH_RESET;
        pSelfCureStateMachine_->isInternetUnknown_ = true;
        pSelfCureStateMachine_->pInternetSelfCureState_->SelfCureForReset(requestCureLevel);
        EXPECT_NE(pSelfCureStateMachine_->noAutoConnCounter_, TEN);
    }

    void SelfCureForResetTest2()
    {
        LOGI("Enter SelfCureForResetTest2");
        int requestCureLevel = WIFI_CURE_RESET_LEVEL_HIGH_RESET;
        pSelfCureStateMachine_->isInternetUnknown_ = false;
        pSelfCureStateMachine_->pInternetSelfCureState_->isHasInternetRecently_ = false;
        pSelfCureStateMachine_->pInternetSelfCureState_->SelfCureForReset(requestCureLevel);
        EXPECT_NE(pSelfCureStateMachine_->noAutoConnCounter_, TEN);
    }

    void SelfCureForResetTest3()
    {
        LOGI("Enter SelfCureForResetTest3");
        int requestCureLevel = WIFI_CURE_RESET_LEVEL_HIGH_RESET;
        pSelfCureStateMachine_->isInternetUnknown_ = false;
        pSelfCureStateMachine_->pInternetSelfCureState_->isHasInternetRecently_ = true;
        pSelfCureStateMachine_->pInternetSelfCureState_->currentRssi_ = MIN_VAL_LEVEL_2_5G;
        pSelfCureStateMachine_->pInternetSelfCureState_->SelfCureForReset(requestCureLevel);
        EXPECT_NE(pSelfCureStateMachine_->instId_, TEN);
    }

    void SelfCureForResetTest4()
    {
        LOGI("Enter SelfCureForResetTest4");
        int requestCureLevel = WIFI_CURE_RESET_LEVEL_HIGH_RESET;
        pSelfCureStateMachine_->isInternetUnknown_ = false;
        pSelfCureStateMachine_->pInternetSelfCureState_->isHasInternetRecently_ = true;
        pSelfCureStateMachine_->pInternetSelfCureState_->currentRssi_ = MIN_VAL_LEVEL_4;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScreenState()).Times(AtLeast(0));
        WifiP2pLinkedInfo linkedInfo;
        linkedInfo.SetConnectState(P2pConnectedState::P2P_CONNECTED);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetP2pInfo(_))
            .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
        pSelfCureStateMachine_->pInternetSelfCureState_->SelfCureForReset(requestCureLevel);
    }

    void SelfCureForResetTest5()
    {
        LOGI("Enter SelfCureForResetTest5");
        int requestCureLevel = WIFI_CURE_RESET_LEVEL_HIGH_RESET;
        pSelfCureStateMachine_->isInternetUnknown_ = false;
        pSelfCureStateMachine_->pInternetSelfCureState_->isHasInternetRecently_ = true;
        pSelfCureStateMachine_->pInternetSelfCureState_->currentRssi_ = MIN_VAL_LEVEL_4;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScreenState()).Times(AtLeast(0));
        WifiP2pLinkedInfo linkedInfo;
        linkedInfo.SetConnectState(P2pConnectedState::P2P_DISCONNECTED);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetP2pInfo(_))
            .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
        pSelfCureStateMachine_->isNotAllowSelfcure_ = true;
        pSelfCureStateMachine_->pInternetSelfCureState_->SelfCureForReset(requestCureLevel);
    }

    void SelfCureForResetTest6()
    {
        LOGI("Enter SelfCureForResetTest6");
        int requestCureLevel = WIFI_CURE_RESET_LEVEL_HIGH_RESET;
        pSelfCureStateMachine_->isInternetUnknown_ = false;
        pSelfCureStateMachine_->pInternetSelfCureState_->isHasInternetRecently_ = true;
        pSelfCureStateMachine_->pInternetSelfCureState_->currentRssi_ = MIN_VAL_LEVEL_4;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScreenState()).Times(AtLeast(0));
        WifiP2pLinkedInfo linkedInfo;
        linkedInfo.SetConnectState(P2pConnectedState::P2P_DISCONNECTED);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetP2pInfo(_))
            .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
        pSelfCureStateMachine_->isNotAllowSelfcure_ = false;
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetLastNetworkId(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiSelfcureReset(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiToggledState(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), AddDeviceConfig(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig()).Times(AtLeast(0));
        pSelfCureStateMachine_->pInternetSelfCureState_->SelfCureForReset(requestCureLevel);
    }

    void IsSettingsPageTest()
    {
        LOGI("Enter IsSettingsPageTest");
        pSelfCureStateMachine_->IsSettingsPage();
    }

    void NoInternetStateGoInStateSuccess()
    {
        LOGI("Enter NoInternetStateGoInStateSuccess");
        pSelfCureStateMachine_->pNoInternetState_->GoInState();
    }

    void NoInternetStateGoOutStateSuccess()
    {
        LOGI("Enter NoInternetStateGoOutStateSuccess");
        pSelfCureStateMachine_->pNoInternetState_->GoOutState();
    }

    void NoInternetStateExeMsgFail()
    {
        LOGI("Enter NoInternetStateExeMsgFail");
        EXPECT_FALSE(pSelfCureStateMachine_->pNoInternetState_->ExecuteStateMsg(nullptr));
    }

    void NoInternetStateExeMsgSuccess1()
    {
        LOGI("Enter NoInternetStateExeMsgSuccess1");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(1);
        EXPECT_FALSE(pSelfCureStateMachine_->pNoInternetState_->ExecuteStateMsg(msg));
    }

    void NoInternetStateExeMsgSuccess2()
    {
        LOGI("Enter NoInternetStateExeMsgSuccess1");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(CMD_INTERNET_STATUS_DETECT_INTERVAL);
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScreenState()).WillRepeatedly(Return(MODE_STATE_OPEN));
        EXPECT_TRUE(pSelfCureStateMachine_->pNoInternetState_->ExecuteStateMsg(msg));
        EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScreenState()).WillRepeatedly(Return(MODE_STATE_CLOSE));
        EXPECT_TRUE(pSelfCureStateMachine_->pNoInternetState_->ExecuteStateMsg(msg));
    }

    void NoInternetStateExeMsgSuccess3()
    {
        LOGI("Enter NoInternetStateExeMsgSuccess1");
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        msg->SetMessageName(WIFI_CURE_CMD_HTTP_REACHABLE_RCV);
        EXPECT_TRUE(pSelfCureStateMachine_->pNoInternetState_->ExecuteStateMsg(msg));
    }

    void IsHttpReachableTest()
    {
        LOGI("Enter IsHttpReachableTest");
        pSelfCureStateMachine_->IsHttpReachable();
        pSelfCureStateMachine_->mNetWorkDetect_ = nullptr;
        EXPECT_TRUE(pSelfCureStateMachine_->IsHttpReachable() == false);
    }
};

HWTEST_F(SelfCureStateMachineTest, DefaultStateGoInStateSuccess, TestSize.Level1)
{
    DefaultStateGoInStateSuccess();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SelfCureStateMachineTest, DefaultStateGoOutStateSuccess, TestSize.Level1)
{
    DefaultStateGoOutStateSuccess();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
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
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SelfCureStateMachineTest, ConnectedMonitorStateExeMsgFail, TestSize.Level1)
{
    ConnectedMonitorStateExeMsgFail();
}

HWTEST_F(SelfCureStateMachineTest, ConnectedMonitorStateExeMsgSuccess1, TestSize.Level1)
{
    ConnectedMonitorStateExeMsgSuccess1();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
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
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SelfCureStateMachineTest, HandleGatewayChangedTest, TestSize.Level1)
{
    HandleGatewayChangedTest();
}

HWTEST_F(SelfCureStateMachineTest, IsCustNetworkSelfCureTest, TestSize.Level1)
{
    IsCustNetworkSelfCureTest();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
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
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SelfCureStateMachineTest, DisconnectedMonitorGoOutStateSuccess, TestSize.Level1)
{
    DisconnectedMonitorGoOutStateSuccess();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SelfCureStateMachineTest, DisconnectedMonitorExeMsgFail, TestSize.Level1)
{
    DisconnectedMonitorExeMsgFail();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SelfCureStateMachineTest, DisconnectedMonitorExeMsgSuccess1, TestSize.Level1)
{
    DisconnectedMonitorExeMsgSuccess1();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SelfCureStateMachineTest, DisconnectedMonitorExeMsgSuccess2, TestSize.Level1)
{
    DisconnectedMonitorExeMsgSuccess2();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SelfCureStateMachineTest, ConnectionSelfCureGoInStateSuccess, TestSize.Level1)
{
    ConnectionSelfCureGoInStateSuccess();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SelfCureStateMachineTest, ConnectionSelfCureGoOutStateSuccess, TestSize.Level1)
{
    ConnectionSelfCureGoOutStateSuccess();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SelfCureStateMachineTest, ConnectionSelfCureExeMsgFail, TestSize.Level1)
{
    ConnectionSelfCureExeMsgFail();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SelfCureStateMachineTest, ConnectionSelfCureExeMsgSuccess1, TestSize.Level1)
{
    ConnectionSelfCureExeMsgSuccess1();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SelfCureStateMachineTest, InternetSelfCureGoInStateSuccess, TestSize.Level1)
{
    InternetSelfCureGoInStateSuccess();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SelfCureStateMachineTest, InternetSelfCureGoOutStateSuccess, TestSize.Level1)
{
    InternetSelfCureGoOutStateSuccess();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
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
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SelfCureStateMachineTest, GetRecordDhcpResultsTest, TestSize.Level1)
{
    GetRecordDhcpResultsTest();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
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
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SelfCureStateMachineTest, Wifi6SelfCureStateGoOutStateSuccess, TestSize.Level1)
{
    Wifi6SelfCureStateGoOutStateSuccess();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
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

HWTEST_F(SelfCureStateMachineTest, AgeOutWifiConnectFailTest, TestSize.Level1)
{
    AgeOutWifiConnectFailTest();
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

HWTEST_F(SelfCureStateMachineTest, GetWifi7SelfCureTypeTest, TestSize.Level1)
{
    GetWifi7SelfCureTypeTest();
}

HWTEST_F(SelfCureStateMachineTest, ShouldTransToWifi7SelfCureTest, TestSize.Level1)
{
    ShouldTransToWifi7SelfCureTest();
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

HWTEST_F(SelfCureStateMachineTest, IsWifi6NetworkTest4, TestSize.Level1)
{
    IsWifi6NetworkTest4();
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
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SelfCureStateMachineTest, NoInternetStateGoInStateSuccess, TestSize.Level1)
{
    NoInternetStateGoInStateSuccess();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SelfCureStateMachineTest, NoInternetStateGoOutStateSuccess, TestSize.Level1)
{
    NoInternetStateGoOutStateSuccess();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
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
    SelfCureUtils::GetInstance().TransIpAddressToVec(addr);

    addr = CURR_BSSID;
    SelfCureUtils::GetInstance().TransIpAddressToVec(addr);

    addr = "00:aa:bb:cc:dd:ee:ff";
    EXPECT_NE(SelfCureUtils::GetInstance().TransIpAddressToVec(addr).size(), 0);
}

HWTEST_F(SelfCureStateMachineTest, TransVecToIpAddress, TestSize.Level1)
{
    std::vector<uint32_t> vec = {1, 2, 3, 4};
    SelfCureUtils::GetInstance().TransVecToIpAddress(vec);
    
    vec = {0, 0, 0, 0};
    SelfCureUtils::GetInstance().TransVecToIpAddress(vec);
    
    vec = {};
    EXPECT_EQ(SelfCureUtils::GetInstance().TransVecToIpAddress(vec), "");
}

HWTEST_F(SelfCureStateMachineTest, GetLegalIpConfigurationTest, TestSize.Level1)
{
    IpInfo dhcpResults;
    dhcpResults.gateway = 0;
    EXPECT_EQ(pSelfCureStateMachine_->GetLegalIpConfiguration(dhcpResults), -1);

    dhcpResults.ipAddress = 0;
    EXPECT_EQ(pSelfCureStateMachine_->GetLegalIpConfiguration(dhcpResults), -1);

    dhcpResults.ipAddress = 1;
    EXPECT_EQ(pSelfCureStateMachine_->GetLegalIpConfiguration(dhcpResults), -1);
}

HWTEST_F(SelfCureStateMachineTest, GetLegalIpConfigurationTest1, TestSize.Level1)
{
    IpInfo dhcpResults;
    int result = pSelfCureStateMachine_->GetLegalIpConfiguration(dhcpResults);
    EXPECT_EQ(result, -1);
}

HWTEST_F(SelfCureStateMachineTest, GetLegalIpConfigurationTest2, TestSize.Level1)
{
    IpInfo dhcpResults;
    dhcpResults.gateway = 19216801;
    dhcpResults.ipAddress = 19216801;
    int result = pSelfCureStateMachine_->GetLegalIpConfiguration(dhcpResults);
    EXPECT_EQ(result, 0);
}

HWTEST_F(SelfCureStateMachineTest, DoArpTest_Test, TestSize.Level1)
{
    std::string gateway = GATEWAY;
    std::string ipAddress = CURRENT_ADDR;
    EXPECT_FALSE(pSelfCureStateMachine_->DoArpTest(ipAddress, gateway));
}

HWTEST_F(SelfCureStateMachineTest, GetNextIpAddr_WhenGatewayAndCurrentAddrAreEmpty_ReturnEmptyString, TestSize.Level1)
{
    std::string gateway = "";
    std::string currentAddr = "";
    std::vector<std::string> testedAddr = {};
    std::string nextIpAddr = SelfCureUtils::GetInstance().GetNextIpAddr(gateway, currentAddr, testedAddr);
    EXPECT_EQ(nextIpAddr, "");
}

HWTEST_F(SelfCureStateMachineTest, GetNextIpAddr_WhenGatewayIsEmpty_ReturnEmptyString, TestSize.Level1)
{
    std::string gateway = "";
    std::string currentAddr = CURRENT_ADDR;
    std::vector<std::string> testedAddr = TESTED_ADDR;
    std::string nextIpAddr = SelfCureUtils::GetInstance().GetNextIpAddr(gateway, currentAddr, testedAddr);
    EXPECT_EQ(nextIpAddr, "");
}

HWTEST_F(SelfCureStateMachineTest, GetNextIpAddr_WhenCurrentAddrIsEmpty_ReturnEmptyString, TestSize.Level1)
{
    std::string gateway = GATEWAY;
    std::string currentAddr = "";
    std::vector<std::string> testedAddr = TESTED_ADDR;
    std::string nextIpAddr = SelfCureUtils::GetInstance().GetNextIpAddr(gateway, currentAddr, testedAddr);
    EXPECT_EQ(nextIpAddr, "");
}

HWTEST_F(SelfCureStateMachineTest, GetNextIpAddr_WhenTestedAddrIsEmpty_ReturnEmptyString, TestSize.Level1)
{
    std::string gateway = GATEWAY;
    std::string currentAddr = CURRENT_ADDR;
    std::vector<std::string> testedAddr = {};
    std::string nextIpAddr = SelfCureUtils::GetInstance().GetNextIpAddr(gateway, currentAddr, testedAddr);
    EXPECT_EQ(nextIpAddr, "");
}

HWTEST_F(SelfCureStateMachineTest, GetNextIpAddr_WhenGatewayAndCurrentAddrAreValid_ReturnNextIpAddr, TestSize.Level1)
{
    std::string gateway = GATEWAY;
    std::string currentAddr = CURRENT_ADDR;
    std::vector<std::string> testedAddr = TESTED_ADDR;
    EXPECT_NE(SelfCureUtils::GetInstance().GetNextIpAddr(gateway, currentAddr, testedAddr), "");
}

HWTEST_F(SelfCureStateMachineTest, IsIpAddressInvalidTest1, TestSize.Level1)
{
    IpInfo dhcpInfo;
    dhcpInfo.ipAddress = 0;
    dhcpInfo.netmask = 0;
    dhcpInfo.gateway = 0;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _))
        .WillOnce(DoAll(SetArgReferee<0>(dhcpInfo), Return(0)));
    EXPECT_FALSE(pSelfCureStateMachine_->IsIpAddressInvalid());
}

HWTEST_F(SelfCureStateMachineTest, IsIpAddressInvalidTest2, TestSize.Level1)
{
    IpInfo dhcpInfo;
    dhcpInfo.ipAddress = 0x0100007F; // 127.0.0.1
    dhcpInfo.netmask = 0x00FFFFFF;
    dhcpInfo.gateway = 0x0100007F; // 127.0.0.1
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _))
        .WillOnce(DoAll(SetArgReferee<0>(dhcpInfo), Return(0)));
    EXPECT_TRUE(pSelfCureStateMachine_->IsIpAddressInvalid());
}

HWTEST_F(SelfCureStateMachineTest, IsIpAddressInvalidTest3, TestSize.Level1)
{
    IpInfo dhcpInfo;
    dhcpInfo.ipAddress = 0x0500007F; // 127.0.0.5
    dhcpInfo.netmask = 0x00FFFFFF;
    dhcpInfo.gateway = 0x0100007F; // 127.0.0.1
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _))
        .WillOnce(DoAll(SetArgReferee<0>(dhcpInfo), Return(0)));
    EXPECT_FALSE(pSelfCureStateMachine_->IsIpAddressInvalid());
}

HWTEST_F(SelfCureStateMachineTest, IsIpAddressInvalidTest4, TestSize.Level1)
{
    IpInfo dhcpInfo;
    dhcpInfo.ipAddress = 0x0000007F; // 127.0.0.0
    dhcpInfo.netmask = 0x00FFFFFF;
    dhcpInfo.gateway = 0x0100007F; // 127.0.0.1
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _))
        .WillOnce(DoAll(SetArgReferee<0>(dhcpInfo), Return(0)));
    EXPECT_FALSE(pSelfCureStateMachine_->IsIpAddressInvalid());
}

HWTEST_F(SelfCureStateMachineTest, IsIpAddressInvalidTest5, TestSize.Level1)
{
    IpInfo dhcpInfo;
    dhcpInfo.ipAddress = 0xFF00007F; // 127.0.0.255
    dhcpInfo.netmask = 0x00FFFFFF;
    dhcpInfo.gateway = 0x0100007F; // 127.0.0.1
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetIpInfo(_, _))
        .WillOnce(DoAll(SetArgReferee<0>(dhcpInfo), Return(0)));
    EXPECT_FALSE(pSelfCureStateMachine_->IsIpAddressInvalid());
}

HWTEST_F(SelfCureStateMachineTest, TransStrToVecTest, TestSize.Level1)
{
    std::string str = "0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0";
    char c = '|';
    SelfCureUtils::GetInstance().TransStrToVec(str, c);
    c = '/';
    EXPECT_NE(SelfCureUtils::GetInstance().TransStrToVec(str, c).size(), 0);
}

HWTEST_F(SelfCureStateMachineTest, IsUseFactoryMacTest, TestSize.Level1)
{
    std::string MacAddress = CURR_BSSID;
    std::string RealMacAddress = REAL_MAC;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).
        WillRepeatedly(DoAll(SetArgReferee<0>(MacAddress), Return(0)));
    EXPECT_CALL(WifiSettings::GetInstance(), GetRealMacAddress(_, _)).
        WillRepeatedly(DoAll(SetArgReferee<0>(RealMacAddress), Return(0)));
    pSelfCureStateMachine_->IsUseFactoryMac();

    MacAddress = CURR_BSSID;
    RealMacAddress = CURR_BSSID;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).
        WillRepeatedly(DoAll(SetArgReferee<0>(MacAddress), Return(0)));
    EXPECT_CALL(WifiSettings::GetInstance(), GetRealMacAddress(_, _)).
        WillRepeatedly(DoAll(SetArgReferee<0>(RealMacAddress), Return(0)));
    pSelfCureStateMachine_->IsUseFactoryMac();

    MacAddress = "";
    RealMacAddress = REAL_MAC;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).
        WillRepeatedly(DoAll(SetArgReferee<0>(MacAddress), Return(0)));
    EXPECT_CALL(WifiSettings::GetInstance(), GetRealMacAddress(_, _)).
        WillRepeatedly(DoAll(SetArgReferee<0>(RealMacAddress), Return(0)));
    pSelfCureStateMachine_->IsUseFactoryMac();

    MacAddress = CURR_BSSID;
    RealMacAddress = "";
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetMacAddress(_, _)).
        WillRepeatedly(DoAll(SetArgReferee<0>(MacAddress), Return(0)));
    EXPECT_CALL(WifiSettings::GetInstance(), GetRealMacAddress(_, _)).
        WillRepeatedly(DoAll(SetArgReferee<0>(RealMacAddress), Return(0)));
    pSelfCureStateMachine_->IsUseFactoryMac();
}

HWTEST_F(SelfCureStateMachineTest, IsSameEncryptTypeTest, TestSize.Level1)
{
    std::string deviceKeymgmt = "WPA-PSK";
    std::string scanInfoKeymgmt = "WPA-PSK";
    bool result = SelfCureUtils::GetInstance().IsSameEncryptType(scanInfoKeymgmt, deviceKeymgmt);
    EXPECT_TRUE(result);

    deviceKeymgmt = "WPA-EAP";
    scanInfoKeymgmt = "WPA-EAP";
    result = SelfCureUtils::GetInstance().IsSameEncryptType(scanInfoKeymgmt, deviceKeymgmt);
    EXPECT_TRUE(result);

    deviceKeymgmt = "SAE";
    scanInfoKeymgmt = "SAE";
    result = SelfCureUtils::GetInstance().IsSameEncryptType(scanInfoKeymgmt, deviceKeymgmt);
    EXPECT_TRUE(result);

    deviceKeymgmt = "SAE";
    scanInfoKeymgmt = "WPA2-PSK";
    result = SelfCureUtils::GetInstance().IsSameEncryptType(scanInfoKeymgmt, deviceKeymgmt);
    EXPECT_FALSE(result);

    deviceKeymgmt = "NONE";
    scanInfoKeymgmt = "NONE";
    result = SelfCureUtils::GetInstance().IsSameEncryptType(scanInfoKeymgmt, deviceKeymgmt);
    EXPECT_TRUE(result);

    deviceKeymgmt = "NONE";
    scanInfoKeymgmt = "WPA-PSK";
    result = SelfCureUtils::GetInstance().IsSameEncryptType(scanInfoKeymgmt, deviceKeymgmt);
    EXPECT_FALSE(result);

    deviceKeymgmt = "Invalid";
    scanInfoKeymgmt = "WPA-PSK";
    result = SelfCureUtils::GetInstance().IsSameEncryptType(scanInfoKeymgmt, deviceKeymgmt);
    EXPECT_FALSE(result);
}

HWTEST_F(SelfCureStateMachineTest, GetBssidCounterTest, TestSize.Level1)
{
    std::vector<WifiScanInfo> scanResults = {};
    int counter = pSelfCureStateMachine_->GetBssidCounter(scanResults);
    EXPECT_EQ(counter, 0);
    
    WifiScanInfo info;
    info.bssid = "";
    info.ssid = "ssid";
    info.bssidType = 0;
    scanResults = {info};
    pSelfCureStateMachine_->GetBssidCounter(scanResults);

    WifiDeviceConfig config;
    config.keyMgmt = "";
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(config), Return(0)));
    pSelfCureStateMachine_->GetBssidCounter(scanResults);

    info.bssid = CURR_BSSID;
    scanResults = {info};
    pSelfCureStateMachine_->GetBssidCounter(scanResults);

    config.keyMgmt = "WPA_PSK";
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(config), Return(0)));
    pSelfCureStateMachine_->GetBssidCounter(scanResults);
}

HWTEST_F(SelfCureStateMachineTest, IsNeedWifiReassocUseDeviceMac_Test1, TestSize.Level1)
{
    std::string selfCureHistory = "";
    pSelfCureStateMachine_->SetSelfCureHistoryInfo(selfCureHistory);
    EXPECT_FALSE(pSelfCureStateMachine_->IsNeedWifiReassocUseDeviceMac());
}

HWTEST_F(SelfCureStateMachineTest, IsNeedWifiReassocUseDeviceMac_Test2, TestSize.Level1)
{
    WifiDeviceConfig config;
    config.internetSelfCureHistory = "0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0";
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(config), Return(0)));
    EXPECT_FALSE(pSelfCureStateMachine_->IsNeedWifiReassocUseDeviceMac());
}

HWTEST_F(SelfCureStateMachineTest, IsNeedWifiReassocUseDeviceMac_Test3, TestSize.Level1)
{
    WifiDeviceConfig config;
    config.internetSelfCureHistory = "0|0|0|1|2|1|0|0|0|0|0|0|0|0|0|0|0|0";
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(config), Return(0)));
    EXPECT_FALSE(pSelfCureStateMachine_->IsNeedWifiReassocUseDeviceMac());
}

HWTEST_F(SelfCureStateMachineTest, SetSelfCureFailInfo_Test, TestSize.Level1)
{
    WifiSelfCureHistoryInfo info;
    std::vector<std::string> histories = {"1", "1615153293123", "2", "1615153293124", "3", "1615153293125",
                                          "4", "1615153293126", "5", "1615153293127", "6", "1615153293128"};
    int cnt = SELFCURE_FAIL_LENGTH;
    SelfCureUtils::GetInstance().SetSelfCureFailInfo(info, histories, cnt);
}

HWTEST_F(SelfCureStateMachineTest, SetSelfCureFailInfoTest_InvalidHistories, TestSize.Level1)
{
    WifiSelfCureHistoryInfo info;
    std::vector<std::string> histories = {"1", "1615153293123", "2", "1615153293124", "3", "1615153293125",
                                          "4", "1615153293126", "5", "1615153293127"};
    int cnt = 6;
    EXPECT_EQ(SelfCureUtils::GetInstance().SetSelfCureFailInfo(info, histories, cnt), -1);
}

HWTEST_F(SelfCureStateMachineTest, SetSelfCureFailInfoTest_InvalidCnt, TestSize.Level1)
{
    WifiSelfCureHistoryInfo info;
    std::vector<std::string> histories = {"1", "1615153293123", "2", "1615153293124", "3", "1615153293125",
                                          "4", "1615153293126", "5", "1615153293127", "6", "1615153293128"};
    int cnt = 5;
    EXPECT_EQ(SelfCureUtils::GetInstance().SetSelfCureFailInfo(info, histories, cnt), -1);
}

HWTEST_F(SelfCureStateMachineTest, SetSelfCureFailInfoTest, TestSize.Level1)
{
    WifiSelfCureHistoryInfo info;
    std::vector<std::string> histories = {"1", "2", "3", "4", "5", "6", "7",
        "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18"};
    int cnt = SELFCURE_FAIL_LENGTH;
    EXPECT_EQ(SelfCureUtils::GetInstance().SetSelfCureFailInfo(info, histories, cnt), 0);
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
    int result = SelfCureUtils::GetInstance().SetSelfCureFailInfo(info, histories, cnt);
    EXPECT_EQ(result, -1);
}

HWTEST_F(SelfCureStateMachineTest, SetSelfCureFailInfoInvalidHistoriesSizeTest, TestSize.Level1)
{
    WifiSelfCureHistoryInfo info;
    std::vector<std::string> histories = {"1", "2", "3", "4", "5", "6", "7",
        "8", "9", "10", "11", "12", "13", "14", "15", "16", "17"};
    int cnt = SELFCURE_FAIL_LENGTH;
    int result = SelfCureUtils::GetInstance().SetSelfCureFailInfo(info, histories, cnt);
    EXPECT_EQ(result, -1);
}

HWTEST_F(SelfCureStateMachineTest, SetSelfCureConnectFailInfoTest, TestSize.Level1)
{
    WifiSelfCureHistoryInfo info;
    std::vector<std::string> histories = {"0", "0", "0", "0", "0", "0", "0",
        "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"};
    int cnt = SELFCURE_FAIL_LENGTH;
    EXPECT_EQ(SelfCureUtils::GetInstance().SetSelfCureConnectFailInfo(info, histories, cnt), 0);
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
    EXPECT_EQ(SelfCureUtils::GetInstance().SetSelfCureConnectFailInfo(info, histories, cnt), -1);
}

HWTEST_F(SelfCureStateMachineTest, SetSelfCureConnectFailInfoInvalidCntTest, TestSize.Level1)
{
    WifiSelfCureHistoryInfo info;
    std::vector<std::string> histories = {"0", "0", "0", "0", "0", "0", "0",
        "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"};
    int cnt = 2;
    EXPECT_EQ(SelfCureUtils::GetInstance().SetSelfCureConnectFailInfo(info, histories, cnt), -1);
}

HWTEST_F(SelfCureStateMachineTest, IsSuppOnCompletedStateTest, TestSize.Level1)
{
    WifiLinkedInfo linkedInfo;
    linkedInfo.connState = ConnState::CONNECTED;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
    pSelfCureStateMachine_->IsSuppOnCompletedState();

    linkedInfo.connState = ConnState::DISCONNECTED;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
    pSelfCureStateMachine_->IsSuppOnCompletedState();
}

HWTEST_F(SelfCureStateMachineTest, IfPeriodicArpDetectionTest, TestSize.Level1)
{
    EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).WillRepeatedly(Return(4));
    pSelfCureStateMachine_->IfPeriodicArpDetection();

    WifiLinkedInfo linkedInfo;
    linkedInfo.connState = ConnState::CONNECTED;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScreenState()).WillRepeatedly(Return(1));
    pSelfCureStateMachine_->IfPeriodicArpDetection();
}

HWTEST_F(SelfCureStateMachineTest, PeriodicArpDetection_WhenMsgIsNullptr_ReturnsFalse, TestSize.Level1)
{
    pSelfCureStateMachine_->PeriodicArpDetection();

    EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).WillRepeatedly(Return(4));
    pSelfCureStateMachine_->PeriodicArpDetection();

    WifiLinkedInfo linkedInfo;
    linkedInfo.connState = ConnState::CONNECTED;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScreenState()).WillRepeatedly(Return(1));
    pSelfCureStateMachine_->PeriodicArpDetection();
}

HWTEST_F(SelfCureStateMachineTest, IfP2pConnectedTest, TestSize.Level1)
{
    bool expectedResult = false;
    WifiP2pLinkedInfo linkedInfo;
    linkedInfo.SetConnectState(P2pConnectedState::P2P_DISCONNECTED);
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetP2pInfo(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
    EXPECT_EQ(expectedResult, pSelfCureStateMachine_->IfP2pConnected());

    linkedInfo.SetConnectState(P2pConnectedState::P2P_CONNECTED);
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetP2pInfo(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
    expectedResult = true;
    EXPECT_EQ(expectedResult, pSelfCureStateMachine_->IfP2pConnected());
}

HWTEST_F(SelfCureStateMachineTest, GetIpAssignmentTest, TestSize.Level1)
{
    AssignIpMethod ipAssignment;
    int result = pSelfCureStateMachine_->GetIpAssignment(ipAssignment);
    EXPECT_EQ(result, 0);

    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).Times(AtLeast(0)).WillOnce(Return(-1));
    pSelfCureStateMachine_->GetIpAssignment(ipAssignment);
}

HWTEST_F(SelfCureStateMachineTest, GetAuthTypeTest, TestSize.Level1)
{
    pSelfCureStateMachine_->GetAuthType();

    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).Times(AtLeast(0)).WillOnce(Return(-1));
    pSelfCureStateMachine_->GetAuthType();
}

HWTEST_F(SelfCureStateMachineTest, GetLastHasInternetTimeTest, TestSize.Level1)
{
    pSelfCureStateMachine_->GetLastHasInternetTime();

    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).Times(AtLeast(0)).WillOnce(Return(-1));
    pSelfCureStateMachine_->GetLastHasInternetTime();
}

HWTEST_F(SelfCureStateMachineTest, GetNetworkStatusHistoryTest, TestSize.Level1)
{
    pSelfCureStateMachine_->GetNetworkStatusHistory();

    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).Times(AtLeast(0)).WillOnce(Return(-1));
    pSelfCureStateMachine_->GetNetworkStatusHistory();
}

HWTEST_F(SelfCureStateMachineTest, SetSelfCureHistoryInfoTest, TestSize.Level1)
{
    std::string selfCureHistory = "1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18";
    int result = pSelfCureStateMachine_->SetSelfCureHistoryInfo(selfCureHistory);
    EXPECT_EQ(result, 0);

    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).Times(AtLeast(0)).WillOnce(Return(-1));
    pSelfCureStateMachine_->SetSelfCureHistoryInfo(selfCureHistory);
}

HWTEST_F(SelfCureStateMachineTest, GetSelfCureHistoryInfoTest, TestSize.Level1)
{
    pSelfCureStateMachine_->GetSelfCureHistoryInfo();

    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).Times(AtLeast(0)).WillOnce(Return(-1));
    pSelfCureStateMachine_->GetSelfCureHistoryInfo();
}

HWTEST_F(SelfCureStateMachineTest, SetSelfCureHistoryInfoZeroTest, TestSize.Level1)
{
    std::string selfCureHistory = "0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0";
    int result = pSelfCureStateMachine_->SetSelfCureHistoryInfo(selfCureHistory);
    EXPECT_EQ(result, 0);

    selfCureHistory = "";
    result = pSelfCureStateMachine_->SetSelfCureHistoryInfo(selfCureHistory);
    EXPECT_EQ(result, -1);
}

HWTEST_F(SelfCureStateMachineTest, SetIsReassocWithFactoryMacAddress_Test1, TestSize.Level1)
{
    int isReassocWithFactoryMacAddress = 1;
    int result = pSelfCureStateMachine_->SetIsReassocWithFactoryMacAddress(isReassocWithFactoryMacAddress);
    EXPECT_EQ(result, 0);
}

HWTEST_F(SelfCureStateMachineTest, SetIsReassocWithFactoryMacAddress_Test2, TestSize.Level1)
{
    int isReassocWithFactoryMacAddress = 0;
    int result = pSelfCureStateMachine_->SetIsReassocWithFactoryMacAddress(isReassocWithFactoryMacAddress);
    EXPECT_EQ(result, 0);
}

HWTEST_F(SelfCureStateMachineTest, SetIsReassocWithFactoryMacAddress_Test3, TestSize.Level1)
{
    int isReassocWithFactoryMacAddress = -1;
    int result = pSelfCureStateMachine_->SetIsReassocWithFactoryMacAddress(isReassocWithFactoryMacAddress);
    EXPECT_EQ(result, 0);

    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).Times(AtLeast(0)).WillOnce(Return(-1));
    pSelfCureStateMachine_->SetIsReassocWithFactoryMacAddress(isReassocWithFactoryMacAddress);
}

HWTEST_F(SelfCureStateMachineTest, GetCurrentWifiDeviceConfigTest, TestSize.Level1)
{
    WifiDeviceConfig config;
    pSelfCureStateMachine_->GetCurrentWifiDeviceConfig(config);

    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).Times(AtLeast(0)).WillOnce(Return(-1));
    pSelfCureStateMachine_->GetCurrentWifiDeviceConfig(config);

    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _)).Times(AtLeast(0)).WillOnce(Return(-1));
    pSelfCureStateMachine_->GetCurrentWifiDeviceConfig(config);
}

HWTEST_F(SelfCureStateMachineTest, SelfCureAcceptable_StaticIp_ReturnsTrue, TestSize.Level1)
{
    WifiSelfCureHistoryInfo historyInfo;
    historyInfo.staticIpSelfCureFailedCnt = 0;
    int requestCureLevel = WIFI_CURE_RESET_LEVEL_LOW_3_STATIC_IP;
    bool result = SelfCureUtils::GetInstance().SelfCureAcceptable(historyInfo, requestCureLevel);
    ASSERT_TRUE(result);
}

HWTEST_F(SelfCureStateMachineTest, SelfCureAcceptable_MiddleReassoc_ReturnsTrue, TestSize.Level1)
{
    WifiSelfCureHistoryInfo historyInfo;
    historyInfo.reassocSelfCureFailedCnt = 0;
    int requestCureLevel = WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC;
    bool result = SelfCureUtils::GetInstance().SelfCureAcceptable(historyInfo, requestCureLevel);
    ASSERT_TRUE(result);
}

HWTEST_F(SelfCureStateMachineTest, SelfCureAcceptable_RandMacReassoc_ReturnsTrue, TestSize.Level1)
{
    WifiSelfCureHistoryInfo historyInfo;
    historyInfo.randMacSelfCureFailedCnt = 0;
    int requestCureLevel = WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC;
    bool result = SelfCureUtils::GetInstance().SelfCureAcceptable(historyInfo, requestCureLevel);
    ASSERT_TRUE(result);
}

HWTEST_F(SelfCureStateMachineTest, SelfCureAcceptable_HighReset_ReturnsTrue, TestSize.Level1)
{
    WifiSelfCureHistoryInfo historyInfo;
    historyInfo.resetSelfCureFailedCnt = 0;
    int requestCureLevel = WIFI_CURE_RESET_LEVEL_HIGH_RESET;
    bool result = SelfCureUtils::GetInstance().SelfCureAcceptable(historyInfo, requestCureLevel);
    ASSERT_TRUE(result);
}

HWTEST_F(SelfCureStateMachineTest, HandleNetworkConnectedTest, TestSize.Level1)
{
    pSelfCureStateMachine_->HandleNetworkConnected();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SelfCureStateMachineTest, UpdateSelfCureConnectHistoryInfo_Success_Reassoc, TestSize.Level1)
{
    WifiSelfCureHistoryInfo historyInfo;
    int requestCureLevel = WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC;
    bool success = true;
    SelfCureUtils::GetInstance().UpdateSelfCureConnectHistoryInfo(historyInfo, requestCureLevel, success);
    ASSERT_EQ(historyInfo.reassocSelfCureConnectFailedCnt, 0);
    ASSERT_EQ(historyInfo.lastReassocSelfCureConnectFailedTs, 0);
}

HWTEST_F(SelfCureStateMachineTest, UpdateSelfCureConnectHistoryInfo_Failure_Reassoc, TestSize.Level1)
{
    WifiSelfCureHistoryInfo historyInfo;
    int requestCureLevel = WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC;
    bool success = false;
    SelfCureUtils::GetInstance().UpdateSelfCureConnectHistoryInfo(historyInfo, requestCureLevel, success);
    ASSERT_EQ(historyInfo.reassocSelfCureConnectFailedCnt, 1);
}

HWTEST_F(SelfCureStateMachineTest, UpdateSelfCureConnectHistoryInfo_Success_RandMacReassoc, TestSize.Level1)
{
    WifiSelfCureHistoryInfo historyInfo;
    int requestCureLevel = WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC;
    bool success = true;
    SelfCureUtils::GetInstance().UpdateSelfCureConnectHistoryInfo(historyInfo, requestCureLevel, success);
    ASSERT_EQ(historyInfo.randMacSelfCureConnectFailedCnt, 0);
    ASSERT_EQ(historyInfo.lastRandMacSelfCureConnectFailedCntTs, 0);
}

HWTEST_F(SelfCureStateMachineTest, UpdateSelfCureConnectHistoryInfo_Failure_RandMacReassoc, TestSize.Level1)
{
    WifiSelfCureHistoryInfo historyInfo;
    int requestCureLevel = WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC;
    bool success = false;
    SelfCureUtils::GetInstance().UpdateSelfCureConnectHistoryInfo(historyInfo, requestCureLevel, success);
    ASSERT_EQ(historyInfo.randMacSelfCureConnectFailedCnt, 1);
}

HWTEST_F(SelfCureStateMachineTest, UpdateSelfCureConnectHistoryInfo_Success_Reset, TestSize.Level1)
{
    WifiSelfCureHistoryInfo historyInfo;
    int requestCureLevel = WIFI_CURE_RESET_LEVEL_HIGH_RESET;
    bool success = true;
    SelfCureUtils::GetInstance().UpdateSelfCureConnectHistoryInfo(historyInfo, requestCureLevel, success);
    ASSERT_EQ(historyInfo.resetSelfCureConnectFailedCnt, 0);
    ASSERT_EQ(historyInfo.lastResetSelfCureConnectFailedTs, 0);
}

HWTEST_F(SelfCureStateMachineTest, UpdateSelfCureConnectHistoryInfo_Failure_Reset, TestSize.Level1)
{
    WifiSelfCureHistoryInfo historyInfo;
    int requestCureLevel = WIFI_CURE_RESET_LEVEL_HIGH_RESET;
    bool success = false;
    SelfCureUtils::GetInstance().UpdateSelfCureConnectHistoryInfo(historyInfo, requestCureLevel, success);
    ASSERT_EQ(historyInfo.resetSelfCureConnectFailedCnt, 1);
}

HWTEST_F(SelfCureStateMachineTest, UpdateReassocAndResetHistoryInfo_SuccessfulReassoc, TestSize.Level1)
{
    WifiSelfCureHistoryInfo historyInfo;
    int requestCureLevel = WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC;
    bool success = true;

    SelfCureUtils::GetInstance().UpdateSelfCureHistoryInfo(historyInfo, requestCureLevel, success);

    EXPECT_EQ(historyInfo.reassocSelfCureFailedCnt, 0);
    EXPECT_EQ(historyInfo.lastReassocSelfCureFailedTs, 0);
}

HWTEST_F(SelfCureStateMachineTest, UpdateReassocAndResetHistoryInfo_FailedReassoc, TestSize.Level1)
{
    WifiSelfCureHistoryInfo historyInfo;
    int requestCureLevel = WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC;
    bool success = false;

    SelfCureUtils::GetInstance().UpdateSelfCureHistoryInfo(historyInfo, requestCureLevel, success);

    EXPECT_EQ(historyInfo.reassocSelfCureFailedCnt, 1);
    EXPECT_NE(historyInfo.lastReassocSelfCureFailedTs, 0);
}

HWTEST_F(SelfCureStateMachineTest, UpdateReassocAndResetHistoryInfo_SuccessfulRandMacReassoc, TestSize.Level1)
{
    WifiSelfCureHistoryInfo historyInfo;
    int requestCureLevel = WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC;
    bool success = true;

    SelfCureUtils::GetInstance().UpdateSelfCureHistoryInfo(historyInfo, requestCureLevel, success);

    EXPECT_EQ(historyInfo.randMacSelfCureFailedCnt, 0);
    EXPECT_EQ(historyInfo.lastRandMacSelfCureFailedCntTs, 0);
}

HWTEST_F(SelfCureStateMachineTest, UpdateReassocAndResetHistoryInfo_FailedRandMacReassoc, TestSize.Level1)
{
    WifiSelfCureHistoryInfo historyInfo;
    int requestCureLevel = WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC;
    bool success = false;

    SelfCureUtils::GetInstance().UpdateSelfCureHistoryInfo(historyInfo, requestCureLevel, success);

    EXPECT_EQ(historyInfo.randMacSelfCureFailedCnt, 1);
    EXPECT_NE(historyInfo.lastRandMacSelfCureFailedCntTs, 0);
}

HWTEST_F(SelfCureStateMachineTest, UpdateReassocAndResetHistoryInfo_SuccessfulHighReset, TestSize.Level1)
{
    WifiSelfCureHistoryInfo historyInfo;
    int requestCureLevel = WIFI_CURE_RESET_LEVEL_HIGH_RESET;
    bool success = true;

    SelfCureUtils::GetInstance().UpdateSelfCureHistoryInfo(historyInfo, requestCureLevel, success);

    EXPECT_EQ(historyInfo.resetSelfCureFailedCnt, 0);
    EXPECT_EQ(historyInfo.lastResetSelfCureFailedTs, 0);
}

HWTEST_F(SelfCureStateMachineTest, UpdateReassocAndResetHistoryInfo_FailedHighReset, TestSize.Level1)
{
    WifiSelfCureHistoryInfo historyInfo;
    int requestCureLevel = WIFI_CURE_RESET_LEVEL_HIGH_RESET;
    bool success = false;

    SelfCureUtils::GetInstance().UpdateSelfCureHistoryInfo(historyInfo, requestCureLevel, success);

    EXPECT_EQ(historyInfo.resetSelfCureFailedCnt, 1);
    EXPECT_NE(historyInfo.lastResetSelfCureFailedTs, 0);
}

HWTEST_F(SelfCureStateMachineTest, IfMultiGateway_Test, TestSize.Level1)
{
    EXPECT_EQ(pSelfCureStateMachine_->IfMultiGateway(), false);
}

HWTEST_F(SelfCureStateMachineTest, IsSelfCureOnGoing_Test, TestSize.Level1)
{
    EXPECT_EQ(pSelfCureStateMachine_->IsSelfCureOnGoing(), false);
}

HWTEST_F(SelfCureStateMachineTest, SetHttpMonitorStatusTest, TestSize.Level1)
{
    bool isHttpReachable = true;
    pSelfCureStateMachine_->SetHttpMonitorStatus(isHttpReachable);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SelfCureStateMachineTest, GetCurrentRssiTest, TestSize.Level1)
{
    EXPECT_EQ(pSelfCureStateMachine_->GetCurrentRssi(), 0);
}

HWTEST_F(SelfCureStateMachineTest, GetIsReassocWithFactoryMacAddressTest, TestSize.Level1)
{
    EXPECT_EQ(pSelfCureStateMachine_->GetIsReassocWithFactoryMacAddress(), 0);
}

HWTEST_F(SelfCureStateMachineTest, IsEncryptedAuthTypeTest, TestSize.Level1)
{
    std::string authType = "";
    pSelfCureStateMachine_->IsEncryptedAuthType(authType);

    authType = "KEY_MGMT_WPA_PSK";
    pSelfCureStateMachine_->IsEncryptedAuthType(authType);

    authType = KEY_MGMT_WAPI_PSK;
    pSelfCureStateMachine_->IsEncryptedAuthType(authType);

    authType = "KEY_MGMT_SAE";
    EXPECT_EQ(pSelfCureStateMachine_->IsEncryptedAuthType(authType), false);
}

HWTEST_F(SelfCureStateMachineTest, IsSoftApSsidSameWithWifiTest, TestSize.Level1)
{
    HotspotConfig curApConfig;
    curApConfig.SetSsid("test");
    WifiLinkedInfo linkedInfo;
    linkedInfo.connState = ConnState::CONNECTED;
    linkedInfo.ssid = "test1";
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _)).Times(AtLeast(0)).WillOnce(Return(0));
    EXPECT_TRUE(pSelfCureStateMachine_->IsSoftApSsidSameWithWifi(curApConfig) == false);
}
 
HWTEST_F(SelfCureStateMachineTest, CheckConflictIpForSoftApTest, TestSize.Level1)
{
    pSelfCureStateMachine_->CheckConflictIpForSoftAp();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}
 
HWTEST_F(SelfCureStateMachineTest, RecoverySoftApTest, TestSize.Level1)
{
    pSelfCureStateMachine_->RecoverySoftAp();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(SelfCureStateMachineTest, IsHttpReachableTest, TestSize.Level1)
{
    IsHttpReachableTest();
}

HWTEST_F(SelfCureStateMachineTest, InitCurrentGatewayTest, TestSize.Level1)
{
    pSelfCureStateMachine_->pInternetSelfCureState_->InitCurrentGateway();
    EXPECT_NE(pSelfCureStateMachine_->noAutoConnCounter_, TEN);
}

HWTEST_F(SelfCureStateMachineTest, UpdateSelfcureStateTest, TestSize.Level1)
{
    pSelfCureStateMachine_->isSelfCureOnGoing_ = false;
    pSelfCureStateMachine_->UpdateSelfcureState(WIFI_CURE_RESET_LEVEL_IDLE, true);
    EXPECT_TRUE(pSelfCureStateMachine_->isSelfCureOnGoing_);
    pSelfCureStateMachine_->UpdateSelfcureState(WIFI_CURE_RESET_LEVEL_IDLE, false);
    EXPECT_FALSE(pSelfCureStateMachine_->isSelfCureOnGoing_);

    pSelfCureStateMachine_->UpdateSelfcureState(WIFI_CURE_RESET_LEVEL_WIFI6, true);
    EXPECT_TRUE(pSelfCureStateMachine_->isSelfCureOnGoing_);
    pSelfCureStateMachine_->UpdateSelfcureState(WIFI_CURE_RESET_LEVEL_WIFI6, false);
    EXPECT_FALSE(pSelfCureStateMachine_->isSelfCureOnGoing_);

    pSelfCureStateMachine_->UpdateSelfcureState(WIFI_CURE_RESET_LEVEL_LOW_3_STATIC_IP, true);
    EXPECT_TRUE(pSelfCureStateMachine_->isSelfCureOnGoing_);
    pSelfCureStateMachine_->UpdateSelfcureState(WIFI_CURE_RESET_LEVEL_LOW_3_STATIC_IP, false);
    EXPECT_FALSE(pSelfCureStateMachine_->isSelfCureOnGoing_);

    pSelfCureStateMachine_->UpdateSelfcureState(WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC, true);
    EXPECT_TRUE(pSelfCureStateMachine_->isSelfCureOnGoing_);
    pSelfCureStateMachine_->UpdateSelfcureState(WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC, false);
    EXPECT_FALSE(pSelfCureStateMachine_->isSelfCureOnGoing_);

    pSelfCureStateMachine_->UpdateSelfcureState(WIFI_CURE_RESET_LEVEL_MULTI_GATEWAY, true);
    EXPECT_TRUE(pSelfCureStateMachine_->isSelfCureOnGoing_);
    pSelfCureStateMachine_->UpdateSelfcureState(WIFI_CURE_RESET_LEVEL_MULTI_GATEWAY, false);
    EXPECT_FALSE(pSelfCureStateMachine_->isSelfCureOnGoing_);

    pSelfCureStateMachine_->UpdateSelfcureState(WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC, true);
    EXPECT_TRUE(pSelfCureStateMachine_->isSelfCureOnGoing_);
    pSelfCureStateMachine_->UpdateSelfcureState(WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC, false);
    EXPECT_FALSE(pSelfCureStateMachine_->isSelfCureOnGoing_);

    pSelfCureStateMachine_->UpdateSelfcureState(WIFI_CURE_RESET_LEVEL_HIGH_RESET_WIFI_ON, true);
    EXPECT_TRUE(pSelfCureStateMachine_->isSelfCureOnGoing_);
    pSelfCureStateMachine_->UpdateSelfcureState(WIFI_CURE_RESET_LEVEL_HIGH_RESET_WIFI_ON, false);
    EXPECT_FALSE(pSelfCureStateMachine_->isSelfCureOnGoing_);
}
} // namespace Wifi
} // namespace OHOS