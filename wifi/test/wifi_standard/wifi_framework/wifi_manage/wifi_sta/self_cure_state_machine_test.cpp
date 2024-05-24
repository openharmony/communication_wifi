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
static const int64_t TIME_MILLS = 1615153293123;
static const std::string CURR_BSSID = "11:22:33:ef:ac:0e";
static const std::string GATEWAY = "192.168.0.1";
static const std::string CURRENT_ADDR = "192.168.0.100";
static const std::vector<std::string> TESTED_ADDR = {"192.168.0.101", "192.168.0.102", "192.168.0.103"};

class SelfCureStateMachineTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        EXPECT_CALL(WifiSettings::GetInstance(), GetLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SetWifiSelfcureReset(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        pSelfCureStateMachine = std::make_unique<SelfCureStateMachine>();
        pSelfCureStateMachine->Initialize();
    }

    virtual void TearDown()
    {
        pSelfCureStateMachine.reset();
    }

    std::unique_ptr<SelfCureStateMachine> pSelfCureStateMachine;

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
        InternalMessage msg;
        msg.SetMessageName(1);
        EXPECT_FALSE(pSelfCureStateMachine->pDefaultState->ExecuteStateMsg(&msg));
    }

    void ConnectedMonitorStateGoInStateSuccess()
    {
        LOGI("Enter ConnectedMonitorStateGoInStateSuccess");
        EXPECT_CALL(WifiSettings::GetInstance(), GetWifiSelfcureReset()).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetStaIfaceName()).WillRepeatedly(Return("sta"));
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
    }

    void ConnectedMonitorStateExeMsgSuccess1()
    {
        LOGI("Enter ConnectedMonitorStateExeMsgSuccess1");
        InternalMessage msg;
        msg.SetMessageName(WIFI_CURE_CMD_PERIODIC_ARP_DETECTED);
        pSelfCureStateMachine->pConnectedMonitorState->ExecuteStateMsg(&msg);
    }

    void InitSelfCureCmsHandleMapTest()
    {
        LOGI("Enter InitSelfCureCmsHandleMapTest");
        pSelfCureStateMachine->pConnectedMonitorState->InitSelfCureCmsHandleMap();
    }

    void TransitionToSelfCureStateTest()
    {
        LOGI("Enter TransitionToSelfCureStateTest");
        int resaon = WIFI_CURE_INTERNET_FAILED_TYPE_ROAMING;
        pSelfCureStateMachine->pConnectedMonitorState->TransitionToSelfCureState(resaon);

        resaon = WIFI_CURE_INTERNET_FAILED_TYPE_TCP;
        EXPECT_CALL(WifiSettings::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetIpv6Info(_, _)).Times(AtLeast(0));
        pSelfCureStateMachine->pConnectedMonitorState->TransitionToSelfCureState(resaon);
    }

    void HandleResetupSelfCureTest()
    {
        LOGI("Enter TransitionToSelfCureStateTest");
        pSelfCureStateMachine->pConnectedMonitorState->SetupSelfCureMonitor();
    }

    void RequestReassocWithFactoryMacTest()
    {
        LOGI("Enter RequestReassocWithFactoryMacTest");
        pSelfCureStateMachine->pConnectedMonitorState->RequestReassocWithFactoryMac();
    }

    void HandleInvalidIpTest()
    {
        LOGI("Enter HandleInvalidIpTest");
        InternalMessage msg;
        msg.SetMessageName(WIFI_CURE_CMD_INVALID_IP_CONFIRM);
        pSelfCureStateMachine->mIsHttpReachable = true;
        pSelfCureStateMachine->pConnectedMonitorState->HandleInvalidIp(&msg);
        pSelfCureStateMachine->mIsHttpReachable = false;
        EXPECT_CALL(WifiSettings::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetIpv6Info(_, _)).Times(AtLeast(0));
        pSelfCureStateMachine->pConnectedMonitorState->HandleInvalidIp(&msg);
    }

    void HandleInternetFailedDetectedTest()
    {
        LOGI("Enter HandleInternetFailedDetectedTest");
        InternalMessage msg;
        msg.SetMessageName(WIFI_CURE_CMD_INTERNET_FAILURE_DETECTED);
        pSelfCureStateMachine->mIsHttpReachable = true;
        pSelfCureStateMachine->pConnectedMonitorState->HandleInternetFailedDetected(&msg);
        pSelfCureStateMachine->mIsHttpReachable = false;
        EXPECT_CALL(WifiSettings::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetIpv6Info(_, _)).Times(AtLeast(0));
        pSelfCureStateMachine->pConnectedMonitorState->HandleInternetFailedDetected(&msg);
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
        InternalMessage msg;
        msg.SetMessageName(1);
        EXPECT_FALSE(pSelfCureStateMachine->pDisconnectedMonitorState->ExecuteStateMsg(&msg));
    }

    void DisconnectedMonitorExeMsgSuccess2()
    {
        LOGI("Enter DisconnectedMonitorExeMsgSuccess2");
        InternalMessage msg;
        msg.SetMessageName(WIFI_CURE_NOTIFY_NETWORK_CONNECTED_RCVD);
        EXPECT_TRUE(pSelfCureStateMachine->pDisconnectedMonitorState->ExecuteStateMsg(&msg));
    }

    void DisconnectedMonitorExeMsgSuccess3()
    {
        LOGI("Enter DisconnectedMonitorExeMsgSuccess3");
        InternalMessage msg;
        msg.SetMessageName(WIFI_CURE_OPEN_WIFI_SUCCEED_RESET);
        EXPECT_CALL(WifiSettings::GetInstance(), GetScreenState()).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetLastNetworkId()).Times(AtLeast(0));
        EXPECT_TRUE(pSelfCureStateMachine->pDisconnectedMonitorState->ExecuteStateMsg(&msg));
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
        InternalMessage msg;
        msg.SetMessageName(1);
        EXPECT_FALSE(pSelfCureStateMachine->pConnectionSelfCureState->ExecuteStateMsg(&msg));
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
        InternalMessage msg;
        msg.SetMessageName(WIFI_CURE_CMD_INTERNET_FAILED_SELF_CURE);
        pSelfCureStateMachine->pInternetSelfCureState->ExecuteStateMsg(&msg);
    }

    void InitSelfCureIssHandleMapTest()
    {
        LOGI("Enter InitSelfCureIssHandleMapTest");
        pSelfCureStateMachine->pInternetSelfCureState->InitSelfCureIssHandleMap();
    }

    void HandleInternetFailedSelfCureTest()
    {
        LOGI("Enter HandleInternetFailedSelfCureTest");
        pSelfCureStateMachine->pInternetSelfCureState->HandleInternetFailedSelfCure(nullptr);
        InternalMessage msg;
        msg.SetMessageName(WIFI_CURE_CMD_INTERNET_FAILED_SELF_CURE);
        pSelfCureStateMachine->pInternetSelfCureState->HandleInternetFailedSelfCure(&msg);
    }

    void HandleSelfCureWifiLinkTest()
    {
        LOGI("Enter HandleSelfCureWifiLinkTest");
        pSelfCureStateMachine->pInternetSelfCureState->HandleSelfCureWifiLink(nullptr);
        InternalMessage msg;
        msg.SetMessageName(WIFI_CURE_CMD_SELF_CURE_WIFI_LINK);
        pSelfCureStateMachine->pInternetSelfCureState->HandleSelfCureWifiLink(&msg);
    }

    void HandleNetworkDisconnectedTest()
    {
        LOGI("Enter HandleNetworkDisconnectedTest");
        pSelfCureStateMachine->pInternetSelfCureState->HandleNetworkDisconnected(nullptr);
        InternalMessage msg;
        msg.SetMessageName(WIFI_CURE_NOTIFY_NETWORK_DISCONNECTED_RCVD);
        pSelfCureStateMachine->pInternetSelfCureState->HandleNetworkDisconnected(&msg);
    }

    void HandleInternetRecoveryTest()
    {
        LOGI("Enter HandleInternetRecoveryTest");
        pSelfCureStateMachine->pInternetSelfCureState->HandleInternetRecovery(nullptr);
        InternalMessage msg;
        msg.SetMessageName(WIFI_CURE_CMD_INTERNET_RECOVERY_CONFIRM);
        pSelfCureStateMachine->pInternetSelfCureState->HandleInternetRecovery(&msg);
    }

    void HandleRssiChangedEventTest()
    {
        LOGI("Enter HandleRssiChangedEventTest");
        pSelfCureStateMachine->pInternetSelfCureState->HandleRssiChangedEvent(nullptr);
        InternalMessage msg;
        msg.SetMessageName(WIFI_CURE_NOTIFY_RSSI_LEVEL_CHANGED_EVENT);
        pSelfCureStateMachine->pInternetSelfCureState->HandleRssiChangedEvent(&msg);
    }

    void HandleP2pDisconnectedTest()
    {
        LOGI("Enter HandleP2pDisconnectedTest");
        pSelfCureStateMachine->pInternetSelfCureState->HandleP2pDisconnected(nullptr);
        InternalMessage msg;
        msg.SetMessageName(WIFI_CURE_CMD_P2P_DISCONNECTED_EVENT);
        pSelfCureStateMachine->pInternetSelfCureState->HandleP2pDisconnected(&msg);
    }

    void HandlePeriodicArpDetecteTest()
    {
        LOGI("Enter HandlePeriodicArpDetecteTest");
        pSelfCureStateMachine->pInternetSelfCureState->HandlePeriodicArpDetecte(nullptr);
        InternalMessage msg;
        msg.SetMessageName(WIFI_CURE_CMD_PERIODIC_ARP_DETECTED);
        pSelfCureStateMachine->pInternetSelfCureState->HandlePeriodicArpDetecte(&msg);
    }

    void HandleArpFailedDetectedTest()
    {
        LOGI("Enter HandleArpFailedDetectedTest");
        pSelfCureStateMachine->pInternetSelfCureState->HandleArpFailedDetected(nullptr);
        InternalMessage msg;
        msg.SetMessageName(WIFI_CURE_CMD_ARP_FAILED_DETECTED);
        EXPECT_CALL(WifiSettings::GetInstance(), GetWifi6BlackListCache(_)).Times(AtLeast(0)).WillOnce(Return(0));
        pSelfCureStateMachine->selfCureOnGoing = true;
        pSelfCureStateMachine->pInternetSelfCureState->HandleArpFailedDetected(&msg);
        pSelfCureStateMachine->selfCureOnGoing = false;
        pSelfCureStateMachine->pInternetSelfCureState->HandleArpFailedDetected(&msg);
        pSelfCureStateMachine->mIsHttpReachable = false;
        pSelfCureStateMachine->pInternetSelfCureState->HandleArpFailedDetected(&msg);
        pSelfCureStateMachine->mIsHttpReachable = true;
        pSelfCureStateMachine->pInternetSelfCureState->HandleArpFailedDetected(&msg);
    }

    void SelectSelfCureByFailedReasonTest()
    {
        LOGI("Enter SelectSelfCureByFailedReasonTest");
        int internetFailedType = WIFI_CURE_INTERNET_FAILED_TYPE_DNS;
        pSelfCureStateMachine->pInternetSelfCureState->userSetStaticIpConfig = true;
        pSelfCureStateMachine->pInternetSelfCureState->SelectSelfCureByFailedReason(internetFailedType);
        pSelfCureStateMachine->pInternetSelfCureState->userSetStaticIpConfig = false;
        pSelfCureStateMachine->pInternetSelfCureState->SelectSelfCureByFailedReason(internetFailedType);
    }

    void SelectBestSelfCureSolutionTest()
    {
        LOGI("Enter SelectBestSelfCureSolutionTest");
        int internetFailedType = WIFI_CURE_INTERNET_FAILED_INVALID_IP;
        pSelfCureStateMachine->pInternetSelfCureState->SelectBestSelfCureSolution(internetFailedType);
        internetFailedType = WIFI_CURE_INTERNET_FAILED_TYPE_ROAMING;
        pSelfCureStateMachine->pInternetSelfCureState->SelectBestSelfCureSolution(internetFailedType);
        internetFailedType = WIFI_CURE_INTERNET_FAILED_TYPE_DNS;
        pSelfCureStateMachine->pInternetSelfCureState->SelectBestSelfCureSolution(internetFailedType);
        internetFailedType = WIFI_CURE_INTERNET_FAILED_RAND_MAC;
        pSelfCureStateMachine->pInternetSelfCureState->SelectBestSelfCureSolution(internetFailedType);
        internetFailedType = WIFI_CURE_INTERNET_FAILED_TYPE_TCP;
        pSelfCureStateMachine->pInternetSelfCureState->SelectBestSelfCureSolution(internetFailedType);
    }

    void SelfCureWifiLinkTest()
    {
        LOGI("Enter SelfCureWifiLinkTest");
        EXPECT_CALL(WifiSettings::GetInstance(), SetLastNetworkId(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SetWifiSelfcureReset(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SetWifiToggledState(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), AddDeviceConfig(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig()).Times(AtLeast(0));
        int requestCureLevel = WIFI_CURE_RESET_LEVEL_LOW_1_DNS;
        pSelfCureStateMachine->pInternetSelfCureState->SelfCureWifiLink(requestCureLevel);
        requestCureLevel = WIFI_CURE_RESET_LEVEL_LOW_2_RENEW_DHCP;
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

    void SelfCureForRenewDhcpTest()
    {
        LOGI("Enter SelfCureForRenewDhcpTest");
        int requestCureLevel = WIFI_CURE_RESET_LEVEL_LOW_2_RENEW_DHCP;
        pSelfCureStateMachine->pInternetSelfCureState->SelfCureForRenewDhcp(requestCureLevel);
    }

    void SelfCureForInvalidIpTest()
    {
        LOGI("Enter SelfCureForInvalidIpTest");
        pSelfCureStateMachine->pInternetSelfCureState->SelfCureForInvalidIp();
    }

    void SelfCureForReassocTest()
    {
        LOGI("Enter SelfCureForReassocTest");
        int requestCureLevel = WIFI_CURE_RESET_LEVEL_MIDDLE_REASSOC;
        pSelfCureStateMachine->pInternetSelfCureState->SelfCureForReassoc(requestCureLevel);
    }

    void SelfCureForRandMacReassocTest()
    {
        LOGI("Enter SelfCureForRandMacReassocTest");
        EXPECT_CALL(WifiSettings::GetInstance(), AddDeviceConfig(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig()).Times(AtLeast(0));
        pSelfCureStateMachine->pInternetSelfCureState->SelfCureForRandMacReassoc();
    }

    void SelectedSelfCureAcceptableTest()
    {
        LOGI("Enter SelectedSelfCureAcceptableTest");
        pSelfCureStateMachine->pInternetSelfCureState->currentAbnormalType = WIFI_CURE_INTERNET_FAILED_TYPE_DNS;
        pSelfCureStateMachine->pInternetSelfCureState->SelectedSelfCureAcceptable();
        pSelfCureStateMachine->pInternetSelfCureState->currentAbnormalType = WIFI_CURE_INTERNET_FAILED_TYPE_TCP;
        pSelfCureStateMachine->pInternetSelfCureState->SelectedSelfCureAcceptable();
    }

    void HandleInternetFailedAndUserSetStaticIpTest()
    {
        LOGI("Enter HandleInternetFailedAndUserSetStaticIpTest");
        int internetFailedType = WIFI_CURE_INTERNET_FAILED_TYPE_DNS;
        pSelfCureStateMachine->pInternetSelfCureState->hasInternetRecently = true;
        pSelfCureStateMachine->pInternetSelfCureState->HandleInternetFailedAndUserSetStaticIp(internetFailedType);
        pSelfCureStateMachine->pInternetSelfCureState->hasInternetRecently = false;
        pSelfCureStateMachine->internetUnknown = false;
        pSelfCureStateMachine->pInternetSelfCureState->HandleInternetFailedAndUserSetStaticIp(internetFailedType);
    }

    void HandleIpConfigTimeoutTest()
    {
        LOGI("Enter HandleIpConfigTimeoutTest");
        EXPECT_CALL(WifiSettings::GetInstance(), GetScanInfoList(_)).Times(AtLeast(0));
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
    }

    void ConfirmInternetSelfCureTest()
    {
        LOGI("Enter ConfirmInternetSelfCureTest");
        EXPECT_CALL(WifiSettings::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetRealMacAddress(_, _)).Times(testing::AtLeast(0));
        int currentCureLevel = WIFI_CURE_RESET_LEVEL_IDLE;
        pSelfCureStateMachine->pInternetSelfCureState->ConfirmInternetSelfCure(currentCureLevel);
        currentCureLevel = WIFI_CURE_RESET_LEVEL_RAND_MAC_REASSOC;
        pSelfCureStateMachine->mIsHttpReachable = true;
        pSelfCureStateMachine->pInternetSelfCureState->ConfirmInternetSelfCure(currentCureLevel);
        pSelfCureStateMachine->mIsHttpReachable = false;
        pSelfCureStateMachine->internetUnknown = true;
        pSelfCureStateMachine->pInternetSelfCureState->ConfirmInternetSelfCure(currentCureLevel);
        pSelfCureStateMachine->internetUnknown = false;
        pSelfCureStateMachine->pInternetSelfCureState->ConfirmInternetSelfCure(currentCureLevel);
    }

    void HandleSelfCureFailedForRandMacReassocTest()
    {
        LOGI("Enter HandleSelfCureFailedForRandMacReassocTest");
        EXPECT_CALL(WifiSettings::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetRealMacAddress(_, _)).Times(testing::AtLeast(0));
        pSelfCureStateMachine->useWithRandMacAddress == RAND_MAC_REASSOC;
        pSelfCureStateMachine->pInternetSelfCureState->HandleSelfCureFailedForRandMacReassoc();
        pSelfCureStateMachine->useWithRandMacAddress == FAC_MAC_REASSOC;
        pSelfCureStateMachine->pInternetSelfCureState->HandleSelfCureFailedForRandMacReassoc();
    }

    void HandleHttpReachableAfterSelfCureTest()
    {
        LOGI("Enter HandleHttpReachableAfterSelfCureTest");
        int currentCureLevel = 1;
        pSelfCureStateMachine->pInternetSelfCureState->HandleHttpReachableAfterSelfCure(currentCureLevel);
        currentCureLevel = WIFI_CURE_RESET_LEVEL_LOW_3_STATIC_IP;
        pSelfCureStateMachine->pInternetSelfCureState->setStaticIp4InvalidIp = false;
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
        EXPECT_CALL(WifiSettings::GetInstance(), GetScreenState()).Times(AtLeast(0));
        WifiP2pLinkedInfo linkedInfo;
        linkedInfo.SetConnectState(P2pConnectedState::P2P_DISCONNECTED);
        EXPECT_CALL(WifiSettings::GetInstance(), GetP2pInfo(_))
            .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
        pSelfCureStateMachine->notAllowSelfcure = false;
        pSelfCureStateMachine->pInternetSelfCureState->HandleRssiChanged();
        pSelfCureStateMachine->pInternetSelfCureState->currentRssi = MIN_VAL_LEVEL_4;
        pSelfCureStateMachine->pInternetSelfCureState->delayedResetSelfCure = true;
        pSelfCureStateMachine->pInternetSelfCureState->HandleRssiChanged();
        pSelfCureStateMachine->pInternetSelfCureState->delayedResetSelfCure = false;
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
    }

    void InitExeMsgSuccess1()
    {
        LOGI("Enter InitExeMsgSuccess1");
        InternalMessage msg;
        msg.SetMessageName(WIFI_CURE_CMD_WIFI6_SELFCURE);
        EXPECT_TRUE(pSelfCureStateMachine->pWifi6SelfCureState->ExecuteStateMsg(&msg));
    }

    void InitExeMsgSuccess2()
    {
        LOGI("Enter InitExeMsgSuccess2");
        InternalMessage msg;
        msg.SetMessageName(WIFI_CURE_CMD_WIFI6_BACKOFF_SELFCURE);
        EXPECT_TRUE(pSelfCureStateMachine->pWifi6SelfCureState->ExecuteStateMsg(&msg));
    }

    void CanArpReachableFailedTest()
    {
        LOGI("Enter CanArpReachableFailedTest");
        IpInfo ipInfo;
        ipInfo.gateway = 0;
        EXPECT_CALL(WifiSettings::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetIpInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(ipInfo), Return(0)));
        EXPECT_CALL(WifiSettings::GetInstance(), GetStaIfaceName()).WillRepeatedly(Return("sta"));
        EXPECT_FALSE(pSelfCureStateMachine->CanArpReachable());
    }

    void CanArpReachableTest()
    {
        LOGI("Enter CanArpReachableTest");
        IpInfo ipInfo;
        ipInfo.gateway = 1;
        EXPECT_CALL(WifiSettings::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetIpInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(ipInfo), Return(0)));
        EXPECT_CALL(WifiSettings::GetInstance(), GetStaIfaceName()).WillRepeatedly(Return("sta"));
        EXPECT_FALSE(pSelfCureStateMachine->CanArpReachable());
    }

    void InitExeMsgSuccess3()
    {
        LOGI("Enter InitExeMsgSuccess3");
        InternalMessage msg;
        msg.SetMessageName(WIFI_CURE_CMD_WIFI6_WITH_HTC_PERIODIC_ARP_DETECTED);
        EXPECT_CALL(WifiSettings::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SetWifiSelfcureReset(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetStaIfaceName()).WillRepeatedly(Return("sta"));
        EXPECT_TRUE(pSelfCureStateMachine->pWifi6SelfCureState->ExecuteStateMsg(&msg));
    }

    void InitExeMsgSuccess4()
    {
        LOGI("Enter InitExeMsgSuccess4");
        InternalMessage msg;
        msg.SetMessageName(WIFI_CURE_CMD_WIFI6_WITHOUT_HTC_PERIODIC_ARP_DETECTED);
        EXPECT_CALL(WifiSettings::GetInstance(), GetMacAddress(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetIpInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SetWifiSelfcureReset(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetStaIfaceName()).WillRepeatedly(Return("sta"));
        EXPECT_TRUE(pSelfCureStateMachine->pWifi6SelfCureState->ExecuteStateMsg(&msg));
    }

    void InitExeMsgSuccess5()
    {
        LOGI("Enter InitExeMsgSuccess5");
        InternalMessage msg;
        msg.SetMessageName(WIFI_CURE_CMD_WIFI6_WITH_HTC_ARP_FAILED_DETECTED);
        EXPECT_CALL(WifiSettings::GetInstance(), InsertWifi6BlackListCache(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), RemoveWifi6BlackListCache(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetWifi6BlackListCache(_)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_TRUE(pSelfCureStateMachine->pWifi6SelfCureState->ExecuteStateMsg(&msg));
    }

    void InitExeMsgSuccess6()
    {
        LOGI("Enter InitExeMsgSuccess6");
        InternalMessage msg;
        msg.SetMessageName(WIFI_CURE_CMD_WIFI6_WITHOUT_HTC_ARP_FAILED_DETECTED);
        EXPECT_CALL(WifiSettings::GetInstance(), InsertWifi6BlackListCache(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), RemoveWifi6BlackListCache(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetWifi6BlackListCache(_)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_TRUE(pSelfCureStateMachine->pWifi6SelfCureState->ExecuteStateMsg(&msg));
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
        EXPECT_CALL(WifiSettings::GetInstance(), GetWifi6BlackListCache(_))
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

        EXPECT_CALL(WifiSettings::GetInstance(), GetWifi6BlackListCache(_))
            .WillRepeatedly(DoAll(SetArgReferee<0>(wifi6BlackListCache), Return(0)));
        pSelfCureStateMachine->SendBlaListToDriver();
    }

    void BlackListToStringTest()
    {
        LOGI("Enter BlackListToStringTest");
        std::map<std::string, Wifi6BlackListInfo> wifi6BlackListCache = {};
        EXPECT_CALL(WifiSettings::GetInstance(), GetWifi6BlackListCache(_))
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

        EXPECT_CALL(WifiSettings::GetInstance(), GetWifi6BlackListCache(_))
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
    }

    void AgeOutWifi6BlackTest()
    {
        LOGI("Enter AgeOutWifi6BlackTest");
        std::map<std::string, Wifi6BlackListInfo> wifi6BlackListCache;
        std::string currentBssid = CURR_BSSID;
        Wifi6BlackListInfo wifi6BlackListInfo(1, TIME_MILLS);
        wifi6BlackListCache.emplace(std::make_pair(currentBssid, wifi6BlackListInfo));
        EXPECT_CALL(WifiSettings::GetInstance(), RemoveWifi6BlackListCache(_)).Times(AtLeast(0));
        pSelfCureStateMachine->AgeOutWifi6Black(wifi6BlackListCache);
    }

    void ShouldTransToWifi6SelfCureTest()
    {
        LOGI("Enter ShouldTransToWifi6SelfCureTest");
        std::string currConnectedBssid = "";
        InternalMessage msg;
        msg.SetMessageName(1);
        EXPECT_FALSE(pSelfCureStateMachine->ShouldTransToWifi6SelfCure(&msg, currConnectedBssid));
    }

    void ShouldTransToWifi6SelfCureTest2()
    {
        LOGI("Enter ShouldTransToWifi6SelfCureTest2");
        std::string currConnectedBssid = CURR_BSSID;
        EXPECT_CALL(WifiSettings::GetInstance(), GetScanInfoList(_)).Times(AtLeast(0));
        InternalMessage msg;
        msg.SetMessageName(1);
        EXPECT_FALSE(pSelfCureStateMachine->ShouldTransToWifi6SelfCure(&msg, currConnectedBssid));
    }

    void GetCurrentBssidTest()
    {
        LOGI("Enter GetCurrentBssidTest");
        std::string currConnectedBssid = "";
        EXPECT_CALL(WifiSettings::GetInstance(), GetLinkedInfo(_, _)).Times(AtLeast(0));
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
        EXPECT_CALL(WifiSettings::GetInstance(), GetLinkedInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));
        EXPECT_FALSE(pSelfCureStateMachine->IsWifi6Network(currConnectedBssid));
    }

    void IsWifi6NetworkTest3()
    {
        LOGI("Enter IsWifi6NetworkTest3");
        std::string currConnectedBssid = CURR_BSSID;
        WifiLinkedInfo wifiLinkedInfo;
        wifiLinkedInfo.supportedWifiCategory = WifiCategory::WIFI6;
        EXPECT_CALL(WifiSettings::GetInstance(), GetLinkedInfo(_, _))
            .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));
        EXPECT_TRUE(pSelfCureStateMachine->IsWifi6Network(currConnectedBssid));
    }

    void DisconnectedExeMsgSuccess0()
    {
        LOGI("Enter DisconnectedExeMsgSuccess0");
        InternalMessage msg;
        msg.SetMessageName(WIFI_CURE_OPEN_WIFI_SUCCEED_RESET);
        EXPECT_CALL(WifiSettings::GetInstance(), GetWifiSelfcureReset()).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetScreenState()).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetLastNetworkId()).Times(AtLeast(0));
        EXPECT_TRUE(pSelfCureStateMachine->pDisconnectedMonitorState->ExecuteStateMsg(&msg));
    }

    void HandleResetConnectNetworkTest()
    {
        LOGI("Enter HandleResetConnectNetworkTest");
        InternalMessage msg;
        msg.SetMessageName(WIFI_CURE_OPEN_WIFI_SUCCEED_RESET);
        EXPECT_CALL(WifiSettings::GetInstance(), GetWifiSelfcureReset()).Times(AtLeast(0)).WillOnce(Return(false));
        pSelfCureStateMachine->pDisconnectedMonitorState->HandleResetConnectNetwork(&msg);
    }

    void HandleResetConnectNetworkTest2()
    {
        LOGI("Enter HandleResetConnectNetworkTest2");
        InternalMessage msg;
        msg.SetMessageName(WIFI_CURE_OPEN_WIFI_SUCCEED_RESET);
        EXPECT_CALL(WifiSettings::GetInstance(), GetWifiSelfcureReset()).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetScreenState()).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetLastNetworkId()).Times(AtLeast(0));
        pSelfCureStateMachine->pDisconnectedMonitorState->HandleResetConnectNetwork(&msg);
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
        EXPECT_CALL(WifiSettings::GetInstance(), GetScreenState()).Times(AtLeast(0));
        WifiP2pLinkedInfo linkedInfo;
        linkedInfo.SetConnectState(P2pConnectedState::P2P_CONNECTED);
        EXPECT_CALL(WifiSettings::GetInstance(), GetP2pInfo(_))
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
        EXPECT_CALL(WifiSettings::GetInstance(), GetScreenState()).Times(AtLeast(0));
        WifiP2pLinkedInfo linkedInfo;
        linkedInfo.SetConnectState(P2pConnectedState::P2P_DISCONNECTED);
        EXPECT_CALL(WifiSettings::GetInstance(), GetP2pInfo(_))
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
        EXPECT_CALL(WifiSettings::GetInstance(), GetScreenState()).Times(AtLeast(0));
        WifiP2pLinkedInfo linkedInfo;
        linkedInfo.SetConnectState(P2pConnectedState::P2P_DISCONNECTED);
        EXPECT_CALL(WifiSettings::GetInstance(), GetP2pInfo(_))
            .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
        pSelfCureStateMachine->notAllowSelfcure = false;
        EXPECT_CALL(WifiSettings::GetInstance(), GetLinkedInfo(_, _)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _)).Times(AtLeast(0)).WillOnce(Return(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SetLastNetworkId(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SetWifiSelfcureReset(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SetWifiToggledState(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), AddDeviceConfig(_)).Times(AtLeast(0));
        EXPECT_CALL(WifiSettings::GetInstance(), SyncDeviceConfig()).Times(AtLeast(0));
        pSelfCureStateMachine->pInternetSelfCureState->SelfCureForReset(requestCureLevel);
    }

    void IsSettingsPageTest()
    {
        LOGI("Enter IsSettingsPageTest");
        pSelfCureStateMachine->IsSettingsPage();
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

HWTEST_F(SelfCureStateMachineTest, RequestReassocWithFactoryMacTest, TestSize.Level1)
{
    RequestReassocWithFactoryMacTest();
}

HWTEST_F(SelfCureStateMachineTest, HandleInvalidIpTest, TestSize.Level1)
{
    HandleInvalidIpTest();
}

HWTEST_F(SelfCureStateMachineTest, HandleInternetFailedDetectedTest, TestSize.Level1)
{
    HandleInternetFailedDetectedTest();
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

HWTEST_F(SelfCureStateMachineTest, SelfCureWifiLinkTest, TestSize.Level1)
{
    SelfCureWifiLinkTest();
}
HWTEST_F(SelfCureStateMachineTest, SelfCureForRenewDhcpTest, TestSize.Level1)
{
    SelfCureForRenewDhcpTest();
}

HWTEST_F(SelfCureStateMachineTest, SelfCureForInvalidIpTest, TestSize.Level1)
{
    SelfCureForInvalidIpTest();
}

HWTEST_F(SelfCureStateMachineTest, SelfCureForReassocTest, TestSize.Level1)
{
    SelfCureForReassocTest();
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

HWTEST_F(SelfCureStateMachineTest, GetLegalIpConfigurationTest3, TestSize.Level1)
{
    IpInfo dhcpResults;
    dhcpResults.gateway = 19216801;
    dhcpResults.ipAddress = 19216801;
    int result = pSelfCureStateMachine->GetLegalIpConfiguration(dhcpResults);
    EXPECT_EQ(result, 0);
}

HWTEST_F(SelfCureStateMachineTest, GetLegalIpConfigurationTest4, TestSize.Level1)
{
    IpInfo dhcpResults;
    dhcpResults.gateway = 19216801;
    dhcpResults.ipAddress = 19216801;
    int result = pSelfCureStateMachine->GetLegalIpConfiguration(dhcpResults);
    EXPECT_EQ(result, 0);
}

HWTEST_F(SelfCureStateMachineTest, GetLegalIpConfigurationTest5, TestSize.Level1)
{
    IpInfo dhcpResults;
    dhcpResults.gateway = 19216801;
    dhcpResults.ipAddress = 19216801;
    int result = pSelfCureStateMachine->GetLegalIpConfiguration(dhcpResults);
    EXPECT_EQ(result, 0);
}

HWTEST_F(SelfCureStateMachineTest, GetNextIpAddr_WhenGatewayAndCurrentAddrAreEmpty_ReturnEmptyString, TestSize.Level1) {
    std::string gateway = "";
    std::string currentAddr = "";
    std::vector<std::string> testedAddr = {};
    std::string nextIpAddr = pSelfCureStateMachine->GetNextIpAddr(gateway, currentAddr, testedAddr);
    EXPECT_EQ(nextIpAddr, "");
}

HWTEST_F(SelfCureStateMachineTest, GetNextIpAddr_WhenGatewayIsEmpty_ReturnEmptyString, TestSize.Level1) {
    std::string gateway = "";
    std::string currentAddr = CURRENT_ADDR;
    std::vector<std::string> testedAddr = TESTED_ADDR;
    std::string nextIpAddr = pSelfCureStateMachine->GetNextIpAddr(gateway, currentAddr, testedAddr);
    EXPECT_EQ(nextIpAddr, "");
}

HWTEST_F(SelfCureStateMachineTest, GetNextIpAddr_WhenCurrentAddrIsEmpty_ReturnEmptyString, TestSize.Level1) {
    std::string gateway = GATEWAY;
    std::string currentAddr = "";
    std::vector<std::string> testedAddr = TESTED_ADDR;
    std::string nextIpAddr = pSelfCureStateMachine->GetNextIpAddr(gateway, currentAddr, testedAddr);
    EXPECT_EQ(nextIpAddr, "");
}

HWTEST_F(SelfCureStateMachineTest, GetNextIpAddr_WhenTestedAddrIsEmpty_ReturnEmptyString, TestSize.Level1) {
    std::string gateway = GATEWAY;
    std::string currentAddr = CURRENT_ADDR;
    std::vector<std::string> testedAddr = {};
    std::string nextIpAddr = pSelfCureStateMachine->GetNextIpAddr(gateway, currentAddr, testedAddr);
    EXPECT_EQ(nextIpAddr, "");
}

HWTEST_F(SelfCureStateMachineTest, GetNextIpAddr_WhenGatewayAndCurrentAddrAreValid_ReturnNextIpAddr, TestSize.Level1) {
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
    EXPECT_CALL(WifiSettings::GetInstance(), GetIpInfo(_, _))
        .WillOnce(DoAll(SetArgReferee<0>(dhcpInfo), Return(0)));
    EXPECT_FALSE(pSelfCureStateMachine->IsIpAddressInvalid());
}

HWTEST_F(SelfCureStateMachineTest, IsIpAddressInvalidTest2, TestSize.Level1)
{
    IpInfo dhcpInfo;
    dhcpInfo.ipAddress = 0x0100007F; // 127.0.0.1
    dhcpInfo.netmask = 0x00FFFFFF;
    dhcpInfo.gateway = 0x0100007F; // 127.0.0.1
    EXPECT_CALL(WifiSettings::GetInstance(), GetIpInfo(_, _))
        .WillOnce(DoAll(SetArgReferee<0>(dhcpInfo), Return(0)));
    EXPECT_TRUE(pSelfCureStateMachine->IsIpAddressInvalid());
}

HWTEST_F(SelfCureStateMachineTest, IsIpAddressInvalidTest3, TestSize.Level1)
{
    IpInfo dhcpInfo;
    dhcpInfo.ipAddress = 0x0500007F; // 127.0.0.5
    dhcpInfo.netmask = 0x00FFFFFF;
    dhcpInfo.gateway = 0x0100007F; // 127.0.0.1
    EXPECT_CALL(WifiSettings::GetInstance(), GetIpInfo(_, _))
        .WillOnce(DoAll(SetArgReferee<0>(dhcpInfo), Return(0)));
    EXPECT_FALSE(pSelfCureStateMachine->IsIpAddressInvalid());
}

HWTEST_F(SelfCureStateMachineTest, IsIpAddressInvalidTest4, TestSize.Level1)
{
    IpInfo dhcpInfo;
    dhcpInfo.ipAddress = 0x0000007F; // 127.0.0.0
    dhcpInfo.netmask = 0x00FFFFFF;
    dhcpInfo.gateway = 0x0100007F; // 127.0.0.1
    EXPECT_CALL(WifiSettings::GetInstance(), GetIpInfo(_, _))
        .WillOnce(DoAll(SetArgReferee<0>(dhcpInfo), Return(0)));
    EXPECT_FALSE(pSelfCureStateMachine->IsIpAddressInvalid());
}

HWTEST_F(SelfCureStateMachineTest, IsIpAddressInvalidTest5, TestSize.Level1)
{
    IpInfo dhcpInfo;
    dhcpInfo.ipAddress = 0xFF00007F; // 127.0.0.255
    dhcpInfo.netmask = 0x00FFFFFF;
    dhcpInfo.gateway = 0x0100007F; // 127.0.0.1
    EXPECT_CALL(WifiSettings::GetInstance(), GetIpInfo(_, _))
        .WillOnce(DoAll(SetArgReferee<0>(dhcpInfo), Return(0)));
    EXPECT_FALSE(pSelfCureStateMachine->IsIpAddressInvalid());
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
}

HWTEST_F(SelfCureStateMachineTest, IsNeedWifiReassocUseDeviceMac_Test1, TestSize.Level1)
{
    std::string selfCureHistory = "";
    pSelfCureStateMachine->SetSelfCureHistoryInfo(selfCureHistory);
    EXPECT_FALSE(pSelfCureStateMachine->IsNeedWifiReassocUseDeviceMac());
}

HWTEST_F(SelfCureStateMachineTest, IsNeedWifiReassocUseDeviceMac_Test2, TestSize.Level1)
{
    std::string selfCureHistory = "0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0";
    pSelfCureStateMachine->SetSelfCureHistoryInfo(selfCureHistory);
    EXPECT_FALSE(pSelfCureStateMachine->IsNeedWifiReassocUseDeviceMac());
}

HWTEST_F(SelfCureStateMachineTest, IsNeedWifiReassocUseDeviceMac_Test3, TestSize.Level1)
{
    std::string selfCureHistory = "0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0";
    pSelfCureStateMachine->SetSelfCureHistoryInfo(selfCureHistory);
    EXPECT_FALSE(pSelfCureStateMachine->IsNeedWifiReassocUseDeviceMac());
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

HWTEST_F(SelfCureStateMachineTest, PeriodicArpDetection_WhenMsgIsNullptr_ReturnsFalse, TestSize.Level1)
{
    pSelfCureStateMachine->PeriodicArpDetection();
}

HWTEST_F(SelfCureStateMachineTest, IfP2pConnectedTest, TestSize.Level1)
{
    bool expectedResult = false;
    WifiP2pLinkedInfo linkedInfo;
    linkedInfo.SetConnectState(P2pConnectedState::P2P_DISCONNECTED);
    EXPECT_CALL(WifiSettings::GetInstance(), GetP2pInfo(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
    EXPECT_EQ(expectedResult, pSelfCureStateMachine->IfP2pConnected());
    linkedInfo.SetConnectState(P2pConnectedState::P2P_CONNECTED);
    EXPECT_CALL(WifiSettings::GetInstance(), GetP2pInfo(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
    expectedResult = true;
    EXPECT_EQ(expectedResult, pSelfCureStateMachine->IfP2pConnected());
}

HWTEST_F(SelfCureStateMachineTest, GetIpAssignmentTest, TestSize.Level1)
{
    AssignIpMethod ipAssignment;
    int result = pSelfCureStateMachine->GetIpAssignment(ipAssignment);
    EXPECT_EQ(result, 0);
}

HWTEST_F(SelfCureStateMachineTest, GetNetworkStatusHistoryTest, TestSize.Level1)
{
    pSelfCureStateMachine->GetNetworkStatusHistory();
}

HWTEST_F(SelfCureStateMachineTest, SetSelfCureHistoryInfoTest, TestSize.Level1)
{
    std::string selfCureHistory = "1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18";
    int result = pSelfCureStateMachine->SetSelfCureHistoryInfo(selfCureHistory);
    EXPECT_EQ(result, 0);
}

HWTEST_F(SelfCureStateMachineTest, SetSelfCureHistoryInfoZeroTest, TestSize.Level1)
{
    std::string selfCureHistory = "0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0|0";
    int result = pSelfCureStateMachine->SetSelfCureHistoryInfo(selfCureHistory);
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
}

HWTEST_F(SelfCureStateMachineTest, GetCurrentWifiDeviceConfigTest, TestSize.Level1)
{
    WifiDeviceConfig config;
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
    EXPECT_CALL(WifiSettings::GetInstance(), GetIpInfo(_, _))
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

} // namespace Wifi
} // namespace OHOS
