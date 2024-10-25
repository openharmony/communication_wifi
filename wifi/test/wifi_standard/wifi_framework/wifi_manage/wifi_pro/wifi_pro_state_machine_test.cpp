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
#include "define.h"
#include "wifi_log.h"
#include "wifi_errcode.h"
#include "state_machine.h"
#include "wifi_pro_common.h"
#include "iscan_service.h"
#include "wifi_logger.h"
#include "wifi_msg.h"
#include "wifi_pro_state_machine.h"
#include "wifi_service_manager.h"
#include "wifi_pro_utils.h"
#include "net_conn_client.h"
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

class WifiProStateMachineTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        wifiProStateMachine_ = new WifiProStateMachine();
        pWifiProStateMachine_ = std::make_unique<WifiProStateMachine>();
        defaultState_ = std::make_unique<WifiProStateMachine::DefaultState>(wifiProStateMachine_);
        wifiProEnableState_ = std::make_unique<WifiProStateMachine::WifiProEnableState>(wifiProStateMachine_);
        wifiProDisabledState_ = std::make_unique<WifiProStateMachine::WifiProDisabledState>(wifiProStateMachine_);
        wifiConnectedState_ = std::make_unique<WifiProStateMachine::WifiConnectedState>(wifiProStateMachine_);
        wifiDisconnectedState_ = std::make_unique<WifiProStateMachine::WifiDisconnectedState>(wifiProStateMachine_);
        wifiHasNetState_ = std::make_unique<WifiProStateMachine::WifiHasNetState>(wifiProStateMachine_);
        wifiNoNetState_ = std::make_unique<WifiProStateMachine::WifiNoNetState>(wifiProStateMachine_);
        wifiPortalState_ = std::make_unique<WifiProStateMachine::WifiPortalState>(wifiProStateMachine_);
        pWifiProStateMachine_->Initialize();
    }

    virtual void TearDown()
    {
        if (pWifiProStateMachine_->pCurrWifiInfo_ != nullptr) {
            pWifiProStateMachine_->pCurrWifiInfo_.reset();
        }
        
        if (pWifiProStateMachine_->pCurrWifiDeviceConfig_ != nullptr) {
            pWifiProStateMachine_->pCurrWifiDeviceConfig_.reset();
        }
        if (wifiProStateMachine_ != nullptr) {
            delete wifiProStateMachine_;
            wifiProStateMachine_ = nullptr;
        }

        pWifiProStateMachine_.reset();
    }

    WifiProStateMachine *wifiProStateMachine_;
    std::unique_ptr<WifiProStateMachine> pWifiProStateMachine_;
    std::unique_ptr<WifiProStateMachine::DefaultState> defaultState_;
    std::unique_ptr<WifiProStateMachine::WifiProEnableState> wifiProEnableState_;
    std::unique_ptr<WifiProStateMachine::WifiProDisabledState> wifiProDisabledState_;
    std::unique_ptr<WifiProStateMachine::WifiConnectedState> wifiConnectedState_;
    std::unique_ptr<WifiProStateMachine::WifiDisconnectedState> wifiDisconnectedState_;
    std::unique_ptr<WifiProStateMachine::WifiHasNetState> wifiHasNetState_;
    std::unique_ptr<WifiProStateMachine::WifiNoNetState> wifiNoNetState_;
    std::unique_ptr<WifiProStateMachine::WifiPortalState> wifiPortalState_;
};

HWTEST_F(WifiProStateMachineTest, HandleRssiChangedInLinkMonitorStateTest, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_WIFI_RSSI_CHANGED);
    msg->SetParam1(-30);
    auto pWiFiLinkMonitorState = pWifiProStateMachine_->pWifiHasNetState_;
    pWiFiLinkMonitorState->rssiLevel2Or3ScanedCounter_ = 1;
    pWiFiLinkMonitorState->HandleRssiChangedInHasNet(msg);
    EXPECT_EQ(pWiFiLinkMonitorState->rssiLevel2Or3ScanedCounter_, 1);
}

HWTEST_F(WifiProStateMachineTest, IsReachWifiScanThresholdTest01, TestSize.Level1)
{
    // wifi signal 4 bars
    int32_t signalLevel = SIG_LEVEL_4;
    int32_t ret = pWifiProStateMachine_->IsReachWifiScanThreshold(signalLevel);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WifiProStateMachineTest, IsReachWifiScanThresholdTest02, TestSize.Level1)
{
    // The wifi signal is lower than 3 bars
    int32_t signalLevel = SIG_LEVEL_2;
    int32_t ret = pWifiProStateMachine_->IsReachWifiScanThreshold(signalLevel);
    EXPECT_EQ(ret, true);
}

HWTEST_F(WifiProStateMachineTest, IsReachWifiScanThresholdTest03, TestSize.Level1)
{
    // The wifi signal is equal to 3 bars, and there are switching records within 14 days
    int32_t signalLevel = SIG_LEVEL_3;
    WifiLinkedInfo wifiLinkedInfo;
    wifiLinkedInfo.supplicantState = SupplicantState::INVALID;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));
    pWifiProStateMachine_->pCurrWifiInfo_ = std::make_shared<WifiLinkedInfo>(wifiLinkedInfo);

    WifiDeviceConfig wifiDeviceConfig;
    wifiDeviceConfig.lastTrySwitchWifiTimestamp = WifiProUtils::GetCurrentTimeMs();
    pWifiProStateMachine_->pCurrWifiDeviceConfig_ = std::make_shared<WifiDeviceConfig>(wifiDeviceConfig);
    bool ret = pWifiProStateMachine_->IsReachWifiScanThreshold(signalLevel);
    EXPECT_EQ(ret, true);
}

HWTEST_F(WifiProStateMachineTest, IsReachWifiScanThresholdTest04, TestSize.Level1)
{
    // The wifi signal is equal to 3 bars, and there is no connection record within 14 days.
    int32_t signalLevel = SIG_LEVEL_3;
    WifiLinkedInfo wifiLinkedInfo;
    wifiLinkedInfo.supplicantState = SupplicantState::INVALID;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));
    pWifiProStateMachine_->pCurrWifiInfo_ = std::make_shared<WifiLinkedInfo>(wifiLinkedInfo);

    WifiDeviceConfig wifiDeviceConfig;
    wifiDeviceConfig.lastTrySwitchWifiTimestamp = 0;
    pWifiProStateMachine_->pCurrWifiDeviceConfig_ = std::make_shared<WifiDeviceConfig>(wifiDeviceConfig);
    bool ret = pWifiProStateMachine_->IsReachWifiScanThreshold(signalLevel);
    EXPECT_EQ(ret, false);
}

HWTEST_F(WifiProStateMachineTest, IsKeepCurrWifiConnectedTest01, TestSize.Level1)
{
    pWifiProStateMachine_->isWifiNoInternet_ = true;
    EXPECT_EQ(pWifiProStateMachine_->IsKeepCurrWifiConnected(), false);
}

HWTEST_F(WifiProStateMachineTest, IsKeepCurrWifiConnectedTest02, TestSize.Level1)
{
    pWifiProStateMachine_->isWifiNoInternet_ = false;
    EXPECT_EQ(pWifiProStateMachine_->IsKeepCurrWifiConnected(), false);
}

HWTEST_F(WifiProStateMachineTest, RefreshConnectedNetWorkTest01, TestSize.Level1)
{
    WifiLinkedInfo wifiLinkedInfo;
    wifiLinkedInfo.supplicantState = SupplicantState::AUTHENTICATING;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));
    pWifiProStateMachine_->RefreshConnectedNetWork();
    EXPECT_NE(pWifiProStateMachine_->wifiSwitchReason_, TEN);
}

HWTEST_F(WifiProStateMachineTest, RefreshConnectedNetWorkTest02, TestSize.Level1)
{
    WifiLinkedInfo wifiLinkedInfo;
    wifiLinkedInfo.supplicantState = SupplicantState::AUTHENTICATING;
    wifiLinkedInfo.networkId = 1;

    std::vector<WifiDeviceConfig> configs;
    WifiDeviceConfig wifiDeviceConfig;
    wifiDeviceConfig.networkId = 1;
    configs.push_back(wifiDeviceConfig);

    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(wifiLinkedInfo), Return(0)));
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(configs), Return(0)));

    pWifiProStateMachine_->RefreshConnectedNetWork();
    EXPECT_NE(pWifiProStateMachine_->wifiSwitchReason_, TEN);
}

HWTEST_F(WifiProStateMachineTest, DefaultStateExecuteStateMsgTest01, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_REMOVE_BLOCK_LIST);
    std::string test = "test";
    msg->SetMessageObj(test);
    EXPECT_EQ(defaultState_->ExecuteStateMsg(msg), true);
}

HWTEST_F(WifiProStateMachineTest, DefaultStateExecuteStateMsgTest02, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_WIFI_CONNECT_STATE_CHANGED);
    EXPECT_EQ(defaultState_->ExecuteStateMsg(msg), false);
}

HWTEST_F(WifiProStateMachineTest, DefaultStateHandleRemoveBlockListTest01, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    std::string bssid = "TEST";
    msg->SetMessageObj(bssid);
    defaultState_->HandleRemoveBlockList(msg);
    EXPECT_NE(defaultState_->pWifiProStateMachine_->wifiSwitchReason_, TEN);
}

HWTEST_F(WifiProStateMachineTest, DefaultStateHandleWifiProSwitchChangedTest01, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    defaultState_->HandleWifiProSwitchChanged(msg);
    EXPECT_EQ(defaultState_->pWifiProStateMachine_->isWifiProEnabled_, true);
}

HWTEST_F(WifiProStateMachineTest, WifiProEnableStateExecuteStateMsgTest01, TestSize.Level1)
{
    wifiProEnableState_->GoOutState();
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_WIFI_CONNECT_STATE_CHANGED);
    EXPECT_EQ(wifiProEnableState_->ExecuteStateMsg(msg), true);
}

HWTEST_F(WifiProStateMachineTest, WifiProEnableStateExecuteStateMsgTest02, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_NOTIFY_WIFI_PRO_SWITCH_CHANGED);
    EXPECT_EQ(wifiProEnableState_->ExecuteStateMsg(msg), false);
}

HWTEST_F(WifiProStateMachineTest, WifiProEnableStateTransitionNetStateTest01, TestSize.Level1)
{
    wifiProEnableState_->pWifiProStateMachine_ = new WifiProStateMachine();
    wifiProEnableState_->pWifiProStateMachine_->instId_ = 0;
    
    WifiLinkedInfo linkedInfo;
    linkedInfo.connState = ConnState::CONNECTED;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));

    wifiProEnableState_->TransitionNetState();
    EXPECT_NE(wifiProEnableState_->pWifiProStateMachine_, nullptr);
}

HWTEST_F(WifiProStateMachineTest, WifiProEnableStateHandleWifiConnectStateChangedInEnableTest01, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetParam1(17);
    wifiProEnableState_->HandleWifiConnectStateChangedInEnable(msg);

    msg->SetParam1(23);
    wifiProEnableState_->HandleWifiConnectStateChangedInEnable(msg);

    msg->SetParam1(0);
    wifiProEnableState_->HandleWifiConnectStateChangedInEnable(msg);
    EXPECT_NE(wifiProEnableState_->pWifiProStateMachine_->wifiSwitchReason_, TEN);
}

HWTEST_F(WifiProStateMachineTest, WifiProDisabledStateGoInStateTest01, TestSize.Level1)
{
    wifiProDisabledState_->GoInState();
    EXPECT_NE(wifiProDisabledState_->pWifiProStateMachine_->wifiSwitchReason_, TEN);
}

HWTEST_F(WifiProStateMachineTest, WifiProDisabledStateGoOutStateTest01, TestSize.Level1)
{
    wifiProDisabledState_->GoOutState();
    EXPECT_NE(wifiProDisabledState_->pWifiProStateMachine_->wifiSwitchReason_, TEN);
}

HWTEST_F(WifiProStateMachineTest, WifiProDisabledStateExecuteStateMsgTest01, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(0);
    msg->SetParam1(1);
    wifiProDisabledState_->pWifiProStateMachine_ = new WifiProStateMachine();
    EXPECT_EQ(wifiProDisabledState_->ExecuteStateMsg(msg), true);
}

HWTEST_F(WifiProStateMachineTest, WifiProDisabledStateExecuteStateMsgTest02, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(1);
    EXPECT_EQ(wifiProDisabledState_->ExecuteStateMsg(msg), false);
}

HWTEST_F(WifiProStateMachineTest, WifiConnectedStateGoInStateTest01, TestSize.Level1)
{
    wifiConnectedState_->GoInState();
    EXPECT_NE(wifiConnectedState_->pWifiProStateMachine_->wifiSwitchReason_, TEN);
}

HWTEST_F(WifiProStateMachineTest, WifiConnectedStateGoOutStateTest01, TestSize.Level1)
{
    wifiConnectedState_->GoOutState();
    EXPECT_NE(wifiConnectedState_->pWifiProStateMachine_->wifiSwitchReason_, TEN);
}

HWTEST_F(WifiProStateMachineTest, WifiConnectedStateExecuteStateMsgTest01, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_CHECK_WIFI_INTERNET_RESULT);
    msg->SetParam1(20);
    EXPECT_EQ(wifiConnectedState_->ExecuteStateMsg(msg), true);
}

HWTEST_F(WifiProStateMachineTest, WifiConnectedStateExecuteStateMsgTest02, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_CHECK_WIFI_INTERNET_RESULT);
    msg->SetParam1(18);
    EXPECT_EQ(wifiConnectedState_->ExecuteStateMsg(msg), true);
}

HWTEST_F(WifiProStateMachineTest, WifiConnectedStateExecuteStateMsgTest03, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_CHECK_WIFI_INTERNET_RESULT);
    msg->SetParam1(19);
    EXPECT_EQ(wifiConnectedState_->ExecuteStateMsg(msg), true);
}

HWTEST_F(WifiProStateMachineTest, WifiConnectedStateExecuteStateMsgTest04, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_WIFI_CONNECT_STATE_CHANGED);
    msg->SetParam1(23);
    EXPECT_EQ(wifiConnectedState_->ExecuteStateMsg(msg), true);
}

HWTEST_F(WifiProStateMachineTest, WifiConnectedStateExecuteStateMsgTest05, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_WIFI_CONNECT_STATE_CHANGED);
    msg->SetParam1(22);
    EXPECT_EQ(wifiConnectedState_->ExecuteStateMsg(msg), true);
}

HWTEST_F(WifiProStateMachineTest, WifiConnectedStateExecuteStateMsgTest06, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_DISCONNECT_DISCONNECTED);
    msg->SetParam1(23);
    EXPECT_EQ(wifiConnectedState_->ExecuteStateMsg(msg), false);
}

HWTEST_F(WifiProStateMachineTest, WifiConnectedStateInitConnectedStateTest01, TestSize.Level1)
{
    wifiConnectedState_->pWifiProStateMachine_->duanBandHandoverType_ = 1;
    wifiConnectedState_->InitConnectedState();

    wifiConnectedState_->pWifiProStateMachine_->duanBandHandoverType_ = 2;
    wifiConnectedState_->InitConnectedState();
    EXPECT_NE(wifiConnectedState_->pWifiProStateMachine_->wifiSwitchReason_, TEN);
}

HWTEST_F(WifiProStateMachineTest, WifiDisconnectedStateGoInStateTest01, TestSize.Level1)
{
    wifiDisconnectedState_->GoInState();
    EXPECT_NE(wifiDisconnectedState_->pWifiProStateMachine_->wifiSwitchReason_, TEN);
}

HWTEST_F(WifiProStateMachineTest, WifiDisconnectedStateGoOutStateTest01, TestSize.Level1)
{
    wifiDisconnectedState_->GoOutState();
    EXPECT_NE(wifiDisconnectedState_->pWifiProStateMachine_->wifiSwitchReason_, TEN);
}

HWTEST_F(WifiProStateMachineTest, WifiDisconnectedStateExecuteStateMsgTest01, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_WIFI_CONNECT_STATE_CHANGED);
    msg->SetParam1(17);
    EXPECT_EQ(wifiDisconnectedState_->ExecuteStateMsg(msg), true);
}

HWTEST_F(WifiProStateMachineTest, WifiDisconnectedStateExecuteStateMsgTest02, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_NOTIFY_WIFI_PRO_SWITCH_CHANGED);
    EXPECT_EQ(wifiDisconnectedState_->ExecuteStateMsg(msg), false);
}

HWTEST_F(WifiProStateMachineTest, WifiHasNetStateGoInStateTest01, TestSize.Level1)
{
    wifiHasNetState_->GoInState();
    EXPECT_NE(wifiHasNetState_->pWifiProStateMachine_->wifiSwitchReason_, TEN);
}

HWTEST_F(WifiProStateMachineTest, WifiHasNetStateGoOutStateTest01, TestSize.Level1)
{
    wifiHasNetState_->GoOutState();
    EXPECT_NE(wifiHasNetState_->pWifiProStateMachine_->wifiSwitchReason_, TEN);
}

HWTEST_F(WifiProStateMachineTest, WifiHasNetStateExecuteStateMsgTest01, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_WIFI_RSSI_CHANGED);
    wifiHasNetState_->isWifi2WifiSwitching_ = true;
    EXPECT_EQ(wifiHasNetState_->ExecuteStateMsg(msg), true);
}

HWTEST_F(WifiProStateMachineTest, WifiHasNetStateExecuteStateMsgTest02, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_WIFI_RSSI_CHANGED);
    wifiHasNetState_->isWifi2WifiSwitching_ = false;
    wifiHasNetState_->pWifiProStateMachine_ = new WifiProStateMachine();
    wifiHasNetState_->pWifiProStateMachine_->isWifiNoInternet_ = false;
    wifiHasNetState_->pWifiProStateMachine_->instId_ = 1;
    WifiLinkedInfo linkedInfo;
    linkedInfo.rssi = 1;
    linkedInfo.band = 1;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));

    EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _))
        .WillRepeatedly(Return(4));
    EXPECT_EQ(wifiHasNetState_->ExecuteStateMsg(msg), true);
}

HWTEST_F(WifiProStateMachineTest, WifiHasNetStateExecuteStateMsgTest03, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_WIFI_CONNECT_STATE_CHANGED);
    wifiHasNetState_->isWifi2WifiSwitching_ = true;
    msg->SetParam1(17);
    std::string bssid = "TEST";
    msg->SetMessageObj(bssid);
    wifiHasNetState_->targetBssid_ = "TEST1";
    wifiHasNetState_->isWifi2WifiSwitching_ = false;
    EXPECT_EQ(wifiHasNetState_->ExecuteStateMsg(msg), true);
}

HWTEST_F(WifiProStateMachineTest, WifiHasNetStateExecuteStateMsgTest04, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_WIFI_CONNECT_STATE_CHANGED);
    wifiHasNetState_->isWifi2WifiSwitching_ = true;
    msg->SetParam1(17);
    std::string bssid = "TEST";
    msg->SetMessageObj(bssid);
    wifiHasNetState_->targetBssid_ = "TEST";
    wifiHasNetState_->isWifi2WifiSwitching_ = false;
    EXPECT_EQ(wifiHasNetState_->ExecuteStateMsg(msg), true);
}

HWTEST_F(WifiProStateMachineTest, WifiHasNetStateExecuteStateMsgTest05, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_REQUEST_SCAN_DELAY);
    
    EXPECT_EQ(wifiHasNetState_->ExecuteStateMsg(msg), true);
}

HWTEST_F(WifiProStateMachineTest, WifiHasNetStateExecuteStateMsgTest06, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_HANDLE_SCAN_RESULT);
    std::vector<InterScanInfo> scanInfos;
    msg->SetMessageObj(scanInfos);
    wifiHasNetState_->isScanTriggered_ = true;
    EXPECT_EQ(wifiHasNetState_->ExecuteStateMsg(msg), true);
}

HWTEST_F(WifiProStateMachineTest, WifiHasNetStateExecuteStateMsgTest07, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_CHECK_WIFI_INTERNET_RESULT);
    msg->SetParam1(19);
    EXPECT_EQ(wifiHasNetState_->ExecuteStateMsg(msg), true);
}

HWTEST_F(WifiProStateMachineTest, WifiHasNetStateExecuteStateMsgTest08, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_WIFI2WIFI_FAILED);
    EXPECT_EQ(wifiHasNetState_->ExecuteStateMsg(msg), true);
}

HWTEST_F(WifiProStateMachineTest, WifiHasNetStateTryStartScanTest01, TestSize.Level1)
{
    bool hasSwitchRecord = true;
    int32_t signalLevel = 2;
    wifiHasNetState_->TryStartScan(hasSwitchRecord, signalLevel);
    EXPECT_NE(wifiHasNetState_->pWifiProStateMachine_->wifiSwitchReason_, TEN);
}

HWTEST_F(WifiProStateMachineTest, WifiHasNetStateTryStartScanTest02, TestSize.Level1)
{
    bool hasSwitchRecord = true;
    int32_t signalLevel = 1;
    wifiHasNetState_->rssiLevel0Or1ScanedCounter_ = 1;
    wifiHasNetState_->TryStartScan(hasSwitchRecord, signalLevel);
    EXPECT_NE(wifiHasNetState_->pWifiProStateMachine_->wifiSwitchReason_, TEN);
}

HWTEST_F(WifiProStateMachineTest, WifiHasNetStateHandleWifi2WifiFailedTest01, TestSize.Level1)
{
    wifiHasNetState_->HandleWifi2WifiFailed(true);
    EXPECT_EQ(wifiHasNetState_->isWifi2WifiSwitching_, false);
}

HWTEST_F(WifiProStateMachineTest, WifiHasNetStateHandleCheckResultInHasNetTest01, TestSize.Level1)
{
    NetworkSelectionResult networkSelectionResult;
    wifiHasNetState_->HandleCheckResultInHasNet(networkSelectionResult);
    EXPECT_EQ(wifiHasNetState_->isWifi2WifiSwitching_, false);
}

HWTEST_F(WifiProStateMachineTest, WifiHasNetStateTryWifiHandoverPreferentiallyTest01, TestSize.Level1)
{
    NetworkSelectionResult networkSelectionResult;
    wifiHasNetState_->TryWifiHandoverPreferentially(networkSelectionResult);
    EXPECT_EQ(wifiHasNetState_->isWifi2WifiSwitching_, false);
}

HWTEST_F(WifiProStateMachineTest, WifiHasNetStateTryWifiRoveOutTest01, TestSize.Level1)
{
    NetworkSelectionResult networkSelectionResult;
    wifiHasNetState_->TryWifiRoveOut(networkSelectionResult);
    EXPECT_EQ(wifiHasNetState_->isWifi2WifiSwitching_, false);
}

HWTEST_F(WifiProStateMachineTest, WifiHasNetStateHandleWifiRoveOutTest01, TestSize.Level1)
{
    NetworkSelectionResult networkSelectionResult;
    wifiHasNetState_->isDisableWifiAutoSwitch_ = true;
    wifiHasNetState_->HandleWifiRoveOut(networkSelectionResult);

    wifiHasNetState_->isDisableWifiAutoSwitch_ = false;
    wifiHasNetState_->HandleWifiRoveOut(networkSelectionResult);
    EXPECT_EQ(wifiHasNetState_->isWifi2WifiSwitching_, false);
}

HWTEST_F(WifiProStateMachineTest, WifiHasNetStateTryWifi2WifiTest01, TestSize.Level1)
{
    NetworkSelectionResult networkSelectionResult;
    wifiHasNetState_->pWifiProStateMachine_->isWifiNoInternet_ = false;
    wifiHasNetState_->TryWifi2Wifi(networkSelectionResult);

    wifiHasNetState_->pWifiProStateMachine_->isWifiNoInternet_ = true;
    wifiHasNetState_->TryWifi2Wifi(networkSelectionResult);
    EXPECT_EQ(wifiHasNetState_->isWifi2WifiSwitching_, false);
}

HWTEST_F(WifiProStateMachineTest, WifiHasNetStateWifi2WifiFailedTest01, TestSize.Level1)
{
    wifiHasNetState_->Wifi2WifiFailed();
    EXPECT_EQ(wifiHasNetState_->isWifi2WifiSwitching_, false);
}

HWTEST_F(WifiProStateMachineTest, WifiHasNetStateHandleWifiToWifiTest01, TestSize.Level1)
{
    int32_t switchReason = WIFI_SWITCH_REASON_POOR_RSSI;
    NetworkSelectionResult networkSelectionResult;
    EXPECT_EQ(wifiHasNetState_->HandleWifiToWifi(switchReason, networkSelectionResult), false);

    switchReason = WIFI_SWITCH_REASON_NO_INTERNET;
    wifiHasNetState_->HandleWifiToWifi(switchReason, networkSelectionResult);
}

HWTEST_F(WifiProStateMachineTest, WifiHasNetStateUpdateWifiSwitchTimeStampTest01, TestSize.Level1)
{
    WifiLinkedInfo linkedInfo;
    WifiDeviceConfig config;
    linkedInfo.networkId = 1;

    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));

    EXPECT_CALL(WifiSettings::GetInstance(), GetSignalLevel(_, _, _))
        .WillRepeatedly(Return(0));

    EXPECT_EQ(wifiHasNetState_->isWifi2WifiSwitching_, false);
}

HWTEST_F(WifiProStateMachineTest, WifiHasNetStateTrySwitchWifiNetworkTest01, TestSize.Level1)
{
    NetworkSelectionResult networkSelectionResult;
    EXPECT_EQ(wifiHasNetState_->TrySwitchWifiNetwork(networkSelectionResult), false);
}

HWTEST_F(WifiProStateMachineTest, WifiHasNetStateIsCallingInCsTest01, TestSize.Level1)
{
    EXPECT_EQ(wifiHasNetState_->IsCallingInCs(), false);
}

HWTEST_F(WifiProStateMachineTest, WifiHasNetStateIsFullscreenTest01, TestSize.Level1)
{
    EXPECT_EQ(wifiHasNetState_->IsFullscreen(), false);
}

HWTEST_F(WifiProStateMachineTest, WifiNoNetStateGoInStateTest01, TestSize.Level1)
{
    wifiNoNetState_->GoInState();
    wifiNoNetState_->GoOutState();
    EXPECT_EQ(wifiNoNetState_->pWifiProStateMachine_->isWifiNoInternet_, true);
}

HWTEST_F(WifiProStateMachineTest, WifiNoNetStateExecuteStateMsgTest01, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_CHECK_WIFI_INTERNET_RESULT);
    msg->SetParam1(19);
    EXPECT_EQ(wifiNoNetState_->ExecuteStateMsg(msg), true);
}

HWTEST_F(WifiProStateMachineTest, WifiNoNetStateExecuteStateMsgTest02, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_CHECK_WIFI_INTERNET_RESULT);
    msg->SetParam1(18);
    EXPECT_EQ(wifiNoNetState_->ExecuteStateMsg(msg), true);
}

HWTEST_F(WifiProStateMachineTest, WifiNoNetStateExecuteStateMsgTest03, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_WIFI2WIFI_FAILED);
    msg->SetParam1(19);
    EXPECT_EQ(wifiNoNetState_->ExecuteStateMsg(msg), false);
}

HWTEST_F(WifiProStateMachineTest, WifiPortalStateGoInStateTest01, TestSize.Level1)
{
    wifiPortalState_->GoInState();
    wifiPortalState_->GoOutState();
    EXPECT_EQ(wifiPortalState_->pWifiProStateMachine_->isWifiNoInternet_, false);
}

HWTEST_F(WifiProStateMachineTest, WifiPortalStateExecuteStateMsgTest01, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_CHECK_WIFI_INTERNET_RESULT);
    msg->SetParam1(19);
    EXPECT_EQ(wifiPortalState_->ExecuteStateMsg(msg), true);
}

HWTEST_F(WifiProStateMachineTest, WifiPortalStateExecuteStateMsgTest02, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_CHECK_WIFI_INTERNET_RESULT);
    msg->SetParam1(20);
    EXPECT_EQ(wifiPortalState_->ExecuteStateMsg(msg), true);
}

HWTEST_F(WifiProStateMachineTest, WifiPortalStateExecuteStateMsgTest03, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_WIFI2WIFI_FAILED);
    msg->SetParam1(19);
    EXPECT_EQ(wifiPortalState_->ExecuteStateMsg(msg), false);
}
} // namespace Wifi
} // namespace OHOS
