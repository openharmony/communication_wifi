/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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
#include <memory>
#include "wifi_intelligence_state_machine.h"
#include "wifi_pro_common.h"
#include "internal_message.h"
#include "mock_wifi_config_center.h"
#include "mock_wifi_settings.h"
#include "mock_wifi_scan_config.h"
#include "wifi_msg.h"
#include "wifi_internal_msg.h"
#include "wifi_manager.h"
#include "mock_state_machine.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::NotNull;
using ::testing::ext::TestSize;
using ::testing::Matcher;

namespace OHOS {
namespace Wifi {

class WifiIntelligenceStateMachineTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        testing::Mock::AllowLeak(&WifiConfigCenter::GetInstance());
        testing::Mock::AllowLeak(&WifiSettings::GetInstance());
    }
    static void TearDownTestCase()
    {
        testing::Mock::VerifyAndClearExpectations(&WifiConfigCenter::GetInstance());
        testing::Mock::VerifyAndClearExpectations(&WifiSettings::GetInstance());
    }

    virtual void SetUp()
    {
        wifiIntelligenceStateMachine_ = std::make_unique<WifiIntelligenceStateMachine>(0);
        wifiIntelligenceStateMachine_->InitWifiIntelligenceStates();
        wifiIntelligenceStateMachine_->BuildStateTree();

        defaultState_ = std::make_unique<WifiIntelligenceStateMachine::DefaultState>(
            wifiIntelligenceStateMachine_.get());
        initialState_ = std::make_unique<WifiIntelligenceStateMachine::InitialState>(
            wifiIntelligenceStateMachine_.get());
        enabledState_ = std::make_unique<WifiIntelligenceStateMachine::EnabledState>(
            wifiIntelligenceStateMachine_.get());
        disabledState_ = std::make_unique<WifiIntelligenceStateMachine::DisabledState>(
            wifiIntelligenceStateMachine_.get());
        stopState_ = std::make_unique<WifiIntelligenceStateMachine::StopState>(
            wifiIntelligenceStateMachine_.get());
        disconnectedState_ = std::make_unique<WifiIntelligenceStateMachine::DisconnectedState>(
            wifiIntelligenceStateMachine_.get());
        connectedState_ = std::make_unique<WifiIntelligenceStateMachine::ConnectedState>(
            wifiIntelligenceStateMachine_.get());
        internetReadyState_ = std::make_unique<WifiIntelligenceStateMachine::InternetReadyState>(
            wifiIntelligenceStateMachine_.get());
        noInternetState_ = std::make_unique<WifiIntelligenceStateMachine::NoInternetState>(
            wifiIntelligenceStateMachine_.get());

        testing::Mock::VerifyAndClearExpectations(&WifiConfigCenter::GetInstance());
        testing::Mock::VerifyAndClearExpectations(&WifiSettings::GetInstance());
    }

    virtual void TearDown()
    {
        if (wifiIntelligenceStateMachine_) {
            wifiIntelligenceStateMachine_->StopHandlerThread();
            wifiIntelligenceStateMachine_->StopTimer(EVENT_SCAN_AGAIN);
            wifiIntelligenceStateMachine_->StopTimer(EVENT_UPDATE_TARGET_SSID);
            wifiIntelligenceStateMachine_->StopTimer(EVENT_WIFI_HANLE_OPEN);
            wifiIntelligenceStateMachine_->StopTimer(EVENT_WIFI_HANLE_OPEN_WAIT_SUC);
            wifiIntelligenceStateMachine_->StopTimer(EVENT_HANDLE_STATE_CHANGE);
        }

        defaultState_.reset();
        initialState_.reset();
        enabledState_.reset();
        disabledState_.reset();
        stopState_.reset();
        disconnectedState_.reset();
        connectedState_.reset();
        internetReadyState_.reset();
        noInternetState_.reset();

        wifiIntelligenceStateMachine_.reset();

        testing::Mock::VerifyAndClearExpectations(&WifiConfigCenter::GetInstance());
        testing::Mock::VerifyAndClearExpectations(&WifiSettings::GetInstance());
    }

public:
    std::unique_ptr<WifiIntelligenceStateMachine> wifiIntelligenceStateMachine_;
    std::unique_ptr<WifiIntelligenceStateMachine::DefaultState> defaultState_;
    std::unique_ptr<WifiIntelligenceStateMachine::InitialState> initialState_;
    std::unique_ptr<WifiIntelligenceStateMachine::EnabledState> enabledState_;
    std::unique_ptr<WifiIntelligenceStateMachine::DisabledState> disabledState_;
    std::unique_ptr<WifiIntelligenceStateMachine::StopState> stopState_;
    std::unique_ptr<WifiIntelligenceStateMachine::DisconnectedState> disconnectedState_;
    std::unique_ptr<WifiIntelligenceStateMachine::ConnectedState> connectedState_;
    std::unique_ptr<WifiIntelligenceStateMachine::InternetReadyState> internetReadyState_;
    std::unique_ptr<WifiIntelligenceStateMachine::NoInternetState> noInternetState_;
};

HWTEST_F(WifiIntelligenceStateMachineTest, InitWifiIntelligenceStatesTest, TestSize.Level1)
{
    EXPECT_EQ(wifiIntelligenceStateMachine_->InitWifiIntelligenceStates(), WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiIntelligenceStateMachineTest, InitializeTest, TestSize.Level1)
{
    EXPECT_EQ(wifiIntelligenceStateMachine_->Initialize(), WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiIntelligenceStateMachineTest, ExecuteStateMsgTest_NullMsg, TestSize.Level1)
{
    InternalMessagePtr msg = nullptr;
    bool result = defaultState_->ExecuteStateMsg(msg);
    EXPECT_FALSE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, DefaultState_ExecuteStateMsg_WifiEnabled, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_WIFI_ENABLED);
    bool result = defaultState_->ExecuteStateMsg(msg);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, DefaultState_ExecuteStateMsg_WifiDisabled_CloseWifi, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_WIFI_DISABLED);
    msg->SetParam1(static_cast<int32_t>(OperateResState::CLOSE_WIFI_SUCCEED));
    bool result = defaultState_->ExecuteStateMsg(msg);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, DefaultState_ExecuteStateMsg_WifiDisabled_SemiWifi, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_WIFI_DISABLED);
    msg->SetParam1(static_cast<int32_t>(OperateResState::ENABLE_SEMI_WIFI_SUCCEED));
    bool result = defaultState_->ExecuteStateMsg(msg);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, DefaultState_ExecuteStateMsg_ConnectStateChanged_Connected, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_WIFI_CONNECT_STATE_CHANGED);
    msg->SetParam1(static_cast<int32_t>(OperateResState::CONNECT_AP_CONNECTED));
    bool result = defaultState_->ExecuteStateMsg(msg);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, DefaultState_ExecuteStateMsg_ConnectStateChanged_Disconnected, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_WIFI_CONNECT_STATE_CHANGED);
    msg->SetParam1(static_cast<int32_t>(OperateResState::DISCONNECT_DISCONNECTED));
    bool result = defaultState_->ExecuteStateMsg(msg);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, DefaultState_ExecuteStateMsg_ScreenOn, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_SCREEN_ON);
    bool result = defaultState_->ExecuteStateMsg(msg);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, DefaultState_ExecuteStateMsg_ScreenOff, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_SCREEN_OFF);
    bool result = defaultState_->ExecuteStateMsg(msg);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, DefaultState_ExecuteStateMsg_ScanAgain, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_SCAN_AGAIN);
    bool result = defaultState_->ExecuteStateMsg(msg);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, DefaultState_ExecuteStateMsg_ConfigurationChanged_RemoveAll, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_CONFIGURATION_CHANGED);
    msg->SetParam1(static_cast<int32_t>(ConfigChange::CONFIG_REMOVE));
    msg->SetParam2(1);
    WifiDeviceConfig config;
    msg->SetMessageObj(config);
    bool result = defaultState_->ExecuteStateMsg(msg);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, DefaultState_ExecuteStateMsg_ConfigurationChanged_RemoveBySsid, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_CONFIGURATION_CHANGED);
    msg->SetParam1(static_cast<int32_t>(ConfigChange::CONFIG_REMOVE));
    msg->SetParam2(0);
    WifiDeviceConfig config;
    config.ssid = "TestSSID";
    config.keyMgmt = "WPA";
    config.bssid = "00:00:00:00:00:00";
    msg->SetMessageObj(config);
    bool result = defaultState_->ExecuteStateMsg(msg);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, DefaultState_ExecuteStateMsg_ConfigurationChanged_RemoveByBssid, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_CONFIGURATION_CHANGED);
    msg->SetParam1(static_cast<int32_t>(ConfigChange::CONFIG_REMOVE));
    msg->SetParam2(0);
    WifiDeviceConfig config;
    config.ssid = "";
    config.keyMgmt = "WPA";
    config.bssid = "00:00:00:00:00:00";
    msg->SetMessageObj(config);
    bool result = defaultState_->ExecuteStateMsg(msg);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, DefaultState_GoInState, TestSize.Level1)
{
    defaultState_->GoInState();
}

HWTEST_F(WifiIntelligenceStateMachineTest, DefaultState_GoOutState, TestSize.Level1)
{
    defaultState_->GoOutState();
}

HWTEST_F(WifiIntelligenceStateMachineTest, InitialState_GoInState_NotRunning, TestSize.Level1)
{
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiMidState(_))
        .WillRepeatedly(Return(WifiOprMidState::CLOSED));
    initialState_->GoInState();
}

HWTEST_F(WifiIntelligenceStateMachineTest, InitialState_GoInState_Running, TestSize.Level1)
{
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiMidState(_))
        .WillRepeatedly(Return(WifiOprMidState::RUNNING));
    initialState_->GoInState();
}

HWTEST_F(WifiIntelligenceStateMachineTest, InitialState_ExecuteStateMsg_NullMsg, TestSize.Level1)
{
    InternalMessagePtr msg = nullptr;
    bool result = initialState_->ExecuteStateMsg(msg);
    EXPECT_FALSE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, InitialState_ExecuteStateMsg_AnyMsg, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_WIFI_ENABLED);
    bool result = initialState_->ExecuteStateMsg(msg);
    EXPECT_FALSE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, InitialState_GoOutState, TestSize.Level1)
{
    initialState_->GoOutState();
}

HWTEST_F(WifiIntelligenceStateMachineTest, EnabledState_GoInState, TestSize.Level1)
{
    enabledState_->GoInState();
}

HWTEST_F(WifiIntelligenceStateMachineTest, EnabledState_GoOutState, TestSize.Level1)
{
    enabledState_->GoOutState();
}

HWTEST_F(WifiIntelligenceStateMachineTest, EnabledState_ExecuteStateMsg_NullMsg, TestSize.Level1)
{
    InternalMessagePtr msg = nullptr;
    bool result = enabledState_->ExecuteStateMsg(msg);
    EXPECT_FALSE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, EnabledState_ExecuteStateMsg_WifiEnabled, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_WIFI_ENABLED);
    bool result = enabledState_->ExecuteStateMsg(msg);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, EnabledState_ExecuteStateMsg_OtherMsg, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_WIFI_DISABLED);
    bool result = enabledState_->ExecuteStateMsg(msg);
    EXPECT_FALSE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, DisabledState_GoInState, TestSize.Level1)
{
    disabledState_->GoInState();
}

HWTEST_F(WifiIntelligenceStateMachineTest, DisabledState_GoOutState, TestSize.Level1)
{
    disabledState_->GoOutState();
}

HWTEST_F(WifiIntelligenceStateMachineTest, DisabledState_ExecuteStateMsg_NullMsg, TestSize.Level1)
{
    InternalMessagePtr msg = nullptr;
    bool result = disabledState_->ExecuteStateMsg(msg);
    EXPECT_FALSE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, DisabledState_ExecuteStateMsg_WifiDisabled, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_WIFI_DISABLED);
    bool result = disabledState_->ExecuteStateMsg(msg);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, DisabledState_ExecuteStateMsg_ConnectStateChanged_Disconnected, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_WIFI_CONNECT_STATE_CHANGED);
    msg->SetParam1(static_cast<int32_t>(OperateResState::DISCONNECT_DISCONNECTED));
    bool result = disabledState_->ExecuteStateMsg(msg);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, DisabledState_FilterFromBlackList_AllValid, TestSize.Level1)
{
    std::vector<ApInfoData> datas;
    ApInfoData data1 = {.bssid = "00:00:00:00:00:01", .ssid = "Test1", .inBlacklist = 0};
    ApInfoData data2 = {.bssid = "00:00:00:00:00:02", .ssid = "Test2", .inBlacklist = 0};
    datas.push_back(data1);
    datas.push_back(data2);
    auto results = disabledState_->FilterFromBlackList(datas);
    EXPECT_EQ(results.size(), 2);
}

HWTEST_F(WifiIntelligenceStateMachineTest, DisabledState_FilterFromBlackList_WithBlacklist, TestSize.Level1)
{
    std::vector<ApInfoData> datas;
    ApInfoData data1 = {.bssid = "00:00:00:00:00:01", .ssid = "Test1", .inBlacklist = 0};
    ApInfoData data2 = {.bssid = "00:00:00:00:00:02", .ssid = "Test2", .inBlacklist = 1};
    datas.push_back(data1);
    datas.push_back(data2);
    auto results = disabledState_->FilterFromBlackList(datas);
    EXPECT_EQ(results.size(), 1);
}

HWTEST_F(WifiIntelligenceStateMachineTest, StopState_GoOutState, TestSize.Level1)
{
    stopState_->GoOutState();
}

HWTEST_F(WifiIntelligenceStateMachineTest, StopState_ExecuteStateMsg_NullMsg, TestSize.Level1)
{
    InternalMessagePtr msg = nullptr;
    bool result = stopState_->ExecuteStateMsg(msg);
    EXPECT_FALSE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, StopState_ExecuteStateMsg_WifiDisabled_SemiWifi, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_WIFI_DISABLED);
    msg->SetParam1(static_cast<int32_t>(OperateResState::ENABLE_SEMI_WIFI_SUCCEED));
    bool result = stopState_->ExecuteStateMsg(msg);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, StopState_ExecuteStateMsg_WifiDisabled_CloseWifi, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_WIFI_DISABLED);
    msg->SetParam1(static_cast<int32_t>(OperateResState::CLOSE_WIFI_SUCCEED));
    bool result = stopState_->ExecuteStateMsg(msg);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, StopState_ExecuteStateMsg_ConnectStateChanged, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_WIFI_CONNECT_STATE_CHANGED);
    bool result = stopState_->ExecuteStateMsg(msg);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, DisconnectedState_ExecuteStateMsg_NullMsg, TestSize.Level1)
{
    InternalMessagePtr msg = nullptr;
    bool result = disconnectedState_->ExecuteStateMsg(msg);
    EXPECT_FALSE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, DisconnectedState_ExecuteStateMsg_UpdateTargetSsid, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_UPDATE_TARGET_SSID);
    bool result = disconnectedState_->ExecuteStateMsg(msg);
    EXPECT_TRUE(result);
    EXPECT_EQ(wifiIntelligenceStateMachine_->mTargetSsid_, "");
}

HWTEST_F(WifiIntelligenceStateMachineTest, ConnectedState_GoInState, TestSize.Level1)
{
    WifiLinkedInfo linkedInfo;
    linkedInfo.networkId = 1;
    linkedInfo.bssid = "00:00:00:00:00:00";

    WifiDeviceConfig config;
    config.ssid = "TestSSID";
    config.keyMgmt = "WPA";

    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(config), Return(0)));

    wifiIntelligenceStateMachine_->mIsAutoOpenSearch_ = true;
    connectedState_->GoInState();
    EXPECT_EQ(wifiIntelligenceStateMachine_->mTargetSsid_, "TestSSID");
}

HWTEST_F(WifiIntelligenceStateMachineTest, ConnectedState_GoInState_NotAutoOpen, TestSize.Level1)
{
    WifiLinkedInfo linkedInfo;
    linkedInfo.networkId = 1;
    linkedInfo.bssid = "00:00:00:00:00:00";

    WifiDeviceConfig config;
    config.ssid = "TestSSID";
    config.keyMgmt = "WPA";

    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(config), Return(0)));

    wifiIntelligenceStateMachine_->mIsAutoOpenSearch_ = false;
    connectedState_->GoInState();
}

HWTEST_F(WifiIntelligenceStateMachineTest, ConnectedState_GoOutState, TestSize.Level1)
{
    connectedState_->GoOutState();
}

HWTEST_F(WifiIntelligenceStateMachineTest, ConnectedState_ExecuteStateMsg_NullMsg, TestSize.Level1)
{
    InternalMessagePtr msg = nullptr;
    bool result = connectedState_->ExecuteStateMsg(msg);
    EXPECT_FALSE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, ConnectedState_ExecuteStateMsg_CheckInternetResult, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_CHECK_WIFI_INTERNET_RESULT);
    msg->SetParam1(static_cast<int32_t>(OperateResState::CONNECT_NETWORK_ENABLED));
    WifiLinkedInfo linkedInfo;
    linkedInfo.networkId = 1;
    linkedInfo.bssid = "00:00:00:00:00:00";
    WifiDeviceConfig config;
    config.ssid = "TestSSID";
    config.keyMgmt = "WPA";
    config.isPortal = false;

    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(config), Return(0)));

    bool result = connectedState_->ExecuteStateMsg(msg);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, ConnectedState_HandleWifiInternetChangeRes_GetConfigFailed, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetParam1(static_cast<int32_t>(OperateResState::CONNECT_NETWORK_ENABLED));
    WifiLinkedInfo linkedInfo;
    linkedInfo.networkId = 1;

    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
        .WillRepeatedly(Return(-1));

    connectedState_->HandleWifiInternetChangeRes(msg);
}

HWTEST_F(WifiIntelligenceStateMachineTest, ConnectedState_HandleWifiInternetChangeRes_NetworkDisabled, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetParam1(static_cast<int32_t>(OperateResState::CONNECT_NETWORK_DISABLED));
    WifiLinkedInfo linkedInfo;
    linkedInfo.networkId = 1;
    WifiDeviceConfig config;
    config.ssid = "TestSSID";
    config.keyMgmt = "WPA";

    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(config), Return(0)));

    connectedState_->HandleWifiInternetChangeRes(msg);
}

HWTEST_F(WifiIntelligenceStateMachineTest, ConnectedState_HandleWifiInternetChangeRes_CheckPortal, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetParam1(static_cast<int32_t>(OperateResState::CONNECT_CHECK_PORTAL));
    WifiLinkedInfo linkedInfo;
    linkedInfo.networkId = 1;
    WifiDeviceConfig config;
    config.ssid = "TestSSID";
    config.keyMgmt = "WPA";

    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(config), Return(0)));

    connectedState_->HandleWifiInternetChangeRes(msg);
}

HWTEST_F(WifiIntelligenceStateMachineTest, ConnectedState_HandleWifiInternetChangeRes_NetworkEnabled_IsPortal, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetParam1(static_cast<int32_t>(OperateResState::CONNECT_NETWORK_ENABLED));
    WifiLinkedInfo linkedInfo;
    linkedInfo.networkId = 1;
    WifiDeviceConfig config;
    config.ssid = "TestSSID";
    config.keyMgmt = "WPA";
    config.isPortal = true;

    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(config), Return(0)));

    connectedState_->HandleWifiInternetChangeRes(msg);
}

HWTEST_F(WifiIntelligenceStateMachineTest, ConnectedState_HandleWifiInternetChangeRes_NetworkEnabled_NotPortal, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetParam1(static_cast<int32_t>(OperateResState::CONNECT_NETWORK_ENABLED));
    WifiLinkedInfo linkedInfo;
    linkedInfo.networkId = 1;
    WifiDeviceConfig config;
    config.ssid = "TestSSID";
    config.keyMgmt = "WPA";
    config.isPortal = false;

    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));
    EXPECT_CALL(WifiSettings::GetInstance(), GetDeviceConfig(_, _, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(config), Return(0)));

    connectedState_->HandleWifiInternetChangeRes(msg);
}

HWTEST_F(WifiIntelligenceStateMachineTest, InternetReadyState_GoInState_ValidBssid, TestSize.Level1)
{
    WifiLinkedInfo linkedInfo;
    linkedInfo.networkId = 1;
    linkedInfo.bssid = "00:00:00:00:00:00";
    linkedInfo.isDataRestricted = false;

    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));

    internetReadyState_->GoInState();
}

HWTEST_F(WifiIntelligenceStateMachineTest, InternetReadyState_GoInState_MobileAp, TestSize.Level1)
{
    WifiLinkedInfo linkedInfo;
    linkedInfo.networkId = 1;
    linkedInfo.bssid = "00:00:00:00:00:00";
    linkedInfo.isDataRestricted = true;

    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));

    internetReadyState_->GoInState();
}

HWTEST_F(WifiIntelligenceStateMachineTest, InternetReadyState_GoInState_EmptyBssid, TestSize.Level1)
{
    WifiLinkedInfo linkedInfo;
    linkedInfo.networkId = 1;
    linkedInfo.bssid = "";
    linkedInfo.isDataRestricted = false;

    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));

    internetReadyState_->GoInState();
}

HWTEST_F(WifiIntelligenceStateMachineTest, InternetReadyState_GoOutState, TestSize.Level1)
{
    internetReadyState_->GoOutState();
}

HWTEST_F(WifiIntelligenceStateMachineTest, InternetReadyState_ExecuteStateMsg_NullMsg, TestSize.Level1)
{
    InternalMessagePtr msg = nullptr;
    bool result = internetReadyState_->ExecuteStateMsg(msg);
    EXPECT_FALSE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, InternetReadyState_ExecuteStateMsg_CellStateChange, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_CELL_STATE_CHANGE);
    WifiLinkedInfo linkedInfo;
    linkedInfo.networkId = 1;
    linkedInfo.bssid = "00:00:00:00:00:00";
    linkedInfo.isDataRestricted = false;

    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));

    bool result = internetReadyState_->ExecuteStateMsg(msg);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, InternetReadyState_ExecuteStateMsg_ScreenOn, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_SCREEN_ON);
    WifiLinkedInfo linkedInfo;
    linkedInfo.networkId = 1;
    linkedInfo.bssid = "00:00:00:00:00:00";
    linkedInfo.isDataRestricted = false;

    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));

    bool result = internetReadyState_->ExecuteStateMsg(msg);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, InternetReadyState_ExecuteStateMsg_CheckInternetResult, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_CHECK_WIFI_INTERNET_RESULT);
    msg->SetParam1(static_cast<int32_t>(OperateResState::CONNECT_NETWORK_ENABLED));
    bool result = internetReadyState_->ExecuteStateMsg(msg);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, InternetReadyState_ExecuteStateMsg_OpenWaitSuc, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_WIFI_HANLE_OPEN_WAIT_SUC);
    bool result = internetReadyState_->ExecuteStateMsg(msg);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, InternetReadyState_ExecuteStateMsg_OtherMsg, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_WIFI_DISABLED);
    bool result = internetReadyState_->ExecuteStateMsg(msg);
    EXPECT_FALSE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, NoInternetState_GoInState_ValidBssid, TestSize.Level1)
{
    WifiLinkedInfo linkedInfo;
    linkedInfo.networkId = 1;
    linkedInfo.bssid = "00:00:00:00:00:00";

    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));

    noInternetState_->GoInState();
}

HWTEST_F(WifiIntelligenceStateMachineTest, NoInternetState_GoInState_EmptyBssid, TestSize.Level1)
{
    WifiLinkedInfo linkedInfo;
    linkedInfo.networkId = 1;
    linkedInfo.bssid = "";

    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));

    noInternetState_->GoInState();
}

HWTEST_F(WifiIntelligenceStateMachineTest, NoInternetState_GoOutState, TestSize.Level1)
{
    noInternetState_->GoOutState();
}

HWTEST_F(WifiIntelligenceStateMachineTest, NoInternetState_ExecuteStateMsg_NullMsg, TestSize.Level1)
{
    InternalMessagePtr msg = nullptr;
    bool result = noInternetState_->ExecuteStateMsg(msg);
    EXPECT_FALSE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, NoInternetState_ExecuteStateMsg_AnyMsg, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_WIFI_ENABLED);
    bool result = noInternetState_->ExecuteStateMsg(msg);
    EXPECT_FALSE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, IsInTargetAp_EmptyList, TestSize.Level1)
{
    wifiIntelligenceStateMachine_->mTargetApInfoDatas_.clear();
    bool result = wifiIntelligenceStateMachine_->IsInTargetAp("00:00:00:00:00:00", "TestSSID");
    EXPECT_FALSE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, IsInTargetAp_Found, TestSize.Level1)
{
    ApInfoData data = {.bssid = "00:00:00:00:00:00", .ssid = "TestSSID", .inBlacklist = 0};
    wifiIntelligenceStateMachine_->mTargetApInfoDatas_.push_back(data);
    bool result = wifiIntelligenceStateMachine_->IsInTargetAp("00:00:00:00:00:00", "TestSSID");
    EXPECT_TRUE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, IsInTargetAp_NotFound, TestSize.Level1)
{
    ApInfoData data = {.bssid = "00:00:00:00:00:01", .ssid = "OtherSSID", .inBlacklist = 0};
    wifiIntelligenceStateMachine_->mTargetApInfoDatas_.push_back(data);
    bool result = wifiIntelligenceStateMachine_->IsInTargetAp("00:00:00:00:00:00", "TestSSID");
    EXPECT_FALSE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, IsInBlacklist_NotFound, TestSize.Level1)
{
    bool result = wifiIntelligenceStateMachine_->IsInBlacklist("00:00:00:00:00:00");
    EXPECT_FALSE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, IsInMonitorNearbyAp_EmptyList, TestSize.Level1)
{
    wifiIntelligenceStateMachine_->mTargetApInfoDatas_.clear();
    std::vector<WifiScanInfo> scanInfoList;
    WifiScanInfo scanInfo;
    scanInfo.bssid = "00:00:00:00:00:00";
    scanInfo.ssid = "TestSSID";
    scanInfoList.push_back(scanInfo);
    bool result = wifiIntelligenceStateMachine_->IsInMonitorNearbyAp(scanInfoList);
    EXPECT_FALSE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, IsInMonitorNearbyAp_Found, TestSize.Level1)
{
    ApInfoData data = {.bssid = "00:00:00:00:00:01", .ssid = "TestSSID", .inBlacklist = 0};
    data.nearbyApInfos.push_back("00:00:00:00:00:00");
    wifiIntelligenceStateMachine_->mTargetApInfoDatas_.push_back(data);
    std::vector<WifiScanInfo> scanInfoList;
    WifiScanInfo scanInfo;
    scanInfo.bssid = "00:00:00:00:00:00";
    scanInfo.ssid = "TestSSID";
    scanInfoList.push_back(scanInfo);
    bool result = wifiIntelligenceStateMachine_->IsInMonitorNearbyAp(scanInfoList);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, IsInMonitorNearbyAp_NotFound, TestSize.Level1)
{
    ApInfoData data = {.bssid = "00:00:00:00:00:01", .ssid = "TestSSID", .inBlacklist = 0};
    data.nearbyApInfos.push_back("00:00:00:00:00:02");
    wifiIntelligenceStateMachine_->mTargetApInfoDatas_.push_back(data);
    std::vector<WifiScanInfo> scanInfoList;
    WifiScanInfo scanInfo;
    scanInfo.bssid = "00:00:00:00:00:00";
    scanInfo.ssid = "TestSSID";
    scanInfoList.push_back(scanInfo);
    bool result = wifiIntelligenceStateMachine_->IsInMonitorNearbyAp(scanInfoList);
    EXPECT_FALSE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, StopScanAp, TestSize.Level1)
{
    wifiIntelligenceStateMachine_->mIsScanning_ = true;
    wifiIntelligenceStateMachine_->mScanTimes_ = 5;
    wifiIntelligenceStateMachine_->mScanType_ = 2;
    wifiIntelligenceStateMachine_->StopScanAp();
    EXPECT_FALSE(wifiIntelligenceStateMachine_->mIsScanning_);
    EXPECT_EQ(wifiIntelligenceStateMachine_->mScanTimes_, 0);
    EXPECT_EQ(wifiIntelligenceStateMachine_->mScanType_, 1);
}

HWTEST_F(WifiIntelligenceStateMachineTest, InitPunishParameter, TestSize.Level1)
{
    wifiIntelligenceStateMachine_->mLastCellChangeScanTime_ = 100;
    wifiIntelligenceStateMachine_->mLastScanPingpongTime_ = 200;
    wifiIntelligenceStateMachine_->mScanPingpongNum_ = 5;
    wifiIntelligenceStateMachine_->InitPunishParameter();
    EXPECT_EQ(wifiIntelligenceStateMachine_->mLastCellChangeScanTime_, 0);
    EXPECT_EQ(wifiIntelligenceStateMachine_->mLastScanPingpongTime_, 0);
    EXPECT_EQ(wifiIntelligenceStateMachine_->mScanPingpongNum_, 1);
}

HWTEST_F(WifiIntelligenceStateMachineTest, HandleWifiDisabledTest00, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetParam1(static_cast<int32_t>(OperateResState::CONNECT_AP_CONNECTED));
    defaultState_->HandleWifiDisabled(msg);
    int state = static_cast<int>(OperateResState::CONNECT_AP_CONNECTED);
    EXPECT_EQ(msg->GetParam1(), state);
}

HWTEST_F(WifiIntelligenceStateMachineTest, HandleWifiDisabledTest01, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetParam1(static_cast<int>(OperateResState::ENABLE_SEMI_WIFI_SUCCEED));
    defaultState_->HandleWifiDisabled(msg);
    int state = static_cast<int>(OperateResState::ENABLE_SEMI_WIFI_SUCCEED);
    EXPECT_EQ(msg->GetParam1(), state);
}

HWTEST_F(WifiIntelligenceStateMachineTest, ProcessScanResult_EmptyList, TestSize.Level1)
{
    std::vector<WifiScanInfo> scanInfoList;
    std::string cellId = "testCellId";
    bool result = wifiIntelligenceStateMachine_->ProcessScanResult(scanInfoList, cellId);
    EXPECT_FALSE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, ProcessScanResult_NonEmptyList, TestSize.Level1)
{
    std::vector<WifiScanInfo> scanInfoList;
    WifiScanInfo scanInfo;
    scanInfo.bssid = "00:00:00:00:00:00";
    scanInfo.ssid = "TestSSID";
    scanInfoList.push_back(scanInfo);
    std::string cellId = "testCellId";
    bool result = wifiIntelligenceStateMachine_->ProcessScanResult(scanInfoList, cellId);
}

HWTEST_F(WifiIntelligenceStateMachineTest, IsHasTargetAp_Found, TestSize.Level1)
{
    ApInfoData data = {.bssid = "00:00:00:00:00:00", .ssid = "TestSSID", .inBlacklist = 0};
    wifiIntelligenceStateMachine_->mTargetApInfoDatas_.push_back(data);
    std::vector<WifiScanInfo> scanInfoList;
    WifiScanInfo scanInfo;
    scanInfo.bssid = "00:00:00:00:00:00";
    scanInfo.ssid = "TestSSID";
    scanInfoList.push_back(scanInfo);
    bool result = wifiIntelligenceStateMachine_->IsHasTargetAp(scanInfoList);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, IsHasTargetAp_NotFound, TestSize.Level1)
{
    wifiIntelligenceStateMachine_->mTargetApInfoDatas_.clear();
    std::vector<WifiScanInfo> scanInfoList;
    WifiScanInfo scanInfo;
    scanInfo.bssid = "00:00:00:00:00:00";
    scanInfo.ssid = "TestSSID";
    scanInfoList.push_back(scanInfo);
    bool result = wifiIntelligenceStateMachine_->IsHasTargetAp(scanInfoList);
    EXPECT_FALSE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, IsHasTargetAp_InBlacklist, TestSize.Level1)
{
    ApInfoData data = {.bssid = "00:00:00:00:00:00", .ssid = "TestSSID", .inBlacklist = 1};
    wifiIntelligenceStateMachine_->mTargetApInfoDatas_.push_back(data);
    std::vector<WifiScanInfo> scanInfoList;
    WifiScanInfo scanInfo;
    scanInfo.bssid = "00:00:00:00:00:00";
    scanInfo.ssid = "TestSSID";
    scanInfoList.push_back(scanInfo);
    bool result = wifiIntelligenceStateMachine_->IsHasTargetAp(scanInfoList);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, HandleScanResult_EmptyList, TestSize.Level1)
{
    std::vector<WifiScanInfo> scanInfoList;
    bool result = wifiIntelligenceStateMachine_->HandleScanResult(scanInfoList);
    EXPECT_FALSE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, DisabledState_HandleMsgStateChange_EmptyCellId, TestSize.Level1)
{
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScreenState())
        .WillRepeatedly(Return(MODE_STATE_OPEN));
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_CELL_STATE_CHANGE);
    disabledState_->HandleMsgStateChange(msg);
}

HWTEST_F(WifiIntelligenceStateMachineTest, DisabledState_HandleWifiOpen_SatelliteStart, TestSize.Level1)
{
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiDetailState(_))
        .WillRepeatedly(Return(WifiDetailState::STATE_SEMI_ACTIVE));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScreenState())
        .WillRepeatedly(Return(MODE_STATE_OPEN));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetApMidState(_))
        .WillRepeatedly(Return(WifiOprMidState::CLOSED));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), IsScreenLandscape())
        .WillRepeatedly(Return(false));

    auto msg = std::make_shared<InternalMessage>();
    disabledState_->HandleWifiOpen(msg);
}

HWTEST_F(WifiIntelligenceStateMachineTest, DisabledState_ExecuteStateMsg_ConfigurationChanged_Landscape, TestSize.Level1)
{
    EXPECT_CALL(WifiConfigCenter::GetInstance(), IsScreenLandscape())
        .WillRepeatedly(Return(true));
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_CONFIGURATION_CHANGED);
    msg->SetParam1(static_cast<int32_t>(ConfigChange::CONFIG_REMOVE));
    msg->SetParam2(1);
    WifiDeviceConfig config;
    msg->SetMessageObj(config);
    bool result = disabledState_->ExecuteStateMsg(msg);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, DisabledState_ExecuteStateMsg_CellStateChange, TestSize.Level1)
{
    EXPECT_CALL(WifiConfigCenter::GetInstance(), IsScreenLandscape())
        .WillRepeatedly(Return(false));
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_CELL_STATE_CHANGE);
    bool result = disabledState_->ExecuteStateMsg(msg);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, DisabledState_ExecuteStateMsg_HandleStateChange, TestSize.Level1)
{
    EXPECT_CALL(WifiConfigCenter::GetInstance(), IsScreenLandscape())
        .WillRepeatedly(Return(false));
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_HANDLE_STATE_CHANGE);
    bool result = disabledState_->ExecuteStateMsg(msg);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, DisabledState_ExecuteStateMsg_WifiFindTarget, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_WIFI_FIND_TARGET);
    bool result = disabledState_->ExecuteStateMsg(msg);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, DisabledState_ExecuteStateMsg_HandleScanResult_Scanning, TestSize.Level1)
{
    if (WifiConfigCenter::GetInstance().GetWifiScanConfig() == nullptr) {
        GTEST_SKIP() << "Skipped: GetWifiScanConfig() returns nullptr";
    }
    wifiIntelligenceStateMachine_->mIsScanning_ = true;
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_HANDLE_SCAN_RESULT);
    bool result = disabledState_->ExecuteStateMsg(msg);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, DisabledState_ExecuteStateMsg_HandleScanResult_NotScanning, TestSize.Level1)
{
    if (WifiConfigCenter::GetInstance().GetWifiScanConfig() == nullptr) {
        GTEST_SKIP() << "Skipped: GetWifiScanConfig() returns nullptr";
    }
    wifiIntelligenceStateMachine_->mIsScanning_ = false;
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_HANDLE_SCAN_RESULT);
    bool result = disabledState_->ExecuteStateMsg(msg);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, DisabledState_ExecuteStateMsg_WifiHandleOpen, TestSize.Level1)
{
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetWifiDetailState(_))
        .WillRepeatedly(Return(WifiDetailState::STATE_SEMI_ACTIVE));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetScreenState())
        .WillRepeatedly(Return(MODE_STATE_OPEN));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetApMidState(_))
        .WillRepeatedly(Return(WifiOprMidState::CLOSED));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), IsScreenLandscape())
        .WillRepeatedly(Return(false));

    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_WIFI_HANLE_OPEN);
    bool result = disabledState_->ExecuteStateMsg(msg);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, DisabledState_ExecuteStateMsg_ConnectStateChanged_Other, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_WIFI_CONNECT_STATE_CHANGED);
    msg->SetParam1(static_cast<int32_t>(OperateResState::CONNECT_AP_CONNECTED));
    bool result = disabledState_->ExecuteStateMsg(msg);
    EXPECT_FALSE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, InternetReadyState_ExecuteStateMsg_CellStateChange_MobileAp, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_CELL_STATE_CHANGE);
    WifiLinkedInfo linkedInfo;
    linkedInfo.networkId = 1;
    linkedInfo.bssid = "00:00:00:00:00:00";
    linkedInfo.isDataRestricted = true;

    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));

    bool result = internetReadyState_->ExecuteStateMsg(msg);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, InternetReadyState_ExecuteStateMsg_ScreenOn_MobileAp, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_SCREEN_ON);
    WifiLinkedInfo linkedInfo;
    linkedInfo.networkId = 1;
    linkedInfo.bssid = "00:00:00:00:00:00";
    linkedInfo.isDataRestricted = true;

    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));

    bool result = internetReadyState_->ExecuteStateMsg(msg);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, InternetReadyState_ExecuteStateMsg_ScreenOn_EmptyCellId, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_SCREEN_ON);
    WifiLinkedInfo linkedInfo;
    linkedInfo.networkId = 1;
    linkedInfo.bssid = "00:00:00:00:00:00";
    linkedInfo.isDataRestricted = false;

    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetLinkedInfo(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<0>(linkedInfo), Return(0)));

    bool result = internetReadyState_->ExecuteStateMsg(msg);
    EXPECT_TRUE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, StopState_ExecuteStateMsg_Default, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_WIFI_ENABLED);
    bool result = stopState_->ExecuteStateMsg(msg);
    EXPECT_FALSE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, DisconnectedState_ExecuteStateMsg_Default, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_WIFI_ENABLED);
    bool result = disconnectedState_->ExecuteStateMsg(msg);
    EXPECT_FALSE(result);
}

HWTEST_F(WifiIntelligenceStateMachineTest, ConnectedState_ExecuteStateMsg_Default, TestSize.Level1)
{
    auto msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(EVENT_WIFI_DISABLED);
    bool result = connectedState_->ExecuteStateMsg(msg);
    EXPECT_FALSE(result);
}
} // namespace Wifi
} // namespace OHOS