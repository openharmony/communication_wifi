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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include "mock_wifi_settings.h"
#include "mock_wifi_config_center.h"
#include "wifi_log.h"
#include "wifi_logger.h"
#include "wifi_internal_msg.h"
#include "wifi_msg.h"
#include "wifi_errcode.h"
#include "wifi_country_code_manager.h"
#include "i_wifi_country_code_change_listener.h"
#include "state_machine.h"
#include "i_ap_service_callbacks.h"
#include "sta_service_callback.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

namespace OHOS {
namespace Wifi {
static std::string g_errLog;
void WifiManLogCallback(const LogType type, const LogLevel level,
    const unsigned int domain, const char *tag, const char *msg)
{
    g_errLog = msg;
}
DEFINE_WIFILOG_LABEL("WifiCountryCodeManagerTest");

class WifiCountryCodeChangeObserver : public IWifiCountryCodeChangeListener {
public:
    WifiCountryCodeChangeObserver(const std::string &name, StateMachine &stateMachineObj)
        : IWifiCountryCodeChangeListener(name, stateMachineObj) {}
    ~WifiCountryCodeChangeObserver() {}
    ErrCode OnWifiCountryCodeChanged(const std::string &wifiCountryCode)
    {
        return WIFI_OPT_SUCCESS;
    }
    std::string GetListenerModuleName()
    {
        return m_listenerModuleName;
    }
};

class MockStateMachine : public StateMachine {
public:
    explicit MockStateMachine(const std::string &name) : StateMachine(name) {};
    ~MockStateMachine() {};
    MOCK_METHOD2(StartTimer, void(int, int64_t));
    MOCK_METHOD1(StopTimer, void(int));
    MOCK_METHOD1(SendMessage, void(int));
    MOCK_METHOD2(SendMessage, void(int, int));
    MOCK_METHOD3(SendMessage, void(int, int, int));
    MOCK_METHOD1(SendMessage, void(InternalMessagePtr));
    MOCK_METHOD2(SendMessage, void(int, const std::any&));
    MOCK_METHOD4(SendMessage, void(int, int, int, const std::any&));
};

class WifiCountryCodeManagerTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        m_mockStateMachine = new (std::nothrow) MockStateMachine("MockStateMachine");
        LOG_SetCallback(WifiManLogCallback);
    }
    virtual void TearDown()
    {
        if (m_mockStateMachine != nullptr) {
            delete m_mockStateMachine;
            m_mockStateMachine = nullptr;
        }
    }

    MockStateMachine *m_mockStateMachine;
};

HWTEST_F(WifiCountryCodeManagerTest, GetInstanceTest, TestSize.Level1)
{
    WIFI_LOGI("GetInstanceTest enter");
    WifiCountryCodeManager::GetInstance();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiCountryCodeManagerTest, InitTest, TestSize.Level1)
{
    WIFI_LOGI("InitTest enter");
    EXPECT_EQ(ErrCode::WIFI_OPT_SUCCESS, WifiCountryCodeManager::GetInstance().Init());
}

HWTEST_F(WifiCountryCodeManagerTest, GetStaCallbackTest, TestSize.Level1)
{
    WIFI_LOGI("GetStaCallbackTest enter");
    WifiCountryCodeManager::GetInstance().GetStaCallback();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiCountryCodeManagerTest, GetApCallbackTest, TestSize.Level1)
{
    WIFI_LOGI("GetApCallbackTest enter");
    WifiCountryCodeManager::GetInstance().GetApCallback();
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiCountryCodeManagerTest, GetWifiCountryCodeTest, TestSize.Level1)
{
    WIFI_LOGI("GetWifiCountryCodeTest enter");
    std::string code = "CN";
    WifiCountryCodeManager::GetInstance().GetWifiCountryCode(code);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiCountryCodeManagerTest, SetWifiCountryCodeFromExternalSuccessTest, TestSize.Level1)
{
    WIFI_LOGI("SetWifiCountryCodeFromExternalSuccessTest enter");
    std::string code = "CN";
    EXPECT_EQ(ErrCode::WIFI_OPT_SUCCESS, WifiCountryCodeManager::GetInstance().SetWifiCountryCodeFromExternal(code));
}

HWTEST_F(WifiCountryCodeManagerTest, TriggerUpdateWifiCountryCodeTest, TestSize.Level1)
{
    WifiCountryCodeManager::GetInstance().wifiCountryCodePolicyConf_ =
        std::bitset<WIFI_COUNTRY_CODE_POLICE_DEF_LEN>(31);  // 31: all the algorithms will take effect
    WifiCountryCodeManager::GetInstance().TriggerUpdateWifiCountryCode(TRIGGER_UPDATE_REASON_TEL_NET_CHANGE);
    WifiCountryCodeManager::GetInstance().TriggerUpdateWifiCountryCode(TRIGGER_UPDATE_REASON_SCAN_CHANGE);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiCountryCodeManagerTest, IsAllowUpdateWifiCountryCodeTest, TestSize.Level1)
{
    WIFI_LOGI("IsAllowUpdateWifiCountryCodeTest enter");
    WifiCountryCodeManager::GetInstance().m_isFirstConnected = true;
    EXPECT_TRUE(WifiCountryCodeManager::GetInstance().IsAllowUpdateWifiCountryCode());

    std::map <int, WifiLinkedInfo> tempInfos;
    WifiLinkedInfo info1;
    info1.connState = ConnState::CONNECTED;
    tempInfos.emplace(1, info1);
    WifiCountryCodeManager::GetInstance().m_isFirstConnected = false;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetAllWifiLinkedInfo()).WillRepeatedly(Return(tempInfos));
    EXPECT_FALSE(WifiCountryCodeManager::GetInstance().IsAllowUpdateWifiCountryCode());
}

HWTEST_F(WifiCountryCodeManagerTest, GetWifiCountryCodePolicySuccessTest, TestSize.Level1)
{
    WIFI_LOGI("GetWifiCountryCodePolicySuccessTest enter");
    WifiCountryCodeManager::GetInstance().GetWifiCountryCodePolicy();
    EXPECT_FALSE(WifiCountryCodeManager::GetInstance().IsAllowUpdateWifiCountryCode());
}

HWTEST_F(WifiCountryCodeManagerTest, UpdateWifiCountryCodeTest, TestSize.Level1)
{
    WIFI_LOGI("UpdateWifiCountryCodeTest enter");

    std::map <int, WifiLinkedInfo> tempInfos;
    WifiLinkedInfo info1;
    info1.connState = ConnState::CONNECTED;
    tempInfos.emplace(1, info1);
    WifiCountryCodeManager::GetInstance().m_isFirstConnected = false;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetAllWifiLinkedInfo()).WillOnce(Return(tempInfos));
    EXPECT_EQ(ErrCode::WIFI_OPT_FAILED, WifiCountryCodeManager::GetInstance().UpdateWifiCountryCode());

    WifiCountryCodeManager::GetInstance().m_isFirstConnected = true;
    std::string tempCode = "CN";
    EXPECT_EQ(ErrCode::WIFI_OPT_SUCCESS, WifiCountryCodeManager::GetInstance().UpdateWifiCountryCode(tempCode));

    WifiCountryCodeManager::GetInstance().m_isFirstConnected = true;
    EXPECT_EQ(ErrCode::WIFI_OPT_SUCCESS, WifiCountryCodeManager::GetInstance().UpdateWifiCountryCode());

    WifiCountryCodeManager::GetInstance().m_isFirstConnected = true;
    WifiCountryCodeManager::GetInstance().m_wifiCountryCodePolicy->m_policyList.clear();
    EXPECT_EQ(ErrCode::WIFI_OPT_FAILED, WifiCountryCodeManager::GetInstance().UpdateWifiCountryCode());
}

HWTEST_F(WifiCountryCodeManagerTest, NotifyWifiCountryCodeChangeListenersTest, TestSize.Level1)
{
    WIFI_LOGI("NotifyWifiCountryCodeChangeListenersTest enter");
    auto m_apObserver = std::make_shared<WifiCountryCodeChangeObserver>("TestModuleName", *m_mockStateMachine);
    WifiCountryCodeManager::GetInstance().RegisterWifiCountryCodeChangeListener(m_apObserver);
    std::string code = "CN";
    WifiCountryCodeManager::GetInstance().NotifyWifiCountryCodeChangeListeners(code);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiCountryCodeManagerTest, RegisterWifiCountryCodeChangeListenerTest, TestSize.Level1)
{
    WIFI_LOGI("RegisterWifiCountryCodeChangeListenerTest enter");
    auto m_apObserver = std::make_shared<WifiCountryCodeChangeObserver>("TestModuleName", *m_mockStateMachine);
    EXPECT_EQ(ErrCode::WIFI_OPT_SUCCESS,
        WifiCountryCodeManager::GetInstance().RegisterWifiCountryCodeChangeListener(m_apObserver));
}

HWTEST_F(WifiCountryCodeManagerTest, UnregisterWifiCountryCodeChangeListenerSuccessTest, TestSize.Level1)
{
    WIFI_LOGI("UnregisterWifiCountryCodeChangeListenerSuccessTest enter");
    auto m_apObserver = std::make_shared<WifiCountryCodeChangeObserver>("TestModuleName", *m_mockStateMachine);
    EXPECT_EQ(ErrCode::WIFI_OPT_SUCCESS,
        WifiCountryCodeManager::GetInstance().RegisterWifiCountryCodeChangeListener(m_apObserver));
    EXPECT_EQ(ErrCode::WIFI_OPT_SUCCESS,
        WifiCountryCodeManager::GetInstance().UnregisterWifiCountryCodeChangeListener(m_apObserver));
}

HWTEST_F(WifiCountryCodeManagerTest, UnregisterWifiCountryCodeChangeListenerFailTest, TestSize.Level1)
{
    WIFI_LOGI("UnregisterWifiCountryCodeChangeListenerFailTest enter");
    auto m_apObserver = std::make_shared<WifiCountryCodeChangeObserver>("TestModuleName", *m_mockStateMachine);
    EXPECT_EQ(ErrCode::WIFI_OPT_SUCCESS,
        WifiCountryCodeManager::GetInstance().RegisterWifiCountryCodeChangeListener(m_apObserver));
    auto m_apObserver1 = std::make_shared<WifiCountryCodeChangeObserver>("TestModuleName_1", *m_mockStateMachine);
    EXPECT_EQ(ErrCode::WIFI_OPT_FAILED,
        WifiCountryCodeManager::GetInstance().UnregisterWifiCountryCodeChangeListener(m_apObserver1));
}

HWTEST_F(WifiCountryCodeManagerTest, DealStaOpenResTest, TestSize.Level1)
{
    WIFI_LOGI("DealStaOpenResTest enter");
    std::map <int, WifiLinkedInfo> tempInfos;
    WifiLinkedInfo info1;
    info1.connState = ConnState::CONNECTED;
    tempInfos.emplace(1, info1);
    WifiCountryCodeManager::GetInstance().m_isFirstConnected = false;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetAllWifiLinkedInfo()).WillRepeatedly(Return(tempInfos));
    EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiStateOnAirplaneChanged(_)).WillRepeatedly(Return(1));
    EXPECT_CALL(WifiSettings::GetInstance(), SetLastAirplaneMode(_, _)).WillRepeatedly(Return(1));
    WifiCountryCodeManager::GetInstance().DealStaOpened(0);
}

HWTEST_F(WifiCountryCodeManagerTest, DealStaCloseResTest, TestSize.Level1)
{
    WIFI_LOGI("DealStaCloseResTest enter");
    EXPECT_CALL(WifiConfigCenter::GetInstance(), SetWifiStateOnAirplaneChanged(_)).WillRepeatedly(Return(1));
    EXPECT_CALL(WifiSettings::GetInstance(), SetLastAirplaneMode(_, _)).WillRepeatedly(Return(1));
    WifiCountryCodeManager::GetInstance().DealStaStopped(0);
}

HWTEST_F(WifiCountryCodeManagerTest, DealStaConnChangedTest, TestSize.Level1)
{
    WIFI_LOGI("DealStaConnChangedTest enter");
    WifiLinkedInfo info;
    WifiCountryCodeManager::GetInstance().DealStaConnChanged(OperateResState::CONNECT_CONNECTING, info, 0);
    WifiCountryCodeManager::GetInstance().DealStaConnChanged(OperateResState::CONNECT_AP_CONNECTED, info, 0);
    WifiCountryCodeManager::GetInstance().DealStaConnChanged(OperateResState::DISCONNECT_DISCONNECTING, info, 0);
    WifiCountryCodeManager::GetInstance().DealStaConnChanged(OperateResState::DISCONNECT_DISCONNECTED, info, 0);
    EXPECT_FALSE(g_errLog.find("service is null") != std::string::npos);
}

HWTEST_F(WifiCountryCodeManagerTest, DealApStateChangedTest, TestSize.Level1)
{
    WIFI_LOGI("DealApStateChangedTest enter");
    std::map <int, WifiLinkedInfo> tempInfos;
    WifiLinkedInfo info1;
    info1.connState = ConnState::CONNECTED;
    tempInfos.emplace(1, info1);
    WifiCountryCodeManager::GetInstance().m_isFirstConnected = false;
    EXPECT_CALL(WifiConfigCenter::GetInstance(), GetAllWifiLinkedInfo()).WillRepeatedly(Return(tempInfos));
    WifiCountryCodeManager::GetInstance().DealApStateChanged(ApState::AP_STATE_STARTING, 0);
    WifiCountryCodeManager::GetInstance().DealApStateChanged(ApState::AP_STATE_STARTED, 0);
    WifiCountryCodeManager::GetInstance().DealApStateChanged(ApState::AP_STATE_CLOSING, 0);
    WifiCountryCodeManager::GetInstance().DealApStateChanged(ApState::AP_STATE_CLOSED, 0);
    WifiCountryCodeManager::GetInstance().DealApStateChanged(ApState::AP_STATE_IDLE, 0);
    WifiCountryCodeManager::GetInstance().DealApStateChanged(ApState::AP_STATE_NONE, 0);
}

HWTEST_F(WifiCountryCodeManagerTest, UpdateWifiCountryCodeCacheSuccessTest, TestSize.Level1)
{
    WIFI_LOGI("UpdateWifiCountryCodeCacheSuccessTest enter");
    EXPECT_EQ(ErrCode::WIFI_OPT_FAILED,
        WifiCountryCodeManager::GetInstance().UpdateWifiCountryCodeCache(""));

    std::string code = "CN";
    EXPECT_EQ(ErrCode::WIFI_OPT_FAILED,
        WifiCountryCodeManager::GetInstance().UpdateWifiCountryCodeCache(code));
}
}
}