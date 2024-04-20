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
#include "wifi_settings.h"
#include "wifi_config_center.h"

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
    MOCK_METHOD1(SendMessage, void(InternalMessage*));
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

HWTEST_F(WifiCountryCodeManagerTest, InitTest, TestSize.Level1)
{
    WIFI_LOGI("InitTest enter");
    EXPECT_EQ(ErrCode::WIFI_OPT_SUCCESS, WifiCountryCodeManager::GetInstance().Init());
}

HWTEST_F(WifiCountryCodeManagerTest, SetWifiCountryCodeFromExternalSuccessTest, TestSize.Level1)
{
    WIFI_LOGI("SetWifiCountryCodeFromExternalSuccessTest enter");
    std::string code = "CN";
    EXPECT_EQ(ErrCode::WIFI_OPT_SUCCESS, WifiCountryCodeManager::GetInstance().SetWifiCountryCodeFromExternal(code));
}

HWTEST_F(WifiCountryCodeManagerTest, UpdateWifiCountryCodeTest, TestSize.Level1)
{
    WIFI_LOGI("UpdateWifiCountryCodeTest enter");
    EXPECT_EQ(ErrCode::WIFI_OPT_SUCCESS, WifiCountryCodeManager::GetInstance().UpdateWifiCountryCode());
}

HWTEST_F(WifiCountryCodeManagerTest, NotifyWifiCountryCodeChangeListenersTest, TestSize.Level1)
{
    WIFI_LOGI("NotifyWifiCountryCodeChangeListenersTest enter");
    auto m_apObserver = std::make_shared<WifiCountryCodeChangeObserver>("TestModuleName", *m_mockStateMachine);
    WifiCountryCodeManager::GetInstance().RegisterWifiCountryCodeChangeListener(m_apObserver);
    std::string code = "CN";
    WifiCountryCodeManager::GetInstance().NotifyWifiCountryCodeChangeListeners(code);
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
    StaServiceCallback cbk = WifiCountryCodeManager::GetInstance().GetStaCallback();
    sleep(1);
    ASSERT_TRUE(cbk.OnStaOpenRes != nullptr);
    cbk.OnStaOpenRes(OperateResState::OPEN_WIFI_FAILED, 0);
    sleep(1);
    cbk.OnStaOpenRes(OperateResState::OPEN_WIFI_OPENING, 0);
    sleep(1);
    cbk.OnStaOpenRes(OperateResState::OPEN_WIFI_SUCCEED, 0);
    sleep(1);
    WifiSettings::GetInstance().SetWifiStateOnAirplaneChanged(1);
    cbk.OnStaOpenRes(OperateResState::OPEN_WIFI_SUCCEED, 0);
    sleep(1);
    cbk.OnStaOpenRes(OperateResState::OPEN_WIFI_DISABLED, 0);
    sleep(2);
}

HWTEST_F(WifiCountryCodeManagerTest, DealStaCloseResTest, TestSize.Level1)
{
    WIFI_LOGI("DealStaCloseResTest enter");
    StaServiceCallback cbk = WifiCountryCodeManager::GetInstance().GetStaCallback();
    sleep(1);
    ASSERT_TRUE(cbk.OnStaOpenRes != nullptr);
    ASSERT_TRUE(cbk.OnStaCloseRes != nullptr);
    cbk.OnStaOpenRes(OperateResState::OPEN_WIFI_SUCCEED, 0);
    cbk.OnStaCloseRes(OperateResState::CLOSE_WIFI_CLOSING, 0);
    cbk.OnStaCloseRes(OperateResState::CLOSE_WIFI_SUCCEED, 0);
    WifiSettings::GetInstance().SetWifiStateOnAirplaneChanged(1);
    WifiConfigCenter::GetInstance().SetP2pMidState(WifiOprMidState::RUNNING);
    cbk.OnStaCloseRes(OperateResState::CLOSE_WIFI_SUCCEED, 0);
    sleep(2);
}

HWTEST_F(WifiCountryCodeManagerTest, DealApStateChangedTest, TestSize.Level1)
{
    WIFI_LOGI("DealApStateChangedTest enter");
    IApServiceCallbacks cbk = WifiCountryCodeManager::GetInstance().GetApCallback();
    sleep(1);
    ASSERT_TRUE(cbk.OnApStateChangedEvent != nullptr);
    cbk.OnApStateChangedEvent(ApState::AP_STATE_STARTING, 0);
    cbk.OnApStateChangedEvent(ApState::AP_STATE_STARTED, 0);
    cbk.OnApStateChangedEvent(ApState::AP_STATE_CLOSING, 0);
    cbk.OnApStateChangedEvent(ApState::AP_STATE_CLOSED, 0);
    cbk.OnApStateChangedEvent(ApState::AP_STATE_IDLE, 0);
    cbk.OnApStateChangedEvent(ApState::AP_STATE_NONE, 0);
    sleep(2);
}

HWTEST_F(WifiCountryCodeManagerTest, UpdateWifiCountryCodeCacheSuccessTest, TestSize.Level1)
{
    WIFI_LOGI("UpdateWifiCountryCodeCacheSuccessTest enter");
    std::string code = "CN";
    EXPECT_EQ(ErrCode::WIFI_OPT_SUCCESS,
        WifiCountryCodeManager::GetInstance().UpdateWifiCountryCodeCache(code));
}
}
}