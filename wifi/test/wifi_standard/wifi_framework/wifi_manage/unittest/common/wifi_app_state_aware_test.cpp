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
#include "wifi_log.h"
#include "wifi_logger.h"
#include "wifi_app_state_aware.h"
using namespace OHOS;
using namespace OHOS::Wifi;
using namespace testing;
using ::testing::_;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

class MockWifiAppStateAwareCallbacks : public WifiAppStateAwareCallbacks {
public:
    MOCK_METHOD(void, OnForegroundAppChanged, (const AppExecFwk::AppStateData &, int));
};

class WifiAppStateAwareTest : public Test {
public:
    void SetUp() override
    {
        callbacks_ = std::make_shared<MockWifiAppStateAwareCallbacks>();
        WifiAppStateAware::GetInstance().InitAppStateAware(*callbacks_);
    }

    void TearDown() override
    {
        callbacks_.reset();
    }

protected:
    std::shared_ptr<MockWifiAppStateAwareCallbacks> callbacks_;
};

HWTEST_F(WifiAppStateAwareTest, Connect_ReturnsTrueWhenAppMgrProxyIsNotNull, TestSize.Level1)
{
    EXPECT_TRUE(WifiAppStateAware::GetInstance().Connect());
}

HWTEST_F(WifiAppStateAwareTest, RegisterAppStateObserver_CallsRegisterApplicationStateObserver, TestSize.Level1)
{
    WifiAppStateAware::GetInstance().RegisterAppStateObserver();
}

HWTEST_F(WifiAppStateAwareTest, UnSubscribeAppState_CallsUnregisterApplicationStateObserver, TestSize.Level1)
{
    WifiAppStateAware::GetInstance().UnSubscribeAppState();
}

HWTEST_F(WifiAppStateAwareTest, OnForegroundAppChanged_CallsOnForegroundAppChangedCallback, TestSize.Level1)
{
    AppExecFwk::AppStateData *appStateData = new (std::nothrow) AppExecFwk::AppStateData();
    ASSERT_NE(appStateData, nullptr);
    appStateData->bundleName = "";
    appStateData->isFocused = true;
    appStateData->state = static_cast<int32_t>(AppExecFwk::ApplicationState::APP_STATE_FOREGROUND);
    appStateData->uid = -1;
    callbacks_->OnForegroundAppChanged(*appStateData, 0);
}