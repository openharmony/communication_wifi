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

HWTEST_F(WifiAppStateAwareTest, UpdateCurForegroundAppInfo_AddForegroundApp, TestSize.Level1)
{
    AppExecFwk::AppStateData appStateData;
    appStateData.uid = 1;
    appStateData.state = static_cast<int32_t>(AppExecFwk::ApplicationState::APP_STATE_FOREGROUND);
    std::vector<AppExecFwk::AppStateData> appStateDataList = {};
    WifiAppStateAware::GetInstance().curForegroundApps_ = appStateDataList;
    bool ret = WifiAppStateAware::GetInstance().UpdateCurForegroundAppInfo(appStateData);
    EXPECT_EQ(WifiAppStateAware::GetInstance().curForegroundApps_.size(), 1);
    EXPECT_TRUE(ret);
}

HWTEST_F(WifiAppStateAwareTest, UpdateCurForegroundAppInfo_RemoveForegroundApp, TestSize.Level1)
{
    AppExecFwk::AppStateData changeAppStateData;
    changeAppStateData.uid = 1;
    changeAppStateData.state = static_cast<int32_t>(AppExecFwk::ApplicationState::APP_STATE_BACKGROUND);

    AppExecFwk::AppStateData historyAppStateData;
    std::vector<AppExecFwk::AppStateData> appStateDataList = {};
    historyAppStateData.uid = 1;
    historyAppStateData.state = static_cast<int32_t>(AppExecFwk::ApplicationState::APP_STATE_FOREGROUND);
    appStateDataList.push_back(historyAppStateData);
    WifiAppStateAware::GetInstance().curForegroundApps_ = appStateDataList
    bool ret = WifiAppStateAware::GetInstance().UpdateCurForegroundAppInfo(changeAppStateData);
    EXPECT_EQ(WifiAppStateAware::GetInstance().curForegroundApps_.size(), 0);
    EXPECT_TRUE(ret);
}

HWTEST_F(WifiAppStateAwareTest, UpdateCurForegroundAppInfo_NoNeedUpdate, TestSize.Level1)
{
    AppExecFwk::AppStateData changeAppStateData;
    changeAppStateData.uid = 1;
    changeAppStateData.state = static_cast<int32_t>(AppExecFwk::ApplicationState::APP_STATE_FOREGROUND);

    AppExecFwk::AppStateData historyAppStateData;
    std::vector<AppExecFwk::AppStateData> appStateDataList = {};
    historyAppStateData.uid = 1;
    historyAppStateData.state = static_cast<int32_t>(AppExecFwk::ApplicationState::APP_STATE_FOREGROUND);
    appStateDataList.push_back(historyAppStateData);
    WifiAppStateAware::GetInstance().curForegroundApps_ = appStateDataList
    bool ret = WifiAppStateAware::GetInstance().UpdateCurForegroundAppInfo(changeAppStateData);
    EXPECT_EQ(WifiAppStateAware::GetInstance().curForegroundApps_.size(), 1);
    EXPECT_FALSE(ret);
}

HWTEST_F(WifiAppStateAwareTest, HasRecordInCurForegroundApps_True, TestSize.Level1)
{
    AppExecFwk::AppStateData historyAppStateData;
    historyAppStateData.uid = 1;
    historyAppStateData.state = static_cast<int32_t>(AppExecFwk::ApplicationState::APP_STATE_FOREGROUND);
    std::vector<AppExecFwk::AppStateData> appStateDataList = {};
    appStateDataList.push_back(historyAppStateData);

    AppExecFwk::AppStateData changeAppStateData;
    changeAppStateData.uid = 1;

    bool ret = WifiAppStateAware::GetInstance().HasRecordInCurForegroundApps(changeAppStateData);
    EXPECT_TRUE(ret);
}

HWTEST_F(WifiAppStateAwareTest, HasRecordInCurForegroundApps_False, TestSize.Level1)
{
    AppExecFwk::AppStateData historyAppStateData;
    historyAppStateData.uid = 1;
    historyAppStateData.state = static_cast<int32_t>(AppExecFwk::ApplicationState::APP_STATE_FOREGROUND);
    std::vector<AppExecFwk::AppStateData> appStateDataList = {};
    appStateDataList.push_back(historyAppStateData);

    AppExecFwk::AppStateData changeAppStateData;
    changeAppStateData.uid = 2;

    bool ret = WifiAppStateAware::GetInstance().HasRecordInCurForegroundApps(changeAppStateData);
    EXPECT_FALSE(ret);
}

HWTEST_F(WifiAppStateAwareTest, IsForegroundApp_True, TestSize.Level1)
{
    AppExecFwk::AppStateData historyAppStateData;
    historyAppStateData.uid = 1;
    historyAppStateData.state = static_cast<int32_t>(AppExecFwk::ApplicationState::APP_STATE_FOREGROUND);
    std::vector<AppExecFwk::AppStateData> appStateDataList = {};
    appStateDataList.push_back(historyAppStateData);

    bool ret = WifiAppStateAware::GetInstance().IsForegroundApp(1);
    EXPECT_TRUE(ret);
}

HWTEST_F(WifiAppStateAwareTest, IsForegroundApp_False, TestSize.Level1)
{
    AppExecFwk::AppStateData historyAppStateData;
    historyAppStateData.uid = 1;
    historyAppStateData.state = static_cast<int32_t>(AppExecFwk::ApplicationState::APP_STATE_FOREGROUND);
    std::vector<AppExecFwk::AppStateData> appStateDataList = {};
    appStateDataList.push_back(historyAppStateData);

    bool ret = WifiAppStateAware::GetInstance().IsForegroundApp(2);
    EXPECT_FALSE(ret);
}