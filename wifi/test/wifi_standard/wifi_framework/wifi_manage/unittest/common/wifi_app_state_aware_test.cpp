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
static std::string g_errLog = "wifitest";
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
    std::shared_ptr<WifiAppStateAware> wifiAppStateAware_;
};

HWTEST_F(WifiAppStateAwareTest, Connect_ReturnsTrueWhenAppMgrProxyIsNotNull, TestSize.Level1)
{
    ASSERT_NE(WifiAppStateAware::GetInstance().GetAppMgr(), nullptr);
}

HWTEST_F(WifiAppStateAwareTest, RegisterAppStateObserver_CallsRegisterApplicationStateObserver, TestSize.Level1)
{
    WifiAppStateAware::GetInstance().RegisterAppStateObserver();
    EXPECT_FALSE(g_errLog.find("processWiTasDecisiveMessage")!=std::string::npos);
}

HWTEST_F(WifiAppStateAwareTest, UnSubscribeAppState_CallsUnregisterApplicationStateObserver, TestSize.Level1)
{
    WifiAppStateAware::GetInstance().UnSubscribeAppState();
    EXPECT_FALSE(g_errLog.find("processWiTasDecisiveMessage")!=std::string::npos);
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

HWTEST_F(WifiAppStateAwareTest, IsForegroundApp_True, TestSize.Level1)
{
    AppExecFwk::AppStateData historyAppStateData;
    historyAppStateData.uid = 1;
    historyAppStateData.state = static_cast<int32_t>(AppExecFwk::ApplicationState::APP_STATE_FOREGROUND);
    std::vector<AppExecFwk::AppStateData> appStateDataList = {};
    appStateDataList.push_back(historyAppStateData);

    bool ret = WifiAppStateAware::GetInstance().IsForegroundApp(1);
    EXPECT_FALSE(ret);
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

HWTEST_F(WifiAppStateAwareTest, OnForegroundAppChangedTest001, TestSize.Level1)
{
    WifiAppStateAware wifiAppStateAware;
    AppExecFwk::AppStateData appStateData;
    appStateData.bundleName = "";
    appStateData.isFocused = true;
    appStateData.state = static_cast<int32_t>(AppExecFwk::ApplicationState::APP_STATE_FOREGROUND);
    appStateData.uid = -1;
    wifiAppStateAware.OnForegroundAppChanged(appStateData, 0);
    EXPECT_FALSE(g_errLog.find("processWiTasDecisiveMessage")!=std::string::npos);
}

HWTEST_F(WifiAppStateAwareTest, GetProcessRunningInfosTest001, TestSize.Level1)
{
    WifiAppStateAware wifiAppStateAware;
    std::vector<AppExecFwk::RunningProcessInfo> info;
    AppExecFwk::RunningProcessInfo runningProcessInfo;
    info.push_back(runningProcessInfo);
    EXPECT_EQ(wifiAppStateAware.GetProcessRunningInfos(info), WIFI_OPT_SUCCESS);
}

HWTEST_F(WifiAppStateAwareTest, IsForegroundAppTest001, TestSize.Level1)
{
    WifiAppStateAware wifiAppStateAware;
    std::string test = "TEST";
    EXPECT_EQ(wifiAppStateAware.IsForegroundApp(test), false);
}

HWTEST_F(WifiAppStateAwareTest, GetRunningProcessNameByPidTest001, TestSize.Level1)
{
    WifiAppStateAware wifiAppStateAware;
    std::string test = "TEST";
    int uid = 1;
    int pid = 1;
    EXPECT_EQ(wifiAppStateAware.GetRunningProcessNameByPid(uid, pid), "");
}

HWTEST_F(WifiAppStateAwareTest, OnAppStartedTest001, TestSize.Level1)
{
    AppStateObserver appStateObserver;
    AppExecFwk::AppStateData *appStateData = new (std::nothrow) AppExecFwk::AppStateData();
    ASSERT_NE(appStateData, nullptr);
    appStateData->bundleName = "";
    appStateData->isFocused = true;
    appStateData->state = static_cast<int32_t>(AppExecFwk::ApplicationState::APP_STATE_FOREGROUND);
    appStateData->uid = -1;
    appStateObserver.OnAppStarted(*appStateData);
}

HWTEST_F(WifiAppStateAwareTest, OnAppStoppedTest001, TestSize.Level1)
{
    AppStateObserver appStateObserver;
    AppExecFwk::AppStateData *appStateData = new (std::nothrow) AppExecFwk::AppStateData();
    ASSERT_NE(appStateData, nullptr);
    appStateData->bundleName = "";
    appStateData->isFocused = true;
    appStateData->state = static_cast<int32_t>(AppExecFwk::ApplicationState::APP_STATE_FOREGROUND);
    appStateData->uid = -1;
    appStateObserver.OnAppStopped(*appStateData);
}

HWTEST_F(WifiAppStateAwareTest, OnAppStoppedTest002, TestSize.Level1)
{
    AppStateObserver appStateObserver;
    AppExecFwk::AppStateData *appStateData = new (std::nothrow) AppExecFwk::AppStateData();
    ASSERT_NE(appStateData, nullptr);
    appStateData->bundleName = "TEST";
    appStateData->isFocused = true;
    appStateData->state = static_cast<int32_t>(AppExecFwk::ApplicationState::APP_STATE_FOREGROUND);
    appStateData->uid = -1;
    appStateObserver.OnAppStopped(*appStateData);
}

HWTEST_F(WifiAppStateAwareTest, OnForegroundApplicationChangedTest001, TestSize.Level1)
{
    AppStateObserver appStateObserver;
    AppExecFwk::AppStateData *appStateData = new (std::nothrow) AppExecFwk::AppStateData();
    ASSERT_NE(appStateData, nullptr);
    appStateData->bundleName = "";
    appStateData->isFocused = true;
    appStateData->state = static_cast<int32_t>(AppExecFwk::ApplicationState::APP_STATE_FOREGROUND);
    appStateData->uid = -1;
    appStateObserver.OnForegroundApplicationChanged(*appStateData);
}

HWTEST_F(WifiAppStateAwareTest, CheckAssociatedAppInForegroundTest001, TestSize.Level1)
{
    WifiAppStateAware wifiAppStateAware;
    int32_t testUid = 1000;
    EXPECT_FALSE(wifiAppStateAware.CheckAssociatedAppInForeground(testUid));
}
 
HWTEST_F(WifiAppStateAwareTest, IsAppInFilterListTest001, TestSize.Level1)
{
    WifiAppStateAware wifiAppStateAware;
    std::string packageName = "Test";
    std::string callerName = "com.test.caller.nonfilter";
    EXPECT_FALSE(wifiAppStateAware.IsAppInFilterList(packageName, callerName));
}