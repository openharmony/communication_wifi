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
#include "app_network_speed_limit_service.h"
#include "wifi_app_state_aware.h"
#include "mock_wifi_app_parser.h"

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
DEFINE_WIFILOG_LABEL("AppNetworkSpeedLimitServiceTest");

class AppNetworkSpeedLimitServiceTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase()
    {
        WifiAppStateAware& wifiAppStateAware = WifiAppStateAware::GetInstance();
        wifiAppStateAware.appChangeEventHandler.reset();
        wifiAppStateAware.mAppStateObserver = nullptr;
    }
    virtual void SetUp() {}
    virtual void TearDown() {}
};

HWTEST_F(AppNetworkSpeedLimitServiceTest, Init, TestSize.Level1)
{
    WIFI_LOGI("InitTest enter");
    EXPECT_EQ(BG_LIMIT_OFF, AppNetworkSpeedLimitService::GetInstance().m_bgLimitRecordMap[BG_LIMIT_CONTROL_ID_GAME]);
    EXPECT_EQ(BG_LIMIT_OFF, AppNetworkSpeedLimitService::GetInstance().m_bgLimitRecordMap[BG_LIMIT_CONTROL_ID_STREAM]);
    EXPECT_EQ(BG_LIMIT_OFF, AppNetworkSpeedLimitService::GetInstance().m_bgLimitRecordMap[BG_LIMIT_CONTROL_ID_TEMP]);
    EXPECT_EQ(BG_LIMIT_OFF,
        AppNetworkSpeedLimitService::GetInstance().m_bgLimitRecordMap[BG_LIMIT_CONTROL_ID_MODULE_FOREGROUND_OPT]);
}

HWTEST_F(AppNetworkSpeedLimitServiceTest, LimitSpeed_HighTemp, TestSize.Level1)
{
    WIFI_LOGI("LimitSpeed_HighTemp enter");
    AppNetworkSpeedLimitService::GetInstance().LimitSpeed(BG_LIMIT_CONTROL_ID_TEMP, BG_LIMIT_LEVEL_3);
    EXPECT_EQ(BG_LIMIT_OFF,
        AppNetworkSpeedLimitService::GetInstance().m_bgLimitRecordMap[BG_LIMIT_CONTROL_ID_TEMP]);
}


HWTEST_F(AppNetworkSpeedLimitServiceTest, GetBgLimitMaxMode, TestSize.Level1)
{
    WIFI_LOGI("GetBgLimitMaxMode enter");
    EXPECT_EQ(BG_LIMIT_OFF, AppNetworkSpeedLimitService::GetInstance().GetBgLimitMaxMode());
}

HWTEST_F(AppNetworkSpeedLimitServiceTest, CheckNetWorkCanBeLimited_GameControlId, TestSize.Level1)
{
    // Prepare
    int controlId = BG_LIMIT_CONTROL_ID_GAME;

    // Execute
    bool result = AppNetworkSpeedLimitService::GetInstance().CheckNetWorkCanBeLimited(controlId);

    // Verify
    EXPECT_TRUE(result);
}

HWTEST_F(AppNetworkSpeedLimitServiceTest, CheckNetWorkCanBeLimited_StreamControlId, TestSize.Level1)
{
    // Prepare
    int controlId = BG_LIMIT_CONTROL_ID_STREAM;

    // Execute
    bool result = AppNetworkSpeedLimitService::GetInstance().CheckNetWorkCanBeLimited(controlId);

    // Verify
    EXPECT_TRUE(result);
}

HWTEST_F(AppNetworkSpeedLimitServiceTest, CheckNetWorkCanBeLimited_TempControlId_WifiConnected, TestSize.Level1)
{
    // Prepare
    int controlId = BG_LIMIT_CONTROL_ID_TEMP;
    AppNetworkSpeedLimitService::GetInstance().m_isWifiConnected = true;

    // Execute
    bool result = AppNetworkSpeedLimitService::GetInstance().CheckNetWorkCanBeLimited(controlId);

    // Verify
    EXPECT_TRUE(result);
}

HWTEST_F(AppNetworkSpeedLimitServiceTest, CheckNetWorkCanBeLimited_TempControlId_WifiDisconnected, TestSize.Level1)
{
    // Prepare
    int controlId = BG_LIMIT_CONTROL_ID_TEMP;
    AppNetworkSpeedLimitService::GetInstance().m_isWifiConnected = false;

    // Execute
    bool result = AppNetworkSpeedLimitService::GetInstance().CheckNetWorkCanBeLimited(controlId);

    // Verify
    EXPECT_FALSE(result);
}

HWTEST_F(AppNetworkSpeedLimitServiceTest, CheckNetWorkCanBeLimited_ModuleForegroundOptControlId, TestSize.Level1)
{
    // Prepare
    int controlId = BG_LIMIT_CONTROL_ID_MODULE_FOREGROUND_OPT;

    // Execute
    bool result = AppNetworkSpeedLimitService::GetInstance().CheckNetWorkCanBeLimited(controlId);

    // Verify
    EXPECT_TRUE(result);
}

HWTEST_F(AppNetworkSpeedLimitServiceTest, IsLimitSpeedBgApp, TestSize.Level1)
{
    WIFI_LOGI("IsLimitSpeedBgApp enter");
    // Prepare
    int controlId = BG_LIMIT_CONTROL_ID_GAME;
    int enable = 1;
    // Execute
    bool result = AppNetworkSpeedLimitService::GetInstance().IsLimitSpeedBgApp(controlId, "com.ohos.wifi", enable);

    // Verify
    EXPECT_TRUE(result);
}
} // namespace Wifi
} // namespace OHOS