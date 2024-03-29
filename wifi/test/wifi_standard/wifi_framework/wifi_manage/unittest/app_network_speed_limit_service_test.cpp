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
    static void TearDownTestCase() {}
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
    EXPECT_CALL(AppParser::GetInstance(), IsHighTempLimitSpeedApp(_)).WillRepeatedly(Return(true));
    AppNetworkSpeedLimitService::GetInstance().LimitSpeed(BG_LIMIT_CONTROL_ID_TEMP, BG_LIMIT_LEVEL_3);
    EXPECT_EQ(BG_LIMIT_LEVEL_3,
        AppNetworkSpeedLimitService::GetInstance().m_bgLimitRecordMap[BG_LIMIT_CONTROL_ID_TEMP]);
}
}
}