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
#include "internal_message.h"
#include "sta_define.h"
#include "define.h"
#include "sta_app_acceleration.h"
#include "sta_service.h"
#include "wifi_app_state_aware.h"
#include "wifi_internal_msg.h"
#include "wifi_msg.h"
#include "mock_wifi_config_center.h"
#include "mock_wifi_settings.h"
#include "mock_if_config.h"
#include "mock_wifi_manager.h"
#include "mock_wifi_app_parser.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;
using namespace OHOS::Wifi;
using namespace testing;
static std::string g_errLog;
void StaAppAccelerationallback(const LogType type, const LogLevel level,
                            const unsigned int domain, const char *tag, const char *msg)
{
    g_errLog = msg;
}

class StaAppAccelerationTest : public Test {
public:
    void SetUp() override
    {
        staAppAcceleration_.reset(new StaAppAcceleration());
        LOG_SetCallback(StaAppAccelerationallback);
    }

    void TearDown() override
    {
        staAppAcceleration_.reset();
    }

protected:
    std::unique_ptr<StaAppAcceleration> staAppAcceleration_;
};

HWTEST_F(StaAppAccelerationTest, HandleScreenStatusChangedTest01, TestSize.Level1)
{
    int screenState = MODE_STATE_OPEN;
    staAppAcceleration_->HandleScreenStatusChanged(screenState);
    screenState = MODE_STATE_CLOSE;
    staAppAcceleration_->HandleScreenStatusChanged(screenState);
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaAppAccelerationTest, SetPmModeTest01, TestSize.Level1)
{
    int mode = 0;
    staAppAcceleration_->SetPmMode(mode);
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaAppAccelerationTest, StartGameBoostTest01, TestSize.Level1)
{
    int uid = 1;
    staAppAcceleration_->gameBoostingFlag = false;
    staAppAcceleration_->StartGameBoost(uid);
    EXPECT_TRUE(staAppAcceleration_->gameBoostingFlag);
    staAppAcceleration_->gameBoostingFlag = true;
    staAppAcceleration_->StartGameBoost(uid);
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaAppAccelerationTest, StopGameBoostTest01, TestSize.Level1)
{
    int uid = 1;
    staAppAcceleration_->gameBoostingFlag = true;
    staAppAcceleration_->StopGameBoost(uid);
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaAppAccelerationTest, SetGameBoostModeTest01, TestSize.Level1)
{
    int enable = 1;
    int uid = 1;
    int type = 1;
    int limitMode = 1;
    staAppAcceleration_->SetGameBoostMode(enable, uid, type, limitMode);
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaAppAccelerationTest, HighPriorityTransmitTest01, TestSize.Level1)
{
    int uid = 1;
    int protocol = 1;
    int enable = 1;
    staAppAcceleration_->HighPriorityTransmit(uid, protocol, enable);
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(StaAppAccelerationTest, StopAllAppAccelerationTest01, TestSize.Level1)
{
    staAppAcceleration_->StopAllAppAcceleration();
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}