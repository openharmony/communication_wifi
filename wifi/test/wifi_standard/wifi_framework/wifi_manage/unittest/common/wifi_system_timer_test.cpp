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
#include "wifi_system_timer.h"
#include "wifi_log.h"
#include "wifi_logger.h"
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
class WifiSysTimerTest : public Test {
public:
    void SetUp() override
    {
        timer_ = std::make_shared<WifiSysTimer>();
    }

protected:
    std::shared_ptr<WifiSysTimer> timer_;
};

HWTEST_F(WifiSysTimerTest, OnTrigger_CallsCallbackFunction, TestSize.Level1)
{
    bool callbackCalled = false;
    timer_->SetCallbackInfo([&callbackCalled]()
                            { callbackCalled = true; });

    timer_->OnTrigger();

    EXPECT_TRUE(callbackCalled);
}

HWTEST_F(WifiSysTimerTest, SetType_SetsTimerType, TestSize.Level1)
{
    int type = 123;
    timer_->SetType(type);

    EXPECT_EQ(timer_->type, type);
}

HWTEST_F(WifiSysTimerTest, SetRepeat_SetsRepeatFlag, TestSize.Level1)
{
    bool repeat = true;
    timer_->SetRepeat(repeat);

    EXPECT_EQ(timer_->repeat, repeat);
}

HWTEST_F(WifiSysTimerTest, SetInterval_SetsInterval, TestSize.Level1)
{
    uint64_t interval = 5000;
    timer_->SetInterval(interval);

    EXPECT_EQ(timer_->interval, interval);
}

HWTEST_F(WifiSysTimerTest, SetWantAgent_SetsWantAgent, TestSize.Level1)
{
    std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> wantAgent =
        std::make_shared<OHOS::AbilityRuntime::WantAgent::WantAgent>();
    timer_->SetWantAgent(wantAgent);

    EXPECT_EQ(timer_->wantAgent, wantAgent);
}