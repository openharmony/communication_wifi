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
#include <string>
#include <vector>
#include "multi_sta_state_machine.h"
#include "wifi_logger.h"
#include "wifi_msg.h"
#include "wifi_errcode.h"
#include "mock_wifi_manager.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;
constexpr int TEN = 10;

namespace OHOS {
namespace Wifi {
static std::unique_ptr<MultiStaStateMachine> multiStaStateMachine_;
class MultiStaStateMachineTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        WifiManager::GetInstance().Init();
    }

    static void TearDownTestCase()
    {
        sleep(TEN);
        multiStaStateMachine_.reset();
        WifiManager::GetInstance().Exit();
    }

    virtual void SetUp()
    {
        multiStaStateMachine_ = std::make_unique<MultiStaStateMachine>();
        multiStaStateMachine_->InitMultiStaStateMachine();
    }

    virtual void TearDown()
    {
        WifiAppStateAware::GetInstance().appChangeEventHandler->RemoveAsyncTask("WIFI_APP_STATE_EVENT");
    }

    static void OnStartFailureTest(int test)
    {
    }
};

HWTEST_F(MultiStaStateMachineTest, DefaultStateExecuteStateMsgTest01, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    multiStaStateMachine_->pDefaultState->GoInState();
    multiStaStateMachine_->pDefaultState->GoOutState();
    EXPECT_EQ(multiStaStateMachine_->pDefaultState->ExecuteStateMsg(msg), true);
}

HWTEST_F(MultiStaStateMachineTest, IdleStateExecuteStateMsgTest01, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    multiStaStateMachine_->pIdleState->GoInState();
    multiStaStateMachine_->pIdleState->GoOutState();
    msg->SetMessageName(MULTI_STA_CMD_START);
    int mid = 1;
    msg->SetParam2(mid);
    multiStaStateMachine_->pIdleState->pMultiStaStateMachine->mcb.onStartFailure = OnStartFailureTest;
    EXPECT_EQ(multiStaStateMachine_->pIdleState->ExecuteStateMsg(msg), true);
}

HWTEST_F(MultiStaStateMachineTest, IdleStateExecuteStateMsgTest02, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    msg->SetMessageName(MULTI_STA_CMD_STARTED);
    int mid = 1;
    msg->SetParam2(mid);
    EXPECT_EQ(multiStaStateMachine_->pIdleState->ExecuteStateMsg(msg), true);
}

HWTEST_F(MultiStaStateMachineTest, StartedStateExecuteStateMsgTest01, TestSize.Level1)
{
    InternalMessagePtr msg = std::make_shared<InternalMessage>();
    multiStaStateMachine_->pStartedState->GoInState();
    multiStaStateMachine_->pStartedState->GoOutState();
    msg->SetMessageName(MULTI_STA_CMD_START);
    EXPECT_EQ(multiStaStateMachine_->pStartedState->ExecuteStateMsg(msg), true);
}
} // namespace Wifi
} // namespace OHOS