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
#include "softap_manager_state_machine.h"
#include "wifi_config_center.h"
#include "wifi_logger.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

#define INVILAD_MSG 0x1111

namespace OHOS {
namespace Wifi {
class SoftapManagerMachineTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        pSoftapManagerMachine = std::make_unique<SoftapManagerMachine>();
        pSoftapManagerMachine->InitSoftapManagerMachine();
        mCb.onStartFailure = DealSoftapStartFailure;
        mCb.onStopped = DealSoftapStop;
        pSoftapManagerMachine->RegisterCallback(mCb);
    }

    virtual void TearDown()
    {
        pSoftapManagerMachine.reset();
    }

    static void DealSoftapStartFailure(int id = 0)
    {
        LOGI("softap start fail");
    }

    static void DealSoftapStop(int id = 0)
    {
        LOGI("softap stop");
    }

    std::unique_ptr<SoftapManagerMachine> pSoftapManagerMachine;
    SoftApModeCallback mCb;

    void DefaultStateGoInStateSuccess()
    {
        pSoftapManagerMachine->pDefaultState->GoInState();
    }

    void DefaultStateGoOutStateSuccess()
    {
        pSoftapManagerMachine->pDefaultState->GoOutState();
    }

    void IdleStateGoInStateSuccess()
    {
        pSoftapManagerMachine->pIdleState->GoInState();
    }

    void IdleStateGoOutStateSuccess()
    {
        pSoftapManagerMachine->pIdleState->GoOutState();
    }

    void StartedStateGoInStateSuccess()
    {
        pSoftapManagerMachine->pStartedState->GoInState();
    }

    void StartedStateGoOutStateSuccess()
    {
        pSoftapManagerMachine->pStartedState->GoOutState();
    }

    void HandleStartInIdleStateTest()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        WifiOprMidState apState = WifiConfigCenter::GetInstance().GetApMidState(0);
        WifiConfigCenter::GetInstance().SetApMidState(apState, WifiOprMidState::RUNNING, 0);
        msg->SetMessageName(SOFTAP_CMD_START);
        sleep(1);
        EXPECT_TRUE(pSoftapManagerMachine->pIdleState->ExecuteStateMsg(msg));
        apState = WifiConfigCenter::GetInstance().GetApMidState(0);
        WifiConfigCenter::GetInstance().SetApMidState(apState, WifiOprMidState::CLOSING, 0);
        EXPECT_TRUE(pSoftapManagerMachine->pIdleState->ExecuteStateMsg(msg));
        apState = WifiConfigCenter::GetInstance().GetApMidState(0);
        WifiConfigCenter::GetInstance().SetApMidState(apState, WifiOprMidState::CLOSED, 0);
        EXPECT_TRUE(pSoftapManagerMachine->pIdleState->ExecuteStateMsg(msg));
    }

    void StopSoftapTest()
    {
        InternalMessagePtr msg = std::make_shared<InternalMessage>();
        WifiOprMidState apState = WifiConfigCenter::GetInstance().GetApMidState(0);
        WifiConfigCenter::GetInstance().SetApMidState(apState, WifiOprMidState::CLOSED, 0);
        msg->SetMessageName(SOFTAP_CMD_STOP);
        sleep(1);
        EXPECT_TRUE(pSoftapManagerMachine->pDefaultState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pSoftapManagerMachine->pIdleState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pSoftapManagerMachine->pStartedState->ExecuteStateMsg(msg));
        EXPECT_FALSE(pSoftapManagerMachine->pDefaultState->ExecuteStateMsg(nullptr));
        EXPECT_FALSE(pSoftapManagerMachine->pIdleState->ExecuteStateMsg(nullptr));
        EXPECT_FALSE(pSoftapManagerMachine->pStartedState->ExecuteStateMsg(nullptr));
        apState = WifiConfigCenter::GetInstance().GetApMidState(0);
        WifiConfigCenter::GetInstance().SetApMidState(apState, WifiOprMidState::CLOSING, 0);
        EXPECT_TRUE(pSoftapManagerMachine->pStartedState->ExecuteStateMsg(msg));
        apState = WifiConfigCenter::GetInstance().GetApMidState(0);
        WifiConfigCenter::GetInstance().SetApMidState(apState, WifiOprMidState::RUNNING, 0);
        EXPECT_TRUE(pSoftapManagerMachine->pStartedState->ExecuteStateMsg(msg));
        msg->SetMessageName(INVILAD_MSG);
        EXPECT_TRUE(pSoftapManagerMachine->pIdleState->ExecuteStateMsg(msg));
        EXPECT_TRUE(pSoftapManagerMachine->pStartedState->ExecuteStateMsg(msg));
    }
};

HWTEST_F(SoftapManagerMachineTest, DefaultStateGoInStateSuccess, TestSize.Level1)
{
    DefaultStateGoInStateSuccess();
}

HWTEST_F(SoftapManagerMachineTest, DefaultStateGoOutStateSuccess, TestSize.Level1)
{
    DefaultStateGoOutStateSuccess();
}

HWTEST_F(SoftapManagerMachineTest, IdleStateGoInStateSuccess, TestSize.Level1)
{
    IdleStateGoInStateSuccess();
}

HWTEST_F(SoftapManagerMachineTest, IdleStateGoOutStateSuccess, TestSize.Level1)
{
    IdleStateGoOutStateSuccess();
}

HWTEST_F(SoftapManagerMachineTest, StartedStateGoInStateSuccess, TestSize.Level1)
{
    StartedStateGoInStateSuccess();
}

HWTEST_F(SoftapManagerMachineTest, StartedStateGoOutStateSuccess, TestSize.Level1)
{
    StartedStateGoOutStateSuccess();
}

HWTEST_F(SoftapManagerMachineTest, HandleStartInIdleStateTest, TestSize.Level1)
{
    HandleStartInIdleStateTest();
}

HWTEST_F(SoftapManagerMachineTest, StopSoftapTest, TestSize.Level1)
{
    StopSoftapTest();
}

}
}