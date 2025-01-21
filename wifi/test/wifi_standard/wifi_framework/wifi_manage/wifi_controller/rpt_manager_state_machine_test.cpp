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
#include "rpt_manager_state_machine.h"
#include "wifi_logger.h"
#include "wifi_log.h"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::StrEq;
using ::testing::TypedEq;
using ::testing::ext::TestSize;

namespace OHOS::Wifi {
    static std::string g_errLog;
    void RptManagerMachineCallback(const LogType type, const LogLevel level,
                                   const unsigned int domain, const char *tag,const char *msg)
    {
        g_errLog = msg;
    }
class RptManagerMachineTest : public testing::Test {
public:
    std::unique_ptr<RptManagerMachine> pRptManagerMachine;
    RptModeCallback mCb;

    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    virtual void SetUp()
    {
        pRptManagerMachine = std::make_unique<RptManagerMachine>();
        pRptManagerMachine->InitRptManagerMachine();
        mCb.onStartFailure = DealRptStartFailure;
        mCb.onStopped = DealRptStop;
        pRptManagerMachine->RegisterCallback(mCb);
        LOG_SetCallback(RptManagerMachineCallback);
    }

    virtual void TearDown()
    {
        pRptManagerMachine.reset();
    }

    static void DealRptStartFailure(int id = 0)
    {
        LOGI("Rpt start fail");
    }

    static void DealRptStop(int id = 0)
    {
        LOGI("Rpt stop");
    }

    std::vector<State*> GetStates()
    {
        return std::vector<State *> {
            pRptManagerMachine->pDefaultState,
            pRptManagerMachine->pIdleState,
            pRptManagerMachine->pStartingState,
            pRptManagerMachine->pP2pConflictState,
            pRptManagerMachine->pStartedState,
            pRptManagerMachine->pStoppingState,
            pRptManagerMachine->pStoppedState
        };
    }

    std::vector<int> GetRptMessages()
    {
        return std::vector<int> {
            RPT_CMD_START,
            RPT_CMD_STOP,
            RPT_CMD_ON_P2P_CLOSE,
            RPT_CMD_ON_GROUP_CREATED,
            RPT_CMD_ON_GROUP_REMOVED,
            RPT_CMD_ON_CREATE_RPT_GROUP_TIMEOUT,
            RPT_CMD_ON_REMOVE_RPT_GROUP_TIMEOUT,
            RPT_CMD_ON_REMOVE_CONFLICT_GROUP_TIMEOUT,
            RPT_CMD_ADD_BLOCK,
            RPT_CMD_DEL_BLOCK,
            RPT_CMD_ON_STATION_JOIN,
            RPT_CMD_ON_STATION_LEAVE
        };
    }

    void TestExecuteStateMsg(const std::vector<int> &messages, State *state)
    {
        for (auto msgId : messages) {
            InternalMessagePtr msg = pRptManagerMachine->CreateMessage(msgId);
            EXPECT_TRUE(state->ExecuteStateMsg(msg));
        }
    }
};

HWTEST_F(RptManagerMachineTest, StateChangeSuccess, TestSize.Level1)
{
    for (auto state : GetStates()) {
        state->GoInState();
        state->GoOutState();
    }
    EXPECT_FALSE(g_errLog.find("service is null")!=std::string::npos);
}

HWTEST_F(RptManagerMachineTest, ExecuteStateMsg_Msg_Is_Null, TestSize.Level1)
{
    for (auto state : GetStates()) {
        EXPECT_FALSE(state->ExecuteStateMsg(nullptr));
    }
}

HWTEST_F(RptManagerMachineTest, ExecuteStateMsg_Machine_Is_Null, TestSize.Level1)
{
    auto origin = pRptManagerMachine->pDefaultState->pRptManagerMachine;
    pRptManagerMachine->pDefaultState->pRptManagerMachine = nullptr;
    pRptManagerMachine->pIdleState->pRptManagerMachine = nullptr;
    pRptManagerMachine->pStartingState->pRptManagerMachine = nullptr;
    pRptManagerMachine->pP2pConflictState->pRptManagerMachine = nullptr;
    pRptManagerMachine->pStartedState->pRptManagerMachine = nullptr;
    pRptManagerMachine->pStoppingState->pRptManagerMachine = nullptr;
    pRptManagerMachine->pStoppedState->pRptManagerMachine = nullptr;

    InternalMessagePtr msg = pRptManagerMachine->CreateMessage();
    for (auto state : GetStates()) {
        EXPECT_FALSE(state->ExecuteStateMsg(msg));
    }

    pRptManagerMachine->pDefaultState->pRptManagerMachine = origin;
    pRptManagerMachine->pIdleState->pRptManagerMachine = origin;
    pRptManagerMachine->pStartingState->pRptManagerMachine = origin;
    pRptManagerMachine->pP2pConflictState->pRptManagerMachine = origin;
    pRptManagerMachine->pStartedState->pRptManagerMachine = origin;
    pRptManagerMachine->pStoppingState->pRptManagerMachine = origin;
    pRptManagerMachine->pStoppedState->pRptManagerMachine = origin;
}

HWTEST_F(RptManagerMachineTest, ExecuteStateMsg_By_DefaultState, TestSize.Level1)
{
    TestExecuteStateMsg(GetRptMessages(), pRptManagerMachine->pDefaultState);
}

HWTEST_F(RptManagerMachineTest, ExecuteStateMsg_By_IdleState, TestSize.Level1)
{
    TestExecuteStateMsg(GetRptMessages(), pRptManagerMachine->pIdleState);
}

HWTEST_F(RptManagerMachineTest, ExecuteStateMsg_By_StartingState, TestSize.Level1)
{
    TestExecuteStateMsg(GetRptMessages(), pRptManagerMachine->pStartingState);
}

HWTEST_F(RptManagerMachineTest, ExecuteStateMsg_By_P2pConflictState, TestSize.Level1)
{
    TestExecuteStateMsg(GetRptMessages(), pRptManagerMachine->pP2pConflictState);
}

HWTEST_F(RptManagerMachineTest, ExecuteStateMsg_By_StartedState, TestSize.Level1)
{
    TestExecuteStateMsg(GetRptMessages(), pRptManagerMachine->pStartedState);
}

HWTEST_F(RptManagerMachineTest, ExecuteStateMsg_By_StoppingState, TestSize.Level1)
{
    TestExecuteStateMsg(GetRptMessages(), pRptManagerMachine->pStoppingState);
}

HWTEST_F(RptManagerMachineTest, ExecuteStateMsg_By_StoppedState, TestSize.Level1)
{
    TestExecuteStateMsg(GetRptMessages(), pRptManagerMachine->pStoppedState);
}

}