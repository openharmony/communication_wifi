/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
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
#include "ap_define.h"
#include "ap_idle_state.h"
#include "mock_pendant.h"
#include "mock_wifi_ap_hal_interface.h"

using namespace OHOS;
using ::testing::_;
using ::testing::Return;

namespace OHOS {
namespace Wifi {
class ApIdleState_test : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    virtual void SetUp()
    {
        pMockPendant = new MockPendant();

        pMockPendant->GetMockApStateMachine().InitialStateMachine();
        pApIdleState = new ApIdleState(pMockPendant->GetMockApStateMachine());
    }
    virtual void TearDown()
    {
        EXPECT_CALL(WifiApHalInterface::GetInstance(), RegisterApEvent(_))
            .WillOnce(Return(WifiErrorNo::WIFI_IDL_OPT_OK));
        delete pApIdleState;
        pApIdleState = nullptr;
        delete pMockPendant;
        pMockPendant = nullptr;
    }

public:
    MockPendant *pMockPendant;
    ApIdleState *pApIdleState;
};

TEST_F(ApIdleState_test, ExecuteStateMsg_SUCCESS)
{
    InternalMessage *msg = new InternalMessage();
    msg->SetMessageName(static_cast<int>(ApStatemachineEvent::CMD_UPDATE_HOTSPOTCONFIG_RESULT));
    EXPECT_TRUE(pApIdleState->ExecuteStateMsg(msg));

    msg->SetMessageName(static_cast<int>(ApStatemachineEvent::CMD_START_HOTSPOT));
    EXPECT_TRUE(pApIdleState->ExecuteStateMsg(msg));
    delete msg;
}

TEST_F(ApIdleState_test, ExecuteStateMsg_FAILED)
{
    InternalMessage *msg = new InternalMessage();

    msg->SetMessageName(static_cast<int>(ApStatemachineEvent::CMD_SET_HOTSPOT_CONFIG));
    EXPECT_FALSE(pApIdleState->ExecuteStateMsg(msg));

    msg->SetMessageName(static_cast<int>(ApStatemachineEvent::CMD_DISCONNECT_STATION));
    EXPECT_FALSE(pApIdleState->ExecuteStateMsg(msg));

    msg = nullptr;
    EXPECT_FALSE(pApIdleState->ExecuteStateMsg(msg));

    delete msg;
}

TEST_F(ApIdleState_test, GoInState)
{
    pApIdleState->GoInState();
}
TEST_F(ApIdleState_test, GoOutState)
{
    pApIdleState->GoOutState();
}
}  // namespace Wifi
}  // namespace OHOS