/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include "p2p_group_remove_state.h"
#include "p2p_state_machine.h"
#include "wifi_logger.h"

namespace OHOS {
namespace Wifi {
constexpr int GROUP_REMOVE_TIMEOUT = 3000;

DEFINE_WIFILOG_P2P_LABEL("P2pGroupRemoveState");
P2pGroupRemoveState::P2pGroupRemoveState(P2pStateMachine &stateMachine)
    : State("P2pGroupRemoveState"), p2pStateMachine(stateMachine)
{}
void P2pGroupRemoveState::GoInState()
{
    WIFI_LOGI("             GoInState");
}

void P2pGroupRemoveState::GoOutState()
{
    WIFI_LOGI("             GoOutState");
    p2pStateMachine.StopTimer(static_cast<int>(P2P_STATE_MACHINE_CMD::P2P_DISABLE_TIMEOUT));
}

bool P2pGroupRemoveState::ExecuteStateMsg(InternalMessagePtr msg)
{
    WIFI_LOGI("P2pGroupRemoveState");
    int msgName = msg->GetMessageName();
    switch (static_cast<P2P_STATE_MACHINE_CMD>(msgName)) {
        case P2P_STATE_MACHINE_CMD::CMD_P2P_DISABLE: {
            p2pStateMachine.StartTimer(static_cast<int>(P2P_STATE_MACHINE_CMD::P2P_DISABLE_TIMEOUT),
                GROUP_REMOVE_TIMEOUT);
            return EXECUTED;
        }
        case P2P_STATE_MACHINE_CMD::CMD_REMOVE_GROUP: {
            return EXECUTED;
        }
        default:
            WIFI_LOGE("Failed:The  P2P state machine does not process messages: [%{public}d]", msgName);
            return NOT_EXECUTED;
    }
}
} // namespace Wifi
} // namespace OHOS
