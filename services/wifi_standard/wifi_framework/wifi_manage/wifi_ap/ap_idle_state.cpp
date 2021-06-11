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
#include "ap_idle_state.h"
#include <typeinfo>
#include "ap_macro.h"
#include "ap_state_machine.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_HOTSPOT_LABEL("ApIdleState");
namespace OHOS {
namespace Wifi {
ApIdleState::ApIdleState() : State("ApIdleState")
{}

ApIdleState::~ApIdleState()
{}

void ApIdleState::GoInState()
{
    WIFI_LOGI("%{public}s  Enter", GetStateName().c_str());
}

void ApIdleState::GoOutState()
{
    WIFI_LOGI("%{public}s  Exit", GetStateName().c_str());
}

bool ApIdleState::ExecuteStateMsg(InternalMessage *msg)
{
    if (msg == nullptr) {
        WIFI_LOGE("fatal error!");
        return false;
    }

    int msgName = msg->GetMessageName();

    switch (static_cast<ApStatemachineEvent>(msgName)) {
        case ApStatemachineEvent::CMD_START_HOTSPOT: {
            ApStateMachine::GetInstance().SwitchState(&ApStateMachine::GetInstance().mApStartedState);
            break;
        }
        case ApStatemachineEvent::CMD_UPDATE_HOTSPOTCONFIG_RESULT: {
            break;
        }
        default:
            return NOT_EXECUTED;
            break;
    }

    return EXECUTED;
}
}  // namespace Wifi
}  // namespace OHOS