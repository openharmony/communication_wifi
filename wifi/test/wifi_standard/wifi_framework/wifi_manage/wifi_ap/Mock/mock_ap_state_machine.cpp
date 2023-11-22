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
#include "mock_ap_state_machine.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_SCAN_LABEL("MockApStateMachine");

namespace OHOS {
namespace Wifi {
void MockApStateMachine::SwitchState(State *targetState)
{
    if (targetState == nullptr) {
        return;
    }
    WIFI_LOGD("MockApStateMachine::SwitchState");
}

void MockApStateMachine::CreateMessage()
{
    WIFI_LOGD("MockApStateMachine::CreateMessage");
}

void MockApStateMachine::SendMessage(int what)
{
    WIFI_LOGD("MockApStateMachine::SendMessage, what is %{public}d.", what);
}

void MockApStateMachine::SendMessage(int what, int arg1)
{
    WIFI_LOGD("MockApStateMachine::SendMessage, what is %{public}d, arg1 is %{public}d.", what, arg1);
}

void MockApStateMachine::SendMessage(int what, int arg1, int arg2)
{
    WIFI_LOGD("MockApStateMachine::SendMessage, what is %{public}d, arg1 is %{public}d, arg2 is %{public}d.", what,
        arg1, arg2);
}

void MockApStateMachine::SendMessage(InternalMessage *msg)
{
    if (msg == nullptr) {
        return;
    }
    WIFI_LOGD("MockApStateMachine::SendMessage, msg is %{public}d.", msg->GetMessageName());
}

void MockApStateMachine::StartTimer(int timerName, int64_t interval)
{
    (void)timerName;
    (void)interval;
    WIFI_LOGD("Enter MockApStateMachine::StartTimer");
}
void MockApStateMachine::StopTimer(int timerName)
{
    (void)timerName;
    WIFI_LOGD("Enter MockApStateMachine::StopTimer");
}
} // namespace Wifi
} // namespace OHOS