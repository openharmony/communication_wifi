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
#include "mock_sta_state_machine.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_LABEL("MockStaStateMachine");

namespace OHOS {
namespace Wifi {
void MockStaStateMachine::SendMessage(int msgName)
{
    WIFI_LOGD("MockStaStateMachine::SendMessage, msgName is %{public}d.", msgName);
}

void MockStaStateMachine::SendMessage(int msgName, int param1)
{
    WIFI_LOGD("MockStaStateMachine::SendMessage, msgName is %{public}d, param1 is %{public}d.", msgName, param1);
}

void MockStaStateMachine::SendMessage(int msgName, int param1, int param2)
{
    WIFI_LOGD("MockStaStateMachine::SendMessage, msgName is %{public}d, param1 is %{public}d, param2 is %{public}d.",
        msgName, param1, param2);
}

void MockStaStateMachine::SendMessage(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return;
    }
    WIFI_LOGD("MockStaStateMachine::SendMessage, msg is %{public}d.", msg->GetMessageName());
}

void MockStaStateMachine::SendMessage(int msgName, const std::any &messageObj)
{
    (void)messageObj;
    WIFI_LOGD("MockStaStateMachine::SendMessage, msgName is %{public}d.", msgName);
}

void MockStaStateMachine::SendMessage(int msgName, int param1, int param2, const std::any &messageObj)
{
    (void)messageObj;
    WIFI_LOGD("MockStaStateMachine::SendMessage, msgName is %{public}d, param1 is %{public}d, param2 is %{public}d.",
        msgName, param1, param2);
}

void MockStaStateMachine::StartConnectToBssid(const int32_t networkId, std::string bssid)
{
    WIFI_LOGD("MockStaStateMachine::StartConnectToBssid, bssid is %{private}s networkId is %{private}d.",
        bssid.c_str(), networkId);
}
 
void MockStaStateMachine::StopTimer(int timerName)
{
    WIFI_LOGD("MockStaStateMachine::StartConnectToBssid, bssid is %{private}d.", timerName);
}

void MessageExecutedLater(int msgName, int64_t delayTimeMs, MsgLogLevel logLevel)
{
    (void)logLevel;
    WIFI_LOGD("MessageExecutedLater, msgName is %{private}d, delayTimeMs is %{public}lld.", msgName, delayTimeMs);
}
}  // namespace Wifi
}  // namespace OHOS
