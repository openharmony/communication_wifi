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
#include "mock_concrete_manager_state_machine.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_LABEL("MockConcreteMangerMachine");

namespace OHOS {
namespace Wifi {
void MockConcreteMangerMachine::SendMessage(int msgName)
{
    WIFI_LOGD("MockConcreteMangerMachine::SendMessage, msgName is %{public}d.", msgName);
}

void MockConcreteMangerMachine::SendMessage(int msgName, int param1)
{
    WIFI_LOGD("SendMessage, msgName is %{public}d, param1 is %{public}d.", msgName, param1);
}

void MockConcreteMangerMachine::SendMessage(int msgName, int param1, int param2)
{
    WIFI_LOGD("SendMessage, msgName is %{public}d, param1 is %{public}d, param2 is %{public}d.",
        msgName, param1, param2);
}

void MockConcreteMangerMachine::SendMessage(InternalMessage *msg)
{
    if (msg == nullptr) {
        return;
    }
    WIFI_LOGD("MockConcreteMangerMachine::SendMessage, msg is %{public}d.", msg->GetMessageName());
}

void MockConcreteMangerMachine::SendMessage(int msgName, const std::any &messageObj)
{
    (void)messageObj;
    WIFI_LOGD("MockConcreteMangerMachine::SendMessage, msgName is %{public}d.", msgName);
}

void MockConcreteMangerMachine::SendMessage(int msgName, int param1, int param2, const std::any &messageObj)
{
    (void)messageObj;
    WIFI_LOGD("SendMessage, msgName is %{public}d, param1 is %{public}d, param2 is %{public}d.",
        msgName, param1, param2);
}
}  // namespace Wifi
}  // namespace OHOS
