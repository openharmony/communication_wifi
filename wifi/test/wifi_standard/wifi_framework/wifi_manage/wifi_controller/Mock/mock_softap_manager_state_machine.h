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
#ifndef OHOS_MOCK_SOFTAPSTATEMACHINE_H
#define OHOS_MOCK_SOFTAPSTATEMACHINE_H

#include <gmock/gmock.h>
#include "softap_manager_state_machine.h"

namespace OHOS {
namespace Wifi {
class MockSoftapManagerStateMachine : public SoftapManagerMachine {
public:
    MockSoftapManagerStateMachine() {}
    ~MockSoftapManagerStateMachine() {}
    void SendMessage(int msgName);
    void SendMessage(int msgName, int param1);
    void SendMessage(int msgName, int param1, int param2);
    void SendMessage(InternalMessage *msg);
    void SendMessage(int msgName, const std::any &messageObj);
    void SendMessage(int msgName, int param1, int param2, const std::any &messageObj);
};
}  // namespace OHOS
}  // namespace Wifi
#endif