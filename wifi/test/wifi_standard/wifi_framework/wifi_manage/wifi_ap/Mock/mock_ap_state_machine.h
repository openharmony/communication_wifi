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

#ifndef OHOS_MOCK_AP_STATE_MACHINE_H
#define OHOS_MOCK_AP_STATE_MACHINE_H

#include <gmock/gmock.h>
#include "internal_message.h"
#include "wifi_msg.h"
#include "ap_state_machine.h"

namespace OHOS {
namespace Wifi {
class MockApStateMachine : public ApStateMachine {
public:
    MockApStateMachine(ApStationsManager &apStationsManager, ApRootState &apRootState, ApIdleState &apIdleState,
        ApStartedState &apStartedState, ApMonitor &apMonitor)
        : ApStateMachine(apStationsManager, apRootState, apIdleState, apStartedState, apMonitor)
    {}
    ~MockApStateMachine()
    {}
    void SwitchState(State *targetState);
    void CreateMessage();
    void SendMessage(int what);
    void SendMessage(int what, int arg1);
    void SendMessage(int what, int arg1, int arg2);
    void SendMessage(InternalMessagePtr msg);
    void StartTimer(int timerName, int64_t interval);
    void StopTimer(int timerName);
};
} // namespace Wifi
} // namespace OHOS
#endif