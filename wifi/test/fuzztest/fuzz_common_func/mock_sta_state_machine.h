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
#ifndef OHOS_MOCK_STASTATEMACHINE_H
#define OHOS_MOCK_STASTATEMACHINE_H

#include "sta_state_machine.h"

namespace OHOS {
namespace Wifi {
class MockStaStateMachine : public StaStateMachine {
public:
    MockStaStateMachine() {}
    ~MockStaStateMachine() {}
    void SendMessage(int msgName);
    void SendMessage(int msgName, int param1);
    void SendMessage(int msgName, int param1, int param2);
    void SendMessage(InternalMessagePtr msg);
    void SendMessage(int msgName, const std::any &messageObj);
    void SendMessage(int msgName, int param1, int param2, const std::any &messageObj);
    void StartConnectToBssid(const int32_t networkId, std::string bssid);
    void StopTimer(int timerName);
    void MessageExecutedLater(int msgName, int64_t delayTimeMs, MsgLogLevel logLevel = MsgLogLevel::LOG_D);
};
}  // namespace OHOS
}  // namespace Wifi
#endif