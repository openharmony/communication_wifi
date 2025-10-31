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
#ifndef OHOS_STA_MACHINE_H
#define OHOS_STA_MACHINE_H

#include <gmock/gmock.h>
#include "internal_message.h"
#include "state.h"

namespace OHOS {
namespace Wifi {
class StateMachine {
public:
    explicit StateMachine(const std::string &name);
    virtual ~StateMachine();
    virtual void SendMessage(int msgName);
    virtual void SendMessage(int msgName, int param1);
    virtual void SendMessage(int msgName, int param1, int param2);
    virtual void SendMessage(InternalMessagePtr msg);
    virtual void SendMessage(int msgName, const std::any &messageObj);
    virtual void SendMessage(int msgName, int param1, int param2, const std::any &messageObj);
    void StopTimer(int timerName);
    void StartTimer(int timerName, int64_t interval, MsgLogLevel logLevel = MsgLogLevel::LOG_D);
    void StartConnectToBssid(const int32_t networkId, std::string bssid);
    void StopHandlerThread();
    bool InitialStateMachine(const std::string &name = "RunHandleThread");
    void StartStateMachine();
    void NotExecutedMessage(const InternalMessagePtr msg);
    InternalMessagePtr CreateMessage();
    InternalMessagePtr CreateMessage(const InternalMessagePtr orig);
    InternalMessagePtr CreateMessage(int msgName);
    InternalMessagePtr CreateMessage(int msgName, int param1);
    InternalMessagePtr CreateMessage(int msgName, int param1, int param2);
    InternalMessagePtr CreateMessage(int msgName, const std::any &messageObj);
    InternalMessagePtr CreateMessage(int msgName, int param1, int param2, const std::any &messageObj);
    void MessageExecutedLater(int msgName, int64_t delayTimeMs, MsgLogLevel logLevel = MsgLogLevel::LOG_D);
    void MessageExecutedLater(int msgName, int param1, int64_t delayTimeMs);
    void MessageExecutedLater(int msgName, int param1, int param2, int64_t delayTimeMs);
    void MessageExecutedLater(InternalMessagePtr msg, int64_t delayTimeMs);
    void MessageExecutedLater(int msgName, const std::any &messageObj, int64_t delayTimeMs);
    void MessageExecutedLater(int msgName, int param1, int param2, const std::any &messageObj, int64_t delayTimeMs);
    void SendMessageAtFrontOfQueue(int msgName, int param1);
    std::string GetCurStateName();
    void StatePlus(State *state, State *upper);
    void StateDelete(State *state);
    void SetFirstState(State *firstState);
    void SwitchState(State *targetState);
    void DelayMessage(const InternalMessagePtr msg);
};
}  // namespace OHOS
}  // namespace Wifi
#endif