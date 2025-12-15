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
#include "mock_state_machine.h"
#include "wifi_logger.h"
#include "internal_message.h"

DEFINE_WIFILOG_LABEL("MockStateMachine");

namespace OHOS {
namespace Wifi {

StateMachine::StateMachine(const std::string &name)
{}

StateMachine::~StateMachine()
{}
void StateMachine::SendMessage(int msgName)
{
    WIFI_LOGD("StateMachine::SendMessage, msgName is %{public}d.", msgName);
}

void StateMachine::SendMessage(int msgName, int param1)
{
    WIFI_LOGD("StateMachine::SendMessage, msgName is %{public}d, param1 is %{public}d.", msgName, param1);
}

void StateMachine::SendMessage(int msgName, int param1, int param2)
{
    WIFI_LOGD("StateMachine::SendMessage, msgName is %{public}d, param1 is %{public}d, param2 is %{public}d.",
        msgName, param1, param2);
}

void StateMachine::SendMessage(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return;
    }
    WIFI_LOGD("StateMachine::SendMessage, msg is %{public}d.", msg->GetMessageName());
}

void StateMachine::SendMessage(int msgName, const std::any &messageObj)
{
    (void)messageObj;
    WIFI_LOGD("StateMachine::SendMessage, msgName is %{public}d.", msgName);
}

void StateMachine::SendMessage(int msgName, int param1, int param2, const std::any &messageObj)
{
    (void)messageObj;
    WIFI_LOGD("StateMachine::SendMessage, msgName is %{public}d, param1 is %{public}d, param2 is %{public}d.",
        msgName, param1, param2);
}

void StateMachine::StartConnectToBssid(const int32_t networkId, std::string bssid)
{
    WIFI_LOGD("StateMachine::StartConnectToBssid, bssid is %{private}s networkId is %{private}d.",
        bssid.c_str(), networkId);
}

void StateMachine::StopTimer(int timerName)
{
    WIFI_LOGD("StateMachine::StopTimer, timerName is %{private}d.", timerName);
}

void StateMachine::StartTimer(int timerName, int64_t interval, MsgLogLevel logLevel)
{
    WIFI_LOGD("StateMachine::StartTimer, timerName is %{private}d.", timerName);
}

void StateMachine::StopHandlerThread()
{
}
bool StateMachine::InitialStateMachine(const std::string &name)
{
    return true;
}
void StateMachine::StartStateMachine()
{
}

void StateMachine::NotExecutedMessage(const InternalMessagePtr msg)
{
}
InternalMessagePtr StateMachine::CreateMessage()
{
    auto pMessage = std::make_shared<InternalMessage>();
    return pMessage;
}
InternalMessagePtr StateMachine::CreateMessage(const InternalMessagePtr orig)
{
    InternalMessagePtr m = CreateMessage();
    if (m == nullptr) {
        return nullptr;
    }
    m->SetMessageName(orig->GetMessageName());
    m->SetParam1(orig->GetParam1());
    m->SetParam2(orig->GetParam2());
    m->SetMessageObj(orig->GetMessageObj());
    m->CopyMessageBody(orig->GetMessageBody());
    return m;
}
InternalMessagePtr StateMachine::CreateMessage(int msgName)
{
    InternalMessagePtr m = CreateMessage();
    if (m == nullptr) {
        return nullptr;
    }

    m->SetMessageName(msgName);
    return m;
}
InternalMessagePtr StateMachine::CreateMessage(int msgName, int param1)
{
    InternalMessagePtr m = CreateMessage();
    if (m == nullptr) {
        return nullptr;
    }

    m->SetMessageName(msgName);
    m->SetParam1(param1);
    return m;
}
InternalMessagePtr StateMachine::CreateMessage(int msgName, int param1, int param2)
{
    InternalMessagePtr m = CreateMessage();
    if (m == nullptr) {
        return nullptr;
    }

    m->SetMessageName(msgName);
    m->SetParam1(param1);
    m->SetParam2(param2);
    return m;
}
InternalMessagePtr StateMachine::CreateMessage(int msgName, const std::any &messageObj)
{
    InternalMessagePtr m = CreateMessage();
    if (m == nullptr) {
        return nullptr;
    }

    m->SetMessageName(msgName);

    m->SetMessageObj(messageObj);
    return m;
}
InternalMessagePtr StateMachine::CreateMessage(int msgName, int param1, int param2, const std::any &messageObj)
{
    InternalMessagePtr m = CreateMessage();
    if (m == nullptr) {
        return nullptr;
    }

    m->SetMessageName(msgName);
    m->SetParam1(param1);
    m->SetParam2(param2);
    m->SetMessageObj(messageObj);
    return m;
}
void StateMachine::MessageExecutedLater(int msgName, int64_t delayTimeMs, MsgLogLevel logLevel)
{
    WIFI_LOGD("MessageExecutedLater, msgName is %{private}d, delayTimeMs is %{public}lld.", msgName, delayTimeMs);
}

void StateMachine::MessageExecutedLater(int msgName, int param1, int64_t delayTimeMs)
{
    WIFI_LOGD("MessageExecutedLater, msgName is %{public}d, param1 is %{public}d, delayTimeMs is %{public}lld.",
        msgName,
        param1,
        delayTimeMs);
}
void StateMachine::MessageExecutedLater(int msgName, int param1, int param2, int64_t delayTimeMs)
{
    WIFI_LOGD("MessageExecutedLater, msgName is %{public}d, param1 is %{public}d, param2 is %{public}d, "
              "delayTimeMs is %{public}lld.",
        msgName,
        param1,
        param2,
        delayTimeMs);
}
void StateMachine::MessageExecutedLater(InternalMessagePtr msg, int64_t delayTimeMs)
{
    (void)msg;
    WIFI_LOGD("MessageExecutedLater, delayTimeMs is %{public}lld.", delayTimeMs);
}
void StateMachine::MessageExecutedLater(int msgName, const std::any &messageObj, int64_t delayTimeMs)
{
    (void)messageObj;
    WIFI_LOGD("MessageExecutedLater, msgName is %{public}d, delayTimeMs is %{public}lld.", msgName, delayTimeMs);
}
void StateMachine::MessageExecutedLater(
    int msgName, int param1, int param2, const std::any &messageObj, int64_t delayTimeMs)
{
    (void)messageObj;
    WIFI_LOGD("StateMachine::MessageExecutedLater, msgName is %{public}d, param1 is %{public}d, param2 is %{public}d, "
              "delayTimeMs is %{public}lld.",
        msgName,
        param1,
        param2,
        delayTimeMs);
}
void StateMachine::SendMessageAtFrontOfQueue(int msgName, int param1)
{
    WIFI_LOGD("StateMachine::SendMessageAtFrontOfQueue, msgName is %{public}d, param1 is %{public}d.", msgName, param1);
}
std::string StateMachine::GetCurStateName()
{
    return "";
}
void StateMachine::StatePlus(State *state, State *upper)
{}
void StateMachine::StateDelete(State *state)
{}
void StateMachine::SetFirstState(State *firstState)
{}
void StateMachine::SwitchState(State *targetState)
{}
void StateMachine::DelayMessage(const InternalMessagePtr msg)
{}
}  // namespace Wifi
}  // namespace OHOS
