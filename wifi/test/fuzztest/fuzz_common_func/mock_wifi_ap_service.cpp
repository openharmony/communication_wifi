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

#include "mock_wifi_ap_service.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_LABEL("MockApService");

namespace OHOS {
namespace Wifi {

void MockApRootState::GoInState()
{
    WIFI_LOGI("Instance %{public}d %{public}s  GoInState.", m_id, GetStateName().c_str());
}

void MockApRootState::GoOutState()
{
    WIFI_LOGI("Instance %{public}d %{public}s  GoOutState.", m_id, GetStateName().c_str());
}

bool MockApRootState::ExecuteStateMsg(InternalMessagePtr msg)
{
    return true;
}

void MockApIdleState::GoInState()
{
    WIFI_LOGI("Instance %{public}d %{public}s  GoInState.", m_id, GetStateName().c_str());
}

void MockApIdleState::GoOutState()
{
    WIFI_LOGI("Instance %{public}d %{public}s  GoOutState.", m_id, GetStateName().c_str());
}

bool MockApIdleState::ExecuteStateMsg(InternalMessagePtr msg)
{
    return true;
}

void MockApStartedState::GoInState()
{
    WIFI_LOGI("Instance %{public}d %{public}s  GoInState.", m_id, GetStateName().c_str());
}

void MockApStartedState::GoOutState()
{
    WIFI_LOGI("Instance %{public}d %{public}s  GoOutState.", m_id, GetStateName().c_str());
}

bool MockApStartedState::ExecuteStateMsg(InternalMessagePtr msg)
{
    return true;
}

void MockApStateMachine::SwitchState(State *targetState)
{
    return;
}

void MockApStateMachine::CreateMessage()
{
    return;
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
    WIFI_LOGD("MockApStateMachine::SendMessage, what is %{public}d, arg1 is %{public}d, arg2 is %{public}d.",
        what, arg1, arg2);
}

void MockApStateMachine::SendMessage(InternalMessagePtr msg)
{
    return;
}

void MockApStateMachine::StartTimer(int timerName, int64_t interval, MsgLogLevel logLevel)
{
    (void)timerName;
    (void)interval;
    return;
}

void MockApStateMachine::StopTimer(int timerName)
{
    WIFI_LOGD("MockApStateMachine::StopTimer, timerName is %{public}d.", timerName);
}

void MockApMonitor::StationChangeEvent(StationInfo &staInfo, const int event)
{
    return;
}

void MockApMonitor::StartMonitor()
{
    return;
}

void MockApMonitor::StopMonitor()
{
    return;
}
}
}