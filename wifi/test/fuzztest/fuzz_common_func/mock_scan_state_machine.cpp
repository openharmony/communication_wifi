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
#include "mock_scan_state_machine.h"
#include "wifi_logger.h"

DEFINE_WIFILOG_SCAN_LABEL("MockScanStateMachine");

namespace OHOS {
namespace Wifi {
void MockScanStateMachine::SendMessage(int what)
{
    WIFI_LOGE("MockScanStateMachine::SendMessage, what is %{public}d.", what);
}

void MockScanStateMachine::SendMessage(int what, int arg1)
{
    WIFI_LOGE("MockScanStateMachine::SendMessage, what is %{public}d, arg1 is %{public}d.", what, arg1);
}

void MockScanStateMachine::SendMessage(int what, int arg1, int arg2)
{
    WIFI_LOGE("MockScanStateMachine::SendMessage, what is %{public}d, arg1 is %{public}d, arg2 is %{public}d.", what,
        arg1, arg2);
}

void MockScanStateMachine::SendMessage(InternalMessagePtr msg)
{
    if (msg == nullptr) {
        return;
    }
    WIFI_LOGE("MockScanStateMachine::SendMessage, msg is %{public}d.", msg->GetMessageName());
}

void MockScanStateMachine::StartTimer(int timerName, int64_t interval, MsgLogLevel logLevel)
{
    (void)timerName;
    (void)interval;
    WIFI_LOGE("Enter MockScanStateMachine::StartTimer");
}
void MockScanStateMachine::StopTimer(int timerName)
{
    (void)timerName;
    WIFI_LOGE("Enter MockScanStateMachine::StopTimer");
}
bool InitialStateMachine()
{
    WIFI_LOGE("Enter MockScanStateMachine::InitialStateMachine");
    return true;
}
InternalMessagePtr CreateMessage(int msgName, int param1)
{
    WIFI_LOGE("Enter MockScanStateMachine::CreateMessage");
    return nullptr;
}
InternalMessagePtr CreateMessage(int msgName)
{
    WIFI_LOGE("Enter MockScanStateMachine::CreateMessage");
    return nullptr;
}

WifiManagers &WifiManagers::GetInstance()
{
    static WifiManagers gWifiManager;
    return gWifiManager;
}

WifiManagers::WifiManagers()
{
    InitScanCallback();
}

IScanSerivceCallbacks WifiManagers::GetScanCallback(void)
{
    return mScanCallback;
}

void WifiManagers::InitScanCallback(void)
{
    using namespace std::placeholders;
    mScanCallback.OnScanStartEvent = std::bind(&WifiManagers::DealScanOpenRes, this, _1);
    mScanCallback.OnScanStopEvent = std::bind(&WifiManagers::DealScanCloseRes, this, _1);
    mScanCallback.OnScanFinishEvent = std::bind(&WifiManagers::DealScanFinished, this, _1, _2);
    mScanCallback.OnScanInfoEvent = std::bind(&WifiManagers::DealScanInfoNotify, this, _1, _2);
    mScanCallback.OnStoreScanInfoEvent = std::bind(&WifiManagers::DealStoreScanInfoEvent, this, _1, _2);
    return;
}

void WifiManagers::DealScanOpenRes(int instId)
{
    return;
}

void WifiManagers::DealScanCloseRes(int instId)
{
    return;
}

void WifiManagers::DealScanFinished(int state, int instId)
{
    return;
}

void WifiManagers::DealScanInfoNotify(std::vector<InterScanInfo> &results, int instId)
{
    return;
}

void WifiManagers::DealStoreScanInfoEvent(std::vector<InterScanInfo> &results, int instId)
{
    return;
}

} // namespace Wifi
} // namespace OHOS