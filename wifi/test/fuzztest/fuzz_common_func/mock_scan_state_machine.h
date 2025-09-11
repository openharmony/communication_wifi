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
#ifndef OHOS_MOCK_SCANSTATEMACHINE_H
#define OHOS_MOCK_SCANSTATEMACHINE_H

#include "scan_state_machine.h"
#include "iscan_service_callbacks.h"

namespace OHOS {
namespace Wifi {
class MockScanStateMachine : public ScanStateMachine {
public:
    MockScanStateMachine()
    {}
    ~MockScanStateMachine()
    {}
    void SendMessage(int what);
    void SendMessage(int what, int arg1);
    void SendMessage(int what, int arg1, int arg2);
    void SendMessage(InternalMessagePtr msg);
    void StartTimer(int timerName, int64_t interval, MsgLogLevel logLevel = MsgLogLevel::LOG_I);
    void StopTimer(int timerName);
    bool InitialStateMachine();
    InternalMessagePtr CreateMessage(int msgName, int param1);
    InternalMessagePtr CreateMessage(int msgName);
};

class WifiManagers {
public:
    WifiManagers();
    ~WifiManagers() = default;
    static WifiManagers &GetInstance();
    IScanSerivceCallbacks GetScanCallback();

    void DealScanOpenRes(int instId = 0);
    void DealScanCloseRes(int instId = 0);
    void DealScanFinished(int state, int instId = 0);
    void DealScanInfoNotify(std::vector<InterScanInfo> &results, int instId = 0);
    void DealStoreScanInfoEvent(std::vector<InterScanInfo> &results, int instId = 0);
    void DealStaOpenRes(OperateResState state, int instId = 0);

private:
    IScanSerivceCallbacks mScanCallback;
    void InitScanCallback(void);
};
}  // namespace Wifi
}  // namespace OHOS
#endif