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
#ifndef OHOS_MOCK_STA_MONITOR_H
#define OHOS_MOCK_STA_MONITOR_H

#include <gmock/gmock.h>

#include "sta_state_machine.h"
#include "wifi_errcode.h"

namespace OHOS {
namespace Wifi {
class MockStaMonitor {
public:
    virtual ~MockStaMonitor() = default;
    virtual ErrCode InitStaMonitor() = 0;
    virtual ErrCode UnInitStaMonitor() const = 0;
    virtual void SetStateMachine(StaStateMachine *paraStaStateMachine) = 0;
    virtual void OnConnectChangedCallBack(int status, int networkId, const std::string &bssid,
        int locallyGenerated) = 0;
    virtual void OnWpaStateChangedCallBack(int status, void *pInstance) = 0;
    virtual void OnWpaSsidWrongKeyCallBack(const std::string &bssid, void *pInstance) = 0;
    virtual void OnWpsPbcOverlapCallBack(int status, void *pInstance) = 0;
    virtual void OnWpsTimeOutCallBack(int status, void *pInstance) = 0;
};

class StaMonitor : public MockStaMonitor {
public:

    MOCK_METHOD0(InitStaMonitor, ErrCode());
    MOCK_CONST_METHOD0(UnInitStaMonitor, ErrCode());
    MOCK_METHOD1(SetStateMachine, void(StaStateMachine *paraStaStateMachine));
    MOCK_METHOD4(OnConnectChangedCallBack, void(int status, int networkId, const std::string &bssid,
        int locallyGenerated));
    MOCK_METHOD2(OnWpaStateChangedCallBack, void(int status, void *pInstance));
    MOCK_METHOD2(OnWpaSsidWrongKeyCallBack, void(const std::string &bssid, void *pInstance));
    MOCK_METHOD2(OnWpsPbcOverlapCallBack, void(int status, void *pInstance));
    MOCK_METHOD2(OnWpsTimeOutCallBack, void(int status, void *pInstance));
};
}  // namespace Wifi
}  // namespace OHOS
#endif