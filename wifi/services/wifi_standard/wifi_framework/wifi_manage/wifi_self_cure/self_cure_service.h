/*
 * Copyright (C) 2023-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_SELF_CURE_SERVICE_H
#define OHOS_SELF_CURE_SERVICE_H

#include <vector>
#include "self_cure_state_machine.h"
#include "wifi_errcode.h"
#include "define.h"
#include "self_cure_common.h"
#include "wifi_service_manager.h"
#include "ip2p_service_callbacks.h"

namespace OHOS {
namespace Wifi {
class SelfCureService {
    FRIEND_GTEST(SelfCureService);
public:
    explicit SelfCureService(int instId = 0);
    virtual ~SelfCureService();
    virtual ErrCode InitSelfCureService();
    virtual void RegisterSelfCureServiceCallback(const std::vector<SelfCureServiceCallback> &callbacks) const;
    void HandleRssiLevelChanged(int rssi);
    void HandleStaConnChanged(OperateResState state, const WifiLinkedInfo &info);
    void HandleP2pConnChanged(const WifiP2pLinkedInfo &info);
private:
    SelfCureStateMachine *pSelfCureStateMachine;
    int m_instId;
};
} //namespace Wifi
} //namespace OHOS
#endif