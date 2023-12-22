/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_POWER_STATE_LISTENER_H
#define OHOS_WIFI_POWER_STATE_LISTENER_H

#include "power_mgr_client.h"
#include "sync_sleep_callback_stub.h"
#include "power_state_callback_stub.h"

namespace OHOS {
namespace Wifi {
using namespace OHOS::PowerMgr;
class WifiPowerStateListener : public SyncSleepCallbackStub {
public:
    WifiPowerStateListener();
    virtual ~WifiPowerStateListener() {}
    static WifiPowerStateListener &GetInstance();
    void OnSyncSleep(bool onForceSleep) override;
    void OnSyncWakeup(bool onForceSleep) override;
private:
    void DealPowerEnterSleepEvent();
    void DealPowerExitSleepEvent();
    std::map <int, bool> bWifiStateBeforeSleep;
};

} // namespace Wifi
} // namespace OHOS
#endif