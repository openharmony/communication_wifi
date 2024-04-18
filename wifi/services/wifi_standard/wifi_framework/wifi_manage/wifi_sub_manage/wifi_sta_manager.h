/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_STA_MANAGER_H
#define OHOS_WIFI_STA_MANAGER_H

#include <mutex>
#include <functional>
#include "wifi_errcode.h"
#include "sta_service_callback.h"
#include "wifi_internal_msg.h"

namespace OHOS {
namespace Wifi {
class WifiStaManager {
public:
    WifiStaManager();
    ~WifiStaManager() = default;

    StaServiceCallback& GetStaCallback(void);
    void StopUnloadStaSaTimer(void);
    void StartUnloadStaSaTimer(void);
    void CloseStaService(int instId = 0);

private:
    void InitStaCallback(void);
    void ForceStopWifi(int instId = 0);
    void DealStaOpenRes(OperateResState state, int instId = 0);
    void DealStaCloseRes(OperateResState state, int instId = 0);
    void DealStaConnChanged(OperateResState state, const WifiLinkedInfo &info, int instId = 0);
    void DealWpsChanged(WpsStartState state, const int pinCode, int instId = 0);
    void DealStreamChanged(StreamDirection direction, int instId = 0);
    void DealRssiChanged(int rssi, int instId = 0);
    void PublishWifiOperateStateHiSysEvent(OperateResState state);
private:
    StaServiceCallback mStaCallback;
    uint32_t unloadStaSaTimerId{0};
    std::mutex unloadStaSaTimerMutex;
    int mLastWifiOpenState = -1;
};

}  // namespace Wifi
}  // namespace OHOS
#endif // OHOS_WIFI_STA_MANAGER_H