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
    void StartSatelliteTimer(void);
    void StopSatelliteTimer(void);
    void DealStaOpened(int instId);
    void DealStaStopped(int instId);
    void StaCloseDhcpSa(void);

private:
    void InitStaCallback(void);
    void DealStaConnChanged(OperateResState state, const WifiLinkedInfo &info, int instId = 0);
    void DealWpsChanged(WpsStartState state, const int pinCode, int instId = 0);
    void DealStreamChanged(StreamDirection direction, int instId = 0);
    void DealRssiChanged(int rssi, int instId = 0);
    void DealAutoSelectNetworkChanged(int networkId, int instId);
    void PublishWifiOperateStateHiSysEvent(OperateResState state);
    void NotifyScanForStaConnChanged(OperateResState state, int networkId, int instId = 0);
    void DealInternetAccessChanged(int internetAccessStatus, int instId);
    void DealSignalPollReport(const std::string &bssid, const int32_t signalLevel, const int32_t instId = 0);
private:
    StaServiceCallback mStaCallback;
    uint32_t unloadStaSaTimerId{0};
    std::mutex unloadStaSaTimerMutex;
    uint32_t satelliteTimerId{0};
    std::mutex satelliteTimerMutex;
};
}  // namespace Wifi
}  // namespace OHOS
#endif // OHOS_WIFI_STA_MANAGER_H