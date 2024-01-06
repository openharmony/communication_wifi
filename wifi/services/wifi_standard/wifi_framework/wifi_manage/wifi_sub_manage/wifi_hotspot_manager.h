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

#ifndef OHOS_WIFI_HOTSPOT_MANAGER_H
#define OHOS_WIFI_HOTSPOT_MANAGER_H

#ifdef FEATURE_AP_SUPPORT
#include <mutex>
#include <functional>
#include "wifi_errcode.h"
#include "wifi_internal_msg.h"
#include "i_ap_service_callbacks.h"

namespace OHOS {
namespace Wifi {
class WifiHotspotManager {
public:
    WifiHotspotManager();
    ~WifiHotspotManager() = default;

    IApServiceCallbacks& GetApCallback(void);
    void StopUnloadApSaTimer(void);
    void StartUnloadApSaTimer(void);
    void CloseApService(int id = 0);

private:
    void InitApCallback(void);
    void DealApStateChanged(ApState bState, int id = 0);
    void DealApGetStaJoin(const StationInfo &info, int id = 0);
    void DealApGetStaLeave(const StationInfo &info, int id = 0);

private:
    IApServiceCallbacks mApCallback;
    uint32_t unloadHotspotSaTimerId{0};
    std::mutex unloadHotspotSaTimerMutex;
};

}  // namespace Wifi
}  // namespace OHOS
#endif
#endif // OHOS_WIFI_HOTSPOT_MANAGER_H