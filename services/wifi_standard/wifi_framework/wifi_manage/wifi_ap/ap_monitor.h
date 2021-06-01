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
#ifndef OHOS_AP_MONITOR_H
#define OHOS_AP_MONITOR_H

#include "wifi_ap_hal_interface.h"
#include "ap_define.h"
#include "ap_stations_manager.h"
#include "wifi_ap_dhcp_interface.h"
#include "wifi_idl_define.h"

namespace OHOS {
namespace Wifi {
class ApMonitor {
public:
    /**
     * @Description  Obtains the single g_instance
     * @param None
     * @return The reference of singleton objects
     */
    static ApMonitor &GetInstance();
    /**
     * @Description  Delete the single g_instance
     * @param None
     * @return None
     */
    static void DeleteInstance();

    /**
     * @Description  IDL called this interface when STA connected or
                     disconnected, report to state machine.
     * @param staInfo - structure stored STA infos, only MAC
     * @param event - event STA connected or disconnected.
     * @return None
     */
    void StationChangeEvent(StationInfo &staInfo, const int event) const;
    /**
     * @Description  Asynchronously notifies the hostapd of the enable and disable status.
     * @param state - hostapd status
     * @return None
     */
    void OnHotspotStateEvent(int state) const;
    /**
     * @Description  start monitor
     * @param None
     * @return None
     */
    void StartMonitor();
    /**
     * @Description  close monitor
     * @param None
     * @return None
     */
    void StopMonitor();

private:
    ApMonitor();
    ~ApMonitor();
    DISALLOW_COPY_AND_ASSIGN(ApMonitor)

private:
    IWifiApEventCallback wifiApEventCallback;
};
}  // namespace Wifi
}  // namespace OHOS

#endif