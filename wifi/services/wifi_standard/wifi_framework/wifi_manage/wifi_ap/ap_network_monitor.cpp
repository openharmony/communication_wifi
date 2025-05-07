/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "ap_network_monitor.h"
#include "wifi_hisysevent.h"
#include "wifi_logger.h"
#include "wifi_config_center.h"

DEFINE_WIFILOG_HOTSPOT_LABEL("WifiApNetworkMonitor");
namespace OHOS {
namespace Wifi {

const int AP_SERVICE_ID = 0;
const int AP_NET_ERROR = 1;

ApNetworkMonitor &ApNetworkMonitor::GetInstance()
{
    static ApNetworkMonitor gApNetworkMonitor;
    return gApNetworkMonitor;
}

void ApNetworkMonitor::DealApNetworkCapabilitiesChanged(const int apStatus)
{
    if (apStatus != 1) {
        return;
    }
    WifiOprMidState apMidState = WifiConfigCenter::GetInstance().GetApMidState(AP_SERVICE_ID);
    if (apMidState != WifiOprMidState::RUNNING) {
        WIFI_LOGI("DealApNetworkCapabilitiesChanged: apMidState is not RUNNING.");
        return;
    }
    std::vector<StationInfo> result;
    WifiConfigCenter::GetInstance().GetStationList(result);
    if (result.empty()) {
        WIFI_LOGI("DealApNetworkCapabilitiesChanged: GetStationList is empty.");
        return;
    }
    WriteSoftApClientAccessNetErrorHiSysEvent(AP_NET_ERROR);
    return;
}

} //namespace Wifi
} //namespace OHOS