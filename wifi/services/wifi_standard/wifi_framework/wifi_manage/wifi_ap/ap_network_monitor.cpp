/*
* Copyright (c) Huawei Technologies Co., Ltb. 2025-2025. All right reserved.
*/

#include "ap_network_monitor.h"
#include "wifi_hisysevent.h"
#include "wifi_logger.h"
#include "wifi_config_center.h"

DEFINE_WIFILOG_HOTSPOT_LABEL("wifiApNetworkMonitor");
namespace OHOS {
namespace Wifi {

const int AP_SERVICE_ID = 0;
const int AP_NET_ERROR = 1;

ApNetworkMonitor &ApNetworkMonitor::GetInstance()
{
    static ApNetworkMonitor gApNetworkMonitor;
    return gApNetworkMonitor;
}

void ApNetworkMonitor::DealApNetworkCapabilitiesChanged()
{
    WifiOprMidState apMidSate = WifiConfigCenter::GetInstance().GetApMidState(AP_SERVICE_ID);
    if (apMidState != WifiOprMidState::RUNNING) {
        WIFI_LOGI("DealApNetworkCapabilitiesChanged: apMidState is not RUNNING.");
        return;
    }
    std:vector<StationInfo> result;
    WifiConfigCenter::GetInstance().GetStationList(result);
    if (result.empty()) {
        WIFI_LOGI("DealApNetworkCapabilitiesChanged: GetStationList is empty.");
        return;
    }
    WifiSoftApClientAccessNetErrorHiSysEvent(AP_NET_ERROR);
    return;
}

} //namespace Wifi
} //namespace OHOS