/*
 * Copyright (C) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_PRO_PERF_5G_CONNECTED_AP_H
#define OHOS_WIFI_PRO_PERF_5G_CONNECTED_AP_H
#include <string>
#include "wifi_scan_msg.h"
#include "ap_connection_info.h"
#include "network_status_history_manager.h"
namespace OHOS {
namespace Wifi {

struct ApInfo {
    long id;
    int networkId;
    std::string ssid;
    std::string bssid;
    std::string keyMgmt;
    int rssi;
    int frequency;
    NetworkStatus networkStatus;
    WifiChannelWidth channelWidth;
    WifiCategory wifiCategory;
    ApConnectionInfo apConnectionInfo;

    ApInfo() : id(-1), networkId(-1), rssi(INVALID_RSSI), frequency(0), networkStatus(NetworkStatus::UNKNOWN)
    {}
    ApInfo(int networkId, std::string ssid, std::string bssid, std::string keyMgmt, int frequency)
    {
        this->networkId = networkId;
        this->ssid = ssid;
        this->bssid = bssid;
        this->keyMgmt = keyMgmt;
        this->frequency = frequency;
        networkStatus = NetworkStatus::UNKNOWN;
        id = -1;
    }
};

struct ConnectedAp {
    ApInfo apInfo;
    bool hasHistoryInfo = false;
    bool is5gAfterPerf = false;
    std::string perf5gStrategyName;
    bool canNotPerf;
    bool isMloConnected;
    WifiLinkType wifiLinkType = WifiLinkType::DEFAULT_LINK;
    ConnectedAp()
    {}
};
}  // namespace Wifi
}  // namespace OHOS
#endif