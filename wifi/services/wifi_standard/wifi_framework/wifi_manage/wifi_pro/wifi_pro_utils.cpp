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

#include <sys/time.h>
#include "net_conn_client.h"
#include "wifi_net_observer.h"
#include "parameters.h"
#include "wifi_config_center.h"
#include "wifi_logger.h"
#include "wifi_msg.h"
#include "wifi_pro_utils.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiProUtils");
int32_t WifiProUtils::GetSignalLevel(int32_t instId)
{
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo);
    return WifiSettings::GetInstance().GetSignalLevel(linkedInfo.rssi, linkedInfo.band, instId);
}

bool WifiProUtils::IsWifiConnected(int32_t instId)
{
    WifiLinkedInfo linkedInfo;
    WifiConfigCenter::GetInstance().GetLinkedInfo(linkedInfo, instId);
    return linkedInfo.connState == ConnState::CONNECTED;
}

int32_t WifiProUtils::GetScanInterval(bool hasWifiSwitchRecord, int32_t rssiLevel)
{
    if (rssiLevel > SIG_LEVEL_MAX) {
        WIFI_LOGI("GetScanInterval, invalid rssiLevel:%{public}d.", rssiLevel);
        return 0;
    }

    return hasWifiSwitchRecord ? QUICK_SCAN_INTERVAL[rssiLevel] : NORMAL_SCAN_INTERVAL[rssiLevel];
}

int32_t WifiProUtils::GetMaxCounter(bool hasWifiSwitchRecord, int32_t rssiLevel)
{
    if (rssiLevel > SIG_LEVEL_MAX) {
        WIFI_LOGI("GetMaxCounter, invalid rssiLevel:%{public}d.", rssiLevel);
        return 0;
    }

    return hasWifiSwitchRecord ? QUICK_SCAN_MAX_COUNTER[rssiLevel] : NORMAL_SCAN_MAX_COUNTER[rssiLevel];
}

int64_t WifiProUtils::GetCurrentTimeMs()
{
    auto timePoint = std::chrono::system_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(timePoint).count();
}

bool WifiProUtils::IsUserSelectNetwork()
{
    return system::GetParameter("persist.wifi.is_connect_from_user", "") == "1";
}

bool WifiProUtils::IsSupplicantConnecting(SupplicantState supplicantState)
{
    return supplicantState == SupplicantState::AUTHENTICATING ||
        supplicantState == SupplicantState::ASSOCIATING ||
        supplicantState == SupplicantState::ASSOCIATED ||
        supplicantState == SupplicantState::FOUR_WAY_HANDSHAKE ||
        supplicantState == SupplicantState::GROUP_HANDSHAKE ||
        supplicantState == SupplicantState::COMPLETED;
}

bool WifiProUtils::IsDefaultNet()
{
    NetManagerStandard::NetHandle defaultNet;
    NetManagerStandard::NetConnClient::GetInstance().GetDefaultNet(defaultNet);
    NetStateObserver netStateObserver;
    int32_t wifiNetId = netStateObserver.GetWifiNetId();
    WIFI_LOGI("IsDefaultNet, default netId:%{public}d, wifiNetId:%{public}d.", defaultNet.GetNetId(), wifiNetId);
    return defaultNet.GetNetId() == wifiNetId;
}

bool WifiProUtils::IsAppInWhiteLists()
{
    return false;
}
}  // namespace Wifi
}  // namespace OHOS
