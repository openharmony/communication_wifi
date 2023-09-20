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

#ifndef OHOS_WIFI_COMMON_MSG_H
#define OHOS_WIFI_COMMON_MSG_H
#include <string>

namespace OHOS {
namespace Wifi {
enum class ServiceType {
    DEFAULT = 0,
    WIFI_EXT = 1,
};

constexpr int RANDOM_DEVICE_ADDRESS = 0;
constexpr int REAL_DEVICE_ADDRESS = 1;

enum class WifiMacAddrInfoType {
    WIFI_SCANINFO_MACADDR_INFO     = 0,
    HOTSPOT_MACADDR_INFO           = 1,
    P2P_DEVICE_MACADDR_INFO        = 2,
    P2P_GROUPSINFO_MACADDR_INFO    = 3,
    P2P_CURRENT_GROUP_MACADDR_INFO = 4,
    INVALID_MACADDR_INFO
};

struct WifiMacAddrInfo {
    std::string bssid; /* mac address */
    int bssidType; /* mac address type */
    bool operator == (const WifiMacAddrInfo& mac)
    {
        if ((bssid == mac.bssid) && (bssidType == mac.bssidType)) {
            return true;
        }
        return false;
    }
    bool operator != (const WifiMacAddrInfo& mac)
    {
        if ((bssid != mac.bssid) || (bssidType != mac.bssidType)) {
            return true;
        }
        return false;
    }
    bool operator < (const WifiMacAddrInfo& mac) const
    {
        if (bssid == mac.bssid) {
            return bssidType < mac.bssidType;
        }
        return bssid < mac.bssid;
    }
    WifiMacAddrInfo& operator = (const WifiMacAddrInfo& mac)
    {
        bssid = mac.bssid;
        bssidType = mac.bssidType;
        return *this;
    }
};
}  // namespace Wifi
}  // namespace OHOS
#endif