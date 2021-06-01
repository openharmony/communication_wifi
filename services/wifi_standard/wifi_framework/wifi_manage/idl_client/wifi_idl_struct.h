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

#ifndef OHOS_WIFI_IDL_STRUCT_H
#define OHOS_WIFI_IDL_STRUCT_H

#include <string>
#include <vector>

namespace OHOS {
namespace Wifi {
#define MAX_WEPKEYS_SIZE (4)
#define AUTH_ALGORITHM_MAX (8)
struct WifiIdlDeviceConfig {
    int networkId;
    int priority;
    int scanSsid;
    int authAlgorithms; /* WifiDeviceConfig.allowedAuthAlgorithms */
    int wepKeyIdx;
    std::string wepKeys[MAX_WEPKEYS_SIZE]; /* max set 4 wepkeys */
    std::string ssid;
    std::string psk;
    std::string keyMgmt;
    std::string eap;
    std::string identity;
    std::string password;
    std::string bssid;

    WifiIdlDeviceConfig()
    {
        networkId = -1;
        priority = -1;
        scanSsid = -1;
        authAlgorithms = -1;
        wepKeyIdx = -1;
    }
};
struct WifiIdlGetDeviceConfig {
    int networkId;
    std::string param;
    std::string value;

    WifiIdlGetDeviceConfig()
    {
        networkId = -1;
    }
};
struct WifiIdlWpsConfig {
    int anyFlag;
    int multiAp;
    std::string bssid;

    WifiIdlWpsConfig()
    {
        anyFlag = -1;
        multiAp = -1;
    }
};

struct WifiIdlRoamCapability {
    int maxBlocklistSize;
    int maxTrustlistSize;

    WifiIdlRoamCapability()
    {
        maxBlocklistSize = 0;
        maxTrustlistSize = 0;
    }
};

struct WifiIdlRoamConfig {
    std::vector<std::string> blocklistBssids;
    std::vector<std::string> trustlistBssids;
};

class WifiWpaNetworkList {
public:
    int id;
    std::string ssid;
    std::string bssid;
    std::string flag;
};

struct WifiInterfaceInfo {
    int index;
    int type;
    std::string name;
    std::string mac;

    WifiInterfaceInfo() : index(0), type(0)
    {}
};
}  // namespace Wifi
}  // namespace OHOS
#endif