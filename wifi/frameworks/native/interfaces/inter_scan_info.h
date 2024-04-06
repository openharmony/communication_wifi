/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_WIFI_INTER_SCAN_INFO_H
#define OHOS_WIFI_INTER_SCAN_INFO_H

#include "wifi_scan_msg.h"
namespace OHOS {
namespace Wifi {
constexpr int WIFI_MODE_UNDEFINED = 0;
constexpr int WIFI_802_11A = 1;
constexpr int WIFI_802_11B = 2;
constexpr int WIFI_802_11G = 3;
constexpr int WIFI_802_11N = 4;
constexpr int WIFI_802_11AC = 5;
constexpr int WIFI_802_11AX = 6;

enum class Ant {
    NETWORK_PRIVATE = 0,
    NETWORK_PRIVATEWITHGUEST = 1,
    NETWORK_CHARGEABLEPUBLIC = 2,
    NETWORK_FREEPUBLIC = 3,
    NETWORK_PERSONAL = 4,
    NETWORK_EMERGENCYONLY = 5,
    NETWORK_RESVD6 = 6,
    NETWORK_RESVD7 = 7,
    NETWORK_RESVD8 = 8,
    NETWORK_RESVD9 = 9,
    NETWORK_RESVD10 = 10,
    NETWORK_RESVD11 = 11,
    NETWORK_RESVD12 = 12,
    NETWORK_RESVD13 = 13,
    NETWORK_TESTOREXPERIMENTAL = 14,
    NETWORK_WILDCARD = 15,
    NETWORK_ANT_INVALID = 16
};

struct InterScanInfo {
    std::string bssid;
    std::string ssid;
    /**
     * Network performance, including authentication,
     * key management, and encryption mechanisms
     * supported by the access point
     */
    std::string capabilities;
    int frequency;
    int band;  /* ap band, 1: 2.4G, 2: 5G */
    WifiChannelWidth channelWidth;
    int centerFrequency0;
    int centerFrequency1;
    int rssi; /* signal level */
    WifiSecurity securityType;
    std::vector<WifiInfoElem> infoElems;
    int64_t features;
    int64_t timestamp;
    Ant ant;
    int wifiMode;
    bool isVhtInfoExist;
    bool isHtInfoExist;
    bool isHeInfoExist;
    bool isErpExist;
    int maxRates;
    bool isHiLinkNetwork;

    InterScanInfo()
        : frequency(0),
          band(0),
          channelWidth(WifiChannelWidth::WIDTH_INVALID),
          centerFrequency0(0),
          centerFrequency1(0),
          rssi(0),
          securityType(WifiSecurity::INVALID),
          features(0),
          timestamp(0),
          ant(Ant::NETWORK_ANT_INVALID),
          wifiMode(WIFI_MODE_UNDEFINED),
          isVhtInfoExist(false),
          isHtInfoExist(false),
          isHeInfoExist(false),
          isErpExist(false),
          maxRates(0),
          isHiLinkNetwork(false) {}

    ~InterScanInfo() {}

    void GetDeviceMgmt(std::string &mgmt) const
    {
        switch (securityType) {
            case WifiSecurity::PSK:
                mgmt = "WPA-PSK";
                break;
            case WifiSecurity::EAP:
                mgmt = "WPA-EAP";
                break;
            case WifiSecurity::SAE:
                mgmt = "SAE";
                break;
            case WifiSecurity::OWE:
                mgmt = "OWE";
                break;
            case WifiSecurity::WEP:
                mgmt = "WEP";
                break;
            default:
                mgmt = "NONE";
                break;
        }
    }

    void GetWifiStandard(int &standard) const
    {
        standard = wifiMode;
    }

    bool IsWifi11bMode() const
    {
        return wifiMode == WIFI_802_11B;
    }
};
}
}
#endif
