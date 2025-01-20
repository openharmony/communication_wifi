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

#ifndef OHOS_WIFI_PRO_PERF_5G_SWITCHABLE_AP_INFO_H
#define OHOS_WIFI_PRO_PERF_5G_SWITCHABLE_AP_INFO_H

#include <string>
#include "connected_ap.h"
#include "relation_ap.h"

namespace OHOS {
namespace Wifi {

struct SwitchableApInfo {
    long id;
    int networkId;
    std::string ssid;
    std::string bssid;
    std::string keyMgmt;
    int networkStatus;
    int frequency;
    std::string rttProduct;
    std::string rttPacketVolume;
    std::string otaLostRates;
    std::string otaPktVolumes;
    std::string otaBadPktProducts;
    long totalUseTime;
    SwitchableApInfo() : networkId(-1), totalUseTime(0)
    {}
    SwitchableApInfo(ApInfo &apInfo)
    {
        id = apInfo.id;
        networkId = apInfo.networkId;
        ssid = apInfo.ssid;
        bssid = apInfo.bssid;
        keyMgmt = apInfo.keyMgmt;
        networkStatus = static_cast<int>(apInfo.networkStatus);
        frequency = apInfo.frequency;
        rttProduct = apInfo.apConnectionInfo.GetRttProductString();
        rttPacketVolume = apInfo.apConnectionInfo.GetRttPacketVolumeString();
        otaLostRates = apInfo.apConnectionInfo.GetOtaLostRatesString();
        otaPktVolumes = apInfo.apConnectionInfo.GetOtaPktVolumesString();
        otaBadPktProducts = apInfo.apConnectionInfo.GetOtaBadPktProductsString();
        totalUseTime = apInfo.apConnectionInfo.GetTotalUseTime();
    }
    void BuildApInfo(ApInfo &apInfo)
    {
        apInfo.id = id;
        apInfo.networkId = networkId;
        apInfo.ssid = ssid;
        apInfo.bssid = bssid;
        apInfo.keyMgmt = keyMgmt;
        apInfo.rssi = INVALID_RSSI;
        apInfo.networkStatus = static_cast<NetworkStatus>(networkStatus);
        apInfo.frequency = frequency;
        BuildApConnectionInfo(apInfo.apConnectionInfo);
    }
    void BuildApConnectionInfo(ApConnectionInfo &apConnectionInfo)
    {
        apConnectionInfo.AddUseTime(totalUseTime);
        apConnectionInfo.SetRttProducts(rttProduct);
        apConnectionInfo.SetRttPacketVolumes(rttPacketVolume);
        apConnectionInfo.SetOtaLostRates(otaLostRates);
        apConnectionInfo.SetOtaPktVolumes(otaPktVolumes);
        apConnectionInfo.SetOtaBadPktProducts(otaBadPktProducts);
    }
};

}  // namespace Wifi
}  // namespace OHOS
#endif