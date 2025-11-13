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
#ifndef WIFI_SCAN_INFO_PARCEL_H
#define WIFI_SCAN_INFO_PARCEL_H

#include "parcel.h"
#include "wifi_scan_msg.h"
#include "wifi_info_elem_parcel.h"
#include <string>
#include <vector>

namespace OHOS {
namespace Wifi {
struct WifiScanInfoParcel : public Parcelable {

    static WifiScanInfoParcel FromWifiScanInfo(const WifiScanInfo &info);
    
    WifiScanInfo ToWifiScanInfo() const;

    std::string bssid;
    std::string ssid;
    int bssidType;
    std::string capabilities;
    int frequency;
    int band;
    WifiChannelWidth channelWidth;
    int centerFrequency0;
    int centerFrequency1;
    int rssi;
    WifiSecurity securityType;
    std::vector<WifiInfoElemParcel> infoElems;
    int64_t features;
    int64_t timestamp;
    int wifiStandard;
    int maxSupportedRxLinkSpeed;
    int maxSupportedTxLinkSpeed;
    int disappearCount;
    int isHiLinkNetwork;
    bool isHiLinkProNetwork;
    WifiCategory supportedWifiCategory;

    bool Marshalling(Parcel &parcel) const override;
    static WifiScanInfoParcel *Unmarshalling(Parcel &parcel);
};
}  // namespace Wifi
}  // namespace OHOS

#endif  // WIFI_SCAN_INFO_PARCEL_H