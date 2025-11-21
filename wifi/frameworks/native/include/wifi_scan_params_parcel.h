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
#ifndef WIFI_SCAN_PARAMS_PARCEL_H
#define WIFI_SCAN_PARAMS_PARCEL_H

#include "parcel.h"
#include <string>
#include <vector>
#include "wifi_scan_msg.h"

namespace OHOS {
namespace Wifi {
struct WifiScanParamsParcel : public Parcelable {
    WifiScanParamsParcel(const WifiScanParams &params);
    WifiScanParams ToWifiScanParams() const;

    WifiScanParamsParcel() = default;
    std::string ssid;
    std::string bssid;
    int band;
    std::vector<int> freqs;

    bool Marshalling(Parcel &parcel) const override;
    static WifiScanParamsParcel *Unmarshalling(Parcel &parcel);
};
}  // namespace Wifi
}  // namespace OHOS

#endif  // WIFI_SCAN_PARAMS_PARCEL_H