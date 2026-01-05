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
#include "wifi_scan_params_parcel.h"

namespace OHOS {
namespace Wifi {
#define MAX_FREQS_SIZE 512

WifiScanParamsParcel::WifiScanParamsParcel(const WifiScanParams &params)
    : ssid(params.ssid), bssid(params.bssid), band(params.band), freqs(params.freqs)
{}

WifiScanParams WifiScanParamsParcel::ToWifiScanParams() const
{
    WifiScanParams params;
    params.ssid = this->ssid;
    params.bssid = this->bssid;
    params.freqs = this->freqs;
    params.band = this->band;
    return params;
}

bool WifiScanParamsParcel::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(ssid))
        return false;
    if (!parcel.WriteString(bssid))
        return false;
    if (!parcel.WriteInt32(band))
        return false;

    if (!parcel.WriteUint32(freqs.size()))
        return false;
    for (int freq : freqs) {
        if (!parcel.WriteInt32(freq))
            return false;
    }

    return true;
}

WifiScanParamsParcel *WifiScanParamsParcel::Unmarshalling(Parcel &parcel)
{
    auto params = std::make_unique<WifiScanParamsParcel>();
    if (!parcel.ReadString(params->ssid) ||
        !parcel.ReadString(params->bssid) ||
        !parcel.ReadInt32(params->band)) {
        return nullptr;
    }

    uint32_t size = 0;
    if (!parcel.ReadUint32(size)) {
        return nullptr;
    }

    if (size < 0|| size > MAX_FREQS_SIZE) {
        return nullptr;
    }
    params->freqs.reserve(size);
    for (uint32_t i = 0; i < size; i++) {
        int freq = 0;
        if (!parcel.ReadInt32(freq)) {
            return nullptr;
        }
        params->freqs.push_back(freq);
    }

    return params.release();
}

}  // namespace Wifi
}  // namespace OHOS