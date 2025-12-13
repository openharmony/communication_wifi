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
#ifndef HOTSPOT_CONFIG_PARCEL_H
#define HOTSPOT_CONFIG_PARCEL_H

#include <string>
#include "parcel.h"
#include "wifi_ap_msg.h"
#include "hotspot_types.h"

namespace OHOS {
namespace Wifi {
template <typename ParcelT, typename T>
inline ParcelT ToParcel(const T& value)
{
    return static_cast<ParcelT>(value);
}

template <typename T, typename ParcelT>
inline T FromParcel(const ParcelT& parcelValue)
{
    return static_cast<T>(parcelValue);
}

StationInfoParcel ToParcel(const StationInfo& info);
StationInfo FromParcel(const StationInfoParcel& parcel);

struct HotspotConfigParcel : public Parcelable {
    HotspotConfigParcel() = default;
    HotspotConfigParcel(const HotspotConfig &info);
    void FromHotspotConfig(const HotspotConfig &info);
    HotspotConfig ToHotspotConfig() const;
    HotspotConfigParcel& operator=(const HotspotConfig& info);
    std::string ssid;
    std::string preSharedKey;
    KeyMgmt securityType;
    BandType band;
    int32_t channel;
    int32_t maxConn;
    std::string ipAddress;
    int32_t leaseTime;
    int32_t apBandWidth;
    std::string randomMac;

    bool Marshalling(Parcel &parcel) const override;
    static HotspotConfigParcel *Unmarshalling(Parcel &parcel);
};

}  // namespace Wifi
}  // namespace OHOS

#endif  // HOTSPOT_CONFIG_PARCEL_H