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
#include "hotspot_config_parcel.h"
#include "wifi_ap_msg.h"

namespace OHOS {
namespace Wifi {
StationInfoParcel ToParcel(const StationInfo& info)
{
    return {
        info.deviceName,
        info.bssid,
        ToParcel<int32_t>(info.bssidType),
        info.ipAddr
    };
}

StationInfo FromParcel(const StationInfoParcel& parcel)
{
    return {
        parcel.deviceName,
        parcel.bssid,
        FromParcel<int>(parcel.bssidType),
        parcel.ipAddr
    };
}

HotspotConfigParcel& HotspotConfigParcel::operator=(const HotspotConfig& info)
{
    ssid = info.GetSsid();
    preSharedKey = info.GetPreSharedKey();
    securityType = info.GetSecurityType();
    band = info.GetBand();
    channel = info.GetChannel();
    maxConn = info.GetMaxConn();
    ipAddress = info.GetIpAddress();
    leaseTime = info.GetLeaseTime();
    apBandWidth = info.GetBandWidth();
    randomMac = info.GetRandomMac();

    return *this;
}

HotspotConfigParcel::HotspotConfigParcel(const HotspotConfig& info)
{
    *this = info;
}

void HotspotConfigParcel::FromHotspotConfig(const HotspotConfig &info)
{
    *this = info;
}

HotspotConfig HotspotConfigParcel::ToHotspotConfig() const
{
    HotspotConfig info;
    info.SetSsid(ssid);
    info.SetPreSharedKey(preSharedKey);
    info.SetSecurityType(securityType);
    info.SetBand(band);
    info.SetChannel(channel);
    info.SetMaxConn(maxConn);
    info.SetIpAddress(ipAddress);
    info.SetLeaseTime(leaseTime);
    info.SetBandWidth(apBandWidth);
    info.SetRandomMac(randomMac);

    return info;
}

bool HotspotConfigParcel::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(ssid) ||
        !parcel.WriteInt32(ToParcel<int32_t>(securityType)) ||
        !parcel.WriteInt32(ToParcel<int32_t>(band)) ||
        !parcel.WriteInt32(channel) ||
        !parcel.WriteString(preSharedKey) ||
        !parcel.WriteInt32(maxConn) ||
        !parcel.WriteString(ipAddress) ||
        !parcel.WriteInt32(leaseTime) ||
        !parcel.WriteInt32(apBandWidth) ||
        !parcel.WriteString(randomMac)) {
        return false;
    }

    return true;
}

HotspotConfigParcel *HotspotConfigParcel::Unmarshalling(Parcel &parcel)
{
    auto info = std::make_unique<HotspotConfigParcel>();
    if (!parcel.ReadString(info->ssid)) {
        return nullptr;
    }

    int32_t securityTypeValue = 0;
    if (!parcel.ReadInt32(securityTypeValue)) {
        return nullptr;
    }
    info->securityType = static_cast<KeyMgmt>(securityTypeValue);

    int32_t bandValue = 0;
    if (!parcel.ReadInt32(bandValue)) {
        return nullptr;
    }
    info->band = static_cast<BandType>(bandValue);

    if (!parcel.ReadInt32(info->channel) ||
        !parcel.ReadString(info->preSharedKey) ||
        !parcel.ReadInt32(info->maxConn) ||
        !parcel.ReadString(info->ipAddress) ||
        !parcel.ReadInt32(info->leaseTime) ||
        !parcel.ReadInt32(info->apBandWidth) ||
        !parcel.ReadString(info->randomMac)) {
        return nullptr;
    }
    
    return info.release();
}

}  // namespace Wifi
}  // namespace OHOS