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
#include "wifi_scan_info_parcel.h"

namespace OHOS {
namespace Wifi {

WifiScanInfoParcel WifiScanInfoParcel::FromWifiScanInfo(const WifiScanInfo &info)
{
    WifiScanInfoParcel parcel;
    parcel.bssid = info.bssid;
    parcel.ssid = info.ssid;
    parcel.bssidType = info.bssidType;
    parcel.capabilities = info.capabilities;
    parcel.frequency = info.frequency;
    parcel.band = info.band;
    parcel.channelWidth = info.channelWidth;
    parcel.centerFrequency0 = info.centerFrequency0;
    parcel.centerFrequency1 = info.centerFrequency1;
    parcel.rssi = info.rssi;
    parcel.securityType = info.securityType;
    parcel.features = info.features;
    parcel.timestamp = info.timestamp;
    parcel.wifiStandard = info.wifiStandard;
    parcel.maxSupportedRxLinkSpeed = info.maxSupportedRxLinkSpeed;
    parcel.maxSupportedTxLinkSpeed = info.maxSupportedTxLinkSpeed;
    parcel.disappearCount = info.disappearCount;
    parcel.isHiLinkNetwork = info.isHiLinkNetwork;
    parcel.isHiLinkProNetwork = info.isHiLinkProNetwork;
    parcel.supportedWifiCategory = info.supportedWifiCategory;
#ifdef WIFI_LOCAL_SECURITY_DETECT_ENABLE
    parcel.riskType = info.riskType;
#endif

    for (const auto &elem : info.infoElems) {
        parcel.infoElems.push_back(WifiInfoElemParcel::FromWifiInfoElem(elem));
    }
    return parcel;
}

WifiScanInfo WifiScanInfoParcel::ToWifiScanInfo() const
{
    WifiScanInfo info;
    info.bssid = bssid;
    info.ssid = ssid;
    info.bssidType = bssidType;
    info.capabilities = capabilities;
    info.frequency = frequency;
    info.band = band;
    info.channelWidth = channelWidth;
    info.centerFrequency0 = centerFrequency0;
    info.centerFrequency1 = centerFrequency1;
    info.rssi = rssi;
    info.securityType = securityType;
    info.features = features;
    info.timestamp = timestamp;
    info.wifiStandard = wifiStandard;
    info.maxSupportedRxLinkSpeed = maxSupportedRxLinkSpeed;
    info.maxSupportedTxLinkSpeed = maxSupportedTxLinkSpeed;
    info.disappearCount = disappearCount;
    info.isHiLinkNetwork = isHiLinkNetwork;
    info.isHiLinkProNetwork = isHiLinkProNetwork;
    info.supportedWifiCategory = supportedWifiCategory;
#ifdef WIFI_LOCAL_SECURITY_DETECT_ENABLE
    info.riskType = riskType;
#endif

    for (const auto &elemParcel : infoElems) {
        info.infoElems.push_back(elemParcel.ToWifiInfoElem());
    }
    return info;
}


bool WifiScanInfoParcel::Marshalling(Parcel &parcel) const
{
    parcel.WriteString(bssid);
    parcel.WriteString(ssid);
    parcel.WriteInt32(bssidType);
    parcel.WriteString(capabilities);
    parcel.WriteInt32(frequency);
    parcel.WriteInt32(band);

    if (!parcel.WriteInt32(static_cast<int32_t>(channelWidth)) ||
        !parcel.WriteInt32(centerFrequency0) ||
        !parcel.WriteInt32(centerFrequency1) ||
        !parcel.WriteInt32(rssi) ||
        !parcel.WriteInt32(static_cast<int32_t>(securityType))) {
        return false;
    }

    if (!parcel.WriteUint32(infoElems.size())) return false;
    for (const auto &elem : infoElems) {
        if (!elem.Marshalling(parcel)) return false;
    }

    if (!parcel.WriteInt64(features) ||
        !parcel.WriteInt64(timestamp) ||
        !parcel.WriteInt32(wifiStandard) ||
        !parcel.WriteInt32(maxSupportedRxLinkSpeed) ||
        !parcel.WriteInt32(maxSupportedTxLinkSpeed) ||
        !parcel.WriteInt32(disappearCount) ||
        !parcel.WriteInt32(isHiLinkNetwork) ||
        !parcel.WriteInt32(static_cast<int32_t>(supportedWifiCategory))) {
        return false;
    }
#ifdef WIFI_LOCAL_SECURITY_DETECT_ENABLE
    if (!parcel.WriteInt32(static_cast<int32_t>(riskType))) {
        return false;
    }
#endif
    return true;
}

bool WifiScanInfoParcel::ReadBasicFields(Parcel &parcel, WifiScanInfoParcel *info)
{
    if (!info) {
        return false;
    }
    parcel.ReadString(info->bssid);
    parcel.ReadString(info->ssid);
    parcel.ReadInt32(info->bssidType);
    parcel.ReadString(info->capabilities);
    parcel.ReadInt32(info->frequency);
    parcel.ReadInt32(info->band);

    int32_t channelWidthValue = 0;
    if (!parcel.ReadInt32(channelWidthValue)) {
        return false;
    }
    info->channelWidth = static_cast<WifiChannelWidth>(channelWidthValue);

    if (!parcel.ReadInt32(info->centerFrequency0) ||
        !parcel.ReadInt32(info->centerFrequency1) ||
        !parcel.ReadInt32(info->rssi)) {
        return false;
    }

    return true;
}

WifiScanInfoParcel *WifiScanInfoParcel::Unmarshalling(Parcel &parcel)
{
    auto info = std::make_unique<WifiScanInfoParcel>();
    if (!ReadBasicFields(parcel, info.get())) {
        return nullptr;
    }
    int32_t securityTypeValue = 0;
    if (!parcel.ReadInt32(securityTypeValue)) {
        return nullptr;
    }
    info->securityType = static_cast<WifiSecurity>(securityTypeValue);
   
    uint32_t elemCount = 0;
    if (!parcel.ReadUint32(elemCount)) return nullptr;
    info->infoElems.reserve(elemCount);
    
    for (uint32_t i = 0; i < elemCount; i++) {
        std::unique_ptr<WifiInfoElemParcel> elem(WifiInfoElemParcel::Unmarshalling(parcel));
        if (!elem) return nullptr;
        info->infoElems.push_back(std::move(*elem));
    }

    if (!parcel.ReadInt64(info->features) ||
        !parcel.ReadInt64(info->timestamp) ||
        !parcel.ReadInt32(info->wifiStandard) ||
        !parcel.ReadInt32(info->maxSupportedRxLinkSpeed) ||
        !parcel.ReadInt32(info->maxSupportedTxLinkSpeed) ||
        !parcel.ReadInt32(info->disappearCount) ||
        !parcel.ReadInt32(info->isHiLinkNetwork) ||
        !parcel.ReadBool(info->isHiLinkProNetwork)) {
        return nullptr;
    }

    int32_t categoryValue = 0;
    if (!parcel.ReadInt32(categoryValue)) {
        return nullptr;
    }
    info->supportedWifiCategory = static_cast<WifiCategory>(categoryValue);
#ifdef WIFI_LOCAL_SECURITY_DETECT_ENABLE
    int32_t riskTypeValue = 0;
    if (!parcel.ReadInt32(riskTypeValue)) {
        return nullptr;
    }
    info->riskType = static_cast<WifiRiskType>(riskTypeValue);
#endif
    return info.release();
}

}  // namespace Wifi
}  // namespace OHOS