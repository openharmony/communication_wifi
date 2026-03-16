/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "oh_wifi.h"
#include "wifi_device.h"
#include <cstring>
#include <string>

std::shared_ptr<OHOS::Wifi::WifiDevice> g_WifiDevicePtr = OHOS::Wifi::WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);

static Wifi_ResultCode WifiErrCodeToResultCode(OHOS::Wifi::ErrCode errCode)
{
    switch (errCode) {
        case OHOS::Wifi::WIFI_OPT_SUCCESS:
            return WIFI_SUCCESS;
        case OHOS::Wifi::WIFI_OPT_PERMISSION_DENIED:
            return WIFI_PERMISSION_DENIED;
        case OHOS::Wifi::WIFI_OPT_INVALID_PARAM:
            return WIFI_INVALID_PARAM;
        case OHOS::Wifi::WIFI_OPT_NOT_SUPPORTED:
            return WIFI_NOT_SUPPORTED;
        case OHOS::Wifi::WIFI_OPT_STA_NOT_OPENED:
            return WIFI_STA_DISABLED;
        default:
            return WIFI_OPERATION_FAILED;
    }
}

Wifi_ResultCode OH_Wifi_IsWifiEnabled(bool *enabled)
{
    if (enabled == nullptr) {
        return WIFI_INVALID_PARAM;
    }

    if (g_WifiDevicePtr == nullptr) {
        return WIFI_OPERATION_FAILED;
    }

    bool isEnabled = false;
    OHOS::Wifi::ErrCode ret = g_WifiDevicePtr->IsWifiActive(isEnabled);
    if (ret != OHOS::Wifi::WIFI_OPT_SUCCESS) {
        return WifiErrCodeToResultCode(ret);
    }

    *enabled = isEnabled;
    return WIFI_SUCCESS;
}

Wifi_ResultCode OH_Wifi_GetDeviceMacAddress(char *macAddr, unsigned int *macAddrLen)
{
    if (macAddr == nullptr || macAddrLen == nullptr) {
        return WIFI_INVALID_PARAM;
    }
 
    if (g_WifiDevicePtr == nullptr) {
        return WIFI_OPERATION_FAILED;
    }

    std::string mac;
    OHOS::Wifi::ErrCode ret = g_WifiDevicePtr->GetDeviceMacAddress(mac);
    if (ret != OHOS::Wifi::WIFI_OPT_SUCCESS) {
        return WifiErrCodeToResultCode(ret);
    }

    if (strncpy_s(macAddr, *macAddrLen, mac.c_str(), mac.length()) != 0) {
        return WIFI_OPERATION_FAILED;
    }

    return WIFI_SUCCESS;
}

Wifi_ResultCode OH_Wifi_GetLinkedInfo(OHWifiLinkedInfo *info)
{
    if (info == nullptr) {
        return WIFI_INVALID_PARAM;
    }

    if (g_WifiDevicePtr == nullptr) {
        return WIFI_OPERATION_FAILED1;
    }
    OHOS::Wifi::WifiLinkedInfo linkedInfo;
    OHOS::Wifi::ErrCode ret = g_WifiDevicePtr->GetLinkedInfo(linkedInfo);
    if (ret != OHOS::Wifi::WIFI_OPT_SUCCESS) {
        return WifiErrCodeToResultCode(ret);
    }
    if (strncpy_s(info->ssid, sizeof(info->ssid), linkedInfo.ssid.c_str(), linkedInfo.ssid.length()) != 0) {
        return WIFI_OPERATION_FAILED3;
    }
    if (strncpy_s(info->bssid, WIFI_MAC_LEN, linkedInfo.bssid.c_str(), linkedInfo.bssid.length()) != 0) {
        return WIFI_OPERATION_FAILED4;
    }
    if (strncpy_s(info->macAddress, WIFI_MAC_LEN, linkedInfo.macAddress.c_str(), linkedInfo.macAddress.length()) != 0) {
        return WIFI_OPERATION_FAILED5;
    }
    info->networkId = linkedInfo.networkId;
    info->rssi = linkedInfo.rssi;
    info->band = linkedInfo.band;
    info->linkSpeed = linkedInfo.linkSpeed;
    info->frequency = linkedInfo.frequency;
    info->ifHiddenSSID = linkedInfo.ifHiddenSSID;
    info->isDataRestricted = linkedInfo.isDataRestricted;
    info->chload = linkedInfo.chload;
    info->snr = linkedInfo.snr;
    info->macType = linkedInfo.macType;
    info->ipAddress = linkedInfo.ipAddress;
    info->supplicantState = static_cast<int>(linkedInfo.supplicantState);
    info->connState = static_cast<int>(linkedInfo.connState);
    info->wifiStandard = linkedInfo.wifiStandard;
    info->maxSupportedRxLinkSpeed = linkedInfo.maxSupportedRxLinkSpeed;
    info->maxSupportedTxLinkSpeed = linkedInfo.maxSupportedTxLinkSpeed;
    info->rxLinkSpeed = linkedInfo.rxLinkSpeed;
    info->txLinkSpeed = linkedInfo.txLinkSpeed;
    info->channelWidth = static_cast<int>(linkedInfo.channelWidth);
    info->supportedWifiCategory = static_cast<int>(linkedInfo.supportedWifiCategory);
    info->isHiLinkNetwork = linkedInfo.isHiLinkNetwork;
    info->isHiLinkProNetwork = linkedInfo.isHiLinkProNetwork;
    info->wifiLinkType = static_cast<int>(linkedInfo.wifiLinkType);
    info->riskType = static_cast<int>(linkedInfo.riskType);
    return WIFI_SUCCESS;
}