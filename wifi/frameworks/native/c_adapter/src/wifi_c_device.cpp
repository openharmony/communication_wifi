/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#include "kits/c/wifi_device.h"
#include "inner_api/wifi_device.h"
#include "inner_api/wifi_scan.h"
#include "kits/c/wifi_scan_info.h"
#include "kits/c/wifi_device_config.h"
#include "wifi_logger.h"
#include "wifi_c_utils.h"
#include "wifi_common_util.h"
#include "inner_api/wifi_msg.h"

DEFINE_WIFILOG_LABEL("WifiCDevice");

static std::map<WifiSecurityType, std::string> g_secTypeKeyMgmtMap = {
    {WIFI_SEC_TYPE_OPEN, "NONE"},
    {WIFI_SEC_TYPE_WEP, "WEP"},
    {WIFI_SEC_TYPE_PSK, "WPA-PSK"},
    {WIFI_SEC_TYPE_SAE, "SAE"},
};

std::shared_ptr<OHOS::Wifi::WifiDevice> wifiDevicePtr = OHOS::Wifi::WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);
std::shared_ptr<OHOS::Wifi::WifiScan> wifiScanPtr = OHOS::Wifi::WifiScan::GetInstance(WIFI_SCAN_ABILITY_ID);

NO_SANITIZE("cfi") WifiErrorCode EnableWifi()
{
    CHECK_PTR_RETURN(wifiDevicePtr, ERROR_WIFI_NOT_AVAILABLE);
    return GetCErrorCode(wifiDevicePtr->EnableWifi());
}

NO_SANITIZE("cfi") WifiErrorCode DisableWifi()
{
    CHECK_PTR_RETURN(wifiDevicePtr, ERROR_WIFI_NOT_AVAILABLE);
    return GetCErrorCode(wifiDevicePtr->DisableWifi());
}

NO_SANITIZE("cfi") int IsWifiActive()
{
    if (wifiDevicePtr == nullptr) {
        return false;
    }

    bool isActive = false;
    OHOS::Wifi::ErrCode ret = wifiDevicePtr->IsWifiActive(isActive);
    return (ret == OHOS::Wifi::WIFI_OPT_SUCCESS) && isActive;
}

NO_SANITIZE("cfi") int IsMeteredHotspot()
{
    if (wifiDevicePtr == nullptr) {
        return false;
    }

    bool isMeteredHotspot = false;
    OHOS::Wifi::ErrCode ret = wifiDevicePtr->IsMeteredHotspot(isMeteredHotspot);
    return (ret == OHOS::Wifi::WIFI_OPT_SUCCESS) && isMeteredHotspot;
}

NO_SANITIZE("cfi") WifiErrorCode Scan()
{
    CHECK_PTR_RETURN(wifiScanPtr, ERROR_WIFI_NOT_AVAILABLE);
    return GetCErrorCode(wifiScanPtr->Scan(true));
}

NO_SANITIZE("cfi") WifiErrorCode GetScanInfoList(WifiScanInfo *result, unsigned int *size)
{
    CHECK_PTR_RETURN(wifiScanPtr, ERROR_WIFI_NOT_AVAILABLE);
    if (result == nullptr || size == nullptr) {
        WIFI_LOGE("Scan info input parameter is nullptr!");
        return ERROR_WIFI_UNKNOWN;
    }

    std::vector<OHOS::Wifi::WifiScanInfo> vecScanInfos;
    OHOS::Wifi::ErrCode ret = wifiScanPtr->GetScanInfoList(vecScanInfos, true);
    int vecSize = (int)vecScanInfos.size();
    for (int i = 0; i < vecSize && i < WIFI_SCAN_HOTSPOT_LIMIT; ++i) {
        if (memcpy_s(result->ssid, WIFI_MAX_SSID_LEN,
            vecScanInfos[i].ssid.c_str(), vecScanInfos[i].ssid.size() + 1) != EOK) {
            return ERROR_WIFI_UNKNOWN;
        }
        if (OHOS::Wifi::MacStrToArray(vecScanInfos[i].bssid, result->bssid) != EOK) {
            WIFI_LOGE("Scan info convert bssid error!");
            return ERROR_WIFI_UNKNOWN;
        }
        result->bssidType = vecScanInfos[i].bssidType;
        result->securityType = static_cast<int>(vecScanInfos[i].securityType);
        result->rssi = vecScanInfos[i].rssi;
        result->band = vecScanInfos[i].band;
        result->frequency = vecScanInfos[i].frequency;
        result->channelWidth = WifiChannelWidth(static_cast<int>(vecScanInfos[i].channelWidth));
        result->centerFrequency0 = vecScanInfos[i].centerFrequency0;
        result->centerFrequency1 = vecScanInfos[i].centerFrequency1;
        result->timestamp = vecScanInfos[i].timestamp;
        ++result;
    }
    *size = (vecSize < WIFI_SCAN_HOTSPOT_LIMIT) ? vecSize : WIFI_SCAN_HOTSPOT_LIMIT;
    return GetCErrorCode(ret);
}

static std::string GetKeyMgmtBySecType(const int securityType)
{
    WifiSecurityType key = WifiSecurityType(securityType);
    std::map<WifiSecurityType, std::string>::const_iterator iter = g_secTypeKeyMgmtMap.find(key);
    return iter == g_secTypeKeyMgmtMap.end() ? "NONE" : iter->second;
}

static int GetSecTypeByKeyMgmt(const std::string& keyMgmt)
{
    for (auto& each : g_secTypeKeyMgmtMap) {
        if (each.second == keyMgmt) {
            return static_cast<int>(each.first);
        }
    }
    return static_cast<int>(WIFI_SEC_TYPE_OPEN);
}

static void GetStaticIpFromC(const IpConfig& ipConfig, OHOS::Wifi::StaticIpAddress& staticIp)
{
    /* Just IPV4 now */
    staticIp.ipAddress.address.addressIpv4 = ipConfig.ipAddress;
    staticIp.gateway.addressIpv4 = ipConfig.gateway;
    if (WIFI_MAX_DNS_NUM > 0) {
        staticIp.dnsServer1.addressIpv4 = ipConfig.dnsServers[0];
    }
    /* Has backup DNS server */
    if (WIFI_MAX_DNS_NUM > 1) {
        staticIp.dnsServer2.addressIpv4 = ipConfig.dnsServers[1];
    }
    /* netmask: automatic calculate netmask, don't support customized set this value currently */
}

static void GetStaticIpFromCpp(const OHOS::Wifi::StaticIpAddress& staticIp, IpConfig& ipConfig)
{
    /* Just IPV4 now */
    ipConfig.ipAddress = staticIp.ipAddress.address.addressIpv4;
    ipConfig.gateway = staticIp.gateway.addressIpv4;
    if (WIFI_MAX_DNS_NUM > 0) {
        ipConfig.dnsServers[0] = staticIp.dnsServer1.addressIpv4;
    }
    /* Has backup DNS server */
    if (WIFI_MAX_DNS_NUM > 1) {
        ipConfig.dnsServers[1] = staticIp.dnsServer2.addressIpv4;
    }
    /* netmask: not support now */
}

static OHOS::Wifi::ErrCode ConvertDeviceConfigFromC(
    const WifiDeviceConfig *config, OHOS::Wifi::WifiDeviceConfig& deviceConfig)
{
    CHECK_PTR_RETURN(config, OHOS::Wifi::WIFI_OPT_INVALID_PARAM);
    if (strnlen(config->ssid, WIFI_MAX_SSID_LEN) == WIFI_MAX_SSID_LEN) {
        return OHOS::Wifi::WIFI_OPT_INVALID_PARAM;
    }
    deviceConfig.ssid = config->ssid;
    if (OHOS::Wifi::IsMacArrayEmpty(config->bssid)) {
        deviceConfig.bssid = "";
    } else {
        deviceConfig.bssid = OHOS::Wifi::MacArrayToStr(config->bssid);
    }
    deviceConfig.bssidType = config->bssidType;
    if (strnlen(config->preSharedKey, WIFI_MAX_KEY_LEN) == WIFI_MAX_KEY_LEN) {
        return OHOS::Wifi::WIFI_OPT_INVALID_PARAM;
    }
    deviceConfig.preSharedKey = config->preSharedKey;
    deviceConfig.keyMgmt = GetKeyMgmtBySecType(config->securityType);
    deviceConfig.networkId = config->netId;
    deviceConfig.frequency = config->freq;
    deviceConfig.wifiPrivacySetting = OHOS::Wifi::WifiPrivacyConfig(config->randomMacType);
    /* wapiPskType is not support, don't verify now */
    if (config->ipType == DHCP) {
        deviceConfig.wifiIpConfig.assignMethod = OHOS::Wifi::AssignIpMethod::DHCP;
    } else if (config->ipType == STATIC_IP) {
        deviceConfig.wifiIpConfig.assignMethod = OHOS::Wifi::AssignIpMethod::STATIC;
        GetStaticIpFromC(config->staticIp, deviceConfig.wifiIpConfig.staticIpAddress);
    } else {
        deviceConfig.wifiIpConfig.assignMethod = OHOS::Wifi::AssignIpMethod::UNASSIGNED;
    }
    deviceConfig.hiddenSSID = config->isHiddenSsid;
    return OHOS::Wifi::WIFI_OPT_SUCCESS;
}

static OHOS::Wifi::ErrCode ConvertDeviceConfigFromCpp(const OHOS::Wifi::WifiDeviceConfig& deviceConfig,
    WifiDeviceConfig *result)
{
    CHECK_PTR_RETURN(result, OHOS::Wifi::WIFI_OPT_INVALID_PARAM);
    if (memcpy_s(result->ssid, WIFI_MAX_SSID_LEN, deviceConfig.ssid.c_str(), deviceConfig.ssid.size() + 1) != EOK) {
        return OHOS::Wifi::WIFI_OPT_FAILED;
    }
    if (OHOS::Wifi::MacStrToArray(deviceConfig.bssid, result->bssid) != EOK) {
        WIFI_LOGE("device config convert bssid error!");
        return OHOS::Wifi::WIFI_OPT_FAILED;
    }
    result->bssidType = deviceConfig.bssidType;
    if (memcpy_s(result->preSharedKey, WIFI_MAX_KEY_LEN, deviceConfig.preSharedKey.c_str(), WIFI_MAX_KEY_LEN) != EOK) {
        return OHOS::Wifi::WIFI_OPT_FAILED;
    }
    result->securityType = GetSecTypeByKeyMgmt(deviceConfig.keyMgmt);
    result->netId = deviceConfig.networkId;
    result->freq = deviceConfig.frequency;
    result->randomMacType = static_cast<int>(deviceConfig.wifiPrivacySetting);
    /* wapiPskType is not support now */
    if (deviceConfig.wifiIpConfig.assignMethod == OHOS::Wifi::AssignIpMethod::DHCP) {
        result->ipType = DHCP;
    } else if (deviceConfig.wifiIpConfig.assignMethod == OHOS::Wifi::AssignIpMethod::STATIC) {
        result->ipType = STATIC_IP;
        GetStaticIpFromCpp(deviceConfig.wifiIpConfig.staticIpAddress, result->staticIp);
    } else {
        result->ipType = UNKNOWN;
    }
    result->isHiddenSsid = deviceConfig.hiddenSSID;
    return OHOS::Wifi::WIFI_OPT_SUCCESS;
}

static void ConvertScanParamsFromC(const WifiScanParams *params, OHOS::Wifi::WifiScanParams& scanParams)
{
    CHECK_PTR_RETURN_VOID(params);
    scanParams.ssid = params->ssid;
    if (OHOS::Wifi::IsMacArrayEmpty(params->bssid)) {
        scanParams.bssid = "";
    } else {
        scanParams.bssid = OHOS::Wifi::MacArrayToStr(params->bssid);
    }
    scanParams.freqs.push_back(params->freqs);
    scanParams.band = params->band;
}

NO_SANITIZE("cfi") WifiErrorCode AddDeviceConfig(const WifiDeviceConfig *config, int *result)
{
    CHECK_PTR_RETURN(wifiDevicePtr, ERROR_WIFI_NOT_AVAILABLE);
    CHECK_PTR_RETURN(config, ERROR_WIFI_INVALID_ARGS);
    CHECK_PTR_RETURN(result, ERROR_WIFI_INVALID_ARGS);
    OHOS::Wifi::WifiDeviceConfig deviceConfig;
    OHOS::Wifi::ErrCode ret = ConvertDeviceConfigFromC(config, deviceConfig);
    if (ret != OHOS::Wifi::WIFI_OPT_SUCCESS) {
        WIFI_LOGE("AddDeviceConfig get device configs from c error!");
        return GetCErrorCode(ret);
    }
    int addResult = -1;
    bool isCandidate = false;
    ret = wifiDevicePtr->AddDeviceConfig(deviceConfig, addResult, isCandidate);
    *result = addResult;
    return GetCErrorCode(ret);
}

NO_SANITIZE("cfi") WifiErrorCode GetDeviceConfigs(WifiDeviceConfig *result, unsigned int *size)
{
    CHECK_PTR_RETURN(wifiDevicePtr, ERROR_WIFI_NOT_AVAILABLE);
    CHECK_PTR_RETURN(result, ERROR_WIFI_INVALID_ARGS);
    CHECK_PTR_RETURN(size, ERROR_WIFI_INVALID_ARGS);
    std::vector<OHOS::Wifi::WifiDeviceConfig> vecDeviceConfigs;
    bool isCandidate = false;
    OHOS::Wifi::ErrCode ret = wifiDevicePtr->GetDeviceConfigs(vecDeviceConfigs, isCandidate);
    if (ret != OHOS::Wifi::WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Get device configs error!");
        return GetCErrorCode(ret);
    }
    *size = (int)vecDeviceConfigs.size();
    for (auto& each : vecDeviceConfigs) {
        OHOS::Wifi::ErrCode retValue = ConvertDeviceConfigFromCpp(each, result++);
        if (retValue != OHOS::Wifi::WIFI_OPT_SUCCESS) {
            ret = retValue;
            WIFI_LOGE("Convert device configs error!");
        }
    }
    return GetCErrorCode(ret);
}

NO_SANITIZE("cfi") WifiErrorCode RemoveDevice(int networkId)
{
    CHECK_PTR_RETURN(wifiDevicePtr, ERROR_WIFI_NOT_AVAILABLE);
    return GetCErrorCode(wifiDevicePtr->RemoveDevice(networkId));
}

WifiErrorCode DisableDeviceConfig(int networkId)
{
    return GetCErrorCode(OHOS::Wifi::WIFI_OPT_NOT_SUPPORTED);
}

WifiErrorCode EnableDeviceConfig(int networkId)
{
    return GetCErrorCode(OHOS::Wifi::WIFI_OPT_NOT_SUPPORTED);
}

NO_SANITIZE("cfi") WifiErrorCode ConnectTo(int networkId)
{
    CHECK_PTR_RETURN(wifiDevicePtr, ERROR_WIFI_NOT_AVAILABLE);
    bool isCandidate = false;
    return GetCErrorCode(wifiDevicePtr->ConnectToNetwork(networkId, isCandidate));
}

NO_SANITIZE("cfi") WifiErrorCode ConnectToDevice(const WifiDeviceConfig *config)
{
    CHECK_PTR_RETURN(wifiDevicePtr, ERROR_WIFI_NOT_AVAILABLE);
    CHECK_PTR_RETURN(config, ERROR_WIFI_INVALID_ARGS);
    OHOS::Wifi::WifiDeviceConfig deviceConfig;
    OHOS::Wifi::ErrCode ret = ConvertDeviceConfigFromC(config, deviceConfig);
    if (ret != OHOS::Wifi::WIFI_OPT_SUCCESS) {
        WIFI_LOGE("ConnectToDevice get device configs from c error!");
        return GetCErrorCode(ret);
    }
    return GetCErrorCode(wifiDevicePtr->ConnectToDevice(deviceConfig));
}

NO_SANITIZE("cfi") WifiErrorCode Disconnect()
{
    CHECK_PTR_RETURN(wifiDevicePtr, ERROR_WIFI_NOT_AVAILABLE);
    return GetCErrorCode(wifiDevicePtr->Disconnect());
}

static OHOS::Wifi::ErrCode GetLinkedInfoFromCpp(const OHOS::Wifi::WifiLinkedInfo& linkedInfo, WifiLinkedInfo *result)
{
    CHECK_PTR_RETURN(result, OHOS::Wifi::WIFI_OPT_INVALID_PARAM);
    if (memcpy_s(result->ssid, WIFI_MAX_SSID_LEN, linkedInfo.ssid.c_str(), linkedInfo.ssid.size() + 1) != EOK) {
        return OHOS::Wifi::WIFI_OPT_FAILED;
    }
    if (OHOS::Wifi::MacStrToArray(linkedInfo.bssid, result->bssid) != EOK) {
        WIFI_LOGE("linked info convert bssid error!");
        return OHOS::Wifi::WIFI_OPT_FAILED;
    }
    result->rssi = linkedInfo.rssi;
    result->band = linkedInfo.band;
    result->frequency = linkedInfo.frequency;
    result->connState = linkedInfo.connState == OHOS::Wifi::ConnState::CONNECTED ? WIFI_CONNECTED : WIFI_DISCONNECTED;
    /* disconnectedReason not support */
    result->ipAddress = linkedInfo.ipAddress;
    result->wifiStandard = linkedInfo.wifiStandard;
    result->maxSupportedRxLinkSpeed = linkedInfo.maxSupportedRxLinkSpeed;
    result->maxSupportedTxLinkSpeed = linkedInfo.maxSupportedTxLinkSpeed;
    result->rxLinkSpeed = linkedInfo.rxLinkSpeed;
    result->txLinkSpeed = linkedInfo.txLinkSpeed;
    return OHOS::Wifi::WIFI_OPT_SUCCESS;
}

NO_SANITIZE("cfi") WifiErrorCode GetLinkedInfo(WifiLinkedInfo *result)
{
    CHECK_PTR_RETURN(wifiDevicePtr, ERROR_WIFI_NOT_AVAILABLE);
    CHECK_PTR_RETURN(result, ERROR_WIFI_INVALID_ARGS);
    OHOS::Wifi::WifiLinkedInfo linkedInfo;
    OHOS::Wifi::ErrCode ret = wifiDevicePtr->GetLinkedInfo(linkedInfo);
    if (ret == OHOS::Wifi::WIFI_OPT_SUCCESS) {
        OHOS::Wifi::ErrCode retValue = GetLinkedInfoFromCpp(linkedInfo, result);
        if (retValue != OHOS::Wifi::WIFI_OPT_SUCCESS) {
            WIFI_LOGE("Get linked info from cpp error!");
            ret = retValue;
        }
    }
    return GetCErrorCode(ret);
}

NO_SANITIZE("cfi") WifiErrorCode GetDisconnectedReason(DisconnectedReason *result)
{
    CHECK_PTR_RETURN(wifiDevicePtr, ERROR_WIFI_NOT_AVAILABLE);
    CHECK_PTR_RETURN(result, ERROR_WIFI_INVALID_ARGS);
    OHOS::Wifi::DisconnectedReason reason;
    OHOS::Wifi::ErrCode ret = wifiDevicePtr->GetDisconnectedReason(reason);
    if (ret == OHOS::Wifi::WIFI_OPT_SUCCESS) {
        *result = (DisconnectedReason)reason;
    } else {
        WIFI_LOGE("GetDisconnectedReason failed:%{public}d", ret);
    }
    return GetCErrorCode(ret);
}

NO_SANITIZE("cfi") WifiErrorCode GetDeviceMacAddress(unsigned char *result)
{
    CHECK_PTR_RETURN(wifiDevicePtr, ERROR_WIFI_NOT_AVAILABLE);
    CHECK_PTR_RETURN(result, ERROR_WIFI_INVALID_ARGS);
    std::string mac;
    OHOS::Wifi::ErrCode ret = wifiDevicePtr->GetDeviceMacAddress(mac);
    if (ret == OHOS::Wifi::WIFI_OPT_SUCCESS) {
        if (OHOS::Wifi::MacStrToArray(mac, result) != EOK) {
            WIFI_LOGE("get mac convert to array error!");
            return ERROR_WIFI_UNKNOWN;
        }
    }
    return GetCErrorCode(ret);
}

NO_SANITIZE("cfi") WifiErrorCode AdvanceScan(WifiScanParams *params)
{
    CHECK_PTR_RETURN(wifiScanPtr, ERROR_WIFI_NOT_AVAILABLE);
    CHECK_PTR_RETURN(params, ERROR_WIFI_INVALID_ARGS);
    OHOS::Wifi::WifiScanParams scanParams;
    ConvertScanParamsFromC(params, scanParams);
    OHOS::Wifi::ErrCode ret = wifiScanPtr->AdvanceScan(scanParams);
    return GetCErrorCode(ret);
}

static OHOS::Wifi::ErrCode GetIpInfoFromCpp(const OHOS::Wifi::IpInfo& ipInfo, IpInfo *info)
{
    CHECK_PTR_RETURN(info, OHOS::Wifi::WIFI_OPT_INVALID_PARAM);
    info->netGate = ipInfo.gateway;
    info->ipAddress = ipInfo.ipAddress;
    info->netMask = ipInfo.netmask;
    info->dns1 = ipInfo.primaryDns;
    info->dns2 = ipInfo.secondDns;
    info->serverAddress = ipInfo.serverIp;
    info->leaseDuration = ipInfo.leaseDuration;
    return OHOS::Wifi::WIFI_OPT_SUCCESS;
}

NO_SANITIZE("cfi") WifiErrorCode GetIpInfo(IpInfo *info)
{
    CHECK_PTR_RETURN(wifiDevicePtr, ERROR_WIFI_NOT_AVAILABLE);
    CHECK_PTR_RETURN(info, ERROR_WIFI_INVALID_ARGS);
    OHOS::Wifi::IpInfo ipInfo;
    OHOS::Wifi::ErrCode ret = wifiDevicePtr->GetIpInfo(ipInfo);
    if (ret == OHOS::Wifi::WIFI_OPT_SUCCESS) {
        OHOS::Wifi::ErrCode retValue = GetIpInfoFromCpp(ipInfo, info);
        if (retValue != OHOS::Wifi::WIFI_OPT_SUCCESS) {
            WIFI_LOGE("Get ip info from cpp error!");
            ret = retValue;
        }
    }
    return GetCErrorCode(ret);
}

static OHOS::Wifi::ErrCode GetIpV6InfoFromCpp(const OHOS::Wifi::IpV6Info& ipInfo, IpV6Info *result)
{
    CHECK_PTR_RETURN(result, OHOS::Wifi::WIFI_OPT_INVALID_PARAM);
    if (memcpy_s(result->linkIpV6Address, DEVICE_IPV6_MAX_LEN, ipInfo.linkIpV6Address.c_str(),
        ipInfo.linkIpV6Address.size() + 1) != EOK) {
        return OHOS::Wifi::WIFI_OPT_FAILED;
    }
    if (memcpy_s(result->globalIpV6Address, DEVICE_IPV6_MAX_LEN, ipInfo.globalIpV6Address.c_str(),
        ipInfo.globalIpV6Address.size() + 1) != EOK) {
        return OHOS::Wifi::WIFI_OPT_FAILED;
    }
    if (memcpy_s(result->randGlobalIpV6Address, DEVICE_IPV6_MAX_LEN, ipInfo.randGlobalIpV6Address.c_str(),
        ipInfo.randGlobalIpV6Address.size() + 1) != EOK) {
        return OHOS::Wifi::WIFI_OPT_FAILED;
    }
    if (memcpy_s(result->gateway, DEVICE_IPV6_MAX_LEN, ipInfo.gateway.c_str(),
        ipInfo.gateway.size() + 1) != EOK) {
        return OHOS::Wifi::WIFI_OPT_FAILED;
    }
    if (memcpy_s(result->netmask, DEVICE_IPV6_MAX_LEN, ipInfo.netmask.c_str(),
        ipInfo.netmask.size() + 1) != EOK) {
        return OHOS::Wifi::WIFI_OPT_FAILED;
    }
    if (memcpy_s(result->primaryDns, DEVICE_IPV6_MAX_LEN, ipInfo.primaryDns.c_str(),
        ipInfo.primaryDns.size() + 1) != EOK) {
        return OHOS::Wifi::WIFI_OPT_FAILED;
    }
    if (memcpy_s(result->secondDns, DEVICE_IPV6_MAX_LEN, ipInfo.secondDns.c_str(),
        ipInfo.secondDns.size() + 1) != EOK) {
        return OHOS::Wifi::WIFI_OPT_FAILED;
    }
    return OHOS::Wifi::WIFI_OPT_SUCCESS;
}

NO_SANITIZE("cfi") WifiErrorCode GetIpv6Info(IpV6Info *info)
{
    CHECK_PTR_RETURN(wifiDevicePtr, ERROR_WIFI_NOT_AVAILABLE);
    CHECK_PTR_RETURN(info, ERROR_WIFI_INVALID_ARGS);
    OHOS::Wifi::IpV6Info ipInfo;
    OHOS::Wifi::ErrCode ret = wifiDevicePtr->GetIpv6Info(ipInfo);
    if (ret == OHOS::Wifi::WIFI_OPT_SUCCESS) {
        OHOS::Wifi::ErrCode retValue = GetIpV6InfoFromCpp(ipInfo, info);
        if (retValue != OHOS::Wifi::WIFI_OPT_SUCCESS) {
            WIFI_LOGE("Get ip info from cpp error!");
            ret = retValue;
        }
    }
    return GetCErrorCode(ret);
}

NO_SANITIZE("cfi") int GetSignalLevel(int rssi, int band)
{
    CHECK_PTR_RETURN(wifiDevicePtr, ERROR_WIFI_NOT_AVAILABLE);
    int level = -1;
    OHOS::Wifi::ErrCode ret = wifiDevicePtr->GetSignalLevel(rssi, band, level);
    if (ret != OHOS::Wifi::WIFI_OPT_SUCCESS) {
        WIFI_LOGW("Get wifi signal level fail: %{public}d", ret);
    }
    return level;
}

NO_SANITIZE("cfi") WifiErrorCode SetLowLatencyMode(int enabled)
{
    CHECK_PTR_RETURN(wifiDevicePtr, ERROR_WIFI_NOT_AVAILABLE);
    bool ret = wifiDevicePtr->SetLowLatencyMode(enabled);
    return ret ? WIFI_SUCCESS : ERROR_WIFI_NOT_AVAILABLE;
}

NO_SANITIZE("cfi") WifiErrorCode IsBandTypeSupported(int bandType, bool *supported)
{
    CHECK_PTR_RETURN(wifiDevicePtr, ERROR_WIFI_NOT_AVAILABLE);
    OHOS::Wifi::ErrCode ret = wifiDevicePtr->IsBandTypeSupported(bandType, *supported);
    return GetCErrorCode(ret);
}

NO_SANITIZE("cfi") WifiErrorCode Get5GHzChannelList(int *result, int *size)
{
    CHECK_PTR_RETURN(wifiDevicePtr, ERROR_WIFI_NOT_AVAILABLE);
    CHECK_PTR_RETURN(result, ERROR_WIFI_INVALID_ARGS);
    CHECK_PTR_RETURN(size, ERROR_WIFI_INVALID_ARGS);
    std::vector<int> vecChannelWidths;
    OHOS::Wifi::ErrCode ret = wifiDevicePtr->Get5GHzChannelList(vecChannelWidths);
    if (ret != OHOS::Wifi::WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Get device configs error!");
        return GetCErrorCode(ret);
    }
    if ((int)vecChannelWidths.size() > *size) {
        WIFI_LOGE("input result size invalid!");
        return GetCErrorCode(OHOS::Wifi::WIFI_OPT_INVALID_PARAM);
    }
    
    *size = (int)vecChannelWidths.size();
    for (auto& each : vecChannelWidths) {
        *result++ = (int)each;
    }
    return GetCErrorCode(ret);
}
#ifndef OHOS_ARCH_LITE
NO_SANITIZE("cfi") WifiErrorCode GetWifiProtect(OHOS::Wifi::WifiProtectMode mode)
{
    CHECK_PTR_RETURN(wifiDevicePtr, ERROR_WIFI_NOT_AVAILABLE);
    return GetCErrorCode(wifiDevicePtr->GetWifiProtect(mode));
}

NO_SANITIZE("cfi") WifiErrorCode StartPortalCertification(int *result, int *size)
{
    CHECK_PTR_RETURN(wifiDevicePtr, ERROR_WIFI_NOT_AVAILABLE);
    CHECK_PTR_RETURN(result, ERROR_WIFI_INVALID_ARGS);
    CHECK_PTR_RETURN(size, ERROR_WIFI_INVALID_ARGS);
    OHOS::Wifi::ErrCode ret = wifiDevicePtr->StartPortalCertification();
    if (ret != OHOS::Wifi::WIFI_OPT_SUCCESS) {
        WIFI_LOGE("StartPortalCertification failed!");
        return GetCErrorCode(ret);
    }
    return GetCErrorCode(ret);
}

NO_SANITIZE("cfi") WifiErrorCode PutWifiProtect()
{
    CHECK_PTR_RETURN(wifiDevicePtr, ERROR_WIFI_NOT_AVAILABLE);
    return GetCErrorCode(wifiDevicePtr->PutWifiProtect());
}

NO_SANITIZE("cfi") WifiErrorCode IsHeldWifiProtect(bool &isHeld)
{
    CHECK_PTR_RETURN(wifiDevicePtr, ERROR_WIFI_NOT_AVAILABLE);
    return GetCErrorCode(wifiDevicePtr->IsHeldWifiProtect(isHeld));
}

NO_SANITIZE("cfi") WifiErrorCode FactoryReset()
{
    CHECK_PTR_RETURN(wifiDevicePtr, ERROR_WIFI_NOT_AVAILABLE);
    return GetCErrorCode(wifiDevicePtr->FactoryReset());
}

NO_SANITIZE("cfi") WifiErrorCode EnableHiLinkHandshake(bool uiFlag, std::string &bssid,
    OHOS::Wifi::WifiDeviceConfig &deviceConfig)
{
    CHECK_PTR_RETURN(wifiDevicePtr, ERROR_WIFI_NOT_AVAILABLE);
    return GetCErrorCode(wifiDevicePtr->EnableHiLinkHandshake(uiFlag, bssid, deviceConfig));
}
#endif
