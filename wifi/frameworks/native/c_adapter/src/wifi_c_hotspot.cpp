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

#include "kits/c/wifi_hotspot.h"
#include "kits/c/wifi_hotspot_config.h"
#include "kits/c/wifi_device_config.h"
#include "inner_api/wifi_hotspot.h"
#include "wifi_logger.h"
#include "wifi_c_utils.h"
#include "ip_tools.h"
#include "wifi_common_util.h"

#define IFACENAME_MIN_LEN 6

DEFINE_WIFILOG_LABEL("WifiCHotspot");

std::shared_ptr<OHOS::Wifi::WifiHotspot> hotspotPtr = OHOS::Wifi::WifiHotspot::GetInstance(WIFI_HOTSPOT_ABILITY_ID);

NO_SANITIZE("cfi") WifiErrorCode EnableHotspot()
{
    CHECK_PTR_RETURN(hotspotPtr, ERROR_WIFI_NOT_AVAILABLE);
    return GetCErrorCode(hotspotPtr->EnableHotspot());
}

NO_SANITIZE("cfi") WifiErrorCode DisableHotspot()
{
    CHECK_PTR_RETURN(hotspotPtr, ERROR_WIFI_NOT_AVAILABLE);
    return GetCErrorCode(hotspotPtr->DisableHotspot());
}

NO_SANITIZE("cfi") int IsHotspotActive(void)
{
    CHECK_PTR_RETURN(hotspotPtr, ERROR_WIFI_NOT_AVAILABLE);
    bool isActive = false;
    OHOS::Wifi::ErrCode ret = hotspotPtr->IsHotspotActive(isActive);
    if (ret != OHOS::Wifi::WIFI_OPT_SUCCESS) {
        WIFI_LOGE("IsHotspotActive return error: %{public}d!", ret);
    }
    return (ret == OHOS::Wifi::WIFI_OPT_SUCCESS && isActive) ? 1 : 0;
}

NO_SANITIZE("cfi") WifiErrorCode IsHotspotDualBandSupported(bool &isSupported)
{
    CHECK_PTR_RETURN(hotspotPtr, ERROR_WIFI_NOT_AVAILABLE);
    return GetCErrorCode(hotspotPtr->IsHotspotDualBandSupported(isSupported));
}

/* Others type is not support for AP */
static std::map<WifiSecurityType, OHOS::Wifi::KeyMgmt> g_mapSecTypeToKeyMgmt = {
    {WifiSecurityType::WIFI_SEC_TYPE_OPEN, OHOS::Wifi::KeyMgmt::NONE},
    {WifiSecurityType::WIFI_SEC_TYPE_PSK, OHOS::Wifi::KeyMgmt::WPA2_PSK},
};

static OHOS::Wifi::KeyMgmt GetKeyMgmtFromSecurityType(int secType)
{
    WifiSecurityType key = WifiSecurityType(secType);
    std::map<WifiSecurityType, OHOS::Wifi::KeyMgmt>::iterator iter = g_mapSecTypeToKeyMgmt.find(key);
    return iter == g_mapSecTypeToKeyMgmt.end() ? OHOS::Wifi::KeyMgmt::NONE : iter->second;
}

static int GetSecurityTypeFromKeyMgmt(OHOS::Wifi::KeyMgmt keyMgmt)
{
    for (auto& each : g_mapSecTypeToKeyMgmt) {
        if (each.second == keyMgmt) {
            return static_cast<int>(each.first);
        }
    }
    return static_cast<int>(WifiSecurityType::WIFI_SEC_TYPE_OPEN);
}

static bool IsSecurityTypeSupported(int secType)
{
    WifiSecurityType key = WifiSecurityType(secType);
    std::map<WifiSecurityType, OHOS::Wifi::KeyMgmt>::iterator iter = g_mapSecTypeToKeyMgmt.find(key);
    return iter != g_mapSecTypeToKeyMgmt.end();
}

static WifiErrorCode GetHotspotConfigFromC(const HotspotConfig *config, OHOS::Wifi::HotspotConfig& hotspotConfig)
{
    CHECK_PTR_RETURN(config, ERROR_WIFI_INVALID_ARGS);
    hotspotConfig.SetSsid(config->ssid);
    if (!IsSecurityTypeSupported(config->securityType)) {
        WIFI_LOGE("Ap security is not supported!");
        return ERROR_WIFI_NOT_SUPPORTED;
    }
    hotspotConfig.SetSecurityType(GetKeyMgmtFromSecurityType(config->securityType));
    hotspotConfig.SetBand(OHOS::Wifi::BandType(config->band));
    hotspotConfig.SetChannel(config->channelNum);
    if (strnlen(config->preSharedKey, WIFI_MAX_KEY_LEN) == WIFI_MAX_KEY_LEN) {
        return ERROR_WIFI_INVALID_ARGS;
    }
    hotspotConfig.SetPreSharedKey(config->preSharedKey);
    if (strnlen(config->ipAddress, WIFI_MAX_IPV4_LEN) == WIFI_MAX_IPV4_LEN) {
        return ERROR_WIFI_INVALID_ARGS;
    }
    hotspotConfig.SetIpAddress(config->ipAddress);
    return WIFI_SUCCESS;
}

static WifiErrorCode GetHotspotConfigFromCpp(const OHOS::Wifi::HotspotConfig& hotspotConfig, HotspotConfig *result)
{
    CHECK_PTR_RETURN(result, ERROR_WIFI_INVALID_ARGS);
    if (memcpy_s(result->ssid, WIFI_MAX_SSID_LEN,
        hotspotConfig.GetSsid().c_str(), hotspotConfig.GetSsid().size() + 1) != EOK) {
        return ERROR_WIFI_UNKNOWN;
    }
    result->securityType = GetSecurityTypeFromKeyMgmt(hotspotConfig.GetSecurityType());
    result->band = static_cast<int>(hotspotConfig.GetBand());
    result->channelNum = hotspotConfig.GetChannel();
    if (memcpy_s(result->preSharedKey, WIFI_MAX_KEY_LEN,
        hotspotConfig.GetPreSharedKey().c_str(), hotspotConfig.GetPreSharedKey().size() + 1) != EOK) {
        return ERROR_WIFI_UNKNOWN;
    }
    if (memcpy_s(result->ipAddress, WIFI_MAX_IPV4_LEN,
        hotspotConfig.GetIpAddress().c_str(), hotspotConfig.GetIpAddress().size() + 1) != EOK) {
        return ERROR_WIFI_UNKNOWN;
    }
    return WIFI_SUCCESS;
}

NO_SANITIZE("cfi") WifiErrorCode SetHotspotConfig(const HotspotConfig *config)
{
    CHECK_PTR_RETURN(config, ERROR_WIFI_INVALID_ARGS);
    CHECK_PTR_RETURN(hotspotPtr, ERROR_WIFI_NOT_AVAILABLE);
    OHOS::Wifi::HotspotConfig hotspotConfig;
    WifiErrorCode ret = GetHotspotConfigFromC(config, hotspotConfig);
    if (ret != WIFI_SUCCESS) {
        return ret;
    }
    return GetCErrorCode(hotspotPtr->SetHotspotConfig(hotspotConfig));
}

NO_SANITIZE("cfi") WifiErrorCode GetHotspotConfig(HotspotConfig *result)
{
    CHECK_PTR_RETURN(hotspotPtr, ERROR_WIFI_NOT_AVAILABLE);
    CHECK_PTR_RETURN(result, ERROR_WIFI_INVALID_ARGS);
    OHOS::Wifi::HotspotConfig hotspotConfig;
    OHOS::Wifi::ErrCode ret = hotspotPtr->GetHotspotConfig(hotspotConfig);
    if (ret == OHOS::Wifi::WIFI_OPT_SUCCESS) {
        WifiErrorCode retValue = GetHotspotConfigFromCpp(hotspotConfig, result);
        if (retValue != WIFI_SUCCESS) {
            WIFI_LOGE("Get hotspot config from cpp error!");
            return retValue;
        }
    }
    return GetCErrorCode(ret);
}

static WifiErrorCode GetStaListFromCpp(const std::vector<OHOS::Wifi::StationInfo>& vecStaList, StationInfo *result)
{
    CHECK_PTR_RETURN(result, ERROR_WIFI_INVALID_ARGS);
    for (auto& each : vecStaList) {
        if (result->name != nullptr) {
            if (memcpy_s(result->name, DEVICE_NAME_LEN, each.deviceName.c_str(), each.deviceName.size() + 1) != EOK) {
                return ERROR_WIFI_UNKNOWN;
            }
        } else {
            WIFI_LOGE("WARN: device name is not pre-allocate memory!");
        }

        if (OHOS::Wifi::MacStrToArray(each.bssid, result->macAddress) != EOK) {
            WIFI_LOGE("Get sta list convert bssid error!");
            return ERROR_WIFI_UNKNOWN;
        }
        result->ipAddress = OHOS::Wifi::Ip2Number(each.ipAddr);
    }
    return WIFI_SUCCESS;
}

NO_SANITIZE("cfi") WifiErrorCode GetStationList(StationInfo *result, unsigned int *size)
{
    CHECK_PTR_RETURN(hotspotPtr, ERROR_WIFI_NOT_AVAILABLE);
    CHECK_PTR_RETURN(result, ERROR_WIFI_INVALID_ARGS);
    CHECK_PTR_RETURN(size, ERROR_WIFI_INVALID_ARGS);
    std::vector<OHOS::Wifi::StationInfo> vecStaList;
    OHOS::Wifi::ErrCode ret = hotspotPtr->GetStationList(vecStaList);
    *size = (int)vecStaList.size();
    if (ret == OHOS::Wifi::WIFI_OPT_SUCCESS) {
        WifiErrorCode retValue = GetStaListFromCpp(vecStaList, result);
        if (retValue != WIFI_SUCCESS) {
            WIFI_LOGE("Get station list from cpp error!");
            return retValue;
        }
    }
    return GetCErrorCode(ret);
}

WifiErrorCode DisassociateSta(unsigned char *mac, int macLen)
{
    CHECK_PTR_RETURN(mac, ERROR_WIFI_INVALID_ARGS);
    return GetCErrorCode(OHOS::Wifi::WIFI_OPT_NOT_SUPPORTED);
}

WifiErrorCode AddTxPowerInfo(int power)
{
    return GetCErrorCode(OHOS::Wifi::WIFI_OPT_NOT_SUPPORTED);
}

WifiErrorCode GetApIfaceName(char *ifaceName, int nameLen)
{
    CHECK_PTR_RETURN(hotspotPtr, ERROR_WIFI_NOT_AVAILABLE);
    CHECK_PTR_RETURN(ifaceName, ERROR_WIFI_INVALID_ARGS);
    if (nameLen < IFACENAME_MIN_LEN) {
        return ERROR_WIFI_INVALID_ARGS;
    }
    std::string iface;
    OHOS::Wifi::ErrCode ret = hotspotPtr->GetApIfaceName(iface);
    if (ret == OHOS::Wifi::WIFI_OPT_SUCCESS) {
        if (iface.size() > static_cast<unsigned long>(nameLen)) {
            return ERROR_WIFI_INVALID_ARGS;
        }
        if (memcpy_s(ifaceName, nameLen, iface.c_str(), iface.size()) != EOK) {
            WIFI_LOGE("memcpy iface name failed");
            return ERROR_WIFI_UNKNOWN;
        }
    }
    return GetCErrorCode(ret);
}