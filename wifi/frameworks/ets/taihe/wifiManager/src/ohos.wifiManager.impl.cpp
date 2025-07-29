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

#include "ohos.wifiManager.proj.hpp"
#include "ohos.wifiManager.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"

#include "define.h"
#include "wifi_callback_taihe.h"
#include "wifi_errorcode_taihe.h"
using namespace OHOS::Wifi;
DEFINE_WIFILOG_LABEL("WifiManagerTaihe");
static std::shared_ptr<WifiDevice> g_wifiDevicePtr = WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);
std::shared_ptr<WifiScan> g_wifiScanPtr = WifiScan::GetInstance(WIFI_SCAN_ABILITY_ID);
static std::shared_ptr<WifiHotspot> g_wifiHotspotPtr = WifiHotspot::GetInstance(WIFI_HOTSPOT_ABILITY_ID);
std::shared_ptr<WifiP2p> g_wifiP2pPtr = WifiP2p::GetInstance(WIFI_P2P_ABILITY_ID);
namespace {
::ohos::wifiManager::WifiScanInfo MakeTmpWifiScanInfo(WifiScanInfo scanInfo)
{
    return {scanInfo.ssid, scanInfo.bssid,
        static_cast<::ohos::wifiManager::WifiSecurityType::key_t>(scanInfo.securityType),
        scanInfo.rssi, scanInfo.band,
        static_cast<::ohos::wifiManager::WifiCategory::key_t>(scanInfo.supportedWifiCategory)};
}

::ohos::wifiManager::WifiLinkedInfo MakeWifiLinkedInfo(WifiLinkedInfo linkedInfo)
{
    ::ohos::wifiManager::ConnState connState =
        static_cast<::ohos::wifiManager::ConnState::key_t>(linkedInfo.connState);
    ::ohos::wifiManager::WifiCategory supportedWifiCategory =
        static_cast<::ohos::wifiManager::WifiCategory::key_t>(linkedInfo.supportedWifiCategory);
    return {linkedInfo.ssid, linkedInfo.bssid, linkedInfo.rssi, linkedInfo.band,
        linkedInfo.macAddress, connState, supportedWifiCategory};
}

::ohos::wifiManager::IpInfo MakeIpInfo(int32_t ipAddress)
{
    return {ipAddress};
}
 
::ohos::wifiManager::Ipv6Info MakeIpv6Info(::taihe::string_view linkIpv6Address)
{
    return {linkIpv6Address};
}

::ohos::wifiManager::StationInfo MakeTmpStationInfo()
{
    return {""};
}

bool IsConnected()
{
    bool isConnected = false;
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return static_cast<ani_boolean>(isConnected);
    }
    ErrCode ret = g_wifiDevicePtr->IsConnected(isConnected);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
    }
    return static_cast<ani_boolean>(isConnected);
}

bool IsWifiActive()
{
    bool activeStatus = false;
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return static_cast<ani_boolean>(activeStatus);
    }
    ErrCode ret = g_wifiDevicePtr->IsWifiActive(activeStatus);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
    }
    return static_cast<ani_boolean>(activeStatus);
}

::ohos::wifiManager::WifiLinkedInfo GetLinkedInfoSync()
{
    WifiLinkedInfo linkedInfo;
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        ::ohos::wifiManager::WifiLinkedInfo errorResult = MakeWifiLinkedInfo(linkedInfo);
        return errorResult;
    }
    ErrCode ret = g_wifiDevicePtr->GetLinkedInfo(linkedInfo);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
    }
    return MakeWifiLinkedInfo(linkedInfo);
}

double GetSignalLevel(double rssi, double band)
{
    int level = -1;
    int tmpRssi = static_cast<int>(rssi);
    int tmpBand = static_cast<int>(band);
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return 0.0;
    }
    ErrCode ret = g_wifiDevicePtr->GetSignalLevel(tmpRssi, tmpBand, level);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
    }
    return static_cast<ani_int>(level);
}

::ohos::wifiManager::IpInfo GetIpInfo()
{
    IpInfo ipInfo;
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        ::ohos::wifiManager::IpInfo errorResult = MakeIpInfo(ipInfo.ipAddress);
        return errorResult;
    }
    ErrCode ret = g_wifiDevicePtr->GetIpInfo(ipInfo);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
    }
    ::ohos::wifiManager::IpInfo result = MakeIpInfo(ipInfo.ipAddress);
    return result;
}

::ohos::wifiManager::Ipv6Info GetIpv6Info()
{
    IpV6Info ipInfo;
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        ::ohos::wifiManager::Ipv6Info errorResult = MakeIpv6Info(ipInfo.linkIpV6Address);
        return errorResult;
    }
    ErrCode ret = g_wifiDevicePtr->GetIpv6Info(ipInfo);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
    }
    ::ohos::wifiManager::Ipv6Info result = MakeIpv6Info(ipInfo.linkIpV6Address);
    return result;
}

bool IsOpenSoftApAllowed()
{
    bool isSupported = false;
    if (g_wifiHotspotPtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_AP_CORE);
        return static_cast<ani_boolean>(isSupported);
    }
    ErrCode ret = g_wifiHotspotPtr->IsOpenSoftApAllowed(isSupported);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_AP_CORE);
    }
    return static_cast<ani_boolean>(isSupported);
}

::taihe::array<::ohos::wifiManager::WifiScanInfo> GetScanInfoList()
{
    bool compatible = false;
    std::vector<WifiScanInfo> scanInfos;
    std::vector<::ohos::wifiManager::WifiScanInfo> result;
    if (g_wifiScanPtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return ::taihe::array<::ohos::wifiManager::WifiScanInfo>(
            taihe::copy_data_t{}, result.data(), result.size());
    }
    ErrCode ret = g_wifiScanPtr->GetScanInfoList(scanInfos, compatible);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
    }
    WIFI_LOGI("GetScanInfoList, size: %{public}zu", scanInfos.size());
    for (WifiScanInfo scanInfo : scanInfos) {
        ::ohos::wifiManager::WifiScanInfo tmpInfo = MakeTmpWifiScanInfo(scanInfo);
        result.emplace_back(tmpInfo);
    }
    return ::taihe::array<::ohos::wifiManager::WifiScanInfo>(taihe::copy_data_t{}, result.data(), result.size());
}

bool IsMeteredHotspot()
{
    bool isMeteredHotspot = false;
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return static_cast<ani_boolean>(isMeteredHotspot);
    }
    ErrCode ret = g_wifiDevicePtr->IsMeteredHotspot(isMeteredHotspot);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
    }
    return static_cast<ani_boolean>(isMeteredHotspot);
}

::ohos::wifiManager::WifiDetailState GetWifiDetailState()
{
    WifiDetailState state = WifiDetailState::STATE_UNKNOWN;
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return static_cast<::ohos::wifiManager::WifiDetailState::key_t>(state);
    }
    ErrCode ret = g_wifiDevicePtr->GetWifiDetailState(state);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
    }
    return static_cast<::ohos::wifiManager::WifiDetailState::key_t>(state);
}

void StationInfoToTaihe(::ohos::wifiManager::StationInfo &tmpInfo, StationInfo stationInfo)
{
    tmpInfo.macAddress = stationInfo.bssid;
}

::taihe::array<::ohos::wifiManager::StationInfo> GetStations()
{
    std::vector<StationInfo> vecStationInfo;
    std::vector<::ohos::wifiManager::StationInfo> result;
    if (g_wifiHotspotPtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_AP_CORE);
        return ::taihe::array<::ohos::wifiManager::StationInfo>(
            taihe::copy_data_t{}, result.data(), result.size());
    }
    ErrCode ret = g_wifiHotspotPtr->GetStationList(vecStationInfo);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_AP_CORE);
    }
    WIFI_LOGI("Get station list size: %{public}zu", vecStationInfo.size());
    for (StationInfo stationInfo : vecStationInfo) {
        ::ohos::wifiManager::StationInfo tmpInfo = MakeTmpStationInfo();
        StationInfoToTaihe(tmpInfo, stationInfo);
        result.emplace_back(tmpInfo);
    }
    return ::taihe::array<::ohos::wifiManager::StationInfo>(taihe::copy_data_t{}, result.data(), result.size());
}

void EnableWifi()
{
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return;
    }
    ErrCode ret = g_wifiDevicePtr->EnableWifi();
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
    }
}

void DisableWifi()
{
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return;
    }
    ErrCode ret = g_wifiDevicePtr->DisableWifi();
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
    }
}

void EnableSemiWifi()
{
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return;
    }
    ErrCode ret = g_wifiDevicePtr->EnableSemiWifi();
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
    }
}

OHOS::sptr<WifiIdlDeviceEventCallback> wifiDeviceCallback =
        OHOS::sptr<WifiIdlDeviceEventCallback>(new (std::nothrow) WifiIdlDeviceEventCallback());

OHOS::sptr<WifiIdlScanEventCallback> wifiScanCallback =
    OHOS::sptr<WifiIdlScanEventCallback>(new (std::nothrow) WifiIdlScanEventCallback());

OHOS::sptr<WifiIdlHotspotEventCallback> wifiHotspotCallback =
    OHOS::sptr<WifiIdlHotspotEventCallback>(new (std::nothrow) WifiIdlHotspotEventCallback());

OHOS::sptr<WifiIdlP2pEventCallback> wifiP2pCallback =
    OHOS::sptr<WifiIdlP2pEventCallback>(new (std::nothrow) WifiIdlP2pEventCallback());

void OnWifiStateChange(::taihe::callback_view<void(double)> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiStateChangeLock);
    auto wifiStateChangedCallback =
        ::taihe::optional<::taihe::callback<void(double)>>{std::in_place_t{}, callback};
    std::vector<std::string> event = {"wifiStateChange"};
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return;
    }
    if (g_wifiStateChangeVec.size() > REGISTERINFO_MAX_NUM) {
        WIFI_LOGE("RegisterInfo Exceeding the maximum value!");
        return;
    }
    ErrCode ret = g_wifiDevicePtr->RegisterCallBack(wifiDeviceCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
    }
    g_wifiStateChangeVec.emplace_back(wifiStateChangedCallback);
}

void OffWifiStateChange(::taihe::optional_view<::taihe::callback<void(double)>> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiStateChangeLock);
    if (g_wifiStateChangeVec.empty()) {
        WIFI_LOGE("Unregister type not registered!");
        return;
    }
    if (callback != nullptr) {
        for (int i = static_cast<int>(g_wifiStateChangeVec.size()) - 1; i >= 0; --i) {
            if (g_wifiStateChangeVec[i] == callback) {
                g_wifiStateChangeVec.erase(g_wifiStateChangeVec.begin() + i);
            }
        }
    } else {
        WIFI_LOGW("Unregister all relevant subscribe for: wifiStateChange");
        g_wifiStateChangeVec.clear();
    }
}

void OnWifiConnectionChange(::taihe::callback_view<void(double)> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiConnectionChangeLock);
    auto wifiConnectionChangeCallback =
        ::taihe::optional<::taihe::callback<void(double)>>{std::in_place_t{}, callback};
    std::vector<std::string> event = {"wifiConnectionChange"};
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return;
    }
    if (g_wifiConnectionChangeVec.size() > REGISTERINFO_MAX_NUM) {
        WIFI_LOGE("RegisterInfo Exceeding the maximum value!");
        return;
    }
    ErrCode ret = g_wifiDevicePtr->RegisterCallBack(wifiDeviceCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
        return;
    }
    g_wifiConnectionChangeVec.emplace_back(wifiConnectionChangeCallback);
}
 
void OffWifiConnectionChange(::taihe::optional_view<::taihe::callback<void(double)>> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiConnectionChangeLock);
    if (g_wifiConnectionChangeVec.empty()) {
        WIFI_LOGE("Unregister type not registered!");
        return;
    }
    if (callback != nullptr) {
        for (int i = static_cast<int>(g_wifiConnectionChangeVec.size()) - 1; i >= 0; --i) {
            if (g_wifiConnectionChangeVec[i] == callback) {
                g_wifiConnectionChangeVec.erase(g_wifiConnectionChangeVec.begin() + i);
            }
        }
    } else {
        WIFI_LOGW("Unregister all relevant subscribe for: wifiConnectionChange");
        g_wifiConnectionChangeVec.clear();
    }
}
 
void OnWifiScanStateChange(::taihe::callback_view<void(double)> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiScanStateChangeLock);
    auto wifiScanStateChangeCallback =
        ::taihe::optional<::taihe::callback<void(double)>>{std::in_place_t{}, callback};
    std::vector<std::string> event = {"wifiScanStateChange"};
    if (g_wifiScanPtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return;
    }
    if (g_wifiScanStateChangeVec.size() > REGISTERINFO_MAX_NUM) {
        WIFI_LOGE("RegisterInfo Exceeding the maximum value!");
        return;
    }
    ErrCode ret = g_wifiScanPtr->RegisterCallBack(wifiScanCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
        return;
    }
    g_wifiScanStateChangeVec.emplace_back(wifiScanStateChangeCallback);
}
 
void OffWifiScanStateChange(::taihe::optional_view<::taihe::callback<void(double)>> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiScanStateChangeLock);
    if (g_wifiScanStateChangeVec.empty()) {
        WIFI_LOGE("Unregister type not registered!");
        return;
    }
    if (callback != nullptr) {
        for (int i = static_cast<int>(g_wifiScanStateChangeVec.size()) - 1; i >= 0; --i) {
            if (g_wifiScanStateChangeVec[i] == callback) {
                g_wifiScanStateChangeVec.erase(g_wifiScanStateChangeVec.begin() + i);
            }
        }
    } else {
        WIFI_LOGW("Unregister all relevant subscribe for: wifiScanStateChange");
        g_wifiScanStateChangeVec.clear();
    }
}
 
void OnWifiRssiChange(::taihe::callback_view<void(double)> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiRssiChangeLock);
    auto wifiRssiChangeCallback =
        ::taihe::optional<::taihe::callback<void(double)>>{std::in_place_t{}, callback};
    std::vector<std::string> event = {"wifiRssiChange"};
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return;
    }
    if (g_wifiRssiChangeVec.size() > REGISTERINFO_MAX_NUM) {
        WIFI_LOGE("RegisterInfo Exceeding the maximum value!");
        return;
    }
    ErrCode ret = g_wifiDevicePtr->RegisterCallBack(wifiDeviceCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
        return;
    }
    g_wifiRssiChangeVec.emplace_back(wifiRssiChangeCallback);
}
 
void OffWifiRssiChange(::taihe::optional_view<::taihe::callback<void(double)>> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiRssiChangeLock);
    if (g_wifiRssiChangeVec.empty()) {
        WIFI_LOGE("Unregister type not registered!");
        return;
    }
    if (callback != nullptr) {
        for (int i = static_cast<int>(g_wifiRssiChangeVec.size()) - 1; i >= 0; --i) {
            if (g_wifiRssiChangeVec[i] == callback) {
                g_wifiRssiChangeVec.erase(g_wifiRssiChangeVec.begin() + i);
            }
        }
    } else {
        WIFI_LOGW("Unregister all relevant subscribe for: wifiRssiChange");
        g_wifiRssiChangeVec.clear();
    }
}

void OnStreamChange(::taihe::callback_view<void(double)> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiStreamChangeLock);
    auto wifiRssiChangeCallback =
        ::taihe::optional<::taihe::callback<void(double)>>{std::in_place_t{}, callback};
    std::vector<std::string> event = {"streamChange"};
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return;
    }
    if (g_wifiStreamChangeVec.size() > REGISTERINFO_MAX_NUM) {
        WIFI_LOGE("RegisterInfo Exceeding the maximum value!");
        return;
    }
    ErrCode ret = g_wifiDevicePtr->RegisterCallBack(wifiDeviceCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
        return;
    }
    g_wifiStreamChangeVec.emplace_back(wifiRssiChangeCallback);
}

void OffStreamChange(::taihe::optional_view<::taihe::callback<void(double)>> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiStreamChangeLock);
    if (g_wifiStreamChangeVec.empty()) {
        WIFI_LOGE("Unregister type not registered!");
        return;
    }
    if (callback != nullptr) {
        for (int i = static_cast<int>(g_wifiStreamChangeVec.size()) - 1; i >= 0; --i) {
            if (g_wifiStreamChangeVec[i] == callback) {
                g_wifiStreamChangeVec.erase(g_wifiStreamChangeVec.begin() + i);
            }
        }
    } else {
        WIFI_LOGW("Unregister all relevant subscribe for: streamChange");
        g_wifiStreamChangeVec.clear();
    }
}

void OnDeviceConfigChange(::taihe::callback_view<void(double)> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiDeviceConfigChangeLock);
    auto wifiDeviceConfigChangeCallback =
        ::taihe::optional<::taihe::callback<void(double)>>{std::in_place_t{}, callback};
    std::vector<std::string> event = {"deviceConfigChange"};
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return;
    }
    if (g_wifiDeviceConfigChangeVec.size() > REGISTERINFO_MAX_NUM) {
        WIFI_LOGE("RegisterInfo Exceeding the maximum value!");
        return;
    }
    ErrCode ret = g_wifiDevicePtr->RegisterCallBack(wifiDeviceCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
        return;
    }
    g_wifiDeviceConfigChangeVec.emplace_back(wifiDeviceConfigChangeCallback);
}

void OffDeviceConfigChange(::taihe::optional_view<::taihe::callback<void(double)>> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiDeviceConfigChangeLock);
    if (g_wifiDeviceConfigChangeVec.empty()) {
        WIFI_LOGE("Unregister type not registered!");
        return;
    }
    if (callback != nullptr) {
        for (int i = static_cast<int>(g_wifiDeviceConfigChangeVec.size()) - 1; i >= 0; --i) {
            if (g_wifiDeviceConfigChangeVec[i] == callback) {
                g_wifiDeviceConfigChangeVec.erase(g_wifiDeviceConfigChangeVec.begin() + i);
            }
        }
    } else {
        WIFI_LOGW("Unregister all relevant subscribe for: deviceConfigChange");
        g_wifiDeviceConfigChangeVec.clear();
    }
}

void OnHotspotStateChange(::taihe::callback_view<void(double)> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiHotspotStateChangeLock);
    auto wifiHotspotStateChangeCallback =
        ::taihe::optional<::taihe::callback<void(double)>>{std::in_place_t{}, callback};
    std::vector<std::string> event = {"hotspotStateChange"};
    if (g_wifiHotspotPtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_AP_CORE);
        return;
    }
    if (g_wifiHotspotStateChangeVec.size() > REGISTERINFO_MAX_NUM) {
        WIFI_LOGE("RegisterInfo Exceeding the maximum value!");
        return;
    }
    ErrCode ret = g_wifiHotspotPtr->RegisterCallBack(wifiHotspotCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_AP_CORE);
        return;
    }
    g_wifiHotspotStateChangeVec.emplace_back(wifiHotspotStateChangeCallback);
}

void OffHotspotStateChange(::taihe::optional_view<::taihe::callback<void(double)>> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiHotspotStateChangeLock);
    if (g_wifiHotspotStateChangeVec.empty()) {
        WIFI_LOGE("Unregister type not registered!");
        return;
    }
    if (callback != nullptr) {
        for (int i = static_cast<int>(g_wifiHotspotStateChangeVec.size()) - 1; i >= 0; --i) {
            if (g_wifiHotspotStateChangeVec[i] == callback) {
                g_wifiHotspotStateChangeVec.erase(g_wifiHotspotStateChangeVec.begin() + i);
            }
        }
    } else {
        WIFI_LOGW("Unregister all relevant subscribe for: hotspotStateChange");
        g_wifiHotspotStateChangeVec.clear();
    }
}

void OnHotspotStaJoin(::taihe::callback_view<void(::ohos::wifiManager::StationInfo const&)> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiHotspotStaJoinLock);
    auto wifiHotspotStaJoinCallback = ::taihe::optional<::taihe::callback<void(
        ::ohos::wifiManager::StationInfo const&)>>{std::in_place_t{}, callback};
    std::vector<std::string> event = {"hotspotStaJoin"};
    if (g_wifiHotspotPtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_AP_CORE);
        return;
    }
    if (g_wifiHotspotStaJoinVec.size() > REGISTERINFO_MAX_NUM) {
        WIFI_LOGE("RegisterInfo Exceeding the maximum value!");
        return;
    }
    ErrCode ret = g_wifiHotspotPtr->RegisterCallBack(wifiHotspotCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_AP_CORE);
        return;
    }
    g_wifiHotspotStaJoinVec.emplace_back(wifiHotspotStaJoinCallback);
}

void OffHotspotStaJoin(
    ::taihe::optional_view<::taihe::callback<void(::ohos::wifiManager::StationInfo const&)>> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiHotspotStaJoinLock);
    if (g_wifiHotspotStaJoinVec.empty()) {
        WIFI_LOGE("Unregister type not registered!");
        return;
    }
    if (callback != nullptr) {
        for (int i = static_cast<int>(g_wifiHotspotStaJoinVec.size()) - 1; i >= 0; --i) {
            if (g_wifiHotspotStaJoinVec[i] == callback) {
                g_wifiHotspotStaJoinVec.erase(g_wifiHotspotStaJoinVec.begin() + i);
            }
        }
    } else {
        WIFI_LOGW("Unregister all relevant subscribe for: hotspotStaJoin");
        g_wifiHotspotStaJoinVec.clear();
    }
}

void OnHotspotStaLeave(::taihe::callback_view<void(::ohos::wifiManager::StationInfo const&)> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiHotspotStaLeaveLock);
    auto wifiHotspotStaLeaveCallback = ::taihe::optional<::taihe::callback<void(
        ::ohos::wifiManager::StationInfo const&)>>{std::in_place_t{}, callback};
    std::vector<std::string> event = {"hotspotStaLeave"};
    if (g_wifiHotspotPtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_AP_CORE);
        return;
    }
    if (g_wifiHotspotStaLeaveVec.size() > REGISTERINFO_MAX_NUM) {
        WIFI_LOGE("RegisterInfo Exceeding the maximum value!");
        return;
    }
    ErrCode ret = g_wifiHotspotPtr->RegisterCallBack(wifiHotspotCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_AP_CORE);
        return;
    }
    g_wifiHotspotStaLeaveVec.emplace_back(wifiHotspotStaLeaveCallback);
}

void OffHotspotStaLeave(
    ::taihe::optional_view<::taihe::callback<void(::ohos::wifiManager::StationInfo const&)>> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiHotspotStaLeaveLock);
    if (g_wifiHotspotStaLeaveVec.empty()) {
        WIFI_LOGE("Unregister type not registered!");
        return;
    }
    if (callback != nullptr) {
        for (int i = static_cast<int>(g_wifiHotspotStaLeaveVec.size()) - 1; i >= 0; --i) {
            if (g_wifiHotspotStaLeaveVec[i] == callback) {
                g_wifiHotspotStaLeaveVec.erase(g_wifiHotspotStaLeaveVec.begin() + i);
            }
        }
    } else {
        WIFI_LOGW("Unregister all relevant subscribe for: hotspotStaLeave");
        g_wifiHotspotStaLeaveVec.clear();
    }
}

void OnP2pStateChange(::taihe::callback_view<void(double)> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiP2pStateChangeLock);
    auto wifiP2pStateChangeCallback =
        ::taihe::optional<::taihe::callback<void(double)>>{std::in_place_t{}, callback};
    std::vector<std::string> event = {"p2pStateChange"};
    if (g_wifiP2pPtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_P2P);
        return;
    }
    if (g_wifiP2pStateChangeVec.size() > REGISTERINFO_MAX_NUM) {
        WIFI_LOGE("RegisterInfo Exceeding the maximum value!");
        return;
    }
    ErrCode ret = g_wifiP2pPtr->RegisterCallBack(wifiP2pCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_P2P);
        return;
    }
    g_wifiP2pStateChangeVec.emplace_back(wifiP2pStateChangeCallback);
}

void OffP2pStateChange(::taihe::optional_view<::taihe::callback<void(double)>> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiP2pStateChangeLock);
    if (g_wifiP2pStateChangeVec.empty()) {
        WIFI_LOGE("Unregister type not registered!");
        return;
    }
    if (callback != nullptr) {
        for (int i = static_cast<int>(g_wifiP2pStateChangeVec.size()) - 1; i >= 0; --i) {
            if (g_wifiP2pStateChangeVec[i] == callback) {
                g_wifiP2pStateChangeVec.erase(g_wifiP2pStateChangeVec.begin() + i);
            }
        }
    } else {
        WIFI_LOGW("Unregister all relevant subscribe for: p2pStateChange");
        g_wifiP2pStateChangeVec.clear();
    }
}

void OnP2pConnectionChange(::taihe::callback_view<void(::ohos::wifiManager::WifiP2pLinkedInfo const&)> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiP2pConnectionChangeLock);
    auto wifiP2pConnectionChangeCallback = ::taihe::optional<::taihe::callback<void(
        ::ohos::wifiManager::WifiP2pLinkedInfo const&)>>{std::in_place_t{}, callback};
    std::vector<std::string> event = {"p2pConnectionChange"};
    if (g_wifiP2pPtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_P2P);
        return;
    }
    if (g_wifiP2pConnectionChangeVec.size() > REGISTERINFO_MAX_NUM) {
        WIFI_LOGE("RegisterInfo Exceeding the maximum value!");
        return;
    }
    ErrCode ret = g_wifiP2pPtr->RegisterCallBack(wifiP2pCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_P2P);
        return;
    }
    g_wifiP2pConnectionChangeVec.emplace_back(wifiP2pConnectionChangeCallback);
}

void OffP2pConnectionChange(
    ::taihe::optional_view<::taihe::callback<void(::ohos::wifiManager::WifiP2pLinkedInfo const&)>> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiP2pConnectionChangeLock);
    if (g_wifiP2pConnectionChangeVec.empty()) {
        WIFI_LOGE("Unregister type not registered!");
        return;
    }
    if (callback != nullptr) {
        for (int i = static_cast<int>(g_wifiP2pConnectionChangeVec.size()) - 1; i >= 0; --i) {
            if (g_wifiP2pConnectionChangeVec[i] == callback) {
                g_wifiP2pConnectionChangeVec.erase(g_wifiP2pConnectionChangeVec.begin() + i);
            }
        }
    } else {
        WIFI_LOGW("Unregister all relevant subscribe for: p2pConnectionChange");
        g_wifiP2pConnectionChangeVec.clear();
    }
}

void OnP2pDeviceChange(::taihe::callback_view<void(::ohos::wifiManager::WifiP2pDevice const&)> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiP2pDeviceChangeLock);
    auto wifiP2pDeviceChangeCallback = ::taihe::optional<::taihe::callback<void(
        ::ohos::wifiManager::WifiP2pDevice const&)>>{std::in_place_t{}, callback};
    std::vector<std::string> event = {"p2pDeviceChange"};
    if (g_wifiP2pPtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_P2P);
        return;
    }
    if (g_wifiP2pDeviceChangeVec.size() > REGISTERINFO_MAX_NUM) {
        WIFI_LOGE("RegisterInfo Exceeding the maximum value!");
        return;
    }
    ErrCode ret = g_wifiP2pPtr->RegisterCallBack(wifiP2pCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_P2P);
        return;
    }
    g_wifiP2pDeviceChangeVec.emplace_back(wifiP2pDeviceChangeCallback);
}

void OffP2pDeviceChange(::taihe::optional_view<::taihe::callback<void(
    ::ohos::wifiManager::WifiP2pDevice const&)>> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiP2pDeviceChangeLock);
    if (g_wifiP2pDeviceChangeVec.empty()) {
        WIFI_LOGE("Unregister type not registered!");
        return;
    }
    if (callback != nullptr) {
        for (int i = static_cast<int>(g_wifiP2pDeviceChangeVec.size()) - 1; i >= 0; --i) {
            if (g_wifiP2pDeviceChangeVec[i] == callback) {
                g_wifiP2pDeviceChangeVec.erase(g_wifiP2pDeviceChangeVec.begin() + i);
            }
        }
    } else {
        WIFI_LOGW("Unregister all relevant subscribe for: p2pDeviceChange");
        g_wifiP2pDeviceChangeVec.clear();
    }
}

void OnP2pPeerDeviceChange(::taihe::callback_view<void(
    ::taihe::array_view<::ohos::wifiManager::WifiP2pDevice>)> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiP2pPeerDeviceChangeLock);
    auto wifiP2pPeerDeviceChangeCallback =
        ::taihe::optional<::taihe::callback<void(
        ::taihe::array_view<::ohos::wifiManager::WifiP2pDevice>)>>{std::in_place_t{}, callback};
    std::vector<std::string> event = {"p2pPeerDeviceChange"};
    if (g_wifiP2pPtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_P2P);
        return;
    }
    if (g_wifiP2pPeerDeviceChangeVec.size() > REGISTERINFO_MAX_NUM) {
        WIFI_LOGE("RegisterInfo Exceeding the maximum value!");
        return;
    }
    ErrCode ret = g_wifiP2pPtr->RegisterCallBack(wifiP2pCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_P2P);
        return;
    }
    g_wifiP2pPeerDeviceChangeVec.emplace_back(wifiP2pPeerDeviceChangeCallback);
}

void OffP2pPeerDeviceChange(::taihe::optional_view<::taihe::callback<void(
    ::taihe::array_view<::ohos::wifiManager::WifiP2pDevice>)>> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiP2pPeerDeviceChangeLock);
    if (g_wifiP2pPeerDeviceChangeVec.empty()) {
        WIFI_LOGE("Unregister type not registered!");
        return;
    }
    if (callback != nullptr) {
        for (int i = static_cast<int>(g_wifiP2pPeerDeviceChangeVec.size()) - 1; i >= 0; --i) {
            if (g_wifiP2pPeerDeviceChangeVec[i] == callback) {
                g_wifiP2pPeerDeviceChangeVec.erase(g_wifiP2pPeerDeviceChangeVec.begin() + i);
            }
        }
    } else {
        WIFI_LOGW("Unregister all relevant subscribe for: p2pPeerDeviceChange");
        g_wifiP2pPeerDeviceChangeVec.clear();
    }
}

void OnP2pPersistentGroupChange(::taihe::callback_view<void(::ohos::wifiManager::UndefinedType const&)> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiP2pPersistentGroupChangeLock);
    auto wifiP2pPersistentGroupChangeCallback = ::taihe::optional<::taihe::callback<void(
        ::ohos::wifiManager::UndefinedType const&)>>{std::in_place_t{}, callback};
    std::vector<std::string> event = {"p2pPersistentGroupChange"};
    if (g_wifiP2pPtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_P2P);
        return;
    }
    if (g_wifiP2pPersistentGroupChangeVec.size() > REGISTERINFO_MAX_NUM) {
        WIFI_LOGE("RegisterInfo Exceeding the maximum value!");
        return;
    }
    ErrCode ret = g_wifiP2pPtr->RegisterCallBack(wifiP2pCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_P2P);
        return;
    }
    g_wifiP2pPersistentGroupChangeVec.emplace_back(wifiP2pPersistentGroupChangeCallback);
}

void OffP2pPersistentGroupChange(::taihe::optional_view<::taihe::callback<void(
    ::ohos::wifiManager::UndefinedType const&)>> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiP2pPersistentGroupChangeLock);
    if (g_wifiP2pPersistentGroupChangeVec.empty()) {
        WIFI_LOGE("Unregister type not registered!");
        return;
    }
    if (callback != nullptr) {
        for (int i = static_cast<int>(g_wifiP2pPersistentGroupChangeVec.size()) - 1; i >= 0; --i) {
            if (g_wifiP2pPersistentGroupChangeVec[i] == callback) {
                g_wifiP2pPersistentGroupChangeVec.erase(g_wifiP2pPersistentGroupChangeVec.begin() + i);
            }
        }
    } else {
        WIFI_LOGW("Unregister all relevant subscribe for: p2pPersistentGroupChange");
        g_wifiP2pPersistentGroupChangeVec.clear();
    }
}

void OnP2pDiscoveryChange(::taihe::callback_view<void(double)> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiP2pDiscoveryChangeLock);
    auto wifiP2pDiscoveryChangeCallback =
        ::taihe::optional<::taihe::callback<void(double)>>{std::in_place_t{}, callback};
    std::vector<std::string> event = {"p2pDiscoveryChange"};
    if (g_wifiP2pPtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_P2P);
        return;
    }
    if (g_wifiP2pDiscoveryChangeVec.size() > REGISTERINFO_MAX_NUM) {
        WIFI_LOGE("RegisterInfo Exceeding the maximum value!");
        return;
    }
    ErrCode ret = g_wifiP2pPtr->RegisterCallBack(wifiP2pCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_P2P);
        return;
    }
    g_wifiP2pDiscoveryChangeVec.emplace_back(wifiP2pDiscoveryChangeCallback);
}

void OffP2pDiscoveryChange(::taihe::optional_view<::taihe::callback<void(double)>> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiP2pDiscoveryChangeLock);
    if (g_wifiP2pDiscoveryChangeVec.empty()) {
        WIFI_LOGE("Unregister type not registered!");
        return;
    }
    if (callback != nullptr) {
        for (int i = static_cast<int>(g_wifiP2pDiscoveryChangeVec.size()) - 1; i >= 0; --i) {
            if (g_wifiP2pDiscoveryChangeVec[i] == callback) {
                g_wifiP2pDiscoveryChangeVec.erase(g_wifiP2pDiscoveryChangeVec.begin() + i);
            }
        }
    } else {
        WIFI_LOGW("Unregister all relevant subscribe for: p2pDiscoveryChange");
        g_wifiP2pDiscoveryChangeVec.clear();
    }
}
}

TH_EXPORT_CPP_API_IsConnected(IsConnected);
TH_EXPORT_CPP_API_IsWifiActive(IsWifiActive);
TH_EXPORT_CPP_API_GetLinkedInfoSync(GetLinkedInfoSync);
TH_EXPORT_CPP_API_GetSignalLevel(GetSignalLevel);
TH_EXPORT_CPP_API_GetIpInfo(GetIpInfo);
TH_EXPORT_CPP_API_GetIpv6Info(GetIpv6Info);
TH_EXPORT_CPP_API_IsOpenSoftApAllowed(IsOpenSoftApAllowed);
TH_EXPORT_CPP_API_GetScanInfoList(GetScanInfoList);
TH_EXPORT_CPP_API_IsMeteredHotspot(IsMeteredHotspot);
TH_EXPORT_CPP_API_GetWifiDetailState(GetWifiDetailState);
TH_EXPORT_CPP_API_GetStations(GetStations);
TH_EXPORT_CPP_API_EnableWifi(EnableWifi);
TH_EXPORT_CPP_API_DisableWifi(DisableWifi);
TH_EXPORT_CPP_API_EnableSemiWifi(EnableSemiWifi);
TH_EXPORT_CPP_API_OnWifiStateChange(OnWifiStateChange);
TH_EXPORT_CPP_API_OffWifiStateChange(OffWifiStateChange);
TH_EXPORT_CPP_API_OnWifiConnectionChange(OnWifiConnectionChange);
TH_EXPORT_CPP_API_OffWifiConnectionChange(OffWifiConnectionChange);
TH_EXPORT_CPP_API_OnWifiScanStateChange(OnWifiScanStateChange);
TH_EXPORT_CPP_API_OffWifiScanStateChange(OffWifiScanStateChange);
TH_EXPORT_CPP_API_OnWifiRssiChange(OnWifiRssiChange);
TH_EXPORT_CPP_API_OffWifiRssiChange(OffWifiRssiChange);
TH_EXPORT_CPP_API_OnStreamChange(OnStreamChange);
TH_EXPORT_CPP_API_OffStreamChange(OffStreamChange);
TH_EXPORT_CPP_API_OnDeviceConfigChange(OnDeviceConfigChange);
TH_EXPORT_CPP_API_OffDeviceConfigChange(OffDeviceConfigChange);
TH_EXPORT_CPP_API_OnHotspotStateChange(OnHotspotStateChange);
TH_EXPORT_CPP_API_OffHotspotStateChange(OffHotspotStateChange);
TH_EXPORT_CPP_API_OnHotspotStaJoin(OnHotspotStaJoin);
TH_EXPORT_CPP_API_OffHotspotStaJoin(OffHotspotStaJoin);
TH_EXPORT_CPP_API_OnHotspotStaLeave(OnHotspotStaLeave);
TH_EXPORT_CPP_API_OffHotspotStaLeave(OffHotspotStaLeave);
TH_EXPORT_CPP_API_OnP2pStateChange(OnP2pStateChange);
TH_EXPORT_CPP_API_OffP2pStateChange(OffP2pStateChange);
TH_EXPORT_CPP_API_OnP2pConnectionChange(OnP2pConnectionChange);
TH_EXPORT_CPP_API_OffP2pConnectionChange(OffP2pConnectionChange);
TH_EXPORT_CPP_API_OnP2pDeviceChange(OnP2pDeviceChange);
TH_EXPORT_CPP_API_OffP2pDeviceChange(OffP2pDeviceChange);
TH_EXPORT_CPP_API_OnP2pPeerDeviceChange(OnP2pPeerDeviceChange);
TH_EXPORT_CPP_API_OffP2pPeerDeviceChange(OffP2pPeerDeviceChange);
TH_EXPORT_CPP_API_OnP2pPersistentGroupChange(OnP2pPersistentGroupChange);
TH_EXPORT_CPP_API_OffP2pPersistentGroupChange(OffP2pPersistentGroupChange);
TH_EXPORT_CPP_API_OnP2pDiscoveryChange(OnP2pDiscoveryChange);
TH_EXPORT_CPP_API_OffP2pDiscoveryChange(OffP2pDiscoveryChange);