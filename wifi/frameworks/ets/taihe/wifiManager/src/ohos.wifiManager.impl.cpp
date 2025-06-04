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

#include "wifi_callback_taihe.h"
using namespace OHOS::Wifi;

static std::shared_ptr<WifiDevice> g_wifiDevicePtr = WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);
std::shared_ptr<WifiScan> g_wifiScanPtr = WifiScan::GetInstance(WIFI_SCAN_ABILITY_ID);
static std::shared_ptr<WifiHotspot> g_wifiHotspotPtr = WifiHotspot::GetInstance(WIFI_HOTSPOT_ABILITY_ID);
std::shared_ptr<WifiP2p> g_wifiP2pPtr = WifiP2p::GetInstance(WIFI_P2P_ABILITY_ID);
namespace {

::ohos::wifiManager::WifiDeviceConfig MakeWifiDeviceConfig(::taihe::string_view ssid,
    ::taihe::optional_view<::taihe::string> bssid, ::taihe::string_view preSharedKey,
    ::ohos::wifiManager::WifiSecurityType securityType)
{
    return {ssid, bssid, preSharedKey, securityType};
}
 
::ohos::wifiManager::WifiScanInfo MakeWifiScanInfo(::taihe::string_view ssid, ::taihe::string_view bssid,
    ::ohos::wifiManager::WifiSecurityType securityType, int32_t rssi, int32_t band,
    ::ohos::wifiManager::WifiCategory supportedWifiCategory)
{
    return {ssid, bssid, securityType, rssi, band, supportedWifiCategory};
}

::ohos::wifiManager::WifiScanInfo MakeTmpWifiScanInfo()
{
    return {"", "", ::ohos::wifiManager::WifiSecurityType::key_t::WIFI_SEC_TYPE_INVALID, 0, 0,
        ::ohos::wifiManager::WifiCategory::key_t::DEFAULT};
}

::ohos::wifiManager::WifiLinkedInfo MakeWifiLinkedInfo(::taihe::string_view ssid,
    ::taihe::string_view bssid, int32_t rssi, int32_t band, ::taihe::string_view macAddress,
    ::ohos::wifiManager::ConnState connState, ::ohos::wifiManager::WifiCategory supportedWifiCategory)
{
    return {ssid, bssid, rssi, band, macAddress, connState, supportedWifiCategory};
}
 
::ohos::wifiManager::IpInfo MakeIpInfo(int32_t ipAddress)
{
    return {ipAddress};
}
 
::ohos::wifiManager::Ipv6Info MakeIpv6Info(::taihe::string_view linkIpv6Address)
{
    return {linkIpv6Address};
}
 
::ohos::wifiManager::StationInfo MakeStationInfo(::taihe::string_view macAddress)
{
    return {macAddress};
}

::ohos::wifiManager::StationInfo MakeTmpStationInfo()
{
    return {""};
}

::ohos::wifiManager::HotspotConfig MakeHotspotConfig(::taihe::string_view ssid,
    ::ohos::wifiManager::WifiSecurityType securityType, int32_t band, ::taihe::string_view preSharedKey)
{
    return {ssid, securityType, band, preSharedKey};
}

bool IsConnected()
{
    bool isConnected = false;
    ErrCode ret = g_wifiDevicePtr->IsConnected(isConnected);
    if (ret != WIFI_OPT_SUCCESS) {
        taihe::set_error("IsConnected return error");
    }
    return static_cast<ani_boolean>(isConnected);
}

bool IsWifiActive()
{
    bool activeStatus = false;
    ErrCode ret = g_wifiDevicePtr->IsWifiActive(activeStatus);
    if (ret != WIFI_OPT_SUCCESS) {
        taihe::set_error("isWifiActive return error");
    }
    return static_cast<ani_boolean>(activeStatus);
}

double GetSignalLevel(double rssi, double band)
{
    int level = -1;
    int tmpRssi = static_cast<int>(rssi);
    int tmpBand = static_cast<int>(band);
    ErrCode ret = g_wifiDevicePtr->GetSignalLevel(tmpRssi, tmpBand, level);
    if (ret != WIFI_OPT_SUCCESS) {
        taihe::set_error("getSignalLevel return error");
    }
    return static_cast<ani_int>(level);
}

::ohos::wifiManager::IpInfo GetIpInfo()
{
    IpInfo ipInfo;
    ErrCode ret = g_wifiDevicePtr->GetIpInfo(ipInfo);
    if (ret != WIFI_OPT_SUCCESS) {
        taihe::set_error("getIpInfo return error");
    }
    ::ohos::wifiManager::IpInfo result = MakeIpInfo(ipInfo.ipAddress);
    return result;
}

::ohos::wifiManager::Ipv6Info GetIpv6Info()
{
    IpV6Info ipInfo;
    ErrCode ret = g_wifiDevicePtr->GetIpv6Info(ipInfo);
    if (ret != WIFI_OPT_SUCCESS) {
        taihe::set_error("getIpv6Info return error");
    }
    ::ohos::wifiManager::Ipv6Info result = MakeIpv6Info(ipInfo.linkIpV6Address);
    return result;
}

bool IsOpenSoftApAllowed()
{
    bool isSupported = false;
    ErrCode ret = g_wifiHotspotPtr->IsOpenSoftApAllowed(isSupported);
    if (ret != WIFI_OPT_SUCCESS) {
        taihe::set_error("IsConnected return error");
    }
    return static_cast<ani_boolean>(isSupported);
}

void WifiScanInfoToTaihe(::ohos::wifiManager::WifiScanInfo &tmpInfo, WifiScanInfo scanInfo)
{
    tmpInfo.ssid = scanInfo.ssid;
    tmpInfo.bssid = scanInfo.bssid;
    tmpInfo.securityType = static_cast<::ohos::wifiManager::WifiSecurityType::key_t>(scanInfo.securityType);
    tmpInfo.rssi = scanInfo.rssi;
    tmpInfo.band = scanInfo.band;
    tmpInfo.supportedWifiCategory =
        static_cast<::ohos::wifiManager::WifiCategory::key_t>(scanInfo.supportedWifiCategory);
}

::taihe::array<::ohos::wifiManager::WifiScanInfo> GetScanInfoList()
{
    bool compatible = false;
    std::vector<WifiScanInfo> scanInfos;
    ErrCode ret = g_wifiScanPtr->GetScanInfoList(scanInfos, compatible);
    if (ret != WIFI_OPT_SUCCESS) {
        taihe::set_error("getScanInfoList return error");
    }
    std::vector<::ohos::wifiManager::WifiScanInfo> result;
    for (WifiScanInfo scanInfo : scanInfos) {
        ::ohos::wifiManager::WifiScanInfo tmpInfo = MakeTmpWifiScanInfo();
        WifiScanInfoToTaihe(tmpInfo, scanInfo);
        result.emplace_back(tmpInfo);
    }
    return ::taihe::array<::ohos::wifiManager::WifiScanInfo>(taihe::copy_data_t{}, result.data(), result.size());
}

bool IsMeteredHotspot()
{
    bool isMeteredHotspot = false;
    ErrCode ret = g_wifiDevicePtr->IsMeteredHotspot(isMeteredHotspot);
    if (ret != WIFI_OPT_SUCCESS) {
        taihe::set_error("isMeteredHotspot return error");
    }
    return static_cast<ani_boolean>(isMeteredHotspot);
}

::ohos::wifiManager::WifiDetailState GetWifiDetailState()
{
    WifiDetailState state = WifiDetailState::STATE_UNKNOWN;
    ErrCode ret = g_wifiDevicePtr->GetWifiDetailState(state);
    if (ret != WIFI_OPT_SUCCESS) {
        taihe::set_error("GetWifiDetailState return error");
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
    ErrCode ret = g_wifiHotspotPtr->GetStationList(vecStationInfo);
    if (ret != WIFI_OPT_SUCCESS) {
        taihe::set_error("getStations return error");
    }
    std::vector<::ohos::wifiManager::StationInfo> result;
    for (StationInfo stationInfo : vecStationInfo) {
        ::ohos::wifiManager::StationInfo tmpInfo = MakeTmpStationInfo();
        StationInfoToTaihe(tmpInfo, stationInfo);
        result.emplace_back(tmpInfo);
    }
    return ::taihe::array<::ohos::wifiManager::StationInfo>(taihe::copy_data_t{}, result.data(), result.size());
}

void EnableWifi()
{
    ErrCode ret = g_wifiDevicePtr->EnableWifi();
    if (ret != WIFI_OPT_SUCCESS) {
        taihe::set_error("enableWifi return error");
    }
}

void DisableWifi()
{
    ErrCode ret = g_wifiDevicePtr->DisableWifi();
    if (ret != WIFI_OPT_SUCCESS) {
        taihe::set_error("disableWifi return error");
    }
}

void EnableSemiWifi()
{
    ErrCode ret = g_wifiDevicePtr->EnableSemiWifi();
    if (ret != WIFI_OPT_SUCCESS) {
        taihe::set_error("enableSemiWifi return error");
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
    wifiDeviceCallback->wifiStateChangedCallback_ =
        ::taihe::optional<::taihe::callback<void(double)>>{std::in_place_t{}, callback};
    std::vector<std::string> event = {"wifiStateChange"};
    ErrCode ret = g_wifiDevicePtr->RegisterCallBack(wifiDeviceCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        taihe::set_error("OnWifiStateChange return error");
    }
}

void OffWifiStateChange(::taihe::optional_view<::taihe::callback<void(double)>> callback)
{
}

void OnWifiConnectionChange(::taihe::callback_view<void(double)> callback)
{
    wifiDeviceCallback->wifiConnectionChangeCallback_ =
        ::taihe::optional<::taihe::callback<void(double)>>{std::in_place_t{}, callback};
    std::vector<std::string> event = {"wifiConnectionChange"};
    ErrCode ret = g_wifiDevicePtr->RegisterCallBack(wifiDeviceCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        taihe::set_error("OnWifiConnectionChange return error");
    }
}

void OffWifiConnectionChange(::taihe::optional_view<::taihe::callback<void(double)>> callback)
{
}

void OnWifiScanStateChange(::taihe::callback_view<void(double)> callback)
{
    wifiScanCallback->wifiScanStateChangeCallback_ =
        ::taihe::optional<::taihe::callback<void(double)>>{std::in_place_t{}, callback};
    std::vector<std::string> event = {"wifiScanStateChange"};
    ErrCode ret = g_wifiScanPtr->RegisterCallBack(wifiScanCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        taihe::set_error("OnWifiScanStateChange return error");
    }
}

void OffWifiScanStateChange(::taihe::optional_view<::taihe::callback<void(double)>> callback)
{
}

void OnWifiRssiChange(::taihe::callback_view<void(double)> callback)
{
    wifiDeviceCallback->wifiRssiChangeCallback_ =
        ::taihe::optional<::taihe::callback<void(double)>>{std::in_place_t{}, callback};
    std::vector<std::string> event = {"wifiRssiChange"};
    ErrCode ret = g_wifiDevicePtr->RegisterCallBack(wifiDeviceCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        taihe::set_error("OnWifiRssiChange return error");
    }
}

void OffWifiRssiChange(::taihe::optional_view<::taihe::callback<void(double)>> callback)
{
}

void OnStreamChange(::taihe::callback_view<void(double)> callback)
{
    wifiDeviceCallback->wifiStreamChangeCallback_ =
        ::taihe::optional<::taihe::callback<void(double)>>{std::in_place_t{}, callback};
    std::vector<std::string> event = {"streamChange"};
    ErrCode ret = g_wifiDevicePtr->RegisterCallBack(wifiDeviceCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        taihe::set_error("OnWifiRssiChange return error");
    }
}

void OffStreamChange(::taihe::optional_view<::taihe::callback<void(double)>> callback)
{
}

void OnDeviceConfigChange(::taihe::callback_view<void(double)> callback)
{
    wifiDeviceCallback->wifiDeviceConfigChangeCallback_ =
        ::taihe::optional<::taihe::callback<void(double)>>{std::in_place_t{}, callback};
    std::vector<std::string> event = {"deviceConfigChange"};
    ErrCode ret = g_wifiDevicePtr->RegisterCallBack(wifiDeviceCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        taihe::set_error("OnDeviceConfigChange return error");
    }
}

void OffDeviceConfigChange(::taihe::optional_view<::taihe::callback<void(double)>> callback)
{
}

void OnHotspotStateChange(::taihe::callback_view<void(double)> callback)
{
    wifiHotspotCallback->wifiHotspotStateChangeCallback_ =
        ::taihe::optional<::taihe::callback<void(double)>>{std::in_place_t{}, callback};
    std::vector<std::string> event = {"hotspotStateChange"};
    ErrCode ret = g_wifiHotspotPtr->RegisterCallBack(wifiHotspotCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        taihe::set_error("OnHotspotStateChange return error");
    }
}

void OffHotspotStateChange(::taihe::optional_view<::taihe::callback<void(double)>> callback)
{
}

void OnHotspotStaJoin(::taihe::callback_view<void(::ohos::wifiManager::StationInfo const&)> callback)
{
    wifiHotspotCallback->wifiHotspotStaJoinCallback_ = ::taihe::optional<::taihe::callback<void(
        ::ohos::wifiManager::StationInfo const&)>>{std::in_place_t{}, callback};
    std::vector<std::string> event = {"hotspotStaJoin"};
    ErrCode ret = g_wifiHotspotPtr->RegisterCallBack(wifiHotspotCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        taihe::set_error("OnHotspotStaJoin return error");
    }
}

void OffHotspotStaJoin(
    ::taihe::optional_view<::taihe::callback<void(::ohos::wifiManager::StationInfo const&)>> callback)
{
}

void OnHotspotStaLeave(::taihe::callback_view<void(::ohos::wifiManager::StationInfo const&)> callback)
{
    wifiHotspotCallback->wifiHotspotStaLeaveCallback_ = ::taihe::optional<::taihe::callback<void(
        ::ohos::wifiManager::StationInfo const&)>>{std::in_place_t{}, callback};
    std::vector<std::string> event = {"hotspotStaLeave"};
    ErrCode ret = g_wifiHotspotPtr->RegisterCallBack(wifiHotspotCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        taihe::set_error("OnHotspotStaLeave return error");
    }
}

void OffHotspotStaLeave(
    ::taihe::optional_view<::taihe::callback<void(::ohos::wifiManager::StationInfo const&)>> callback)
{
}

void OnP2pStateChange(::taihe::callback_view<void(double)> callback)
{
    wifiP2pCallback->wifiP2pStateChangeCallback_ =
        ::taihe::optional<::taihe::callback<void(double)>>{std::in_place_t{}, callback};
    std::vector<std::string> event = {"p2pStateChange"};
    ErrCode ret = g_wifiP2pPtr->RegisterCallBack(wifiP2pCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        taihe::set_error("OnP2pStateChange return error");
    }
}

void OffP2pStateChange(::taihe::optional_view<::taihe::callback<void(double)>> callback)
{
}

void OnP2pConnectionChange(::taihe::callback_view<void(::ohos::wifiManager::WifiP2pLinkedInfo const&)> callback)
{
    wifiP2pCallback->wifiP2pConnectionChangeCallback_ =
        ::taihe::optional<::taihe::callback<void(
        ::ohos::wifiManager::WifiP2pLinkedInfo const&)>>{std::in_place_t{}, callback};
    std::vector<std::string> event = {"p2pConnectionChange"};
    ErrCode ret = g_wifiP2pPtr->RegisterCallBack(wifiP2pCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        taihe::set_error("OnP2pConnectionChange return error");
    }
}

void OffP2pConnectionChange(
    ::taihe::optional_view<::taihe::callback<void(::ohos::wifiManager::WifiP2pLinkedInfo const&)>> callback)
{
}

void OnP2pDeviceChange(::taihe::callback_view<void(::ohos::wifiManager::WifiP2pDevice const&)> callback)
{
    wifiP2pCallback->wifiP2pDeviceChangeCallback_ = ::taihe::optional<::taihe::callback<void(
        ::ohos::wifiManager::WifiP2pDevice const&)>>{std::in_place_t{}, callback};
    std::vector<std::string> event = {"p2pDeviceChange"};
    ErrCode ret = g_wifiP2pPtr->RegisterCallBack(wifiP2pCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        taihe::set_error("OnP2pDeviceChange return error");
    }
}

void OffP2pDeviceChange(::taihe::optional_view<::taihe::callback<void(
    ::ohos::wifiManager::WifiP2pDevice const&)>> callback)
{
}

void OnP2pPeerDeviceChange(::taihe::callback_view<void(
    ::taihe::array_view<::ohos::wifiManager::WifiP2pDevice>)> callback)
{
    wifiP2pCallback->wifiP2pPeerDeviceChangeCallback_ =
        ::taihe::optional<::taihe::callback<void(
        ::taihe::array_view<::ohos::wifiManager::WifiP2pDevice>)>>{std::in_place_t{}, callback};
    std::vector<std::string> event = {"p2pPeerDeviceChange"};
    ErrCode ret = g_wifiP2pPtr->RegisterCallBack(wifiP2pCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        taihe::set_error("OnP2pPeerDeviceChange return error");
    }
}

void OffP2pPeerDeviceChange(::taihe::optional_view<::taihe::callback<void(
    ::taihe::array_view<::ohos::wifiManager::WifiP2pDevice>)>> callback)
{
}

void OnP2pPersistentGroupChange(::taihe::callback_view<void(::ohos::wifiManager::UndefinedType const&)> callback)
{
    wifiP2pCallback->wifiP2pPersistentGroupChangeCallback_ = ::taihe::optional<::taihe::callback<void(
        ::ohos::wifiManager::UndefinedType const&)>>{std::in_place_t{}, callback};
    std::vector<std::string> event = {"p2pPersistentGroupChange"};
    ErrCode ret = g_wifiP2pPtr->RegisterCallBack(wifiP2pCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        taihe::set_error("OnP2pPersistentGroupChange return error");
    }
}

void OffP2pPersistentGroupChange(::taihe::optional_view<::taihe::callback<void(
    ::ohos::wifiManager::UndefinedType const&)>> callback)
{
}

void OnP2pDiscoveryChange(::taihe::callback_view<void(double)> callback)
{
    wifiP2pCallback->wifiP2pDiscoveryChangeCallback_ =
        ::taihe::optional<::taihe::callback<void(double)>>{std::in_place_t{}, callback};
    std::vector<std::string> event = {"p2pDiscoveryChange"};
    ErrCode ret = g_wifiP2pPtr->RegisterCallBack(wifiP2pCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        taihe::set_error("OnP2pDiscoveryChange return error");
    }
}

void OffP2pDiscoveryChange(::taihe::optional_view<::taihe::callback<void(double)>> callback)
{
}
}

TH_EXPORT_CPP_API_MakeWifiDeviceConfig(MakeWifiDeviceConfig);
TH_EXPORT_CPP_API_MakeWifiScanInfo(MakeWifiScanInfo);
TH_EXPORT_CPP_API_MakeWifiLinkedInfo(MakeWifiLinkedInfo);
TH_EXPORT_CPP_API_MakeIpInfo(MakeIpInfo);
TH_EXPORT_CPP_API_MakeIpv6Info(MakeIpv6Info);
TH_EXPORT_CPP_API_MakeStationInfo(MakeStationInfo);
TH_EXPORT_CPP_API_MakeHotspotConfig(MakeHotspotConfig);
TH_EXPORT_CPP_API_IsConnected(IsConnected);
TH_EXPORT_CPP_API_IsWifiActive(IsWifiActive);
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