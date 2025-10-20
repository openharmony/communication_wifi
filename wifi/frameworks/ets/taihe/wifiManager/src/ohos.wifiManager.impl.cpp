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
#include "wifi_utils_taihe.h"
#include "wifi_callback_taihe.h"
#include "wifi_errorcode_taihe.h"
using namespace OHOS::Wifi;
DEFINE_WIFILOG_LABEL("WifiManagerTaihe");
static std::shared_ptr<WifiDevice> g_wifiDevicePtr = WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);
std::shared_ptr<WifiScan> g_wifiScanPtr = WifiScan::GetInstance(WIFI_SCAN_ABILITY_ID);
static std::shared_ptr<WifiHotspot> g_wifiHotspotPtr = WifiHotspot::GetInstance(WIFI_HOTSPOT_ABILITY_ID);
std::shared_ptr<WifiP2p> g_wifiP2pPtr = WifiP2p::GetInstance(WIFI_P2P_ABILITY_ID);
namespace {

OHOS::sptr<WifiIdlDeviceEventCallback> wifiDeviceCallback =
    OHOS::sptr<WifiIdlDeviceEventCallback>(new (std::nothrow) WifiIdlDeviceEventCallback());

OHOS::sptr<WifiIdlScanEventCallback> wifiScanCallback =
    OHOS::sptr<WifiIdlScanEventCallback>(new (std::nothrow) WifiIdlScanEventCallback());

OHOS::sptr<WifiIdlHotspotEventCallback> wifiHotspotCallback =
    OHOS::sptr<WifiIdlHotspotEventCallback>(new (std::nothrow) WifiIdlHotspotEventCallback());

OHOS::sptr<WifiIdlP2pEventCallback> wifiP2pCallback =
    OHOS::sptr<WifiIdlP2pEventCallback>(new (std::nothrow) WifiIdlP2pEventCallback());

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

int GetSignalLevel(int rssi, int band)
{
    int level = -1;
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return 0.0;
    }
    ErrCode ret = g_wifiDevicePtr->GetSignalLevel(rssi, band, level);
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
        ::ohos::wifiManager::IpInfo errorResult = MakeIpInfo(ipInfo);
        return errorResult;
    }
    ErrCode ret = g_wifiDevicePtr->GetIpInfo(ipInfo);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
    }
    ::ohos::wifiManager::IpInfo result = MakeIpInfo(ipInfo);
    return result;
}

::ohos::wifiManager::Ipv6Info GetIpv6Info()
{
    IpV6Info ipInfo;
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        ::ohos::wifiManager::Ipv6Info errorResult = MakeIpv6Info(ipInfo);
        return errorResult;
    }
    ErrCode ret = g_wifiDevicePtr->GetIpv6Info(ipInfo);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
    }
    ::ohos::wifiManager::Ipv6Info result = MakeIpv6Info(ipInfo);
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
    for (WifiScanInfo& scanInfo : scanInfos) {
        ::ohos::wifiManager::WifiScanInfo tmpInfo = MakeWifiScanInfo(scanInfo);
        result.emplace_back(tmpInfo);
    }
    return ::taihe::array<::ohos::wifiManager::WifiScanInfo>(taihe::copy_data_t{},
        result.data(), result.size());
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
    for (StationInfo& stationInfo : vecStationInfo) {
        ::ohos::wifiManager::StationInfo tmpInfo = MakeStationInfo(stationInfo);
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

::taihe::array<::ohos::wifiManager::WifiDeviceConfig> GetDeviceConfigs()
{
    WifiDeviceConfig tmpWifiDeviceConfig;
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return {MakeWifiDeviceConfig(tmpWifiDeviceConfig)};
    }
    std::vector<WifiDeviceConfig> vecDeviceConfigs;
    bool isCandidate = false;
    ErrCode ret = g_wifiDevicePtr->GetDeviceConfigs(vecDeviceConfigs, isCandidate);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Get device configs fail: %{public}d", ret);
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
        return {MakeWifiDeviceConfig(tmpWifiDeviceConfig)};
    }
    WIFI_LOGI("Get device configs size: %{public}zu", vecDeviceConfigs.size());
    std::vector<::ohos::wifiManager::WifiDeviceConfig> result;
    for (const WifiDeviceConfig& device : vecDeviceConfigs) {
        result.emplace_back(MakeWifiDeviceConfig(device));
    }
    return ::taihe::array<::ohos::wifiManager::WifiDeviceConfig>(
        taihe::copy_data_t{}, result.data(), result.size());
}

void Disconnect()
{
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return;
    }
    ErrCode ret = g_wifiDevicePtr->Disconnect();
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
        return;
    }
}

void ConnectToNetwork(int32_t networkId)
{
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return;
    }
    bool isCandidate = false;
    ErrCode ret = g_wifiDevicePtr->ConnectToNetwork(networkId, isCandidate);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
        return;
    }
}

::taihe::array<::taihe::string> GetDeviceMacAddress()
{
    std::string macAddr;
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return {static_cast<::taihe::string>(macAddr)};
    }
    ErrCode ret = g_wifiDevicePtr->GetDeviceMacAddress(macAddr);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Get mac address fail: %{public}d", ret);
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
        return {static_cast<::taihe::string>(macAddr)};
    }
    return {static_cast<::taihe::string>(macAddr)};
}

bool IsHotspotActive()
{
    bool isActive = false;
    if (g_wifiHotspotPtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_AP_CORE);
        return isActive;
    }
    ErrCode ret = g_wifiHotspotPtr->IsHotspotActive(isActive);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_AP_CORE);
    }
    return isActive;
}

void P2pConnect(::ohos::wifiManager::WifiP2PConfig const& config)
{
    if (g_wifiP2pPtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_P2P);
        return;
    }
    WifiP2pConfig newConfig = ConvertWifiP2pConfig(config);
    ErrCode ret = g_wifiP2pPtr->P2pConnect(newConfig);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_P2P);
    }
}

::taihe::array<::ohos::wifiManager::WifiDeviceConfig> GetCandidateConfigs()
{
    WifiDeviceConfig tmpResult;
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return {MakeWifiDeviceConfig(tmpResult)};
    }
    std::vector<WifiDeviceConfig> vecDeviceConfigs;
    bool isCandidate = true;
    ErrCode ret = g_wifiDevicePtr->GetDeviceConfigs(vecDeviceConfigs, isCandidate);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
        return {MakeWifiDeviceConfig(tmpResult)};
    }
    std::vector<::ohos::wifiManager::WifiDeviceConfig> result;
    for (const WifiDeviceConfig& device : vecDeviceConfigs) {
        result.emplace_back(MakeWifiDeviceConfig(device));
    }
    return ::taihe::array<::ohos::wifiManager::WifiDeviceConfig>(
        taihe::copy_data_t{}, result.data(), result.size());
}

void P2pCancelConnect()
{
    if (g_wifiP2pPtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_P2P);
        return;
    }
    ErrCode ret = g_wifiP2pPtr->P2pCancelConnect();
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_P2P);
    }
}

void ConnectToCandidateConfig(int32_t networkId)
{
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return;
    }
    bool isCandidate = true;
    ErrCode ret = g_wifiDevicePtr->ConnectToNetwork(networkId, isCandidate);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
        return;
    }
}

void Reconnect()
{
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return;
    }
    ErrCode ret = g_wifiDevicePtr->ReConnect();
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
        return;
    }
}

void Reassociate()
{
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return;
    }
    ErrCode ret = g_wifiDevicePtr->ReAssociate();
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
        return;
    }
}

void ConnectToDevice(::ohos::wifiManager::WifiDeviceConfig const& config)
{
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return;
    }
    WifiDeviceConfig convertedConfig = ConvertWifiDeviceConfig(config);
    ErrCode ret = g_wifiDevicePtr->ConnectToDevice(convertedConfig);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
        return;
    }
}

void SetHotspotConfig(::ohos::wifiManager::HotspotConfig const& config)
{
    if (g_wifiHotspotPtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_AP_CORE);
        return;
    }
    if (!IsSecTypeSupported(config.securityType)) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_AP_CORE);
        return;
    }
    HotspotConfig convertedConfig = ConvertHotspotConfig(config);
    ErrCode ret = g_wifiHotspotPtr->SetHotspotConfig(convertedConfig);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_AP_CORE);
        return;
    }
}

bool IsFeatureSupported(int64_t featureId)
{
    bool isSupported = false;
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_CORE);
        return isSupported;
    }
    ErrCode ret = g_wifiDevicePtr->IsFeatureSupported(featureId, isSupported);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_CORE);
        return isSupported;
    }
    return isSupported;
}

::ohos::wifiManager::HotspotConfig GetHotspotConfig()
{
    HotspotConfig config;
    if (g_wifiHotspotPtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_AP_CORE);
        return MakeHotspotConfig(config);
    }
    ErrCode ret = g_wifiHotspotPtr->GetHotspotConfig(config);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_AP_CORE);
    }
    return MakeHotspotConfig(config);
}

void DisableHotspot()
{
    if (g_wifiHotspotPtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_AP_CORE);
        return;
    }
    ErrCode ret = g_wifiHotspotPtr->DisableHotspot();
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_AP_CORE);
    }
}

void EnableHotspot()
{
    if (g_wifiHotspotPtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_AP_CORE);
        return;
    }
    ErrCode ret = g_wifiHotspotPtr->EnableHotspot();
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_AP_CORE);
    }
}

bool IsHotspotDualBandSupported()
{
    bool isSupported = false;
    if (g_wifiHotspotPtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_AP_CORE);
        return isSupported;
    }
    ErrCode ret = g_wifiHotspotPtr->IsHotspotDualBandSupported(isSupported);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_AP_CORE);
    }
    return isSupported;
}

int64_t GetSupportedFeatures()
{
    long features = -1;
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_CORE);
        return static_cast<int64_t>(features);
    }
    ErrCode ret = g_wifiDevicePtr->GetSupportedFeatures(features);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_CORE);
    }
    return static_cast<int64_t>(features);
}

::taihe::string GetCountryCode()
{
    std::string countryCode;
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_CORE);
        return static_cast<::taihe::string>(countryCode);
    }
    ErrCode ret = g_wifiDevicePtr->GetCountryCode(countryCode);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_CORE);
    }
    return static_cast<::taihe::string>(countryCode);
}

void RemoveDevice(int32_t id)
{
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return;
    }
    ErrCode ret = g_wifiDevicePtr->RemoveDevice(id);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
    }
    return;
}

::taihe::array<::ohos::wifiManager::WifiLinkedInfo> GetMultiLinkedInfo()
{
    WifiLinkedInfo tmpResult;
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return {MakeWifiLinkedInfo(tmpResult)};
    }
    std::vector<WifiLinkedInfo> wifiMultiLinkedInfo;
    ErrCode ret = g_wifiDevicePtr->GetMultiLinkedInfo(wifiMultiLinkedInfo);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("GetMultiLinkedInfo value fail:%{public}d", ret);
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
        return {MakeWifiLinkedInfo(tmpResult)};
    }
    WIFI_LOGI("%{public}s get multi linkedInfo size: %{public}zu",
        __FUNCTION__, wifiMultiLinkedInfo.size());
    std::vector<::ohos::wifiManager::WifiLinkedInfo> result;
    for (WifiLinkedInfo& linkedInfo : wifiMultiLinkedInfo) {
        ::ohos::wifiManager::WifiLinkedInfo tmpInfo = MakeWifiLinkedInfo(linkedInfo);
        result.emplace_back(tmpInfo);
    }
    return ::taihe::array<::ohos::wifiManager::WifiLinkedInfo>(
        taihe::copy_data_t{}, result.data(), result.size());
}

void AllowAutoConnect(int32_t netId, bool isAllowed)
{
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return;
    }
    ErrCode ret = g_wifiDevicePtr->AllowAutoConnect(netId, isAllowed);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
    }
    return;
}

bool IsBandTypeSupported(::ohos::wifiManager::WifiBandType bandType)
{
    bool supported = false;
    int type = static_cast<int>(bandType);
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return supported;
    }
    ErrCode ret = g_wifiDevicePtr->IsBandTypeSupported(type, supported);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
    }
    return supported;
}

void CreateGroup(::ohos::wifiManager::WifiP2PConfig const& config)
{
    if (g_wifiP2pPtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_P2P);
        return;
    }
    WifiP2pConfig configInner = ConvertWifiP2pConfig(config);
    ErrCode ret = g_wifiP2pPtr->CreateGroup(configInner);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_P2P);
    }
    return;
}

void StartDiscoverDevices()
{
    if (g_wifiP2pPtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_P2P);
        return;
    }
    ErrCode ret = g_wifiP2pPtr->DiscoverDevices();
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_P2P);
    }
    return;
}

void RemoveGroup()
{
    if (g_wifiP2pPtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_P2P);
        return;
    }
    ErrCode ret = g_wifiP2pPtr->RemoveGroup();
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_P2P);
    }
    return;
}

void StopDiscoverDevices()
{
    if (g_wifiP2pPtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_P2P);
        return;
    }
    ErrCode ret = g_wifiP2pPtr->StopDiscoverDevices();
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_P2P);
    }
    return;
}

::taihe::array<::ohos::wifiManager::StationInfo> GetHotspotBlockList()
{
    StationInfo tmpStationInfo;
    ::ohos::wifiManager::StationInfo tmpResult = MakeStationInfo(tmpStationInfo);
    if (g_wifiHotspotPtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_AP_CORE);
        return {tmpResult};
    }
    std::vector<StationInfo> vecStationInfo;
    ErrCode ret = g_wifiHotspotPtr->GetBlockLists(vecStationInfo);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_AP_CORE);
        return {tmpResult};
    }
    WIFI_LOGI("Get block list size: %{public}zu", vecStationInfo.size());
    std::vector<::ohos::wifiManager::StationInfo> result;
    for (StationInfo& info : vecStationInfo) {
        ::ohos::wifiManager::StationInfo tmpInfo = MakeStationInfo(info);
        result.emplace_back(tmpInfo);
    }
    return ::taihe::array<::ohos::wifiManager::StationInfo>(taihe::copy_data_t{},
        result.data(), result.size());
}

void SetDeviceName(::taihe::string_view devName)
{
    if (g_wifiP2pPtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_P2P);
        return;
    }
    std::string name = static_cast<std::string>(devName);
    ErrCode ret = g_wifiP2pPtr->SetP2pDeviceName(name);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_P2P);
    }
    return;
}

void EnableHiLinkHandshake(bool isHiLinkEnable, ::taihe::string_view bssid,
    ::ohos::wifiManager::WifiDeviceConfig const& config)
{
    WifiDeviceConfig deviceConfig = ConvertWifiDeviceConfig(config);
    std::string bssidInner = static_cast<std::string>(bssid);
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return;
    }
    ErrCode ret = g_wifiDevicePtr->EnableHiLinkHandshake(isHiLinkEnable, bssidInner, deviceConfig);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
    }
}

void StartPortalCertification()
{
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return;
    }
    ErrCode ret = g_wifiDevicePtr->StartPortalCertification();
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
    }
}

void DeletePersistentGroup(int32_t netId)
{
    if (g_wifiP2pPtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_P2P);
        return;
    }
    WifiP2pGroupInfo groupInfo;
    groupInfo.SetNetworkId(netId);
    ErrCode ret = g_wifiP2pPtr->DeleteGroup(groupInfo);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_P2P);
    }
    return;
}

void DisableNetwork(int32_t netId)
{
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return;
    }
    ErrCode ret = g_wifiDevicePtr->DisableDeviceConfig(netId);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
    }
}

int32_t UpdateNetwork(::ohos::wifiManager::WifiDeviceConfig const& config)
{
    WifiDeviceConfig configInner = ConvertWifiDeviceConfig(config);
    int updateResult = -1;
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return updateResult;
    }
    ErrCode ret = g_wifiDevicePtr->UpdateDeviceConfig(configInner, updateResult);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
    }
    return updateResult;
}

void RemoveAllNetwork()
{
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return;
    }
    ErrCode ret = g_wifiDevicePtr->RemoveAllDevice();
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
    }
    return;
}

void DelHotspotBlockList(::ohos::wifiManager::StationInfo const& stationInfo)
{
    StationInfo stationInfoInner = ConvertStationInfo(stationInfo);
    if (g_wifiHotspotPtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_AP_CORE);
        return;
    }
    ErrCode ret = g_wifiHotspotPtr->DelBlockList(stationInfoInner);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Del block list fail: %{public}d", ret);
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_AP_CORE);
    }
}

void AddHotspotBlockList(::ohos::wifiManager::StationInfo const& stationInfo)
{
    StationInfo stationInfoInner = ConvertStationInfo(stationInfo);
    if (g_wifiHotspotPtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_AP_CORE);
        return;
    }
    ErrCode ret = g_wifiHotspotPtr->AddBlockList(stationInfoInner);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Add block list fail: %{public}d", ret);
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_AP_CORE);
    }
}

void SetScanAlwaysAllowed(bool isScanAlwaysAllowed)
{
    if (g_wifiScanPtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_CORE);
        return;
    }
    ErrCode ret = g_wifiScanPtr->SetScanOnlyAvailable(isScanAlwaysAllowed);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_CORE);
    }
    return;
}

void FactoryReset()
{
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return;
    }
    ErrCode ret = g_wifiDevicePtr->FactoryReset();
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
    }
    return;
}

::taihe::array<int32_t> Get5GChannelList()
{
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return {-1};
    }
    std::vector<int32_t> vec5GChannels;
    ErrCode ret = g_wifiDevicePtr->Get5GHzChannelList(vec5GChannels);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
        return {-1};
    }
    return ::taihe::array<int32_t>(taihe::copy_data_t{}, vec5GChannels.data(), vec5GChannels.size());
}

void StartScan()
{
    if (g_wifiScanPtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return;
    }
    bool compatible = false;
    ErrCode ret = g_wifiScanPtr->Scan(compatible);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
    }
}

::ohos::wifiManager::DisconnectedReason GetDisconnectedReason()
{
    DisconnectedReason reason = DisconnectedReason::DISC_REASON_DEFAULT;
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return static_cast<::ohos::wifiManager::DisconnectedReason::key_t>(reason);
    }
    
    ErrCode ret = g_wifiDevicePtr->GetDisconnectedReason(reason);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("GetDisconnectedReason failed:%{public}d", ret);
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
    }
    return static_cast<::ohos::wifiManager::DisconnectedReason::key_t>(reason);
}

bool GetScanAlwaysAllowed()
{
    bool isScanAlwaysAllowed = false;
    if (g_wifiScanPtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_CORE);
        return isScanAlwaysAllowed;
    }
    ErrCode ret = g_wifiScanPtr->GetScanOnlyAvailable(isScanAlwaysAllowed);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_CORE);
    }
    return isScanAlwaysAllowed;
}

void ConnectToCandidateConfigWithUserActionSync(int32_t networkId)
{
    std::vector<std::string> event = {EVENT_STA_CANDIDATE_CONNECT_CHANGE};
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return;
    }
    ErrCode ret = g_wifiDevicePtr->RegisterCallBack(wifiDeviceCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
    }

    bool isCandidate = true;
    ret = g_wifiDevicePtr->ConnectToNetwork(networkId, isCandidate);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
        return;
    }
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

int32_t AddDeviceConfigSync(::ohos::wifiManager::WifiDeviceConfig const& config)
{
    int32_t networkId = -1;
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return networkId;
    }
    WifiDeviceConfig configInner = ConvertWifiDeviceConfig(config);
    bool isCandidate = false;
    ErrCode ret = g_wifiDevicePtr->AddDeviceConfig(configInner, networkId, isCandidate);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
    }
    return networkId;
}

::taihe::array<::ohos::wifiManager::WifiP2pDevice> GetP2pPeerDevicesSync()
{
    WifiP2pDevice tmpResult;
    if (g_wifiP2pPtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_P2P);
        return {MakeWifiP2pDevice(tmpResult)};
    }
    std::vector<WifiP2pDevice> vecP2pDevices;
    ErrCode ret = g_wifiP2pPtr->QueryP2pDevices(vecP2pDevices);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_P2P);
        return {MakeWifiP2pDevice(tmpResult)};
    }
    std::vector<::ohos::wifiManager::WifiP2pDevice> result;
    for (WifiP2pDevice& device : vecP2pDevices) {
        result.emplace_back(MakeWifiP2pDevice(device));
    }
    return ::taihe::array<::ohos::wifiManager::WifiP2pDevice>(taihe::copy_data_t{},
        result.data(), result.size());
}

::ohos::wifiManager::WifiP2pLinkedInfo GetP2pLinkedInfoSync()
{
    WifiP2pLinkedInfo linkedInfo;
    if (g_wifiP2pPtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_P2P);
        return MakeWifiP2pLinkedInfo(linkedInfo);
    }
    ErrCode ret = g_wifiP2pPtr->QueryP2pLinkedInfo(linkedInfo);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_P2P);
    }
    return MakeWifiP2pLinkedInfo(linkedInfo);
}

int32_t AddCandidateConfigSync(::ohos::wifiManager::WifiDeviceConfig const& config)
{
    int32_t networkId = -1;
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return networkId;
    }
    WifiDeviceConfig configInner = ConvertWifiDeviceConfig(config);
    bool isCandidate = true;
    ErrCode ret = g_wifiDevicePtr->AddDeviceConfig(configInner, networkId, isCandidate);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
    }
    return networkId;
}

void RemoveCandidateConfigSync(int32_t networkId)
{
    if (g_wifiDevicePtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
        return;
    }
    ErrCode ret = g_wifiDevicePtr->RemoveCandidateConfig(networkId);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_STA);
    }
}

::ohos::wifiManager::WifiP2pDevice GetP2pLocalDeviceSync()
{
    WifiP2pDevice deviceInfo;
    if (g_wifiP2pPtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_P2P);
        return MakeWifiP2pDevice(deviceInfo);
    }
    ErrCode ret = g_wifiP2pPtr->QueryP2pLocalDevice(deviceInfo);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_P2P);
    }
    return MakeWifiP2pDevice(deviceInfo);
}

::taihe::array<::ohos::wifiManager::WifiP2pGroupInfo> GetP2pGroupsSync()
{
    WifiP2pGroupInfo info;
    if (g_wifiP2pPtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_P2P);
        return {MakeWifiP2pGroupInfo(info)};
    }
    std::vector<WifiP2pGroupInfo> vecGroupInfoList;
    ErrCode ret = g_wifiP2pPtr->QueryP2pGroups(vecGroupInfoList);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_P2P);
        return {MakeWifiP2pGroupInfo(info)};
    }
    std::vector<::ohos::wifiManager::WifiP2pGroupInfo> result;
    for (WifiP2pGroupInfo &groupInfo : vecGroupInfoList) {
        result.emplace_back(MakeWifiP2pGroupInfo(groupInfo));
    }
    return ::taihe::array<::ohos::wifiManager::WifiP2pGroupInfo>(taihe::copy_data_t{},
        result.data(), result.size());
}

::ohos::wifiManager::WifiP2pGroupInfo GetCurrentGroupSync()
{
    WifiP2pGroupInfo groupInfo;
    if (g_wifiP2pPtr == nullptr) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, WIFI_OPT_FAILED, SYSCAP_WIFI_P2P);
        return MakeWifiP2pGroupInfo(groupInfo);
    }
    ErrCode ret = g_wifiP2pPtr->GetCurrentGroup(groupInfo);
    if (ret != WIFI_OPT_SUCCESS) {
        WifiIdlErrorCode::TaiheSetBusinessError(__FUNCTION__, ret, SYSCAP_WIFI_P2P);
    }
    return MakeWifiP2pGroupInfo(groupInfo);
}

void OnWifiStateChange(::taihe::callback_view<void(int)> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiStateChangeLock);
    auto wifiStateChangedCallback =
        ::taihe::optional<::taihe::callback<void(int)>>{std::in_place_t{}, callback};
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

void OffWifiStateChange(::taihe::optional_view<::taihe::callback<void(int)>> callback)
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

void OnWifiConnectionChange(::taihe::callback_view<void(int)> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiConnectionChangeLock);
    auto wifiConnectionChangeCallback =
        ::taihe::optional<::taihe::callback<void(int)>>{std::in_place_t{}, callback};
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
 
void OffWifiConnectionChange(::taihe::optional_view<::taihe::callback<void(int)>> callback)
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
 
void OnWifiScanStateChange(::taihe::callback_view<void(int)> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiScanStateChangeLock);
    auto wifiScanStateChangeCallback =
        ::taihe::optional<::taihe::callback<void(int)>>{std::in_place_t{}, callback};
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
 
void OffWifiScanStateChange(::taihe::optional_view<::taihe::callback<void(int)>> callback)
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
 
void OnWifiRssiChange(::taihe::callback_view<void(int)> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiRssiChangeLock);
    auto wifiRssiChangeCallback =
        ::taihe::optional<::taihe::callback<void(int)>>{std::in_place_t{}, callback};
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
 
void OffWifiRssiChange(::taihe::optional_view<::taihe::callback<void(int)>> callback)
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

void OnStreamChange(::taihe::callback_view<void(int)> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiStreamChangeLock);
    auto wifiRssiChangeCallback =
        ::taihe::optional<::taihe::callback<void(int)>>{std::in_place_t{}, callback};
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

void OffStreamChange(::taihe::optional_view<::taihe::callback<void(int)>> callback)
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

void OnDeviceConfigChange(::taihe::callback_view<void(int)> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiDeviceConfigChangeLock);
    auto wifiDeviceConfigChangeCallback =
        ::taihe::optional<::taihe::callback<void(int)>>{std::in_place_t{}, callback};
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

void OffDeviceConfigChange(::taihe::optional_view<::taihe::callback<void(int)>> callback)
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

void OnHotspotStateChange(::taihe::callback_view<void(int)> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiHotspotStateChangeLock);
    auto wifiHotspotStateChangeCallback =
        ::taihe::optional<::taihe::callback<void(int)>>{std::in_place_t{}, callback};
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

void OffHotspotStateChange(::taihe::optional_view<::taihe::callback<void(int)>> callback)
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

void OnP2pStateChange(::taihe::callback_view<void(int)> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiP2pStateChangeLock);
    auto wifiP2pStateChangeCallback =
        ::taihe::optional<::taihe::callback<void(int)>>{std::in_place_t{}, callback};
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

void OffP2pStateChange(::taihe::optional_view<::taihe::callback<void(int)>> callback)
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

void OnP2pDiscoveryChange(::taihe::callback_view<void(int)> callback)
{
    std::unique_lock<std::shared_mutex> guard(g_wifiP2pDiscoveryChangeLock);
    auto wifiP2pDiscoveryChangeCallback =
        ::taihe::optional<::taihe::callback<void(int)>>{std::in_place_t{}, callback};
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

void OffP2pDiscoveryChange(::taihe::optional_view<::taihe::callback<void(int)>> callback)
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
TH_EXPORT_CPP_API_GetDeviceConfigs(GetDeviceConfigs);
TH_EXPORT_CPP_API_Disconnect(Disconnect);
TH_EXPORT_CPP_API_ConnectToNetwork(ConnectToNetwork);
TH_EXPORT_CPP_API_GetDeviceMacAddress(GetDeviceMacAddress);
TH_EXPORT_CPP_API_IsHotspotActive(IsHotspotActive);
TH_EXPORT_CPP_API_P2pConnect(P2pConnect);
TH_EXPORT_CPP_API_GetCandidateConfigs(GetCandidateConfigs);
TH_EXPORT_CPP_API_P2pCancelConnect(P2pCancelConnect);
TH_EXPORT_CPP_API_ConnectToCandidateConfig(ConnectToCandidateConfig);
TH_EXPORT_CPP_API_Reconnect(Reconnect);
TH_EXPORT_CPP_API_Reassociate(Reassociate);
TH_EXPORT_CPP_API_ConnectToDevice(ConnectToDevice);
TH_EXPORT_CPP_API_SetHotspotConfig(SetHotspotConfig);
TH_EXPORT_CPP_API_IsFeatureSupported(IsFeatureSupported);
TH_EXPORT_CPP_API_GetHotspotConfig(GetHotspotConfig);
TH_EXPORT_CPP_API_DisableHotspot(DisableHotspot);
TH_EXPORT_CPP_API_EnableHotspot(EnableHotspot);
TH_EXPORT_CPP_API_IsHotspotDualBandSupported(IsHotspotDualBandSupported);
TH_EXPORT_CPP_API_GetSupportedFeatures(GetSupportedFeatures);
TH_EXPORT_CPP_API_GetCountryCode(GetCountryCode);
TH_EXPORT_CPP_API_RemoveDevice(RemoveDevice);
TH_EXPORT_CPP_API_GetMultiLinkedInfo(GetMultiLinkedInfo);
TH_EXPORT_CPP_API_AllowAutoConnect(AllowAutoConnect);
TH_EXPORT_CPP_API_IsBandTypeSupported(IsBandTypeSupported);
TH_EXPORT_CPP_API_CreateGroup(CreateGroup);
TH_EXPORT_CPP_API_StartDiscoverDevices(StartDiscoverDevices);
TH_EXPORT_CPP_API_RemoveGroup(RemoveGroup);
TH_EXPORT_CPP_API_StopDiscoverDevices(StopDiscoverDevices);
TH_EXPORT_CPP_API_GetHotspotBlockList(GetHotspotBlockList);
TH_EXPORT_CPP_API_SetDeviceName(SetDeviceName);
TH_EXPORT_CPP_API_EnableHiLinkHandshake(EnableHiLinkHandshake);
TH_EXPORT_CPP_API_StartPortalCertification(StartPortalCertification);
TH_EXPORT_CPP_API_DeletePersistentGroup(DeletePersistentGroup);
TH_EXPORT_CPP_API_DisableNetwork(DisableNetwork);
TH_EXPORT_CPP_API_UpdateNetwork(UpdateNetwork);
TH_EXPORT_CPP_API_RemoveAllNetwork(RemoveAllNetwork);
TH_EXPORT_CPP_API_DelHotspotBlockList(DelHotspotBlockList);
TH_EXPORT_CPP_API_AddHotspotBlockList(AddHotspotBlockList);
TH_EXPORT_CPP_API_SetScanAlwaysAllowed(SetScanAlwaysAllowed);
TH_EXPORT_CPP_API_FactoryReset(FactoryReset);
TH_EXPORT_CPP_API_Get5GChannelList(Get5GChannelList);
TH_EXPORT_CPP_API_StartScan(StartScan);
TH_EXPORT_CPP_API_GetDisconnectedReason(GetDisconnectedReason);
TH_EXPORT_CPP_API_GetScanAlwaysAllowed(GetScanAlwaysAllowed);
TH_EXPORT_CPP_API_ConnectToCandidateConfigWithUserActionSync(ConnectToCandidateConfigWithUserActionSync);
TH_EXPORT_CPP_API_GetLinkedInfoSync(GetLinkedInfoSync);
TH_EXPORT_CPP_API_AddDeviceConfigSync(AddDeviceConfigSync);
TH_EXPORT_CPP_API_GetP2pPeerDevicesSync(GetP2pPeerDevicesSync);
TH_EXPORT_CPP_API_GetP2pLinkedInfoSync(GetP2pLinkedInfoSync);
TH_EXPORT_CPP_API_AddCandidateConfigSync(AddCandidateConfigSync);
TH_EXPORT_CPP_API_RemoveCandidateConfigSync(RemoveCandidateConfigSync);
TH_EXPORT_CPP_API_GetP2pLocalDeviceSync(GetP2pLocalDeviceSync);
TH_EXPORT_CPP_API_GetP2pGroupsSync(GetP2pGroupsSync);
TH_EXPORT_CPP_API_GetCurrentGroupSync(GetCurrentGroupSync);
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