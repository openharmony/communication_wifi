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

#include "wifi_callback_taihe.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiCallbackTaihe");
std::vector<::taihe::optional<::taihe::callback<void(int)>>>
    g_wifiStateChangeVec = {};
std::shared_mutex g_wifiStateChangeLock;
 
std::vector<::taihe::optional<::taihe::callback<void(int)>>>
    g_wifiConnectionChangeVec = {};
std::shared_mutex g_wifiConnectionChangeLock;
 
std::vector<::taihe::optional<::taihe::callback<void(int)>>>
    g_wifiRssiChangeVec = {};
std::shared_mutex g_wifiRssiChangeLock;
 
std::vector<::taihe::optional<::taihe::callback<void(int)>>>
    g_wifiStreamChangeVec = {};
std::shared_mutex g_wifiStreamChangeLock;
 
std::vector<::taihe::optional<::taihe::callback<void(int)>>>
    g_wifiDeviceConfigChangeVec = {};
std::shared_mutex g_wifiDeviceConfigChangeLock;
 
std::vector<::taihe::optional<::taihe::callback<void(int)>>>
    g_wifiScanStateChangeVec = {};
std::shared_mutex g_wifiScanStateChangeLock;
 
std::vector<::taihe::optional<::taihe::callback<void(int)>>>
    g_wifiHotspotStateChangeVec = {};
std::shared_mutex g_wifiHotspotStateChangeLock;
 
std::vector<::taihe::optional<::taihe::callback<
    void(::ohos::wifiManager::StationInfo const&)>>>
    g_wifiHotspotStaJoinVec = {};
std::shared_mutex g_wifiHotspotStaJoinLock;
 
std::vector<::taihe::optional<::taihe::callback<
    void(::ohos::wifiManager::StationInfo const&)>>>
    g_wifiHotspotStaLeaveVec = {};
std::shared_mutex g_wifiHotspotStaLeaveLock;
 
std::vector<::taihe::optional<::taihe::callback<void(int)>>>
    g_wifiP2pStateChangeVec = {};
std::shared_mutex g_wifiP2pStateChangeLock;
 
std::vector<::taihe::optional<::taihe::callback<
    void(::ohos::wifiManager::WifiP2pLinkedInfo const&)>>>
    g_wifiP2pConnectionChangeVec = {};
std::shared_mutex g_wifiP2pConnectionChangeLock;
 
std::vector<::taihe::optional<::taihe::callback<
    void(::ohos::wifiManager::WifiP2pDevice const&)>>>
    g_wifiP2pDeviceChangeVec = {};
std::shared_mutex g_wifiP2pDeviceChangeLock;
 
std::vector<::taihe::optional<::taihe::callback<
    void(::taihe::array_view<::ohos::wifiManager::WifiP2pDevice>)>>>
    g_wifiP2pPeerDeviceChangeVec = {};
std::shared_mutex g_wifiP2pPeerDeviceChangeLock;
 
std::vector<::taihe::optional<::taihe::callback<
    void(::ohos::wifiManager::UndefinedType const&)>>>
    g_wifiP2pPersistentGroupChangeVec = {};
std::shared_mutex g_wifiP2pPersistentGroupChangeLock;
 
std::vector<::taihe::optional<::taihe::callback<void(int)>>>
    g_wifiP2pDiscoveryChangeVec = {};
std::shared_mutex g_wifiP2pDiscoveryChangeLock;

// device
void WifiIdlDeviceEventCallback::OnWifiStateChanged(int state)
{
    std::shared_lock<std::shared_mutex> guard(g_wifiStateChangeLock);
    WIFI_LOGI("OnWifiStateChanged event: %{public}d [0:DISABLING, 1:DISABLED, 2:ENABLING, 3:ENABLED]",
        state);
    for (auto callback : g_wifiStateChangeVec) {
        (*callback)(state);
    }
}

void WifiIdlDeviceEventCallback::OnWifiConnectionChanged(int state, const WifiLinkedInfo &info)
{
    std::shared_lock<std::shared_mutex> guard(g_wifiStateChangeLock);
    WIFI_LOGI("OnWifiConnectionChanged event: %{public}d [4:CONNECTED, 6:DISCONNECTED, 7:SPECIAL_CONNECT]",
        state);
    for (auto callback : g_wifiConnectionChangeVec) {
        (*callback)(state);
    }
}

void WifiIdlDeviceEventCallback::OnWifiRssiChanged(int rssi)
{
    std::shared_lock<std::shared_mutex> guard(g_wifiRssiChangeLock);
    WIFI_LOGI("OnWifiRssiChanged event: %{public}d", rssi);
    for (auto callback : g_wifiRssiChangeVec) {
        (*callback)(rssi);
    }
}

void WifiIdlDeviceEventCallback::OnWifiWpsStateChanged(int state, const std::string &pinCode)
{
}

void WifiIdlDeviceEventCallback::OnStreamChanged(int direction)
{
    std::shared_lock<std::shared_mutex> guard(g_wifiStreamChangeLock);
    WIFI_LOGD("OnStreamChanged event: %{public}d [0:DATA_NONE, 1:DATA_IN, 2:DATA_OUT, 3:DATA_INOUT]",
        direction);
    for (auto callback : g_wifiStreamChangeVec) {
        (*callback)(direction);
    }
}

void WifiIdlDeviceEventCallback::OnDeviceConfigChanged(ConfigChange value)
{
    std::shared_lock<std::shared_mutex> guard(g_wifiDeviceConfigChangeLock);
    WIFI_LOGI("OnDeviceConfigChanged event: %{public}d", static_cast<int>(value));
    int result = static_cast<int>(value);
    for (auto callback : g_wifiDeviceConfigChangeVec) {
        (*callback)(result);
    }
}

OHOS::sptr<OHOS::IRemoteObject> WifiIdlDeviceEventCallback::AsObject()
{
    return nullptr;
}

// scan
void WifiIdlScanEventCallback::OnWifiScanStateChanged(int state)
{
    std::shared_lock<std::shared_mutex> guard(g_wifiScanStateChangeLock);
    WIFI_LOGI("scan received state changed event: %{public}d", state);
    for (auto callback : g_wifiScanStateChangeVec) {
        (*callback)(state);
    }
}

OHOS::sptr<OHOS::IRemoteObject> WifiIdlScanEventCallback::AsObject()
{
    return nullptr;
}


// hotspot
void WifiIdlHotspotEventCallback::OnHotspotStateChanged(int state)
{
    std::shared_lock<std::shared_mutex> guard(g_wifiHotspotStateChangeLock);
    WIFI_LOGI("Hotspot received state changed event: %{public}d", state);
    for (auto callback : g_wifiHotspotStateChangeVec) {
        (*callback)(state);
    }
}

void WifiIdlHotspotEventCallback::OnHotspotStaJoin(const StationInfo &info)
{
    // bssid -> macAddress
    std::shared_lock<std::shared_mutex> guard(g_wifiHotspotStaJoinLock);
    WIFI_LOGI("Hotspot received sta join event");
    ::ohos::wifiManager::StationInfo result = {info.bssid};
    for (auto callback : g_wifiHotspotStaJoinVec) {
        (*callback)(result);
    }
}

void WifiIdlHotspotEventCallback::OnHotspotStaLeave(const StationInfo &info)
{
    // bssid -> macAddress
    std::shared_lock<std::shared_mutex> guard(g_wifiHotspotStaLeaveLock);
    WIFI_LOGI("Hotspot received sta leave event");
    ::ohos::wifiManager::StationInfo result = {info.bssid};
    for (auto callback : g_wifiHotspotStaLeaveVec) {
        (*callback)(result);
    }
}

OHOS::sptr<OHOS::IRemoteObject> WifiIdlHotspotEventCallback::AsObject()
{
    return nullptr;
}

// p2p
void WifiIdlP2pEventCallback::OnP2pStateChanged(int state)
{
    std::shared_lock<std::shared_mutex> guard(g_wifiP2pStateChangeLock);
    WIFI_LOGI("received p2p state changed event: %{public}d", state);
    for (auto callback : g_wifiP2pStateChangeVec) {
        (*callback)(state);
    }
}

void WifiIdlP2pEventCallback::OnP2pPersistentGroupsChanged(void)
{
    std::shared_lock<std::shared_mutex> guard(g_wifiP2pPersistentGroupChangeLock);
    WIFI_LOGI("received persistent group changed event");
    auto result = ::ohos::wifiManager::UndefinedType::make_undefined();
    for (auto callback : g_wifiP2pPersistentGroupChangeVec) {
        (*callback)(result);
    }
}

void WifiIdlP2pEventCallback::OnP2pThisDeviceChanged(const WifiP2pDevice& device)
{
    std::shared_lock<std::shared_mutex> guard(g_wifiP2pDeviceChangeLock);
    WIFI_LOGI("received this device changed event");
    ::taihe::string_view deviceName = static_cast<::taihe::string_view>(device.GetDeviceName());
    ::taihe::string_view deviceAddress = static_cast<::taihe::string_view>(device.GetDeviceAddress());
    ::ohos::wifiManager::DeviceAddressType deviceAddressType =
        static_cast<::ohos::wifiManager::DeviceAddressType::key_t>(device.GetDeviceAddressType());
    ::taihe::string_view primaryDeviceType = static_cast<::taihe::string_view>(device.GetPrimaryDeviceType());
    ::ohos::wifiManager::P2pDeviceStatus deviceStatus =
        static_cast<::ohos::wifiManager::P2pDeviceStatus::key_t>(device.GetP2pDeviceStatus());
    int groupCapabilities = static_cast<int>(device.GetGroupCapabilitys());
    ::ohos::wifiManager::WifiP2pDevice result = {deviceName, deviceAddress, deviceAddressType,
        primaryDeviceType, deviceStatus, groupCapabilities};
    for (auto callback : g_wifiP2pDeviceChangeVec) {
        (*callback)(result);
    }
}

void WifiIdlP2pEventCallback::OnP2pPeersChanged(const std::vector<WifiP2pDevice>& devices)
{
    std::shared_lock<std::shared_mutex> guard(g_wifiP2pPeerDeviceChangeLock);
    WIFI_LOGI("received p2p peers changed event, devices count: %{public}d", static_cast<int>(devices.size()));
    std::vector<::ohos::wifiManager::WifiP2pDevice> result;
    for (WifiP2pDevice device : devices) {
        ::taihe::string_view deviceName = static_cast<::taihe::string_view>(device.GetDeviceName());
        ::taihe::string_view deviceAddress = static_cast<::taihe::string_view>(device.GetDeviceAddress());
        ::ohos::wifiManager::DeviceAddressType deviceAddressType =
            static_cast<::ohos::wifiManager::DeviceAddressType::key_t>(device.GetDeviceAddressType());
        ::taihe::string_view primaryDeviceType =
            static_cast<::taihe::string_view>(device.GetPrimaryDeviceType());
        ::ohos::wifiManager::P2pDeviceStatus deviceStatus =
            static_cast<::ohos::wifiManager::P2pDeviceStatus::key_t>(device.GetP2pDeviceStatus());
        int groupCapabilities = static_cast<int>(device.GetGroupCapabilitys());
        ::ohos::wifiManager::WifiP2pDevice tmpDevice = {deviceName, deviceAddress, deviceAddressType,
            primaryDeviceType, deviceStatus, groupCapabilities};
        result.emplace_back(tmpDevice);
    }
    ::taihe::array<::ohos::wifiManager::WifiP2pDevice> finalResult =
        ::taihe::array<::ohos::wifiManager::WifiP2pDevice>(taihe::copy_data_t{}, result.data(), result.size());
    for (auto callback : g_wifiP2pPeerDeviceChangeVec) {
        (*callback)(result);
    }
}

void WifiIdlP2pEventCallback::OnP2pServicesChanged(const std::vector<WifiP2pServiceInfo>& srvInfo)
{
}

void WifiIdlP2pEventCallback::OnP2pConnectionChanged(const WifiP2pLinkedInfo& info)
{
    std::shared_lock<std::shared_mutex> guard(g_wifiP2pPeerDeviceChangeLock);
    WIFI_LOGI("received p2p connection changed event, state: %{public}d",
        static_cast<int>(info.GetConnectState()));
    ::ohos::wifiManager::P2pConnectState state =
        static_cast<::ohos::wifiManager::P2pConnectState::key_t>(info.GetConnectState());
    ani_boolean isOwner = static_cast<ani_boolean>(info.IsGroupOwner());
    ::taihe::string_view ownerAddr = static_cast<::taihe::string_view>(info.GetGroupOwnerAddress());
    ::ohos::wifiManager::WifiP2pLinkedInfo result = {state, isOwner, ownerAddr};
    for (auto callback : g_wifiP2pConnectionChangeVec) {
        (*callback)(result);
    }
}

void WifiIdlP2pEventCallback::OnP2pDiscoveryChanged(bool isChange)
{
    std::shared_lock<std::shared_mutex> guard(g_wifiP2pDiscoveryChangeLock);
    WIFI_LOGI("received discovery state changed event");
    int result = static_cast<int>(isChange);
    for (auto callback : g_wifiP2pDiscoveryChangeVec) {
        (*callback)(result);
    }
}

void WifiIdlP2pEventCallback::OnP2pActionResult(P2pActionCallback action, ErrCode code)
{
}

void WifiIdlP2pEventCallback::OnConfigChanged(CfgType type, char* data, int dataLen)
{
}

void WifiIdlP2pEventCallback::OnP2pGcJoinGroup(const OHOS::Wifi::GcInfo &info)
{
    WIFI_LOGI("received OnP2pGcJoinGroup event");
}

void WifiIdlP2pEventCallback::OnP2pGcLeaveGroup(const OHOS::Wifi::GcInfo &info)
{
    WIFI_LOGI("received OnP2pGcLeave event");
}

void WifiIdlP2pEventCallback::OnP2pPrivatePeersChanged(const std::string &priWfdInfo)
{
    WIFI_LOGI("received OnP2pPrivatePeersChanged event");
}

void WifiIdlP2pEventCallback::OnP2pChrErrCodeReport(const int errCode)
{
    WIFI_LOGI("received OnP2pChrErrCodeReport event");
}

OHOS::sptr<OHOS::IRemoteObject> WifiIdlP2pEventCallback::AsObject()
{
    return nullptr;
}
}  // namespace Wifi
}  // namespace OHOS