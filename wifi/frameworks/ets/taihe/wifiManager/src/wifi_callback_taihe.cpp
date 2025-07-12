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
// device
void WifiIdlDeviceEventCallback::OnWifiStateChanged(int state)
{
    double result = static_cast<double>(state);
    if (wifiStateChangedCallback_) {
        (*wifiStateChangedCallback_)(result);
    }
}

void WifiIdlDeviceEventCallback::OnWifiConnectionChanged(int state, const WifiLinkedInfo &info)
{
    double result = static_cast<double>(state);
    if (wifiConnectionChangeCallback_) {
        (*wifiConnectionChangeCallback_)(result);
    }
}

void WifiIdlDeviceEventCallback::OnWifiRssiChanged(int rssi)
{
    double result = static_cast<double>(rssi);
    if (wifiRssiChangeCallback_) {
        (*wifiRssiChangeCallback_)(result);
    }
}

void WifiIdlDeviceEventCallback::OnWifiWpsStateChanged(int state, const std::string &pinCode)
{
}

void WifiIdlDeviceEventCallback::OnStreamChanged(int direction)
{
    double result = static_cast<double>(direction);
    if (wifiStreamChangeCallback_) {
        (*wifiStreamChangeCallback_)(result);
    }
}

void WifiIdlDeviceEventCallback::OnDeviceConfigChanged(ConfigChange value)
{
    double result = static_cast<double>(value);
    if (wifiDeviceConfigChangeCallback_) {
        (*wifiDeviceConfigChangeCallback_)(result);
    }
}

OHOS::sptr<OHOS::IRemoteObject> WifiIdlDeviceEventCallback::AsObject()
{
    return nullptr;
}

// scan
void WifiIdlScanEventCallback::OnWifiScanStateChanged(int state)
{
    double result = static_cast<double>(state);
    if (wifiScanStateChangeCallback_) {
        (*wifiScanStateChangeCallback_)(result);
    }
}

OHOS::sptr<OHOS::IRemoteObject> WifiIdlScanEventCallback::AsObject()
{
    return nullptr;
}


// hotspot
void WifiIdlHotspotEventCallback::OnHotspotStateChanged(int state)
{
    double result = static_cast<double>(state);
    if (wifiHotspotStateChangeCallback_) {
        (*wifiHotspotStateChangeCallback_)(result);
    }
}

void WifiIdlHotspotEventCallback::OnHotspotStaJoin(const StationInfo &info)
{
    // bssid -> macAddress
    ::ohos::wifiManager::StationInfo result = {info.bssid};
    if (wifiHotspotStaJoinCallback_) {
        (*wifiHotspotStaJoinCallback_)(result);
    }
}

void WifiIdlHotspotEventCallback::OnHotspotStaLeave(const StationInfo &info)
{
    // bssid -> macAddress
    ::ohos::wifiManager::StationInfo result = {info.bssid};
    if (wifiHotspotStaLeaveCallback_) {
        (*wifiHotspotStaLeaveCallback_)(result);
    }
}

OHOS::sptr<OHOS::IRemoteObject> WifiIdlHotspotEventCallback::AsObject()
{
    return nullptr;
}

// p2p
void WifiIdlP2pEventCallback::OnP2pStateChanged(int state)
{
    double result = static_cast<double>(state);
    if (wifiP2pStateChangeCallback_) {
        (*wifiP2pStateChangeCallback_)(result);
    }
}

void WifiIdlP2pEventCallback::OnP2pPersistentGroupsChanged(void)
{
    auto result = ::ohos::wifiManager::UndefinedType::make_undefined();
    if (wifiP2pPersistentGroupChangeCallback_) {
        (*wifiP2pPersistentGroupChangeCallback_)(result);
    }
}

void WifiIdlP2pEventCallback::OnP2pThisDeviceChanged(const WifiP2pDevice& device)
{
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
    if (wifiP2pDeviceChangeCallback_) {
        (*wifiP2pDeviceChangeCallback_)(result);
    }
}

void WifiIdlP2pEventCallback::OnP2pPeersChanged(const std::vector<WifiP2pDevice>& devices)
{
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
    if (wifiP2pPeerDeviceChangeCallback_) {
        (*wifiP2pPeerDeviceChangeCallback_)(finalResult);
    }
}

void WifiIdlP2pEventCallback::OnP2pServicesChanged(const std::vector<WifiP2pServiceInfo>& srvInfo)
{
}

void WifiIdlP2pEventCallback::OnP2pConnectionChanged(const WifiP2pLinkedInfo& info)
{
    ::ohos::wifiManager::P2pConnectState state =
        static_cast<::ohos::wifiManager::P2pConnectState::key_t>(info.GetConnectState());
    ani_boolean isOwner = static_cast<ani_boolean>(info.IsGroupOwner());
    ::taihe::string_view ownerAddr = static_cast<::taihe::string_view>(info.GetGroupOwnerAddress());
    ::ohos::wifiManager::WifiP2pLinkedInfo result = {state, isOwner, ownerAddr};
    if (wifiP2pConnectionChangeCallback_) {
        (*wifiP2pConnectionChangeCallback_)(result);
    }
}

void WifiIdlP2pEventCallback::OnP2pDiscoveryChanged(bool isChange)
{
    double result = static_cast<double>(isChange);
    if (wifiP2pDiscoveryChangeCallback_) {
        (*wifiP2pDiscoveryChangeCallback_)(result);
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
}

void WifiIdlP2pEventCallback::OnP2pGcLeaveGroup(const OHOS::Wifi::GcInfo &info)
{
}

void WifiIdlP2pEventCallback::OnP2pPrivatePeersChanged(const std::string &priWfdInfo)
{
}

void WifiIdlP2pEventCallback::OnP2pChrErrCodeReport(const int errCode)
{
}

OHOS::sptr<OHOS::IRemoteObject> WifiIdlP2pEventCallback::AsObject()
{
    return nullptr;
}
}  // namespace Wifi
}  // namespace OHOS