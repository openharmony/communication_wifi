/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#include "wifi_p2p_device_manager.h"
#include "wifi_logger.h"
#include "wifi_settings.h"
#include "wifi_permission_utils.h"
#include "wifi_log.h"

namespace OHOS {
namespace Wifi {
void WifiP2pDeviceManager::Initialize()
{}

bool WifiP2pDeviceManager::AddDevice(const WifiP2pDevice &device)
{
    if (!device.IsValid()) {
        LOGE("WifiP2pDeviceManager::AddDevice: invalid address");
        return false;
    }
    std::unique_lock<std::mutex> lock(deviceMutex);
    for (auto it = p2pDevices.begin(); it != p2pDevices.end(); it++) {
        if (*it == device) {
            LOGE("WifiP2pDeviceManager::AddDevice: device is existed");
            return false;
        }
    }
    LOGI("add a device: name:%{private}s, address:%{private}s, addressType:%{public}d",
        device.GetDeviceName().c_str(), device.GetDeviceAddress().c_str(),
        device.GetDeviceAddressType());
#ifdef SUPPORT_RANDOM_MAC_ADDR
    LOGD("%{public}s: add a device, deviceName: %{private}s, address: %{private}s",
        __func__, device.GetDeviceName().c_str(), device.GetDeviceAddress().c_str());
    WifiSettings::GetInstance().StoreWifiMacAddrPairInfo(WifiMacAddrInfoType::P2P_DEVICE_MACADDR_INFO,
        device.GetDeviceAddress(), "");
#endif
    p2pDevices.push_back(device);
    return true;
}

bool WifiP2pDeviceManager::RemoveDevice(const std::string &deviceAddress)
{
    std::unique_lock<std::mutex> lock(deviceMutex);
    for (auto it = p2pDevices.begin(); it != p2pDevices.end(); it++) {
        if (it->GetDeviceAddress() == deviceAddress) {
            p2pDevices.erase(it);
            LOGI("remove a device: address:%{private}s", deviceAddress.c_str());
            return true;
        }
    }
    return false;
}

bool WifiP2pDeviceManager::RemoveDevice(const WifiP2pDevice &device)
{
    return RemoveDevice(device.GetDeviceAddress());
}

int WifiP2pDeviceManager::ClearAll()
{
    std::unique_lock<std::mutex> lock(deviceMutex);
    int num = p2pDevices.size();
#ifdef SUPPORT_RANDOM_MAC_ADDR
    WifiSettings::GetInstance().ClearMacAddrPairs(WifiMacAddrInfoType::P2P_DEVICE_MACADDR_INFO);
#endif
    p2pDevices.clear();
    LOGI("WifiP2pDeviceManager::ClearAll: clear all address");
    return num;
}

int WifiP2pDeviceManager::GetDevicesList(std::vector<WifiP2pDevice> &devices)
{
    std::unique_lock<std::mutex> lock(deviceMutex);
    devices.assign(p2pDevices.begin(), p2pDevices.end());
    return p2pDevices.size();
}

bool WifiP2pDeviceManager::UpdateDevice(const WifiP2pDevice &device)
{
    if (!device.IsValid()) {
        LOGE("WifiP2pDeviceManager::UpdateDevice: invalid address");
        return false;
    }
    std::unique_lock<std::mutex> lock(deviceMutex);
    for (auto it = p2pDevices.begin(); it != p2pDevices.end(); it++) {
        if (*it == device) {
            *it = device;
            return true;
        }
    }
#ifdef SUPPORT_RANDOM_MAC_ADDR
    LOGD("%{public}s: update a device, deviceName: %{private}s, address: %{private}s",
        __func__, device.GetDeviceName().c_str(), device.GetDeviceAddress().c_str());
    WifiSettings::GetInstance().StoreWifiMacAddrPairInfo(WifiMacAddrInfoType::P2P_DEVICE_MACADDR_INFO,
        device.GetDeviceAddress(), "");
#endif
    p2pDevices.push_back(device);
    return true;
}

bool WifiP2pDeviceManager::UpdateDeviceSupplicantInf(const WifiP2pDevice &device)
{
    if (!device.IsValid()) {
        LOGE("UpdateDeviceSupplicantInf: invalid address");
        return false;
    }
    std::unique_lock<std::mutex> lock(deviceMutex);
    for (auto it = p2pDevices.begin(); it != p2pDevices.end(); it++) {
        if (*it == device) {
            it->SetDeviceName(device.GetDeviceName());
            it->SetDeviceAddressType(REAL_DEVICE_ADDRESS);
            it->SetPrimaryDeviceType(device.GetPrimaryDeviceType());
            it->SetSecondaryDeviceType(device.GetSecondaryDeviceType());
            it->SetWpsConfigMethod(device.GetWpsConfigMethod());
            it->SetDeviceCapabilitys(device.GetDeviceCapabilitys());
            it->SetGroupCapabilitys(device.GetGroupCapabilitys());
            return true;
        }
    }
    WifiP2pDevice updateDevice = device;
#ifdef SUPPORT_RANDOM_MAC_ADDR
    LOGD("%{public}s: receive a event, deviceName: %{private}s, address: %{private}s",
        __func__, device.GetDeviceName().c_str(), device.GetDeviceAddress().c_str());
    WifiSettings::GetInstance().StoreWifiMacAddrPairInfo(WifiMacAddrInfoType::P2P_DEVICE_MACADDR_INFO,
        device.GetDeviceAddress(), "");
#endif
    /* add its if not found . be careful of the return value */
    p2pDevices.push_back(updateDevice);
    return true;
}

bool WifiP2pDeviceManager::UpdateDeviceGroupCap(const std::string &deviceAddress, uint32_t cap)
{
    if (deviceAddress.empty()) {
        LOGE("WifiP2pDeviceManager::UpdateDeviceGroupCap: invalid address");
        return false;
    }
    std::unique_lock<std::mutex> lock(deviceMutex);
    for (auto it = p2pDevices.begin(); it != p2pDevices.end(); it++) {
        if (it->GetDeviceAddress() == deviceAddress) {
            it->SetGroupCapabilitys(cap);
            return true;
        }
    }
    return false;
}

bool WifiP2pDeviceManager::UpdateDeviceGroupCap(const WifiP2pDevice &device)
{
    if (!device.IsValid()) {
        LOGE("WifiP2pDeviceManager::UpdateDeviceGroupCap: invalid address");
        return false;
    }

    return UpdateDeviceGroupCap(device.GetDeviceAddress(), device.GetGroupCapabilitys());
}

bool WifiP2pDeviceManager::UpdateDeviceStatus(const std::string &deviceAddress, P2pDeviceStatus status)
{
    if (deviceAddress.empty()) {
        LOGE("WifiP2pDeviceManager::UpdateDeviceStatus: invalid address");
        return false;
    }

    std::unique_lock<std::mutex> lock(deviceMutex);
    for (auto it = p2pDevices.begin(); it != p2pDevices.end(); it++) {
        if (it->GetDeviceAddress() == deviceAddress) {
            it->SetP2pDeviceStatus(status);
            return true;
        }
    }
    return false;
}

bool WifiP2pDeviceManager::UpdateDeviceStatus(const WifiP2pDevice &device)
{
    if (!device.IsValid()) {
        LOGE("WifiP2pDeviceManager::UpdateDeviceStatus: invalid address");
        return false;
    }

    return UpdateDeviceStatus(device.GetDeviceAddress(), device.GetP2pDeviceStatus());
}

bool WifiP2pDeviceManager::UpdateAllDeviceStatus(const P2pDeviceStatus status)
{
    std::unique_lock<std::mutex> lock(deviceMutex);
    for (auto it = p2pDevices.begin(); it != p2pDevices.end(); it++) {
        it->SetP2pDeviceStatus(status);
    }
    return true;
}

bool WifiP2pDeviceManager::UpdateGroupAddress(const std::string &deviceAddress, const std::string &groupAddress)
{
    if (deviceAddress.empty() || groupAddress.empty()) {
        return false;
    }

    std::unique_lock<std::mutex> lock(deviceMutex);
    for (auto it = p2pDevices.begin(); it != p2pDevices.end(); it++) {
        if (it->GetDeviceAddress() == deviceAddress) {
            it->SetGroupAddress(groupAddress);
            return true;
        }
    }
    return false;
}

bool WifiP2pDeviceManager::UpdateGroupAddress(const WifiP2pDevice &device)
{
    if (!device.IsValid()) {
        return false;
    }

    return UpdateGroupAddress(device.GetDeviceAddress(), device.GetGroupAddress());
}

WifiP2pDevice WifiP2pDeviceManager::GetDevices(const std::string &deviceAddress)
{
    std::unique_lock<std::mutex> lock(deviceMutex);
    for (auto it = p2pDevices.begin(); it != p2pDevices.end(); it++) {
        if (it->GetDeviceAddress() == deviceAddress) {
            return *it;
        }
    }
    WifiP2pDevice ret;
    return ret;
}

const std::string WifiP2pDeviceManager::GetDeviceName(const std::string &deviceAddress)
{
    WifiP2pDevice device = GetDevices(deviceAddress);
    return device.IsValid() ? device.GetDeviceName() : deviceAddress;
}
}  // namespace Wifi
}  // namespace OHOS
