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

#ifndef OHOS_WIFI_CALLBACK_TAIHE_H
#define OHOS_WIFI_CALLBACK_TAIHE_H
#include "ohos.wifiManager.proj.hpp"
#include "ohos.wifiManager.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"

#include "wifi_device.h"
#include "wifi_device_impl.h"
#include "wifi_hotspot.h"
#include "wifi_hotspot_impl.h"
#include "wifi_scan.h"
#include "wifi_scan_impl.h"
#include "wifi_msg.h"
#include "wifi_p2p.h"
#include "wifi_p2p_impl.h"

namespace OHOS {
namespace Wifi {
class WifiIdlDeviceEventCallback : public IWifiDeviceCallBack {
public:
    WifiIdlDeviceEventCallback()
    {
    }

    virtual ~WifiIdlDeviceEventCallback()
    {
    }
public:
    void OnWifiStateChanged(int state) override
    {
        double result = static_cast<double>(state);
        if (wifiStateChangedCallback_) {
            (*wifiStateChangedCallback_)(result);
        }
    }

    void OnWifiConnectionChanged(int state, const WifiLinkedInfo &info) override
    {
        double result = static_cast<double>(state);
        if (wifiConnectionChangeCallback_) {
            (*wifiConnectionChangeCallback_)(result);
        }
    }

    void OnWifiRssiChanged(int rssi) override
    {
        double result = static_cast<double>(rssi);
        if (wifiRssiChangeCallback_) {
            (*wifiRssiChangeCallback_)(result);
        }
    }

    void OnWifiWpsStateChanged(int state, const std::string &pinCode) override
    {
    }

    void OnStreamChanged(int direction) override
    {
        double result = static_cast<double>(direction);
        if (wifiStreamChangeCallback_) {
            (*wifiStreamChangeCallback_)(result);
        }
    }

    void OnDeviceConfigChanged(ConfigChange value) override
    {
        double result = static_cast<double>(value);
        if (wifiDeviceConfigChangeCallback_) {
            (*wifiDeviceConfigChangeCallback_)(result);
        }
    }

    OHOS::sptr<OHOS::IRemoteObject> AsObject() override
    {
        return nullptr;
    }

public:
    ::taihe::optional<::taihe::callback<void(double)>> wifiStateChangedCallback_;
    ::taihe::optional<::taihe::callback<void(double)>> wifiConnectionChangeCallback_;
    ::taihe::optional<::taihe::callback<void(double)>> wifiRssiChangeCallback_;
    ::taihe::optional<::taihe::callback<void(double)>> wifiStreamChangeCallback_;
    ::taihe::optional<::taihe::callback<void(double)>> wifiDeviceConfigChangeCallback_;
};

class WifiIdlScanEventCallback : public IWifiScanCallback {
public:
    WifiIdlScanEventCallback()
    {
    }

    virtual ~WifiIdlScanEventCallback()
    {
    }

public:
    void OnWifiScanStateChanged(int state) override
    {
        double result = static_cast<double>(state);
        if (wifiScanStateChangeCallback_) {
            (*wifiScanStateChangeCallback_)(result);
        }
    }

    OHOS::sptr<OHOS::IRemoteObject> AsObject() override
    {
        return nullptr;
    }
public:
    ::taihe::optional<::taihe::callback<void(double)>> wifiScanStateChangeCallback_;
};

class WifiIdlHotspotEventCallback : public IWifiHotspotCallback {
public:
    WifiIdlHotspotEventCallback()
    {
    }

    virtual ~WifiIdlHotspotEventCallback()
    {
    }

public:
    void OnHotspotStateChanged(int state) override
    {
        double result = static_cast<double>(state);
        if (wifiHotspotStateChangeCallback_) {
            (*wifiHotspotStateChangeCallback_)(result);
        }
    }

    void OnHotspotStaJoin(const StationInfo &info) override
    {
        // bssid -> macAddress
        ::ohos::wifiManager::StationInfo result = {info.bssid};
        if (wifiHotspotStaJoinCallback_) {
            (*wifiHotspotStaJoinCallback_)(result);
        }
    }

    void OnHotspotStaLeave(const StationInfo &info) override
    {
        // bssid -> macAddress
        ::ohos::wifiManager::StationInfo result = {info.bssid};
        if (wifiHotspotStaLeaveCallback_) {
            (*wifiHotspotStaLeaveCallback_)(result);
        }
    }

    OHOS::sptr<OHOS::IRemoteObject> AsObject() override
    {
        return nullptr;
    }

public:
    ::taihe::optional<::taihe::callback<void(double)>> wifiHotspotStateChangeCallback_;
    ::taihe::optional<::taihe::callback<void(::ohos::wifiManager::StationInfo const&)>>
        wifiHotspotStaJoinCallback_;
    ::taihe::optional<::taihe::callback<void(::ohos::wifiManager::StationInfo const&)>>
        wifiHotspotStaLeaveCallback_;
};

class WifiIdlP2pEventCallback : public IWifiP2pCallback {
public:
    WifiIdlP2pEventCallback()
    {
    }

    virtual ~WifiIdlP2pEventCallback()
    {
    }

public:
    void OnP2pStateChanged(int state) override
    {
        double result = static_cast<double>(state);
        if (wifiP2pStateChangeCallback_) {
            (*wifiP2pStateChangeCallback_)(result);
        }
    }

    void OnP2pPersistentGroupsChanged(void) override
    {
        auto result = ::ohos::wifiManager::UndefinedType::make_undefined();
        if (wifiP2pPersistentGroupChangeCallback_) {
            (*wifiP2pPersistentGroupChangeCallback_)(result);
        }
    }

    void OnP2pThisDeviceChanged(const WifiP2pDevice& device) override
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

    void OnP2pPeersChanged(const std::vector<WifiP2pDevice>& devices) override
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

    void OnP2pServicesChanged(const std::vector<WifiP2pServiceInfo>& srvInfo) override
    {
    }

    void OnP2pConnectionChanged(const WifiP2pLinkedInfo& info) override
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

    void OnP2pDiscoveryChanged(bool isChange) override
    {
        double result = static_cast<double>(isChange);
        if (wifiP2pDiscoveryChangeCallback_) {
            (*wifiP2pDiscoveryChangeCallback_)(result);
        }
    }

    void OnP2pActionResult(P2pActionCallback action, ErrCode code) override
    {
    }

    void OnConfigChanged(CfgType type, char* data, int dataLen) override
    {
    }

    void OnP2pGcJoinGroup(const OHOS::Wifi::GcInfo &info) override
    {
    }

    void OnP2pGcLeaveGroup(const OHOS::Wifi::GcInfo &info) override
    {
    }

    void OnP2pPrivatePeersChanged(const std::string &priWfdInfo) override
    {
    }

    void OnP2pChrErrCodeReport(const int errCode) override
    {
    }

    OHOS::sptr<OHOS::IRemoteObject> AsObject() override
    {
        return nullptr;
    }

public:
    ::taihe::optional<::taihe::callback<void(double)>> wifiP2pStateChangeCallback_;
    ::taihe::optional<::taihe::callback<void(::ohos::wifiManager::WifiP2pLinkedInfo const&)>>
        wifiP2pConnectionChangeCallback_;
    ::taihe::optional<::taihe::callback<void(::ohos::wifiManager::WifiP2pDevice const&)>>
        wifiP2pDeviceChangeCallback_;
    ::taihe::optional<::taihe::callback<void(::taihe::array_view<::ohos::wifiManager::WifiP2pDevice>)>>
        wifiP2pPeerDeviceChangeCallback_;
    ::taihe::optional<::taihe::callback<void(::ohos::wifiManager::UndefinedType const&)>>
        wifiP2pPersistentGroupChangeCallback_;
    ::taihe::optional<::taihe::callback<void(double)>> wifiP2pDiscoveryChangeCallback_;
};
}  // namespace Wifi
}  // namespace OHOS
#endif