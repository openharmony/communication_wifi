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

#include <shared_mutex>
#include "wifi_logger.h"
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
extern std::vector<::taihe::optional<::taihe::callback<void(double)>>>
    g_wifiStateChangeVec;
extern std::shared_mutex g_wifiStateChangeLock;
 
extern std::vector<::taihe::optional<::taihe::callback<void(double)>>>
    g_wifiConnectionChangeVec;
extern std::shared_mutex g_wifiConnectionChangeLock;
 
extern std::vector<::taihe::optional<::taihe::callback<void(double)>>>
    g_wifiRssiChangeVec;
extern std::shared_mutex g_wifiRssiChangeLock;
 
extern std::vector<::taihe::optional<::taihe::callback<void(double)>>>
    g_wifiStreamChangeVec;
extern std::shared_mutex g_wifiStreamChangeLock;
 
extern std::vector<::taihe::optional<::taihe::callback<void(double)>>>
    g_wifiDeviceConfigChangeVec;
extern std::shared_mutex g_wifiDeviceConfigChangeLock;
 
extern std::vector<::taihe::optional<::taihe::callback<void(double)>>>
    g_wifiScanStateChangeVec;
extern std::shared_mutex g_wifiScanStateChangeLock;
 
extern std::vector<::taihe::optional<::taihe::callback<void(double)>>>
    g_wifiHotspotStateChangeVec;
extern std::shared_mutex g_wifiHotspotStateChangeLock;
 
extern std::vector<::taihe::optional<::taihe::callback<
    void(::ohos::wifiManager::StationInfo const&)>>>
    g_wifiHotspotStaJoinVec;
extern std::shared_mutex g_wifiHotspotStaJoinLock;
 
extern std::vector<::taihe::optional<::taihe::callback<
    void(::ohos::wifiManager::StationInfo const&)>>>
    g_wifiHotspotStaLeaveVec;
extern std::shared_mutex g_wifiHotspotStaLeaveLock;
 
extern std::vector<::taihe::optional<::taihe::callback<void(double)>>>
    g_wifiP2pStateChangeVec;
extern std::shared_mutex g_wifiP2pStateChangeLock;
 
extern std::vector<::taihe::optional<::taihe::callback<
    void(::ohos::wifiManager::WifiP2pLinkedInfo const&)>>>
    g_wifiP2pConnectionChangeVec;
extern std::shared_mutex g_wifiP2pConnectionChangeLock;
 
extern std::vector<::taihe::optional<::taihe::callback<
    void(::ohos::wifiManager::WifiP2pDevice const&)>>>
    g_wifiP2pDeviceChangeVec;
extern std::shared_mutex g_wifiP2pDeviceChangeLock;
 
extern std::vector<::taihe::optional<::taihe::callback<
    void(::taihe::array_view<::ohos::wifiManager::WifiP2pDevice>)>>>
    g_wifiP2pPeerDeviceChangeVec;
extern std::shared_mutex g_wifiP2pPeerDeviceChangeLock;
 
extern std::vector<::taihe::optional<::taihe::callback<
    void(::ohos::wifiManager::UndefinedType const&)>>>
    g_wifiP2pPersistentGroupChangeVec;
extern std::shared_mutex g_wifiP2pPersistentGroupChangeLock;
 
extern std::vector<::taihe::optional<::taihe::callback<void(double)>>>
    g_wifiP2pDiscoveryChangeVec;
extern std::shared_mutex g_wifiP2pDiscoveryChangeLock;

class WifiIdlDeviceEventCallback : public IWifiDeviceCallBack {
public:
    void OnWifiStateChanged(int state) override;
    void OnWifiConnectionChanged(int state, const WifiLinkedInfo &info) override;
    void OnWifiRssiChanged(int rssi) override;
    void OnWifiWpsStateChanged(int state, const std::string &pinCode) override;
    void OnStreamChanged(int direction) override;
    void OnDeviceConfigChanged(ConfigChange value) override;
    OHOS::sptr<OHOS::IRemoteObject> AsObject() override;

public:
    ::taihe::optional<::taihe::callback<void(double)>> wifiStateChangedCallback_;
    ::taihe::optional<::taihe::callback<void(double)>> wifiConnectionChangeCallback_;
    ::taihe::optional<::taihe::callback<void(double)>> wifiRssiChangeCallback_;
    ::taihe::optional<::taihe::callback<void(double)>> wifiStreamChangeCallback_;
    ::taihe::optional<::taihe::callback<void(double)>> wifiDeviceConfigChangeCallback_;
};

class WifiIdlScanEventCallback : public IWifiScanCallback {
public:
    void OnWifiScanStateChanged(int state) override;
    OHOS::sptr<OHOS::IRemoteObject> AsObject() override;

public:
    ::taihe::optional<::taihe::callback<void(double)>> wifiScanStateChangeCallback_;
};

class WifiIdlHotspotEventCallback : public IWifiHotspotCallback {
public:
    void OnHotspotStateChanged(int state) override;
    void OnHotspotStaJoin(const StationInfo &info) override;
    void OnHotspotStaLeave(const StationInfo &info) override;
    OHOS::sptr<OHOS::IRemoteObject> AsObject() override;

public:
    ::taihe::optional<::taihe::callback<void(double)>> wifiHotspotStateChangeCallback_;
    ::taihe::optional<::taihe::callback<void(::ohos::wifiManager::StationInfo const&)>>
        wifiHotspotStaJoinCallback_;
    ::taihe::optional<::taihe::callback<void(::ohos::wifiManager::StationInfo const&)>>
        wifiHotspotStaLeaveCallback_;
};

class WifiIdlP2pEventCallback : public IWifiP2pCallback {
public:
    void OnP2pStateChanged(int state) override;
    void OnP2pPersistentGroupsChanged(void) override;
    void OnP2pThisDeviceChanged(const WifiP2pDevice& device) override;
    void OnP2pPeersChanged(const std::vector<WifiP2pDevice>& devices) override;
    void OnP2pServicesChanged(const std::vector<WifiP2pServiceInfo>& srvInfo) override;
    void OnP2pConnectionChanged(const WifiP2pLinkedInfo& info) override;
    void OnP2pDiscoveryChanged(bool isChange) override;
    void OnP2pActionResult(P2pActionCallback action, ErrCode code) override;
    void OnConfigChanged(CfgType type, char* data, int dataLen) override;
    void OnP2pGcJoinGroup(const OHOS::Wifi::GcInfo &info) override;
    void OnP2pGcLeaveGroup(const OHOS::Wifi::GcInfo &info) override;
    void OnP2pPrivatePeersChanged(const std::string &priWfdInfo) override;
    void OnP2pChrErrCodeReport(const int errCode) override;
    OHOS::sptr<OHOS::IRemoteObject> AsObject() override;

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