/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "wifi_callback.h"

#include "accesstoken_kit.h"
#include "cj_lambda.h"
#include "ffi_structs.h"
#include "ipc_skeleton.h"
#include "wifi_device.h"
#include "wifi_logger.h"
#include "wifi_scan.h"

DEFINE_WIFILOG_LABEL("CJ_Wifi_Callback");

namespace OHOS::Wifi {

std::shared_ptr<WifiDevice> g_cjWifiStaPtr = WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);
std::shared_ptr<WifiScan> g_cjWifiScanPtr = WifiScan::GetInstance(WIFI_SCAN_ABILITY_ID);
std::shared_ptr<WifiHotspot> g_cjWifiHotspotPtr = WifiHotspot::GetInstance(WIFI_HOTSPOT_ABILITY_ID);
std::shared_ptr<WifiP2p> g_cjWifiP2pPtr = WifiP2p::GetInstance(WIFI_P2P_ABILITY_ID);

CjEventRegister& CjEventRegister::GetInstance()
{
    static CjEventRegister inst;
    return inst;
}

class CjWifiDeviceEventCallback : public IWifiDeviceCallBack {
public:
    CjWifiDeviceEventCallback() {}

    virtual ~CjWifiDeviceEventCallback() {}

public:
    void OnWifiStateChanged(int state) override
    {
        WIFI_LOGI("OnWifiStateChanged event: %{public}d [0:DISABLING, 1:DISABLED, 2:ENABLING, 3:ENABLED]", state);
        if (wifiStateChange == nullptr) {
            WIFI_LOGI("OnWifiStateChanged not registered");
            return;
        }
        if (m_wifiStateConvertMap.find(state) == m_wifiStateConvertMap.end()) {
            WIFI_LOGW("not find state.");
            return;
        }
        wifiStateChange(m_wifiStateConvertMap[state]);
    }

    void OnWifiConnectionChanged(int state, const WifiLinkedInfo& info) override
    {
        WIFI_LOGI("OnWifiConnectionChanged event: %{public}d [4:CONNECTED, 6:DISCONNECTED, 7:SPECIAL_CONNECT]", state);
        if (wifiConnectionChange == nullptr) {
            WIFI_LOGI("OnWifiConnectionChanged not registered");
            return;
        }
        if (m_connectStateConvertMap.find(state) == m_connectStateConvertMap.end()) {
            WIFI_LOGW("not find connect state.");
            return;
        }
        wifiConnectionChange(m_connectStateConvertMap[state]);
    }

    void OnWifiRssiChanged(int rssi) override
    {
        WIFI_LOGI("OnWifiRssiChanged event: %{public}d", rssi);
        if (wifiRssiChange == nullptr) {
            WIFI_LOGI("OnWifiConnectionChanged not registered");
            return;
        }
        wifiRssiChange(rssi);
    }

    void OnWifiWpsStateChanged(int state, const std::string& pinCode) override {}

    void OnStreamChanged(int direction) override {}

    void OnDeviceConfigChanged(ConfigChange value) override {}

    OHOS::sptr<OHOS::IRemoteObject> AsObject() override
    {
        return nullptr;
    }

    void SetCallback(const std::string& type, void (*callback)(int32_t))
    {
        if (type == EVENT_STA_POWER_STATE_CHANGE) {
            wifiStateChange = CJLambda::Create(callback);
        }
        if (type == EVENT_STA_CONN_STATE_CHANGE) {
            wifiConnectionChange = CJLambda::Create(callback);
        }
        if (type == EVENT_STA_RSSI_STATE_CHANGE) {
            wifiRssiChange = CJLambda::Create(callback);
        }
    }

private:
    std::function<void(int32_t)> wifiStateChange { nullptr };
    std::function<void(int32_t)> wifiConnectionChange { nullptr };
    std::function<void(int32_t)> wifiRssiChange { nullptr };

    enum class JsLayerWifiState { DISABLED = 0, ENABLED = 1, ENABLING = 2, DISABLING = 3 };

    enum class JsLayerConnectStatus {
        DISCONNECTED = 0,
        CONNECTED = 1,
        SPECIAL_CONNECT = 2,
    };

    enum class JsLayerStreamDirection {
        STREAM_DIRECTION_NONE = 0,
        STREAM_DIRECTION_DOWN = 1,
        STREAM_DIRECTION_UP = 2,
        STREAM_DIRECTION_UPDOWN = 3
    };

    std::map<int, int> m_wifiStateConvertMap = {
        { static_cast<int>(WifiState::DISABLING), static_cast<int>(JsLayerWifiState::DISABLING) },
        { static_cast<int>(WifiState::DISABLED), static_cast<int>(JsLayerWifiState::DISABLED) },
        { static_cast<int>(WifiState::ENABLING), static_cast<int>(JsLayerWifiState::ENABLING) },
        { static_cast<int>(WifiState::ENABLED), static_cast<int>(JsLayerWifiState::ENABLED) },
    };

    std::map<int, int> m_connectStateConvertMap = {
        { static_cast<int>(ConnState::CONNECTED), static_cast<int>(JsLayerConnectStatus::CONNECTED) },
        { static_cast<int>(ConnState::DISCONNECTED), static_cast<int>(JsLayerConnectStatus::DISCONNECTED) },
        { static_cast<int>(ConnState::SPECIAL_CONNECT), static_cast<int>(JsLayerConnectStatus::SPECIAL_CONNECT) },
    };

    std::map<int, int> m_streamDirectionConvertMap = {
        { static_cast<int>(StreamDirection::STREAM_DIRECTION_NONE),
            static_cast<int>(JsLayerStreamDirection::STREAM_DIRECTION_NONE) },
        { static_cast<int>(StreamDirection::STREAM_DIRECTION_DOWN),
            static_cast<int>(JsLayerStreamDirection::STREAM_DIRECTION_DOWN) },
        { static_cast<int>(StreamDirection::STREAM_DIRECTION_UP),
            static_cast<int>(JsLayerStreamDirection::STREAM_DIRECTION_UP) },
        { static_cast<int>(StreamDirection::STREAM_DIRECTION_UPDOWN),
            static_cast<int>(JsLayerStreamDirection::STREAM_DIRECTION_UPDOWN) },
    };
};

class CjWifiScanEventCallback : public IWifiScanCallback {
public:
    CjWifiScanEventCallback() {}

    virtual ~CjWifiScanEventCallback() {}

public:
    void OnWifiScanStateChanged(int state) override
    {
        WIFI_LOGI("scan received state changed event: %{public}d", state);
        if (wifiScanStateChange == nullptr) {
            WIFI_LOGI("OnWifiScanStateChanged not registered");
            return;
        }
        wifiScanStateChange(state);
    }

    OHOS::sptr<OHOS::IRemoteObject> AsObject() override
    {
        return nullptr;
    }

    void SetScanStateChange(void (*callback)(int32_t))
    {
        wifiScanStateChange = CJLambda::Create(callback);
    }

private:
    std::function<void(int32_t)> wifiScanStateChange { nullptr };
};

class CjWifiHotspotEventCallback : public IWifiHotspotCallback {
public:
    CjWifiHotspotEventCallback() {}

    virtual ~CjWifiHotspotEventCallback() {}

public:
    void OnHotspotStateChanged(int state) override
    {
        WIFI_LOGI("Hotspot received state changed event: %{public}d", state);
        if (hotspotStateChange == nullptr) {
            WIFI_LOGI("OnHotspotStateChanged not registered");
            return;
        }
        if (m_apStateConvertMap.find(state) == m_apStateConvertMap.end()) {
            return;
        }
        hotspotStateChange(m_apStateConvertMap[state]);
    }

    void OnHotspotStaJoin(const StationInfo& info) override {}

    void OnHotspotStaLeave(const StationInfo& info) override {}

    void SetHotspotStateChanged(void (*callback)(int32_t))
    {
        hotspotStateChange = CJLambda::Create(callback);
    }

    OHOS::sptr<OHOS::IRemoteObject> AsObject() override
    {
        return nullptr;
    }

private:
    std::function<void(int32_t)> hotspotStateChange { nullptr };

    enum class JsLayerApState { DISABLED = 0, ENABLED = 1, ENABLING = 2, DISABLING = 3 };

    std::map<int, int> m_apStateConvertMap = {
        { static_cast<int>(ApState::AP_STATE_STARTING), static_cast<int>(JsLayerApState::ENABLING) },
        { static_cast<int>(ApState::AP_STATE_STARTED), static_cast<int>(JsLayerApState::ENABLED) },
        { static_cast<int>(ApState::AP_STATE_CLOSING), static_cast<int>(JsLayerApState::DISABLING) },
        { static_cast<int>(ApState::AP_STATE_CLOSED), static_cast<int>(JsLayerApState::DISABLED) },
    };
};

class CjWifiP2pEventCallback : public IWifiP2pCallback {
public:
    CjWifiP2pEventCallback() {}

    virtual ~CjWifiP2pEventCallback() {}

public:
    void OnP2pStateChanged(int state) override
    {
        WIFI_LOGI("received p2p state changed event: %{public}d", state);
        if (p2pStateChange == nullptr) {
            WIFI_LOGI("OnP2pStateChanged not registered");
            return;
        }
        p2pStateChange(state);
    }

    void OnP2pPersistentGroupsChanged(void) override
    {
        WIFI_LOGI("received persistent group changed event");
        if (p2pPersistentGroupChange == nullptr) {
            WIFI_LOGI("OnP2pPersistentGroupsChanged not registered");
            return;
        }
        p2pPersistentGroupChange();
    }

    void OnP2pThisDeviceChanged(const WifiP2pDevice& device) override
    {
        WIFI_LOGI("received this device changed event");
        if (p2pDeviceChange == nullptr) {
            WIFI_LOGI("OnP2pThisDeviceChanged not registered");
            return;
        }
        CWifiP2pDevice cdevice;
        cdevice.deviceName = const_cast<char*>(device.GetDeviceName().c_str());
        cdevice.deviceAddress = const_cast<char*>(device.GetDeviceAddress().c_str());
        cdevice.primaryDeviceType = const_cast<char*>(device.GetPrimaryDeviceType().c_str());
        cdevice.deviceStatus = static_cast<int32_t>(device.GetP2pDeviceStatus());
        cdevice.groupCapabilities = device.GetGroupCapabilitys();
        cdevice.deviceAddressType = device.GetDeviceAddressType();
        p2pDeviceChange(cdevice);
    }

    void OnP2pPeersChanged(const std::vector<WifiP2pDevice>& devices) override
    {
        WIFI_LOGI("received p2p peers changed event, devices count: %{public}d", static_cast<int>(devices.size()));
        if (p2pPeerDeviceChange == nullptr) {
            WIFI_LOGI("OnP2pPeersChanged not registered");
            return;
        }
        int64_t size = static_cast<int64_t>(devices.size());
        if (size <= 0) {
            return;
        }
        CWifiP2pDevice cdevices[size];
        WifiP2pDeviceArr arr { .head = cdevices, .size = size };
        uint32_t idx = 0;
        for (auto& each : devices) {
            cdevices[idx].deviceName = const_cast<char*>(each.GetDeviceName().c_str());
            cdevices[idx].deviceAddress = const_cast<char*>(each.GetDeviceAddress().c_str());
            cdevices[idx].primaryDeviceType = const_cast<char*>(each.GetPrimaryDeviceType().c_str());
            cdevices[idx].deviceStatus = static_cast<int32_t>(each.GetP2pDeviceStatus());
            cdevices[idx].groupCapabilities = each.GetGroupCapabilitys();
            cdevices[idx].deviceAddressType = each.GetDeviceAddressType();
            idx++;
        }
        p2pPeerDeviceChange(arr);
    }

    void OnP2pServicesChanged(const std::vector<WifiP2pServiceInfo>& srvInfo) override {}

    void OnP2pConnectionChanged(const WifiP2pLinkedInfo& info) override
    {
        WIFI_LOGI("received p2p connection changed event, state: %{public}d", static_cast<int>(info.GetConnectState()));
        if (p2pConnectionChange == nullptr) {
            WIFI_LOGI("OnP2pConnectionChanged not registered");
            return;
        }
        CWifiP2PLinkedInfo cinfo;
        cinfo.connectState = static_cast<int32_t>(info.GetConnectState());
        cinfo.isGroupOwner = info.IsGroupOwner();
        cinfo.groupOwnerAddr = const_cast<char*>(info.GetGroupOwnerAddress().c_str());
        p2pConnectionChange(cinfo);
    }

    void OnP2pDiscoveryChanged(bool isChange) override
    {
        WIFI_LOGI("received discovery state changed event");
        if (p2pDiscoveryChange == nullptr) {
            WIFI_LOGI("OnP2pDiscoveryChanged not registered");
            return;
        }
        p2pDiscoveryChange(static_cast<int32_t>(isChange));
    }

    void OnP2pActionResult(P2pActionCallback action, ErrCode code) override {}

    void OnConfigChanged(CfgType type, char* data, int dataLen) override {}

    void OnP2pGcJoinGroup(const OHOS::Wifi::GcInfo& info) override {}

    void OnP2pGcLeaveGroup(const OHOS::Wifi::GcInfo& info) override {}

    void OnP2pPrivatePeersChanged(const std::string& priWfdInfo) override {}

    void OnP2pChrErrCodeReport(const int errCode) override {}

    OHOS::sptr<OHOS::IRemoteObject> AsObject() override
    {
        return nullptr;
    }

    void SetCallback(const std::string& type, void (*callback)())
    {
        if (type == EVENT_P2P_STATE_CHANGE) {
            p2pStateChange = CJLambda::Create(reinterpret_cast<void (*)(int32_t)>(callback));
        }
        if (type == EVENT_P2P_PERSISTENT_GROUP_CHANGE) {
            p2pPersistentGroupChange = CJLambda::Create(callback);
        }
        if (type == EVENT_P2P_DEVICE_STATE_CHANGE) {
            p2pDeviceChange = CJLambda::Create(reinterpret_cast<void (*)(CWifiP2pDevice)>(callback));
        }
        if (type == EVENT_P2P_PEER_DEVICE_CHANGE) {
            p2pPeerDeviceChange = CJLambda::Create(reinterpret_cast<void (*)(WifiP2pDeviceArr)>(callback));
        }
        if (type == EVENT_P2P_CONN_STATE_CHANGE) {
            p2pConnectionChange = CJLambda::Create(reinterpret_cast<void (*)(CWifiP2PLinkedInfo)>(callback));
        }
        if (type == EVENT_P2P_DISCOVERY_CHANGE) {
            p2pDiscoveryChange = CJLambda::Create(reinterpret_cast<void (*)(int32_t)>(callback));
        }
    }

private:
    std::function<void(int32_t)> p2pStateChange { nullptr };
    std::function<void(CWifiP2PLinkedInfo)> p2pConnectionChange { nullptr };
    std::function<void(CWifiP2pDevice)> p2pDeviceChange { nullptr };
    std::function<void(WifiP2pDeviceArr)> p2pPeerDeviceChange { nullptr };
    std::function<void()> p2pPersistentGroupChange { nullptr };
    std::function<void(int32_t)> p2pDiscoveryChange { nullptr };
};

sptr<CjWifiDeviceEventCallback> cjWifiDeviceCallback =
    sptr<CjWifiDeviceEventCallback>(new (std::nothrow) CjWifiDeviceEventCallback());

sptr<CjWifiScanEventCallback> cjWifiScanCallback =
    sptr<CjWifiScanEventCallback>(new (std::nothrow) CjWifiScanEventCallback());

sptr<CjWifiHotspotEventCallback> cjWifiHotspotCallback =
    sptr<CjWifiHotspotEventCallback>(new (std::nothrow) CjWifiHotspotEventCallback());

sptr<CjWifiP2pEventCallback> cjWifiP2pCallback =
    sptr<CjWifiP2pEventCallback>(new (std::nothrow) CjWifiP2pEventCallback());

int32_t CjEventRegister::Register(const std::string& type, void (*callback)())
{
    WIFI_LOGI("Register event: %{public}s", type.c_str());
    std::vector<std::string> event = { type };

    if (type == EVENT_STA_POWER_STATE_CHANGE || type == EVENT_STA_CONN_STATE_CHANGE ||
        type == EVENT_STA_RSSI_STATE_CHANGE) {
        cjWifiDeviceCallback->SetCallback(type, reinterpret_cast<void (*)(int32_t)>(callback));
        CjEventRegister::GetInstance().RegisterDeviceEvents(event);
    }

    if (type == EVENT_STA_SCAN_STATE_CHANGE) {
        cjWifiScanCallback->SetScanStateChange(reinterpret_cast<void (*)(int32_t)>(callback));
        CjEventRegister::GetInstance().RegisterScanEvents(event);
    }

    if (type == EVENT_HOTSPOT_STATE_CHANGE) {
        cjWifiHotspotCallback->SetHotspotStateChanged(reinterpret_cast<void (*)(int32_t)>(callback));
        CjEventRegister::GetInstance().RegisterHotspotEvents(event);
    }

    if (type == EVENT_P2P_STATE_CHANGE || type == EVENT_P2P_PERSISTENT_GROUP_CHANGE ||
        type == EVENT_P2P_DEVICE_STATE_CHANGE || type == EVENT_P2P_PEER_DEVICE_CHANGE ||
        type == EVENT_P2P_CONN_STATE_CHANGE || type == EVENT_P2P_DISCOVERY_CHANGE) {
        cjWifiP2pCallback->SetCallback(type, callback);
        CjEventRegister::GetInstance().RegisterP2PEvents(event);
    }
    return WIFI_OPT_SUCCESS;
}

int32_t CjEventRegister::UnRegister(const std::string& type)
{
    return WIFI_OPT_SUCCESS;
}

ErrCode CjEventRegister::RegisterDeviceEvents(const std::vector<std::string>& event)
{
    if (g_cjWifiStaPtr == nullptr) {
        WIFI_LOGE("Register sta event get instance failed!");
        return WIFI_OPT_FAILED;
    }
    return g_cjWifiStaPtr->RegisterCallBack(cjWifiDeviceCallback, event);
}

ErrCode CjEventRegister::RegisterScanEvents(const std::vector<std::string>& event)
{
    if (g_cjWifiScanPtr == nullptr) {
        WIFI_LOGE("Register scan event get instance failed!");
        return WIFI_OPT_FAILED;
    }
    return g_cjWifiScanPtr->RegisterCallBack(cjWifiScanCallback, event);
}

ErrCode CjEventRegister::RegisterHotspotEvents(const std::vector<std::string>& event)
{
    if (g_cjWifiHotspotPtr == nullptr) {
        WIFI_LOGE("Register hotspot event get instance failed!");
        return WIFI_OPT_FAILED;
    }
    return g_cjWifiHotspotPtr->RegisterCallBack(cjWifiHotspotCallback, event);
}

ErrCode CjEventRegister::RegisterP2PEvents(const std::vector<std::string>& event)
{
    if (g_cjWifiP2pPtr == nullptr) {
        WIFI_LOGE("Register p2p event get instance failed!");
        return WIFI_OPT_FAILED;
    }
    return g_cjWifiP2pPtr->RegisterCallBack(cjWifiP2pCallback, event);
}

void CjWifiAbilityStatusChange::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    WIFI_LOGI("OnAddSystemAbility systemAbilityId:%{public}d", systemAbilityId);
    std::vector<std::string> event;
    switch (systemAbilityId) {
        case WIFI_DEVICE_ABILITY_ID: {
            event.push_back(EVENT_STA_POWER_STATE_CHANGE);
            event.push_back(EVENT_STA_CONN_STATE_CHANGE);
            event.push_back(EVENT_STA_RSSI_STATE_CHANGE);
            CjEventRegister::GetInstance().RegisterDeviceEvents(event);
            break;
        }
        case WIFI_SCAN_ABILITY_ID: {
            event.push_back(EVENT_STA_SCAN_STATE_CHANGE);
            CjEventRegister::GetInstance().RegisterScanEvents(event);
            break;
        }
        case WIFI_HOTSPOT_ABILITY_ID: {
            event.push_back(EVENT_HOTSPOT_STATE_CHANGE);
            CjEventRegister::GetInstance().RegisterHotspotEvents(event);
            break;
        }
        case WIFI_P2P_ABILITY_ID: {
            event.push_back(EVENT_P2P_STATE_CHANGE);
            event.push_back(EVENT_P2P_PERSISTENT_GROUP_CHANGE);
            event.push_back(EVENT_P2P_DEVICE_STATE_CHANGE);
            event.push_back(EVENT_P2P_PEER_DEVICE_CHANGE);
            event.push_back(EVENT_P2P_CONN_STATE_CHANGE);
            event.push_back(EVENT_P2P_DISCOVERY_CHANGE);
            CjEventRegister::GetInstance().RegisterP2PEvents(event);
            break;
        }
        default:
            WIFI_LOGI("OnAddSystemAbility unhandled sysabilityId:%{public}d", systemAbilityId);
            return;
    }
}
} // namespace OHOS::Wifi