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

#ifndef OHOS_WIFI_SA_EVENT_H
#define OHOS_WIFI_SA_EVENT_H
#include <mutex>
#include "wifi_errcode.h"
#include "wifi_logger.h"
#include "kits/c/wifi_event.h"
#include "iremote_broker.h"
#include "iremote_object.h"
#include "iservice_registry.h"
#include "system_ability_status_change_stub.h"
#include "i_wifi_device_callback.h"
#include "i_wifi_hotspot_callback.h"
#include "i_wifi_scan_callback.h"
#include "i_wifi_p2p_callback.h"
#include "kits/c/wifi_p2p.h"
#include "kits/c/wifi_hid2d.h"
#include "wifi_event_handler.h"

class WifiCDeviceEventCallback : public OHOS::Wifi::IWifiDeviceCallBack {
public:
    WifiCDeviceEventCallback() {
    }

    virtual ~WifiCDeviceEventCallback() {
    }

public:
    void OnWifiStateChanged(int state) override;

    void OnWifiConnectionChanged(int state, const OHOS::Wifi::WifiLinkedInfo &info) override;

    void OnWifiRssiChanged(int rssi) override;

    void OnWifiWpsStateChanged(int state, const std::string &pinCode) override;

    void OnStreamChanged(int direction) override;

    void OnDeviceConfigChanged(OHOS::Wifi::ConfigChange value) override;

    OHOS::sptr<OHOS::IRemoteObject> AsObject() override;

    static std::vector<std::string> deviceCallbackEvent;
};

class WifiCScanEventCallback : public OHOS::Wifi::IWifiScanCallback {
public:
    WifiCScanEventCallback() {
    }

    virtual ~WifiCScanEventCallback() {
    }

public:
    void OnWifiScanStateChanged(int state) override;

    OHOS::sptr<OHOS::IRemoteObject> AsObject() override;

    static std::vector<std::string> scanCallbackEvent;
};

class WifiCHotspotEventCallback : public OHOS::Wifi::IWifiHotspotCallback {
public:
    WifiCHotspotEventCallback() {
    }

    virtual ~WifiCHotspotEventCallback() {
    }

public:
    void OnHotspotStateChanged(int state) override;

    void OnHotspotStaJoin(const OHOS::Wifi::StationInfo &info) override;

    void OnHotspotStaLeave(const OHOS::Wifi::StationInfo &info) override;

    OHOS::sptr<OHOS::IRemoteObject> AsObject() override;

    static std::vector<std::string> hotspotCallbackEvent;
};

class WifiP2pCEventCallback : public OHOS::Wifi::IWifiP2pCallback {
public:
    void OnP2pStateChanged(int state) override;

    void OnP2pPersistentGroupsChanged(void) override;

    void OnP2pThisDeviceChanged(const OHOS::Wifi::WifiP2pDevice &device) override;

    void OnP2pPeersChanged(const std::vector<OHOS::Wifi::WifiP2pDevice> &devices) override;

    void OnP2pServicesChanged(const std::vector<OHOS::Wifi::WifiP2pServiceInfo> &srvInfo) override;

    void OnP2pConnectionChanged(const OHOS::Wifi::WifiP2pLinkedInfo &info) override;

    void OnP2pDiscoveryChanged(bool isChange) override;

    void OnP2pActionResult(OHOS::Wifi::P2pActionCallback action, OHOS::Wifi::ErrCode code) override;

    void OnConfigChanged(OHOS::Wifi::CfgType type, char* data, int dataLen) override;

    void OnP2pGcJoinGroup(const OHOS::Wifi::GcInfo &info) override;

    void OnP2pGcLeaveGroup(const OHOS::Wifi::GcInfo &info) override;

    OHOS::sptr<OHOS::IRemoteObject> AsObject() override;

public:
    WifiP2pCEventCallback()
    {
        stateChangeCb = nullptr;
        groupChangeCb = nullptr;
        connectionChangeCb = nullptr;
        peersChangeCb = nullptr;
        cfgChangeCallback = nullptr;
    }

    virtual ~WifiP2pCEventCallback() {
    }

public:
    P2pStateChangedCallback stateChangeCb;
    P2pPersistentGroupsChangedCallback groupChangeCb;
    P2pConnectionChangedCallback connectionChangeCb;
    P2pPeersChangedCallback peersChangeCb;
    WifiCfgChangCallback cfgChangeCallback;

private:
    std::mutex p2pCallbackMutex;

private:
    WifiP2pLinkedInfo ConvertP2pLinkedInfo(const OHOS::Wifi::WifiP2pLinkedInfo& linkedInfo);
};

namespace OHOS {
namespace Wifi {

class WifiAbilityStatusChange : public SystemAbilityStatusChangeStub {
public:
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
    void Init(int32_t systemAbilityId);
};
}
}

class EventManager {
public:
    EventManager();

    ~EventManager();

    bool AddEventCallback(WifiEvent *cb);

    void RemoveEventCallback(WifiEvent *cb);

    WifiErrorCode RegisterDeviceEvent(const std::vector<std::string> &event);
    WifiErrorCode RegisterScanEvent(const std::vector<std::string> &event);
    WifiErrorCode RegisterHotspotEvent(const std::vector<std::string> &event);
    WifiErrorCode RegisterP2PEvent(const std::vector<std::string> &event);
    WifiErrorCode RegisterWifiEvents();

    bool IsEventRegistered();

    void SetIsEventRegistrated(bool isEventRegistered);

    std::set<WifiEvent*>& GetEventCallBacks();

    void Init();

    void SetP2PCallbackEvent(OHOS::sptr<WifiP2pCEventCallback> &sptr, const std::string &eventName);

    void RemoveP2PCallbackEvent(const std::string &eventName);

    std::set<std::string>& GetP2PCallbackEvent();

    OHOS::sptr<WifiP2pCEventCallback> GetP2PCallbackPtr();

    std::unique_ptr<OHOS::Wifi::WifiEventHandler>& GetWifiCEventHandler();
    
    std::unique_ptr<OHOS::Wifi::WifiEventHandler>& GetWifiP2pCEventHandler();

    static EventManager& GetInstance();

public:
    static std::mutex callbackMutex;

private:
    static std::set<WifiEvent*> m_setEventCallback;
    static bool m_isEventRegistered;
    std::set<std::string> p2pRegisteredCallbackEvent;
    OHOS::sptr<WifiP2pCEventCallback> sptrP2PCallback = nullptr;
    OHOS::sptr<OHOS::ISystemAbilityStatusChange> mSaStatusListener = nullptr;
    std::unique_ptr<OHOS::Wifi::WifiEventHandler> wifiCEventHandler = nullptr;
    std::unique_ptr<OHOS::Wifi::WifiEventHandler> wifiP2pCEventHandler = nullptr;
};
#endif