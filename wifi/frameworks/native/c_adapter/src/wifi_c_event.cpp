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

#include "../../../interfaces/kits/c/wifi_event.h"
#include <set>
#include <vector>
#include "../../../interfaces/kits/c/wifi_device.h"
#include "../../../interfaces/kits/c/wifi_scan_info.h"
#include "i_wifi_device_callback.h"
#include "i_wifi_hotspot_callback.h"
#include "i_wifi_scan_callback.h"
#include "wifi_device.h"
#include "wifi_hotspot.h"
#include "wifi_logger.h"
#include "wifi_scan.h"
#include "wifi_p2p.h"
#include "wifi_common_util.h"
#include "../../src/wifi_sa_event.h"
DEFINE_WIFILOG_LABEL("WifiCEvent");
std::set<WifiEvent*> GetEventCallBacks();
std::unique_ptr<OHOS::Wifi::WifiScan> g_wifiScanPtr = nullptr;

std::vector<std::string> WifiCDeviceEventCallback::deviceCallbackEvent = {
    EVENT_STA_CONN_STATE_CHANGE,
    EVENT_STA_DEVICE_CONFIG_CHANGE,
};

void WifiCDeviceEventCallback::OnWifiStateChanged(int state)
{
    WIFI_LOGI("sta received state changed event: %{public}d", state);
}

NO_SANITIZE("cfi") void WifiCDeviceEventCallback::OnWifiConnectionChanged(int state,
    const OHOS::Wifi::WifiLinkedInfo &info)
{
    WIFI_LOGI("sta received connection changed event: %{public}d", state);
    WifiLinkedInfo linkInfo;
    WifiErrorCode ret = GetLinkedInfo(&linkInfo);
    if (ret != WIFI_SUCCESS) {
        WIFI_LOGE("Received event get linked info failed");
        return;
    }
    std::set<WifiEvent*> setCallbacks = GetEventCallBacks();
    for (auto& callback : setCallbacks) {
        if (callback && callback->OnWifiConnectionChanged) {
            callback->OnWifiConnectionChanged(state, &linkInfo);
        }
    }
}

void WifiCDeviceEventCallback::OnWifiRssiChanged(int rssi)
{
    WIFI_LOGI("sta received rssi changed event: %{public}d", rssi);
}

void WifiCDeviceEventCallback::OnWifiWpsStateChanged(int state, const std::string &pinCode)
{
}

void WifiCDeviceEventCallback::OnStreamChanged(int direction)
{
}

NO_SANITIZE("cfi") void WifiCDeviceEventCallback::OnDeviceConfigChanged(OHOS::Wifi::ConfigChange value)
{
    std::set<WifiEvent*> setCallbacks = GetEventCallBacks();
    for (auto& callback : setCallbacks) {
        if (callback && callback->OnDeviceConfigChange) {
            callback->OnDeviceConfigChange(ConfigChange(static_cast<int>(value)));
        }
    }
}

OHOS::sptr<OHOS::IRemoteObject> WifiCDeviceEventCallback::AsObject()
{
    return nullptr;
}

std::vector<std::string> WifiCScanEventCallback::scanCallbackEvent = {
    EVENT_STA_SCAN_STATE_CHANGE,
};

NO_SANITIZE("cfi") void WifiCScanEventCallback::OnWifiScanStateChanged(int state)
{
    WIFI_LOGI("scan received state changed event: %{public}d", state);
    std::set<WifiEvent*> setCallbacks = GetEventCallBacks();
    for (auto& callback : setCallbacks) {
        if (callback && callback->OnWifiScanStateChanged) {
            callback->OnWifiScanStateChanged(state, WIFI_SCAN_HOTSPOT_LIMIT);
        }
    }
}

OHOS::sptr<OHOS::IRemoteObject> WifiCScanEventCallback::AsObject()
{
    return nullptr;
}

std::vector<std::string> WifiCHotspotEventCallback::hotspotCallbackEvent = {
    EVENT_HOTSPOT_STATE_CHANGE,
    EVENT_HOTSPOT_STA_JOIN,
    EVENT_HOTSPOT_STA_LEAVE,
};

NO_SANITIZE("cfi") void WifiCHotspotEventCallback::OnHotspotStateChanged(int state)
{
    WIFI_LOGI("Hotspot received state changed event: %{public}d", state);
    std::set<WifiEvent*> setCallbacks = GetEventCallBacks();
    for (auto& callback : setCallbacks) {
        if (callback && callback->OnHotspotStateChanged) {
            callback->OnHotspotStateChanged(state);
        }
    }
}

void WifiCHotspotEventCallback::OnHotspotStaJoin(const OHOS::Wifi::StationInfo &info)
{
    WIFI_LOGI("Hotspot received sta join event");
}

void WifiCHotspotEventCallback::OnHotspotStaLeave(const OHOS::Wifi::StationInfo &info)
{
    WIFI_LOGI("Hotspot received sta leave event");
}

OHOS::sptr<OHOS::IRemoteObject> WifiCHotspotEventCallback::AsObject()
{
    return nullptr;
}

OHOS::sptr<WifiCDeviceEventCallback> wifiCDeviceCallback =
    OHOS::sptr<WifiCDeviceEventCallback>(new (std::nothrow) WifiCDeviceEventCallback());
OHOS::sptr<WifiCScanEventCallback> wifiCScanCallback =
    OHOS::sptr<WifiCScanEventCallback>(new (std::nothrow) WifiCScanEventCallback());
OHOS::sptr<WifiCHotspotEventCallback> wifiCHotspotCallback =
    OHOS::sptr<WifiCHotspotEventCallback>(new (std::nothrow) WifiCHotspotEventCallback());

bool EventManager::AddEventCallback(WifiEvent *cb)
{
    if (cb == NULL) {
        return false;
    }
    return m_setEventCallback.insert(cb).second;
}

void EventManager::RemoveEventCallback(WifiEvent *cb)
{
    m_setEventCallback.erase(cb);
}

bool EventManager::IsEventRegistered()
{
    return m_isEventRegistered;
}

void EventManager::SetIsEventRegistrated(bool isEventRegistered)
{
    m_isEventRegistered = isEventRegistered;
}

WifiErrorCode EventManager::RegisterDeviceEvent(const std::vector<std::string> &event)
{
    using namespace OHOS::Wifi;
    if (event.empty()) {
        WIFI_LOGE("Register sta event is empty!");
        return ERROR_WIFI_UNKNOWN;
    }
    std::unique_ptr<WifiDevice> wifiStaPtr = WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);
    if (wifiStaPtr == nullptr) {
        WIFI_LOGE("Register sta event get instance failed!");
        return ERROR_WIFI_UNKNOWN;
    }
    ErrCode ret = wifiStaPtr->RegisterCallBack(wifiCDeviceCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Register sta event failed!");
        return ERROR_WIFI_UNKNOWN;
    }
    return WIFI_SUCCESS;
}

WifiErrorCode EventManager::RegisterScanEvent(const std::vector<std::string> &event)
{
    using namespace OHOS::Wifi;
    if (event.empty()) {
        WIFI_LOGE("Register scan event is empty!");
        return ERROR_WIFI_UNKNOWN;
    }
    if (g_wifiScanPtr == nullptr) {
        WIFI_LOGE("Register scan event get instance failed!");
        return ERROR_WIFI_UNKNOWN;
    }
    ErrCode ret = g_wifiScanPtr->RegisterCallBack(wifiCScanCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Register scan event failed!");
        return ERROR_WIFI_UNKNOWN;
    }
    return WIFI_SUCCESS;
}

WifiErrorCode EventManager::RegisterHotspotEvent(const std::vector<std::string> &event)
{
    using namespace OHOS::Wifi;
    if (event.empty()) {
        WIFI_LOGE("Register hotspot event is empty!");
        return ERROR_WIFI_UNKNOWN;
    }
    std::unique_ptr<WifiHotspot> wifiHotspotPtr = WifiHotspot::GetInstance(WIFI_HOTSPOT_ABILITY_ID);
    if (wifiHotspotPtr == nullptr) {
        WIFI_LOGE("Register hotspot event get instance failed!");
        return ERROR_WIFI_UNKNOWN;
    }
    ErrCode ret = wifiHotspotPtr->RegisterCallBack(wifiCHotspotCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Register hotspot event failed!");
        return ERROR_WIFI_UNKNOWN;
    }
    return WIFI_SUCCESS;
}

WifiErrorCode EventManager::RegisterP2PEvent(const std::vector<std::string> &event)
{
    using namespace OHOS::Wifi;
    if (event.empty()) {
        WIFI_LOGE("Register p2p event is empty!");
        return ERROR_WIFI_UNKNOWN;
    }
    std::unique_ptr<WifiP2p> wifiP2pPtr = WifiP2p::GetInstance(WIFI_P2P_ABILITY_ID);
    if (wifiP2pPtr == nullptr) {
        WIFI_LOGE("Register p2p event get instance failed!");
        return ERROR_WIFI_UNKNOWN;
    }
    OHOS::sptr<WifiP2pCEventCallback> sptrP2PCallback = GetP2PCallbackPtr();
    if (sptrP2PCallback == nullptr) {
        WIFI_LOGE("Register p2p event get p2p callback ptr failed!");
        return ERROR_WIFI_UNKNOWN;
    }
    ErrCode ret = wifiP2pPtr->RegisterCallBack(sptrP2PCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Register p2p event failed!");
        return ERROR_WIFI_UNKNOWN;
    }
    return WIFI_SUCCESS;
}

NO_SANITIZE("cfi") WifiErrorCode EventManager::RegisterWifiEvents()
{
    if (mSaStatusListener == nullptr) {
        mSaStatusListener = new OHOS::Wifi::WifiAbilityStatusChange();
        mSaStatusListener->Init(WIFI_DEVICE_ABILITY_ID);
        mSaStatusListener->Init(WIFI_SCAN_ABILITY_ID);
        mSaStatusListener->Init(WIFI_HOTSPOT_ABILITY_ID);
        mSaStatusListener->Init(WIFI_P2P_ABILITY_ID);
    }

    WifiErrorCode ret = WIFI_SUCCESS;
    ret = RegisterDeviceEvent(WifiCDeviceEventCallback::deviceCallbackEvent);
    if (ret != WIFI_SUCCESS) {
        return ret;
    }

    ret = RegisterScanEvent(WifiCScanEventCallback::scanCallbackEvent);
    if (ret != WIFI_SUCCESS) {
        return ret;
    }

    ret = RegisterHotspotEvent(WifiCHotspotEventCallback::hotspotCallbackEvent);
    if (ret != WIFI_SUCCESS) {
        return ret;
    }
    return WIFI_SUCCESS;
}

std::set<WifiEvent*> EventManager::GetEventCallBacks()
{
    return m_setEventCallback;
}

void EventManager::SetP2PCallbackEvent(OHOS::sptr<WifiP2pCEventCallback> &sptr, const std::string &eventName)
{
    if (sptr == nullptr) {
        WIFI_LOGE("SetP2PCallbackEvent, invalid sptr.");
        return;
    }

    WIFI_LOGI("SetP2PCallbackEvent, eventName:%{public}s", eventName.c_str());
    sptrP2PCallback = sptr;
    p2pRegisteredCallbackEvent.emplace(eventName);
    return;
}

void EventManager::RemoveP2PCallbackEvent(const std::string &eventName)
{
    WIFI_LOGI("RemoveP2PCallbackEvent, eventName:%{public}s", eventName.c_str());
    p2pRegisteredCallbackEvent.erase(eventName);
    return;
}

std::set<std::string>& EventManager::GetP2PCallbackEvent()
{
    return p2pRegisteredCallbackEvent;
}

OHOS::sptr<WifiP2pCEventCallback> EventManager::GetP2PCallbackPtr()
{
    return sptrP2PCallback;
}

EventManager& EventManager::GetInstance()
{
    static EventManager g_eventManger;
    return g_eventManger;
}

void EventManager::Init()
{
    if (mSaStatusListener == nullptr) {
        WIFI_LOGI("EventManager Listener Init!");
        mSaStatusListener = new OHOS::Wifi::WifiAbilityStatusChange();
        mSaStatusListener->Init(WIFI_DEVICE_ABILITY_ID);
        mSaStatusListener->Init(WIFI_SCAN_ABILITY_ID);
        mSaStatusListener->Init(WIFI_HOTSPOT_ABILITY_ID);
        mSaStatusListener->Init(WIFI_P2P_ABILITY_ID);
    }

    g_wifiScanPtr = OHOS::Wifi::WifiScan::GetInstance(WIFI_SCAN_ABILITY_ID);
    if (g_wifiScanPtr == nullptr) {
        WIFI_LOGE("init scan event get instance failed!");
        return;
    }

    return;
}

std::set<WifiEvent*> EventManager::m_setEventCallback;
bool EventManager::m_isEventRegistered = false;

std::set<WifiEvent*> GetEventCallBacks() {
    return EventManager::GetInstance().GetEventCallBacks();
}

WifiErrorCode RegisterWifiEvent(WifiEvent *event) {
    WIFI_LOGI("Register wifi event");
    if (!EventManager::GetInstance().IsEventRegistered()) {
        if (EventManager::GetInstance().RegisterWifiEvents() != WIFI_SUCCESS) {
            WIFI_LOGE("Wifi event register failed!");
            return ERROR_WIFI_UNKNOWN;
        }
        EventManager::GetInstance().SetIsEventRegistrated(true);
    }
    return EventManager::GetInstance().AddEventCallback(event) ? WIFI_SUCCESS : ERROR_WIFI_INVALID_ARGS;
}

WifiErrorCode UnRegisterWifiEvent(WifiEvent *event) {
    WIFI_LOGI("Unregister wifi event");
    EventManager::GetInstance().RemoveEventCallback(event);
    return WIFI_SUCCESS;
}
