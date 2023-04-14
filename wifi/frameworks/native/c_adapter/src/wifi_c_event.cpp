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
#include "../../../interfaces/kits/c/wifi_device.h"
#include "../../../interfaces/kits/c/wifi_scan_info.h"
#include "i_wifi_device_callback.h"
#include "i_wifi_hotspot_callback.h"
#include "i_wifi_scan_callback.h"
#include "wifi_device.h"
#include "wifi_hotspot.h"
#include "wifi_logger.h"
#include "wifi_scan.h"
#include "wifi_common_util.h"
#include "../../src/wifi_sa_event.h"
DEFINE_WIFILOG_LABEL("WifiCEvent");
std::set<WifiEvent*> GetEventCallBacks();

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

NO_SANITIZE("cfi") WifiErrorCode EventManager::RegisterWifiEvents()
{
    if (mSaStatusListener == nullptr) {
        mSaStatusListener = new OHOS::Wifi::WifiAbilityStatusChange();
        mSaStatusListener->Init(WIFI_DEVICE_ABILITY_ID);
        mSaStatusListener->Init(WIFI_SCAN_ABILITY_ID);
        mSaStatusListener->Init(WIFI_HOTSPOT_ABILITY_ID);
        mSaStatusListener->Init(WIFI_P2P_ABILITY_ID);
    }
    using namespace OHOS::Wifi;
    std::unique_ptr<WifiDevice> wifiStaPtr = WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);
    if (wifiStaPtr == nullptr) {
        WIFI_LOGE("Register sta event get instance failed!");
        return ERROR_WIFI_UNKNOWN;
    }
    ErrCode ret = wifiStaPtr->RegisterCallBack(wifiCDeviceCallback);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Register sta event failed!");
        return ERROR_WIFI_UNKNOWN;
    }

    std::unique_ptr<WifiScan> wifiScanPtr = WifiScan::GetInstance(WIFI_SCAN_ABILITY_ID);
    if (wifiScanPtr == nullptr) {
        WIFI_LOGE("Register scan event get instance failed!");
        return ERROR_WIFI_UNKNOWN;
    }
    ret = wifiScanPtr->RegisterCallBack(wifiCScanCallback);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Register scan event failed!");
        return ERROR_WIFI_UNKNOWN;
    }

    std::unique_ptr<WifiHotspot> wifiHotspotPtr = WifiHotspot::GetInstance(WIFI_HOTSPOT_ABILITY_ID);
    if (wifiHotspotPtr == nullptr) {
        WIFI_LOGE("Register hotspot event get instance failed!");
        return ERROR_WIFI_UNKNOWN;
    }
    ret = wifiHotspotPtr->RegisterCallBack(wifiCHotspotCallback);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Register hotspot event failed!");
        return ERROR_WIFI_UNKNOWN;
    }
    return WIFI_SUCCESS;
}

EventManager::EventManager()
{
    
}

bool EventManager::IsEventRegistered()
{
    return m_isEventRegistered;
}

void EventManager::SetIsEventRegistrated(bool isEventRegistered)
{
    m_isEventRegistered = isEventRegistered;
}

std::set<WifiEvent*> EventManager::GetEventCallBacks()
{
    return m_setEventCallback;
}

std::set<WifiEvent*> EventManager::m_setEventCallback;
bool EventManager::m_isEventRegistered = false;
static EventManager g_eventManager;

std::set<WifiEvent*> GetEventCallBacks() {
    return g_eventManager.GetEventCallBacks();
}

WifiErrorCode RegisterWifiEvent(WifiEvent *event) {
    WIFI_LOGI("Register wifi event");
    if (!g_eventManager.IsEventRegistered()) {
        if (g_eventManager.RegisterWifiEvents() != WIFI_SUCCESS) {
            WIFI_LOGE("Wifi event register failed!");
            return ERROR_WIFI_UNKNOWN;
        }
        g_eventManager.SetIsEventRegistrated(true);
    }
    return g_eventManager.AddEventCallback(event) ? WIFI_SUCCESS : ERROR_WIFI_INVALID_ARGS;
}

WifiErrorCode UnRegisterWifiEvent(WifiEvent *event) {
    WIFI_LOGI("Unregister wifi event");
    g_eventManager.RemoveEventCallback(event);
    return WIFI_SUCCESS;
}
