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

#include "kits/c/wifi_event.h"
#include <set>
#include <vector>
#include "kits/c/wifi_device.h"
#include "kits/c/wifi_scan_info.h"
#include "i_wifi_device_callback.h"
#include "i_wifi_hotspot_callback.h"
#include "i_wifi_scan_callback.h"
#include "wifi_device.h"
#include "wifi_hotspot.h"
#include "wifi_logger.h"
#include "wifi_scan.h"
#include "wifi_p2p.h"
#include "wifi_common_util.h"
#include "wifi_sa_event.h"
DEFINE_WIFILOG_LABEL("WifiCEvent");
std::shared_ptr<OHOS::Wifi::WifiDevice> g_wifiStaPtr = OHOS::Wifi::WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);
std::shared_ptr<OHOS::Wifi::WifiScan> g_wifiScanPtr = OHOS::Wifi::WifiScan::GetInstance(WIFI_SCAN_ABILITY_ID);
std::shared_ptr<OHOS::Wifi::WifiP2p> g_wifiP2pPtr = OHOS::Wifi::WifiP2p::GetInstance(WIFI_P2P_ABILITY_ID);
std::shared_ptr<OHOS::Wifi::WifiHotspot> g_wifiHotspotPtr =
    OHOS::Wifi::WifiHotspot::GetInstance(WIFI_HOTSPOT_ABILITY_ID);

std::vector<std::string> WifiCDeviceEventCallback::deviceCallbackEvent = {
    EVENT_STA_CONN_STATE_CHANGE,
    EVENT_STA_DEVICE_CONFIG_CHANGE,
};

void WifiCDeviceEventCallback::OnWifiStateChanged(int state)
{
    WIFI_LOGI("sta received state changed event: %{public}d", state);
}

static OHOS::Wifi::ErrCode ConvertedLinkedInfo(const OHOS::Wifi::WifiLinkedInfo& linkedInfo, WifiLinkedInfo *dstInfo)
{
    if (dstInfo == nullptr) {
        WIFI_LOGE("Error: the ptr is null!");
        return OHOS::Wifi::WIFI_OPT_INVALID_PARAM;
    }

    if (memcpy_s(dstInfo->ssid, WIFI_MAX_SSID_LEN, linkedInfo.ssid.c_str(), linkedInfo.ssid.size() + 1) != EOK) {
        return OHOS::Wifi::WIFI_OPT_FAILED;
    }
    if (OHOS::Wifi::MacStrToArray(linkedInfo.bssid, dstInfo->bssid) != EOK) {
        WIFI_LOGE("linked info convert bssid error!");
        return OHOS::Wifi::WIFI_OPT_FAILED;
    }
    dstInfo->rssi = linkedInfo.rssi;
    dstInfo->band = linkedInfo.band;
    dstInfo->frequency = linkedInfo.frequency;
    dstInfo->connState = linkedInfo.connState == OHOS::Wifi::ConnState::CONNECTED ? WIFI_CONNECTED : WIFI_DISCONNECTED;
    /* disconnectedReason not support */
    dstInfo->ipAddress = linkedInfo.ipAddress;
    dstInfo->wifiStandard = linkedInfo.wifiStandard;
    dstInfo->maxSupportedRxLinkSpeed = linkedInfo.maxSupportedRxLinkSpeed;
    dstInfo->maxSupportedTxLinkSpeed = linkedInfo.maxSupportedTxLinkSpeed;
    dstInfo->rxLinkSpeed = linkedInfo.rxLinkSpeed;
    dstInfo->txLinkSpeed = linkedInfo.txLinkSpeed;
    return OHOS::Wifi::WIFI_OPT_SUCCESS;
}

NO_SANITIZE("cfi") void WifiCDeviceEventCallback::OnWifiConnectionChanged(int state,
    const OHOS::Wifi::WifiLinkedInfo &info)
{
    WIFI_LOGI("sta connection changed event: %{public}d", state);
    WifiLinkedInfo linkInfo;
    OHOS::Wifi::ErrCode retValue = ConvertedLinkedInfo(info, &linkInfo);
    if (retValue != OHOS::Wifi::WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Get linked info from cpp error!");
        return;
    }
    std::unique_lock<std::mutex> lock(EventManager::callbackMutex);
    if (EventManager::g_wifiEvent.OnWifiConnectionChanged) {
        EventManager::g_wifiEvent.OnWifiConnectionChanged(state, &linkInfo);
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
    WIFI_LOGI("sta received device config changed event: %{public}d", static_cast<int>(value));
    std::unique_lock<std::mutex> lock(EventManager::callbackMutex);
    if (EventManager::g_wifiEvent.OnDeviceConfigChange) {
        EventManager::g_wifiEvent.OnDeviceConfigChange(ConfigChange(static_cast<int>(value)));
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
    WIFI_LOGI("ScanStateChanged event: %{public}d", state);
    std::unique_lock<std::mutex> lock(EventManager::callbackMutex);
    if (EventManager::g_wifiEvent.OnWifiScanStateChanged) {
        EventManager::g_wifiEvent.OnWifiScanStateChanged(state, WIFI_SCAN_HOTSPOT_LIMIT);
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
    std::unique_lock<std::mutex> lock(EventManager::callbackMutex);
    if (EventManager::g_wifiEvent.OnHotspotStateChanged) {
        EventManager::g_wifiEvent.OnHotspotStateChanged(state);
    }
}

static OHOS::Wifi::ErrCode ConvertStationInfo(const OHOS::Wifi::StationInfo& staInfo, StationInfo *cStaInfo)
{
    if (cStaInfo == nullptr || cStaInfo->name == nullptr) {
        WIFI_LOGE("Error: the ptr is null!");
        return OHOS::Wifi::WIFI_OPT_INVALID_PARAM;
    }

    if (memcpy_s(cStaInfo->name, DEVICE_NAME_LEN, staInfo.deviceName.c_str(), staInfo.deviceName.size() + 1) != EOK) {
        return OHOS::Wifi::WIFI_OPT_FAILED;
    }
    if (OHOS::Wifi::MacStrToArray(staInfo.bssid, cStaInfo->macAddress) != EOK) {
        WIFI_LOGE("StationInfo bssid Convert to c struct error!");
        return OHOS::Wifi::WIFI_OPT_FAILED;
    }
    cStaInfo->ipAddress = OHOS::Wifi::Ip2Number(staInfo.ipAddr);
    return OHOS::Wifi::WIFI_OPT_SUCCESS;
}

void WifiCHotspotEventCallback::OnHotspotStaJoin(const OHOS::Wifi::StationInfo &info)
{
    std::unique_lock<std::mutex> lock(EventManager::callbackMutex);
    WIFI_LOGI("Hotspot received sta join event");
    StationInfo cStaInfo;
    cStaInfo.name = (char *)malloc(DEVICE_NAME_LEN);
    if (cStaInfo.name == nullptr) {
        WIFI_LOGE("Malloc failed");
        return;
    }
    OHOS::Wifi::ErrCode retValue = ConvertStationInfo(info, &cStaInfo);
    if (retValue != OHOS::Wifi::WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Get station info from cpp error");
        free(cStaInfo.name);
        cStaInfo.name = nullptr;
        return;
    }
    if (EventManager::g_wifiEvent.OnHotspotStaJoin) {
        EventManager::g_wifiEvent.OnHotspotStaJoin(&cStaInfo);
    }
    free(cStaInfo.name);
    cStaInfo.name = nullptr;
}

void WifiCHotspotEventCallback::OnHotspotStaLeave(const OHOS::Wifi::StationInfo &info)
{
    std::unique_lock<std::mutex> lock(EventManager::callbackMutex);
    WIFI_LOGI("Hotspot received sta leave event");
    StationInfo cStaInfo;
    cStaInfo.name = (char *)malloc(DEVICE_NAME_LEN);
    if (cStaInfo.name == nullptr) {
        WIFI_LOGE("Malloc failed");
        return;
    }
    OHOS::Wifi::ErrCode retValue = ConvertStationInfo(info, &cStaInfo);
    if (retValue != OHOS::Wifi::WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Get station info from cpp error");
        free(cStaInfo.name);
        cStaInfo.name = nullptr;
        return;
    }
    if (EventManager::g_wifiEvent.OnHotspotStaLeave) {
        EventManager::g_wifiEvent.OnHotspotStaLeave(&cStaInfo);
    }
    free(cStaInfo.name);
    cStaInfo.name = nullptr;
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

EventManager::EventManager()
{
}

EventManager::~EventManager()
{
}

void EventManager::RemoveEventCallback(WifiEvent *cb)
{
    std::unique_lock<std::mutex> lock(callbackMutex);
    if (cb && cb->OnWifiConnectionChanged) {
        g_wifiEvent.OnWifiConnectionChanged = nullptr;
    }
    if (cb && cb->OnWifiScanStateChanged) {
        g_wifiEvent.OnWifiScanStateChanged = nullptr;
    }
    if (cb && cb->OnHotspotStateChanged) {
        g_wifiEvent.OnHotspotStateChanged = nullptr;
    }
    if (cb && cb->OnHotspotStaJoin) {
        g_wifiEvent.OnHotspotStaJoin = nullptr;
    }
    if (cb && cb->OnHotspotStaLeave) {
        g_wifiEvent.OnHotspotStaLeave = nullptr;
    }
    if (cb && cb->OnDeviceConfigChange) {
        g_wifiEvent.OnDeviceConfigChange = nullptr;
    }
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
    if (g_wifiStaPtr == nullptr) {
        WIFI_LOGE("Register sta event get instance failed!");
        return ERROR_WIFI_UNKNOWN;
    }
    ErrCode ret = g_wifiStaPtr->RegisterCallBack(wifiCDeviceCallback, event);
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
    if (g_wifiHotspotPtr == nullptr) {
        WIFI_LOGE("Register hotspot event get instance failed!");
        return ERROR_WIFI_UNKNOWN;
    }
    ErrCode ret = g_wifiHotspotPtr->RegisterCallBack(wifiCHotspotCallback, event);
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
    if (g_wifiP2pPtr == nullptr) {
        WIFI_LOGE("Register p2p event get instance failed!");
        return ERROR_WIFI_UNKNOWN;
    }
    OHOS::sptr<WifiP2pCEventCallback> sptrP2PCallback = GetP2PCallbackPtr();
    if (sptrP2PCallback == nullptr) {
        WIFI_LOGE("Register p2p event get p2p callback ptr failed!");
        return ERROR_WIFI_UNKNOWN;
    }
    ErrCode ret = g_wifiP2pPtr->RegisterCallBack(sptrP2PCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Register p2p event failed!");
        return ERROR_WIFI_UNKNOWN;
    }
    return WIFI_SUCCESS;
}

NO_SANITIZE("cfi") WifiErrorCode EventManager::RegisterWifiEvents()
{
    std::unique_lock<std::mutex> lock(callbackMutex);
    if (mSaStatusListener == nullptr) {
        int32_t ret;
        auto samgrProxy = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgrProxy == nullptr) {
            WIFI_LOGI("samgrProxy is nullptr!");
            return ERROR_WIFI_UNKNOWN;
        }
        mSaStatusListener = new OHOS::Wifi::WifiAbilityStatusChange();
        if (mSaStatusListener == nullptr) {
            WIFI_LOGI("mSaStatusListener is nullptr!");
            return ERROR_WIFI_UNKNOWN;
        }
        ret = samgrProxy->SubscribeSystemAbility((int32_t)WIFI_DEVICE_ABILITY_ID, mSaStatusListener);
        samgrProxy->SubscribeSystemAbility((int32_t)WIFI_SCAN_ABILITY_ID, mSaStatusListener);
        samgrProxy->SubscribeSystemAbility((int32_t)WIFI_HOTSPOT_ABILITY_ID, mSaStatusListener);
        samgrProxy->SubscribeSystemAbility((int32_t)WIFI_P2P_ABILITY_ID, mSaStatusListener);
        WIFI_LOGI("SubscribeSystemAbility return ret:%{public}d!", ret);
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
    std::unique_lock<std::mutex> lock(callbackMutex);
    if (mSaStatusListener == nullptr) {
        int32_t ret;
        WIFI_LOGI("EventManager Listener Init!");
        auto samgrProxy = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgrProxy == nullptr) {
            WIFI_LOGI("samgrProxy is nullptr!");
            return;
        }
        mSaStatusListener = new OHOS::Wifi::WifiAbilityStatusChange();
        if (mSaStatusListener == nullptr) {
            WIFI_LOGI("mSaStatusListener is nullptr!");
            return;
        }
        ret = samgrProxy->SubscribeSystemAbility((int32_t)WIFI_DEVICE_ABILITY_ID, mSaStatusListener);
        samgrProxy->SubscribeSystemAbility((int32_t)WIFI_SCAN_ABILITY_ID, mSaStatusListener);
        samgrProxy->SubscribeSystemAbility((int32_t)WIFI_HOTSPOT_ABILITY_ID, mSaStatusListener);
        samgrProxy->SubscribeSystemAbility((int32_t)WIFI_P2P_ABILITY_ID, mSaStatusListener);
        WIFI_LOGI("Init, SubscribeSystemAbility return ret:%{public}d!", ret);
    }
    return;
}

std::mutex EventManager::callbackMutex;
WifiEvent EventManager::g_wifiEvent = {0};
bool EventManager::m_isEventRegistered = false;

void EventManager::SaveWifiCallbackInfo(WifiEvent* event)
{
    std::unique_lock<std::mutex> lock(callbackMutex);
    if (event && event->OnWifiConnectionChanged) {
        g_wifiEvent.OnWifiConnectionChanged = event->OnWifiConnectionChanged;
    }
    if (event && event->OnWifiScanStateChanged) {
        g_wifiEvent.OnWifiScanStateChanged = event->OnWifiScanStateChanged;
    }
    if (event && event->OnHotspotStateChanged) {
        g_wifiEvent.OnHotspotStateChanged = event->OnHotspotStateChanged;
    }
    if (event && event->OnHotspotStaJoin) {
        g_wifiEvent.OnHotspotStaJoin = event->OnHotspotStaJoin;
    }
    if (event && event->OnHotspotStaLeave) {
        g_wifiEvent.OnHotspotStaLeave = event->OnHotspotStaLeave;
    }
    if (event && event->OnDeviceConfigChange) {
        g_wifiEvent.OnDeviceConfigChange = event->OnDeviceConfigChange;
    }
}

WifiErrorCode RegisterWifiEvent(WifiEvent *event) {
    WIFI_LOGI("Register wifi event");
    EventManager::GetInstance().SaveWifiCallbackInfo(event);
    if (!EventManager::GetInstance().IsEventRegistered()) {
        if (EventManager::GetInstance().RegisterWifiEvents() == WIFI_SUCCESS) {
            EventManager::GetInstance().SetIsEventRegistrated(true);
        } else {
            WIFI_LOGE("Wifi event register failed!");
        }
    }
    return WIFI_SUCCESS;
}

WifiErrorCode UnRegisterWifiEvent(WifiEvent *event) {
    WIFI_LOGI("Unregister wifi event");
    EventManager::GetInstance().RemoveEventCallback(event);
    return WIFI_SUCCESS;
}
