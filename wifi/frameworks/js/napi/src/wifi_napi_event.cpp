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

#include "wifi_napi_event.h"
#include <uv.h>
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "wifi_device.h"
#include "wifi_logger.h"
#include "wifi_napi_utils.h"
#include "wifi_scan.h"
#include "wifi_napi_errcode.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiNAPIEvent");
constexpr uint32_t INVALID_REF_COUNT = 0xff;
std::shared_ptr<WifiDevice> g_wifiStaPtr = WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);
std::shared_ptr<WifiScan> g_wifiScanPtr = WifiScan::GetInstance(WIFI_SCAN_ABILITY_ID);
std::shared_ptr<WifiHotspot> g_wifiHotspotPtr = WifiHotspot::GetInstance(WIFI_HOTSPOT_ABILITY_ID);
std::shared_ptr<WifiP2p> g_wifiP2pPtr = WifiP2p::GetInstance(WIFI_P2P_ABILITY_ID);

static std::set<std::string> g_supportEventList = {
    EVENT_STA_POWER_STATE_CHANGE,
    EVENT_STA_CONN_STATE_CHANGE,
    EVENT_STA_SCAN_STATE_CHANGE,
    EVENT_STA_RSSI_STATE_CHANGE,
    EVENT_STA_DEVICE_CONFIG_CHANGE,
    EVENT_STREAM_CHANGE,
    EVENT_HOTSPOT_STATE_CHANGE,
    EVENT_HOTSPOT_STA_JOIN,
    EVENT_HOTSPOT_STA_LEAVE,
    EVENT_P2P_STATE_CHANGE,
    EVENT_P2P_CONN_STATE_CHANGE,
    EVENT_P2P_DEVICE_STATE_CHANGE,
    EVENT_P2P_PERSISTENT_GROUP_CHANGE,
    EVENT_P2P_PEER_DEVICE_CHANGE,
    EVENT_P2P_DISCOVERY_CHANGE,
};

std::map<std::string, std::int32_t> g_EventSysCapMap = {
    { EVENT_STA_POWER_STATE_CHANGE, SYSCAP_WIFI_STA },
    { EVENT_STA_CONN_STATE_CHANGE, SYSCAP_WIFI_STA },
    { EVENT_STA_SCAN_STATE_CHANGE, SYSCAP_WIFI_STA },
    { EVENT_STA_RSSI_STATE_CHANGE, SYSCAP_WIFI_STA },
    { EVENT_STA_DEVICE_CONFIG_CHANGE, SYSCAP_WIFI_STA },
    { EVENT_STREAM_CHANGE, SYSCAP_WIFI_STA },
    { EVENT_HOTSPOT_STATE_CHANGE, SYSCAP_WIFI_AP_CORE },
    { EVENT_HOTSPOT_STA_JOIN, SYSCAP_WIFI_AP_CORE },
    { EVENT_HOTSPOT_STA_LEAVE, SYSCAP_WIFI_AP_CORE },
    { EVENT_P2P_STATE_CHANGE, SYSCAP_WIFI_P2P },
    { EVENT_P2P_CONN_STATE_CHANGE, SYSCAP_WIFI_P2P },
    { EVENT_P2P_DEVICE_STATE_CHANGE, SYSCAP_WIFI_P2P },
    { EVENT_P2P_PERSISTENT_GROUP_CHANGE, SYSCAP_WIFI_P2P },
    { EVENT_P2P_PEER_DEVICE_CHANGE, SYSCAP_WIFI_P2P },
    { EVENT_P2P_DISCOVERY_CHANGE, SYSCAP_WIFI_P2P },
};

void NapiEvent::EventNotify(AsyncEventData *asyncEvent)
{
    if (asyncEvent == nullptr) {
        WIFI_LOGE("asyncEvent is null!");
        return;
    }
    WIFI_LOGD("Enter wifi event notify, eventType: %{public}s", asyncEvent->eventType.c_str());

    auto task = [asyncEvent]() {
        napi_value handler = nullptr;
        napi_handle_scope scope = nullptr;
        napi_value jsEvent = nullptr;
        uint32_t refCount = INVALID_REF_COUNT;
        napi_status res;
        bool unrefRef = false;
        {
            bool find = false;
            std::shared_lock<std::shared_mutex> guard(g_regInfoMutex);
            auto it = g_eventRegisterInfo.find(asyncEvent->eventType);
            napi_open_handle_scope(asyncEvent->env, &scope);
            if (scope == nullptr) {
                WIFI_LOGE("napi_send_event, scope is nullptr");
                goto EXIT;
            }
            if (it == g_eventRegisterInfo.end()) {
                WIFI_LOGW("napi_send_event, event has been unregistered.");
                goto EXIT;
            }
            for (auto& each : it->second) {
                if (each.m_regEnv == asyncEvent->env && each.m_regHanderRef == asyncEvent->callbackRef) {
                    find = true;
                    break;
                }
            }
            if (find == false) {
                WIFI_LOGW("napi_send_event, NOT find the event.");
                goto EXIT;
            }
        }
        res = napi_reference_ref(asyncEvent->env, asyncEvent->callbackRef, &refCount);
        WIFI_LOGI("napi_send_event, res: %{public}d, callbackRef: %{private}p, refCount: %{public}d",
            res, asyncEvent->callbackRef, refCount);
        if (res != napi_ok || refCount <= 1) {
            WIFI_LOGE("napi_send_event, do NOT call back, res: %{public}d!", res);
            goto EXIT;
        }
        unrefRef = true;
        res = napi_get_reference_value(asyncEvent->env, asyncEvent->callbackRef, &handler);
        if (res != napi_ok || handler == nullptr) {
            WIFI_LOGE("napi_send_event, handler is nullptr or res: %{public}d!", res);
            goto EXIT;
        }
        napi_value undefine;
        napi_get_undefined(asyncEvent->env, &undefine);
        jsEvent = asyncEvent->packResult();
        if (napi_call_function(asyncEvent->env, nullptr, handler, 1, &jsEvent, &undefine) != napi_ok) {
            WIFI_LOGE("napi_send_event, Report event to Js failed");
        }

    EXIT:
        napi_close_handle_scope(asyncEvent->env, scope);
        if (unrefRef) {
            res = napi_reference_unref(asyncEvent->env, asyncEvent->callbackRef, &refCount);
            WIFI_LOGD("napi_send_event, unref, res: %{public}d, refCount: %{public}d", res, refCount);
        }
        delete asyncEvent;
    };
    if (napi_status::napi_ok != napi_send_event(asyncEvent->env, task, napi_eprio_immediate)) {
        WIFI_LOGE("napi_send_event: Failed to SendEvent");
        delete asyncEvent;
    } else {
        WIFI_LOGD("napi_send_event: Successed to SendEvent");
    }
}

napi_value NapiEvent::CreateResult(const napi_env& env, int value)
{
    napi_value result;
    napi_create_int32(env, value, &result);
    return result;
}

napi_value NapiEvent::CreateResult(const napi_env& env, const StationInfo& info)
{
    napi_value result;
    napi_create_object(env, &result);
    SetValueUtf8String(env, "name", info.deviceName, result);
    SetValueUtf8String(env, "macAddress", info.bssid, result);
    SetValueInt32(env, "macAddressType", info.bssidType, result);
    SetValueUtf8String(env, "ipAddress", info.ipAddr, result);
    return result;
}

napi_value NapiEvent::CreateResult(const napi_env& env, const WifiP2pDevice& device)
{
    napi_value result;
    napi_create_object(env, &result);
    SetValueUtf8String(env, "deviceName", device.GetDeviceName(), result);
    SetValueUtf8String(env, "deviceAddress", device.GetDeviceAddress(), result);
    SetValueInt32(env, "deviceAddressType", device.GetDeviceAddressType(), result);
    SetValueUtf8String(env, "primaryDeviceType", device.GetPrimaryDeviceType(), result);
    SetValueInt32(env, "deviceStatus", static_cast<int>(device.GetP2pDeviceStatus()), result);
    SetValueInt32(env, "groupCapabilities", device.GetGroupCapabilitys(), result);
    return result;
}

napi_value NapiEvent::CreateResult(const napi_env& env, const std::vector<WifiP2pDevice>& devices)
{
    uint32_t idx = 0;
    napi_value arrayResult;
    napi_create_array_with_length(env, devices.size(), &arrayResult);
    for (auto& each : devices) {
        if (napi_set_element(env, arrayResult, idx++, CreateResult(env, each)) != napi_ok) {
            WIFI_LOGE("Array result set element error, idx: %{public}u", idx - 1);
        }
    }
    return arrayResult;
}

napi_value NapiEvent::CreateResult(const napi_env& env, const WifiP2pLinkedInfo& info)
{
    napi_value result;
    napi_create_object(env, &result);
    SetValueInt32(env, "connectState", static_cast<int>(info.GetConnectState()), result);
    SetValueBool(env, "isGroupOwner", info.IsGroupOwner(), result);
    SetValueUtf8String(env, "groupOwnerAddr", info.GetGroupOwnerAddress(), result);
    return result;
}

napi_value NapiEvent::NapiEvent::CreateResult(const napi_env& env, napi_value placehoders)
{
    return placehoders == nullptr ? UndefinedNapiValue(env) : placehoders;
}

class WifiNapiDeviceEventCallback : public IWifiDeviceCallBack, public NapiEvent {
public:
    WifiNapiDeviceEventCallback() {
    }

    virtual ~WifiNapiDeviceEventCallback() {
    }

public:
    void OnWifiStateChanged(int state) override {
        WIFI_LOGI("OnWifiStateChanged event: %{public}d [0:DISABLING, 1:DISABLED, 2:ENABLING, 3:ENABLED]",
            state);
        if (m_wifiStateConvertMap.find(state) == m_wifiStateConvertMap.end()) {
            WIFI_LOGW("not find state.");
            return;
        }
        CheckAndNotify(EVENT_STA_POWER_STATE_CHANGE, m_wifiStateConvertMap[state]);
    }

    void OnWifiConnectionChanged(int state, const WifiLinkedInfo &info) override {
        WIFI_LOGI("OnWifiConnectionChanged event: %{public}d [4:CONNECTED, 6:DISCONNECTED, 7:SPECIAL_CONNECT]", state);
        if (m_connectStateConvertMap.find(state) == m_connectStateConvertMap.end()) {
            WIFI_LOGW("not find connect state.");
            return;
        }
        CheckAndNotify(EVENT_STA_CONN_STATE_CHANGE, m_connectStateConvertMap[state]);
    }

    void OnWifiRssiChanged(int rssi) override {
        WIFI_LOGI("OnWifiRssiChanged event: %{public}d", rssi);
        CheckAndNotify(EVENT_STA_RSSI_STATE_CHANGE, rssi);
    }

    void OnWifiWpsStateChanged(int state, const std::string &pinCode) override {
    }

    void OnStreamChanged(int direction) override
    {
        WIFI_LOGD("OnStreamChanged event: %{public}d [0:DATA_NONE, 1:DATA_IN, 2:DATA_OUT, 3:DATA_INOUT]",
            direction);
        if (m_streamDirectionConvertMap.find(direction) == m_streamDirectionConvertMap.end()) {
            WIFI_LOGW("not find stream state.");
            return;
        }
        CheckAndNotify(EVENT_STREAM_CHANGE, m_streamDirectionConvertMap[direction]);
    }

    void OnDeviceConfigChanged(ConfigChange value) override {
        WIFI_LOGI("OnDeviceConfigChanged event: %{public}d", static_cast<int>(value));
        CheckAndNotify(EVENT_STA_DEVICE_CONFIG_CHANGE, static_cast<int>(value));
    }

    OHOS::sptr<OHOS::IRemoteObject> AsObject() override {
        return nullptr;
    }

private:
    enum class JsLayerWifiState {
        DISABLED = 0,
        ENABLED = 1,
        ENABLING = 2,
        DISABLING = 3
    };

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

class WifiNapiScanEventCallback : public IWifiScanCallback, public NapiEvent {
public:
    WifiNapiScanEventCallback() {
    }

    virtual ~WifiNapiScanEventCallback() {
    }

public:
    void OnWifiScanStateChanged(int state) override {
        WIFI_LOGI("scan received state changed event: %{public}d", state);
        CheckAndNotify(EVENT_STA_SCAN_STATE_CHANGE, state);
    }

    OHOS::sptr<OHOS::IRemoteObject> AsObject() override {
        return nullptr;
    }
};

class WifiNapiHotspotEventCallback : public IWifiHotspotCallback, public NapiEvent {
public:
    WifiNapiHotspotEventCallback() {
    }

    virtual ~WifiNapiHotspotEventCallback() {
    }

public:
    void OnHotspotStateChanged(int state) override {
        WIFI_LOGI("Hotspot received state changed event: %{public}d", state);
        if (m_apStateConvertMap.find(state) == m_apStateConvertMap.end()) {
            return;
        }

        CheckAndNotify(EVENT_HOTSPOT_STATE_CHANGE, m_apStateConvertMap[state]);
    }

    void OnHotspotStaJoin(const StationInfo &info) override {
        WIFI_LOGI("Hotspot received sta join event");
        CheckAndNotify(EVENT_HOTSPOT_STA_JOIN, info);
    }

    void OnHotspotStaLeave(const StationInfo &info) override {
        WIFI_LOGI("Hotspot received sta leave event");
        CheckAndNotify(EVENT_HOTSPOT_STA_LEAVE, info);
    }

    OHOS::sptr<OHOS::IRemoteObject> AsObject() override {
        return nullptr;
    }

private:
    enum class JsLayerApState {
        DISABLED = 0,
        ENABLED = 1,
        ENABLING = 2,
        DISABLING = 3
    };

    std::map<int, int> m_apStateConvertMap = {
        { static_cast<int>(ApState::AP_STATE_STARTING), static_cast<int>(JsLayerApState::ENABLING) },
        { static_cast<int>(ApState::AP_STATE_STARTED), static_cast<int>(JsLayerApState::ENABLED) },
        { static_cast<int>(ApState::AP_STATE_CLOSING), static_cast<int>(JsLayerApState::DISABLING) },
        { static_cast<int>(ApState::AP_STATE_CLOSED), static_cast<int>(JsLayerApState::DISABLED) },
    };
};

class WifiNapiP2pEventCallback : public IWifiP2pCallback, public NapiEvent {
public:
    WifiNapiP2pEventCallback() {
    }

    virtual ~WifiNapiP2pEventCallback() {
    }

public:
    void OnP2pStateChanged(int state) override {
        WIFI_LOGI("received p2p state changed event: %{public}d", state);
        CheckAndNotify(EVENT_P2P_STATE_CHANGE, state);
    }

    void OnP2pPersistentGroupsChanged(void) override {
        WIFI_LOGI("received persistent group changed event");
        CheckAndNotify(EVENT_P2P_PERSISTENT_GROUP_CHANGE, nullptr);
    }

    void OnP2pThisDeviceChanged(const WifiP2pDevice& device) override {
        WIFI_LOGI("received this device changed event");
        CheckAndNotify(EVENT_P2P_DEVICE_STATE_CHANGE, device);
    }

    void OnP2pPeersChanged(const std::vector<WifiP2pDevice>& devices) override {
        WIFI_LOGI("received p2p peers changed event, devices count: %{public}d", static_cast<int>(devices.size()));
        CheckAndNotify(EVENT_P2P_PEER_DEVICE_CHANGE, devices);
    }

    void OnP2pServicesChanged(const std::vector<WifiP2pServiceInfo>& srvInfo) override {
    }

    void OnP2pConnectionChanged(const WifiP2pLinkedInfo& info) override {
        WIFI_LOGI("received p2p connection changed event, state: %{public}d",
            static_cast<int>(info.GetConnectState()));
        CheckAndNotify(EVENT_P2P_CONN_STATE_CHANGE, info);
    }

    void OnP2pDiscoveryChanged(bool isChange) override {
        WIFI_LOGI("received discovery state changed event");
        CheckAndNotify(EVENT_P2P_DISCOVERY_CHANGE, (int)isChange);
    }

    void OnP2pActionResult(P2pActionCallback action, ErrCode code) override {
    }

    void OnConfigChanged(CfgType type, char* data, int dataLen) override {
    }

    void OnP2pGcJoinGroup(const OHOS::Wifi::GcInfo &info) override
    {
        WIFI_LOGI("received OnP2pGcJoinGroup event");
    }

    void OnP2pGcLeaveGroup(const OHOS::Wifi::GcInfo &info) override
    {
        WIFI_LOGI("received OnP2pGcLeave event");
    }

    void OnP2pPrivatePeersChanged(const std::string &priWfdInfo) override
    {
        WIFI_LOGI("received OnP2pPrivatePeersChanged event");
    }

    void OnP2pChrErrCodeReport(const int errCode) override
    {
        WIFI_LOGI("received OnP2pChrErrCodeReport event");
    }

    OHOS::sptr<OHOS::IRemoteObject> AsObject() override {
        return nullptr;
    }
};

napi_value On(napi_env env, napi_callback_info cbinfo) {
    TRACE_FUNC_CALL;
    size_t requireArgc = 2;
    size_t argc = 2;
    napi_value argv[2] = {0};
    napi_value thisVar = 0;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, nullptr);
    if (requireArgc > argc) {
        WIFI_LOGI("requireArgc:%{public}zu, argc:%{public}zu", requireArgc, argc);
        WIFI_NAPI_RETURN(env, false, WIFI_OPT_INVALID_PARAM, 0);
    }

    napi_valuetype eventName = napi_undefined;
    napi_typeof(env, argv[0], &eventName);
    if (eventName != napi_string) {
        WIFI_LOGI("first argv != napi_string");
        WIFI_NAPI_RETURN(env, false, WIFI_OPT_INVALID_PARAM, 0);
    }

    napi_valuetype handler = napi_undefined;
    napi_typeof(env, argv[1], &handler);
    if (handler != napi_function) {
        WIFI_LOGI("second argv != napi_function");
        WIFI_NAPI_RETURN(env, false, WIFI_OPT_INVALID_PARAM, 0);
    }

    char type[64] = {0};
    size_t typeLen = 0;
    napi_get_value_string_utf8(env, argv[0], type, sizeof(type), &typeLen);
    EventRegister::GetInstance().Register(env, type, argv[1]);
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

napi_value Off(napi_env env, napi_callback_info cbinfo) {
    TRACE_FUNC_CALL;
    size_t requireArgc = 1;
    size_t requireArgcWithCb = 2;
    size_t argc = 2;
    napi_value argv[2] = {0};
    napi_value thisVar = 0;
    napi_get_cb_info(env, cbinfo, &argc, argv, &thisVar, nullptr);
    if (requireArgc > argc) {
        WIFI_LOGI("requireArgc:%{public}zu, argc:%{public}zu", requireArgc, argc);
        WIFI_NAPI_RETURN(env, false, WIFI_OPT_INVALID_PARAM, 0);
    }

    napi_valuetype eventName = napi_undefined;
    napi_typeof(env, argv[0], &eventName);
    if (eventName != napi_string) {
        WIFI_LOGI("first argv != napi_string");
        WIFI_NAPI_RETURN(env, false, WIFI_OPT_INVALID_PARAM, 0);
    }

    napi_valuetype handler = napi_undefined;
    if (argc >= requireArgcWithCb) {
        napi_typeof(env, argv[1], &handler);
        if (handler != napi_function && handler != napi_null) {
            WIFI_LOGI("second argv != napi_function");
            WIFI_NAPI_RETURN(env, false, WIFI_OPT_INVALID_PARAM, 0);
        }
    }

    char type[64] = {0};
    size_t typeLen = 0;
    napi_get_value_string_utf8(env, argv[0], type, sizeof(type), &typeLen);
    if (argc >= requireArgcWithCb && handler != napi_null) {
        EventRegister::GetInstance().Unregister(env, type, argv[1]);
    } else {
        EventRegister::GetInstance().Unregister(env, type, nullptr);
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

static int32_t findSysCap(const std::string& type)
{
    int32_t sysCap = SYSCAP_WIFI_STA;
    auto iter = g_EventSysCapMap.find(type);
    if (iter == g_EventSysCapMap.end()) {
        WIFI_LOGI("findSysCap, type:%{public}s, DO NOT find sysCap.", type.c_str());
        return sysCap;
    }
    sysCap = iter->second;
    return sysCap;
}

sptr<WifiNapiDeviceEventCallback> wifiDeviceCallback =
    sptr<WifiNapiDeviceEventCallback>(new (std::nothrow) WifiNapiDeviceEventCallback());

sptr<WifiNapiScanEventCallback> wifiScanCallback =
    sptr<WifiNapiScanEventCallback>(new (std::nothrow) WifiNapiScanEventCallback());

sptr<WifiNapiHotspotEventCallback> wifiHotspotCallback =
    sptr<WifiNapiHotspotEventCallback>(new (std::nothrow) WifiNapiHotspotEventCallback());

sptr<WifiNapiP2pEventCallback> wifiP2pCallback =
    sptr<WifiNapiP2pEventCallback>(new (std::nothrow) WifiNapiP2pEventCallback());

ErrCode EventRegister::RegisterDeviceEvents(const std::vector<std::string> &event)
{
    if (event.empty()) {
        WIFI_LOGE("Register sta event is empty!");
        return WIFI_OPT_FAILED;
    }
    if (g_wifiStaPtr == nullptr) {
        WIFI_LOGE("Register sta event get instance failed!");
        return WIFI_OPT_FAILED;
    }
    ErrCode ret = g_wifiStaPtr->RegisterCallBack(wifiDeviceCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Register sta event failed!");
        return ret;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode EventRegister::RegisterScanEvents(const std::vector<std::string> &event)
{
    if (event.empty()) {
        WIFI_LOGE("Register scan event is empty!");
        return WIFI_OPT_FAILED;
    }
    if (g_wifiScanPtr == nullptr) {
        WIFI_LOGE("Register scan event get instance failed!");
        return WIFI_OPT_FAILED;
    }
    ErrCode ret = g_wifiScanPtr->RegisterCallBack(wifiScanCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Register scan event failed!");
        return ret;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode EventRegister::RegisterHotspotEvents(const std::vector<std::string> &event)
{
    if (event.empty()) {
        WIFI_LOGE("Register hotspot event is empty!");
        return WIFI_OPT_FAILED;
    }
    if (g_wifiHotspotPtr == nullptr) {
        WIFI_LOGE("Register hotspot event get instance failed!");
        return WIFI_OPT_FAILED;
    }
    ErrCode ret = g_wifiHotspotPtr->RegisterCallBack(wifiHotspotCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Register hotspot event failed!");
        return ret;
    }
    return WIFI_OPT_SUCCESS;
}

ErrCode EventRegister::RegisterP2PEvents(const std::vector<std::string> &event)
{
    if (event.empty()) {
        WIFI_LOGE("Register p2p event is empty!");
        return WIFI_OPT_FAILED;
    }
    if (g_wifiP2pPtr == nullptr) {
        WIFI_LOGE("Register p2p event get instance failed!");
        return WIFI_OPT_FAILED;
    }
    ErrCode ret = g_wifiP2pPtr->RegisterCallBack(wifiP2pCallback, event);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Register p2p event failed!");
        return ret;
    }
    return WIFI_OPT_SUCCESS;
}

NO_SANITIZE("cfi") ErrCode EventRegister::RegisterWifiEvents(int32_t sysCap, const std::string& type)
{
    std::vector<std::string> event = {type};
    if (sysCap == SYSCAP_WIFI_STA) {
        ErrCode ret = RegisterDeviceEvents(event);
        if (ret != WIFI_OPT_SUCCESS) {
            return ret;
        }
        return RegisterScanEvents(event);
    }

    if (sysCap == SYSCAP_WIFI_AP_CORE) {
        return RegisterHotspotEvents(event);
    }

    if (sysCap == SYSCAP_WIFI_P2P) {
        return RegisterP2PEvents(event);
    }

    WIFI_LOGE("RegisterWifiEvents, invalid sysCap: %{public}d!", static_cast<int>(sysCap));
    return WIFI_OPT_FAILED;
}

void WifiNapiAbilityStatusChange::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    WIFI_LOGI("OnAddSystemAbility systemAbilityId:%{public}d", systemAbilityId);
    std::vector<std::string> event;
    switch (systemAbilityId) {
        case WIFI_DEVICE_ABILITY_ID: {
            std::unique_lock<std::shared_mutex> guard(g_regInfoMutex);
            for (auto &iter : g_eventRegisterInfo) {
                if (findSysCap(iter.first) == SYSCAP_WIFI_STA) {
                    event.emplace_back(iter.first);
                }
            }
            EventRegister::GetInstance().RegisterDeviceEvents(event);
            break;
        }
        case WIFI_SCAN_ABILITY_ID: {
            std::unique_lock<std::shared_mutex> guard(g_regInfoMutex);
            for (auto &iter : g_eventRegisterInfo) {
                if (findSysCap(iter.first) == SYSCAP_WIFI_STA) {
                    event.emplace_back(iter.first);
                }
            }
            EventRegister::GetInstance().RegisterScanEvents(event);
            break;
        }
        case WIFI_HOTSPOT_ABILITY_ID: {
            std::unique_lock<std::shared_mutex> guard(g_regInfoMutex);
            for (auto &iter : g_eventRegisterInfo) {
                if (findSysCap(iter.first) == SYSCAP_WIFI_AP_CORE) {
                    event.emplace_back(iter.first);
                }
            }
            EventRegister::GetInstance().RegisterHotspotEvents(event);
            break;
        }
        case WIFI_P2P_ABILITY_ID: {
            std::unique_lock<std::shared_mutex> guard(g_regInfoMutex);
            for (auto &iter : g_eventRegisterInfo) {
                if (findSysCap(iter.first) == SYSCAP_WIFI_P2P) {
                    event.emplace_back(iter.first);
                }
            }
            EventRegister::GetInstance().RegisterP2PEvents(event);
            break;
        }
        default:
            WIFI_LOGI("OnAddSystemAbility unhandled sysabilityId:%{public}d", systemAbilityId);
            return;
    }
}

EventRegister& EventRegister::GetInstance()
{
    static EventRegister inst;
    return inst;
}

bool EventRegister::IsEventSupport(const std::string& type)
{
    return g_supportEventList.find(type) != g_supportEventList.end();
}

void EventRegister::Register(const napi_env& env, const std::string& type, napi_value handler)
{
    int32_t sysCap = findSysCap(type);
    WIFI_LOGI("Register event: %{public}s, env: %{private}p, %{public}d.",
        type.c_str(), env, static_cast<int>(sysCap));
    if (!IsEventSupport(type)) {
        WIFI_LOGE("Register type error or not support!");
#ifdef ENABLE_NAPI_WIFI_MANAGER
        HandleSyncErrCode(env, WIFI_OPT_NOT_SUPPORTED, sysCap);
#endif
        return;
    }
    std::unique_lock<std::shared_mutex> guard(g_regInfoMutex);
    ErrCode ret = RegisterWifiEvents(sysCap, type);
    if (ret != WIFI_OPT_SUCCESS) {
#ifdef ENABLE_NAPI_WIFI_MANAGER
        HandleSyncErrCode(env, ret, sysCap);
#endif
        return;
    }

    napi_ref handlerRef = nullptr;
    napi_create_reference(env, handler, 1, &handlerRef);
    RegObj regObj(env, handlerRef);
    auto iter = g_eventRegisterInfo.find(type);
    if (iter == g_eventRegisterInfo.end()) {
        if (g_eventRegisterInfo.size() > REGISTERINFO_MAX_NUM) {
            WIFI_LOGE("RegisterInfo Exceeding the maximum value!");
            return;
        }
        g_eventRegisterInfo[type] = std::vector<RegObj>{regObj};
    } else {
        iter->second.emplace_back(regObj);
    }
}

void EventRegister::DeleteRegisterObj(const napi_env& env, std::vector<RegObj>& vecRegObjs, napi_value& handler)
{
    auto iter = vecRegObjs.begin();
    for (; iter != vecRegObjs.end();) {
        if (env == iter->m_regEnv) {
            napi_value handlerTemp = nullptr;
            napi_get_reference_value(iter->m_regEnv, iter->m_regHanderRef, &handlerTemp);
            bool isEqual = false;
            napi_strict_equals(iter->m_regEnv, handlerTemp, handler, &isEqual);
            if (isEqual) {
                uint32_t refCount = INVALID_REF_COUNT;
                napi_reference_unref(iter->m_regEnv, iter->m_regHanderRef, &refCount);
                WIFI_LOGI("delete ref, m_regEnv: %{private}p, m_regHanderRef: %{private}p, refCount: %{public}d",
                    iter->m_regEnv, iter->m_regHanderRef, refCount);
                if (refCount == 0) {
                    napi_delete_reference(iter->m_regEnv, iter->m_regHanderRef);
                }
                WIFI_LOGI("Delete register object ref.");
                iter = vecRegObjs.erase(iter);
            } else {
                ++iter;
            }
        } else {
            WIFI_LOGI("Unregister event, env is not equal %{private}p, : %{private}p", env, iter->m_regEnv);
            ++iter;
        }
    }
}

void EventRegister::DeleteAllRegisterObj(const napi_env& env, std::vector<RegObj>& vecRegObjs)
{
    auto iter = vecRegObjs.begin();
    for (; iter != vecRegObjs.end();) {
        if (env == iter->m_regEnv) {
            uint32_t refCount = INVALID_REF_COUNT;
            napi_reference_unref(iter->m_regEnv, iter->m_regHanderRef, &refCount);
            WIFI_LOGI("delete all ref, m_regEnv: %{private}p, m_regHanderRef: %{private}p, refCount: %{public}d",
                iter->m_regEnv, iter->m_regHanderRef, refCount);
            if (refCount == 0) {
                napi_delete_reference(iter->m_regEnv, iter->m_regHanderRef);
            }
            iter = vecRegObjs.erase(iter);
        } else {
            WIFI_LOGI("Unregister all event, env is not equal %{private}p, : %{private}p", env, iter->m_regEnv);
            ++iter;
        }
    }
}

void EventRegister::Unregister(const napi_env& env, const std::string& type, napi_value handler)
{
    int32_t sysCap = findSysCap(type);
    WIFI_LOGI("Unregister event: %{public}s, env: %{private}p, sysCap:%{public}d",
        type.c_str(), env, (int)sysCap);
    if (!IsEventSupport(type)) {
        WIFI_LOGE("Unregister type error or not support!");
#ifdef ENABLE_NAPI_WIFI_MANAGER
        HandleSyncErrCode(env, WIFI_OPT_NOT_SUPPORTED, sysCap);
#endif
        return;
    }
    std::unique_lock<std::shared_mutex> guard(g_regInfoMutex);
    auto iter = g_eventRegisterInfo.find(type);
    if (iter == g_eventRegisterInfo.end()) {
        WIFI_LOGE("Unregister type not registered!");
#ifdef ENABLE_NAPI_WIFI_MANAGER
        HandleSyncErrCode(env, WIFI_OPT_INVALID_CONFIG, sysCap);
#endif
        return;
    }
    if (handler != nullptr) {
        DeleteRegisterObj(env, iter->second, handler);
    } else {
        WIFI_LOGW("Unregister all relevant subscribe for: %{public}s", type.c_str());
        DeleteAllRegisterObj(env, iter->second);
    }
    if (iter->second.empty()) {
        g_eventRegisterInfo.erase(iter);
    }
}

void EventRegister::CleanUp(void *data)
{
    std::unique_lock<std::shared_mutex> guard(g_regInfoMutex);
    auto env = *(reinterpret_cast<napi_env*>(data));
    for (auto &event : g_eventRegisterInfo) {
        auto &vecRegObjs = event.second;
        auto iter = vecRegObjs.begin();
        for (; iter != vecRegObjs.end();) {
            if (env == iter->m_regEnv) {
                napi_delete_reference(iter->m_regEnv, iter->m_regHanderRef);
                iter = vecRegObjs.erase(iter);
            } else {
                ++iter;
            }
        }
    }
    delete reinterpret_cast<napi_env*>(data);
    data = nullptr;
}
}  // namespace Wifi
}  // namespace OHOS
