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

#include "wifi_napi_hotspot.h"
#include "wifi_hotspot.h"
#include "wifi_logger.h"
#include <vector>
#include <map>
#include "wifi_napi_errcode.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiNAPIHotspot");

std::shared_ptr<WifiHotspot> wifiHotspotPtr = WifiHotspot::GetInstance(WIFI_HOTSPOT_ABILITY_ID);

std::map<SecTypeJs, KeyMgmt> g_mapSecTypeToKeyMgmt = {
    {SecTypeJs::SEC_TYPE_OPEN, KeyMgmt::NONE},
    {SecTypeJs::SEC_TYPE_PSK, KeyMgmt::WPA2_PSK},
};

NO_SANITIZE("cfi") napi_value EnableHotspot(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiHotspotPtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_AP_CORE);
    ErrCode ret = wifiHotspotPtr->EnableHotspot();
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Enable hotspot error: %{public}d", ret);
    }
    WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_AP_CORE);
}

NO_SANITIZE("cfi") napi_value DisableHotspot(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiHotspotPtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_AP_CORE);
    ErrCode ret = wifiHotspotPtr->DisableHotspot();
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Disable hotspot error: %{public}d", ret);
    }
    WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_AP_CORE);
}

NO_SANITIZE("cfi") napi_value IsHotspotActive(napi_env env, napi_callback_info info)
{
    WIFI_NAPI_ASSERT(env, wifiHotspotPtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_AP_CORE);
    bool isActive = false;
    ErrCode ret = wifiHotspotPtr->IsHotspotActive(isActive);
    WIFI_NAPI_ASSERT(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_AP_CORE);
    napi_value result;
    napi_get_boolean(env, isActive, &result);
    return result;
}

NO_SANITIZE("cfi") napi_value IsHotspotDualBandSupported(napi_env env, napi_callback_info info)
{
    WIFI_NAPI_ASSERT(env, wifiHotspotPtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_AP_CORE);
    bool isSupported = false;
    ErrCode ret = wifiHotspotPtr->IsHotspotDualBandSupported(isSupported);
    WIFI_NAPI_ASSERT(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_AP_CORE);
    napi_value result;
    napi_get_boolean(env, isSupported, &result);
    return result;
}

static KeyMgmt GetKeyMgmtFromJsSecurityType(int secType)
{
    std::map<SecTypeJs, KeyMgmt>::iterator iter = g_mapSecTypeToKeyMgmt.find(SecTypeJs(secType));
    return iter == g_mapSecTypeToKeyMgmt.end() ? KeyMgmt::NONE : iter->second;
}

static int GetJsSecurityTypeFromKeyMgmt(KeyMgmt keyMgmt)
{
    for (auto& each : g_mapSecTypeToKeyMgmt) {
        if (each.second == keyMgmt) {
            return static_cast<int>(each.first);
        }
    }
    return static_cast<int>(SecTypeJs::SEC_TYPE_OPEN);
}

static bool IsSecTypeSupported(int secType)
{
    return g_mapSecTypeToKeyMgmt.find(SecTypeJs(secType)) != g_mapSecTypeToKeyMgmt.end();
}

static void ClearJsLastException(const napi_env& env)
{
    bool isPendingException = false;
    napi_is_exception_pending(env, &isPendingException);
    if (isPendingException) {
        napi_value lastException = nullptr;
        napi_get_and_clear_last_exception(env, &lastException);
    }
}

static bool GetHotspotconfigFromJs(const napi_env& env, const napi_value& object, HotspotConfig& config)
{
    std::string str = "";
    int value = 0;
    JsObjectToString(env, object, "ssid", NAPI_MAX_STR_LENT, str); // 33: ssid max length is 32 + '\0'
    config.SetSsid(str);
    str = "";
    JsObjectToInt(env, object, "securityType", value);
    ClearJsLastException(env);
    if (!IsSecTypeSupported(value)) {
        WIFI_LOGE("securityType is not supported: %{public}d", value);
        return false;
    }
    config.SetSecurityType(GetKeyMgmtFromJsSecurityType(value));
    value = 0;
    JsObjectToInt(env, object, "band", value);
    ClearJsLastException(env);
    config.SetBand(BandType(value)); // 1: 2.4G, 2: 5G
    if (config.GetBand() == BandType::BAND_5GHZ) {
        config.SetChannel(AP_CHANNEL_5G_DEFAULT);
    }
    value = 0;
    if (!JsObjectToString(env, object, "preSharedKey", NAPI_MAX_STR_LENT, str)) { // 64: max length
        return false;
    }
    config.SetPreSharedKey(str);
    JsObjectToInt(env, object, "maxConn", value);
    ClearJsLastException(env);
    config.SetMaxConn(value);
    value = 0;
    JsObjectToInt(env, object, "channel", value);
    ClearJsLastException(env);
    if (value == 0) {
        value = (int)AP_CHANNEL_DEFAULT;
    }
    config.SetChannel(value);
    str = "";
    JsObjectToString(env, object, "ipAddress", NAPI_MAX_IPV4_LEN, str); // 16: ipv4 max length is 15 + '\0'
    config.SetIpAddress(str);
    
    value = 0;
    JsObjectToInt(env, object, "leaseTime", value);
    ClearJsLastException(env);
    if (value < (int)DHCP_LEASE_TIME_MIN) {
        value = (int)DHCP_LEASE_TIME;
    }
    config.SetLeaseTime(value);
    return true;
}

NO_SANITIZE("cfi") napi_value SetHotspotIdleTimeout(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    size_t argc = 1;
    napi_value argv[1];
    napi_value thisVar;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    NAPI_ASSERT(env, argc == 1, "Wrong number of arguments");

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "Wrong argument type. Object expected.");
    NAPI_ASSERT(env, wifiHotspotPtr != nullptr, "Wifi hotspot instance is null.");

    int time = 0;
    napi_get_value_int32(env, argv[0], &time);
    ErrCode ret = wifiHotspotPtr->SetHotspotIdleTimeout(time);
    napi_value result;
    napi_get_boolean(env, ret == WIFI_OPT_SUCCESS, &result);
    return result;
}

NO_SANITIZE("cfi") napi_value SetHotspotConfig(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    size_t argc = 1;
    napi_value argv[1];
    napi_value thisVar;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    WIFI_NAPI_ASSERT(env, valueType == napi_object, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_AP_CORE);
    WIFI_NAPI_ASSERT(env, wifiHotspotPtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_AP_CORE);

    ErrCode ret = WIFI_OPT_FAILED;
    HotspotConfig config;
    if (GetHotspotconfigFromJs(env, argv[0], config)) {
        ClearJsLastException(env);
        ret = wifiHotspotPtr->SetHotspotConfig(config);
        if (ret != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("Set hotspot config error: %{public}d", ret);
        }
    }
    WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_AP_CORE);
}

static void HotspotconfigToJs(const napi_env& env, HotspotConfig& cppConfig, napi_value& result)
{
    SetValueUtf8String(env, "ssid", cppConfig.GetSsid().c_str(), result);
    SetValueInt32(env, "securityType", GetJsSecurityTypeFromKeyMgmt(cppConfig.GetSecurityType()), result);
    SetValueInt32(env, "band", static_cast<int>(cppConfig.GetBand()), result);
    SetValueUtf8String(env, "preSharedKey", cppConfig.GetPreSharedKey().c_str(), result);
    SetValueInt32(env, "maxConn", cppConfig.GetMaxConn(), result);
    SetValueInt32(env, "channel", cppConfig.GetChannel(), result);
    SetValueUtf8String(env, "ipAddress", cppConfig.GetIpAddress(), result);
    SetValueInt32(env, "leaseTime", cppConfig.GetLeaseTime(), result);
}

NO_SANITIZE("cfi") napi_value GetHotspotConfig(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiHotspotPtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_AP_CORE);
    HotspotConfig config;
    ErrCode ret = wifiHotspotPtr->GetHotspotConfig(config);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Get hotspot config error: %{public}d", ret);
    }
    WIFI_NAPI_ASSERT(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_AP_CORE);
    napi_value result;
    napi_create_object(env, &result);
    HotspotconfigToJs(env, config, result);
    return result;
}

static void StationInfoToJsArray(const napi_env& env, const std::vector<StationInfo>& StationInfo,
    const int idx, napi_value& arrayResult)
{
    napi_value result;
    napi_create_object(env, &result);

    SetValueUtf8String(env, "name", StationInfo[idx].deviceName.c_str(), result);
    SetValueUtf8String(env, "macAddress", StationInfo[idx].bssid.c_str(), result);
    SetValueInt32(env, "macAddressType", StationInfo[idx].bssidType, result);
    SetValueUtf8String(env, "ipAddress", StationInfo[idx].ipAddr.c_str(), result);
    napi_status status = napi_set_element(env, arrayResult, idx, result);
    if (status != napi_ok) {
        WIFI_LOGE("Set station element error: %{public}d", status);
    }
}

NO_SANITIZE("cfi") napi_value GetStations(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiHotspotPtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_AP_CORE);
    std::vector<StationInfo> vecStationInfo;
    ErrCode ret = wifiHotspotPtr->GetStationList(vecStationInfo);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Get station list error: %{public}d", ret);
    }
    WIFI_LOGI("Get station list size: %{public}zu", vecStationInfo.size());
    WIFI_NAPI_ASSERT(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_AP_CORE);

    napi_value arrayResult;
    napi_create_array_with_length(env, vecStationInfo.size(), &arrayResult);
    for (size_t i = 0; i != vecStationInfo.size(); ++i) {
        StationInfoToJsArray(env, vecStationInfo, i, arrayResult);
    }
    return arrayResult;
}

static void JsObjToStationInfo(const napi_env& env, const napi_value& object, StationInfo& stationInfo)
{
    JsObjectToString(env, object, "name", WIFI_SSID_MAX_LEN + 1, stationInfo.deviceName);
    JsObjectToString(env, object, "macAddress", WIFI_BSSID_LENGTH, stationInfo.bssid);
    JsObjectToString(env, object, "ipAddress", WIFI_IP_MAX_LEN + 1, stationInfo.ipAddr);
    JsObjectToInt(env, object, "macAddressType", stationInfo.bssidType);
}

NO_SANITIZE("cfi") napi_value AddHotspotBlockedList(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    size_t argc = 1;
    napi_value argv[argc];
    napi_value thisVar;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    WIFI_NAPI_ASSERT(env, valueType == napi_object, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_AP_CORE);
    WIFI_NAPI_ASSERT(env, wifiHotspotPtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_AP_CORE);

    StationInfo stationInfo;
    JsObjToStationInfo(env, argv[0], stationInfo);
    ErrCode ret = wifiHotspotPtr->AddBlockList(stationInfo);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Add block list fail: %{public}d", ret);
    }
    WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_AP_CORE);
}

NO_SANITIZE("cfi") napi_value DelHotspotBlockedList(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    size_t argc = 1;
    napi_value argv[argc];
    napi_value thisVar;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    WIFI_NAPI_ASSERT(env, valueType == napi_object, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_AP_CORE);
    WIFI_NAPI_ASSERT(env, wifiHotspotPtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_AP_CORE);

    StationInfo stationInfo;
    JsObjToStationInfo(env, argv[0], stationInfo);
    ErrCode ret = wifiHotspotPtr->DelBlockList(stationInfo);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Del block list fail: %{public}d", ret);
    }
    WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_AP_CORE);
}

NO_SANITIZE("cfi") napi_value GetHotspotBlockedList(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiHotspotPtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_AP_CORE);
    std::vector<StationInfo> vecStationInfo;
    ErrCode ret = wifiHotspotPtr->GetBlockLists(vecStationInfo);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Get block list error: %{public}d", ret);
    }
    WIFI_LOGI("Get block list size: %{public}zu", vecStationInfo.size());
    WIFI_NAPI_ASSERT(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_AP_CORE);

    napi_value arrayResult;
    napi_create_array_with_length(env, vecStationInfo.size(), &arrayResult);
    for (size_t i = 0; i != vecStationInfo.size(); ++i) {
        StationInfoToJsArray(env, vecStationInfo, i, arrayResult);
    }
    return arrayResult;
}
}  // namespace Wifi
}  // namespace OHOS
