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

#include "wifi_js.h"
#include "securec.h"
#include "wifi_logger.h"
#include "wifi_device.h"
#include "wifi_scan.h"
#include <vector>

using namespace OHOS;
using namespace OHOS::Wifi;

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiJsLog");

std::unique_ptr<WifiDevice> wifiDevicePtr = WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);
std::unique_ptr<WifiScan> wifiScanPtr = WifiScan::GetInstance(WIFI_SCAN_ABILITY_ID);

static napi_value EnableWifi(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1];
    napi_value thisVar;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    NAPI_ASSERT(env, wifiDevicePtr != nullptr, "[NAPI] Wifi device instance is null.");
    ErrCode ret = wifiDevicePtr->EnableWifi();
    napi_value result;
    napi_get_boolean(env, ret == WIFI_OPT_SUCCESS, &result);
    return result;
}

static napi_value DisableWifi(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1];
    napi_value thisVar;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    NAPI_ASSERT(env, wifiDevicePtr != nullptr, "[NAPI] Wifi device instance is null.");
    ErrCode ret = wifiDevicePtr->DisableWifi();
    napi_value result;
    napi_get_boolean(env, ret == WIFI_OPT_SUCCESS, &result);
    return result;
}

static napi_value IsWifiActive(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1];
    napi_value thisVar;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    NAPI_ASSERT(env, wifiDevicePtr != nullptr, "[NAPI] Wifi device instance is null.");
    bool activeStatus = true;
    ErrCode ret = wifiDevicePtr->IsWifiActive(activeStatus);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("[Wifi Js] Get wifi active status fail: %{public}d", ret);
    }

    napi_value result;
    napi_get_boolean(env, activeStatus, &result);
    return result;
}

static napi_value JsObjectToString(const napi_env& env, const napi_value& object,
    const char* fieldStr, const int bufLen, std::string& fieldRef)
{
    bool hasProperty = false;
    NAPI_CALL(env, napi_has_named_property(env, object, fieldStr, &hasProperty));
    if (hasProperty) {
        napi_value field;
        napi_valuetype valueType;

        napi_get_named_property(env, object, fieldStr, &field);
        NAPI_CALL(env, napi_typeof(env, field, &valueType));
        NAPI_ASSERT(env, valueType == napi_string, "Wrong argument type. String expected.");
        if (bufLen <= 0) {
            goto error;
        }
        char *buf = (char *)malloc(bufLen);
        if (buf == nullptr) {
            WIFI_LOGE("[Wifi Js] js object to str malloc failed");
            goto error;
        }
        (void)memset_s(buf, bufLen, 0, bufLen);
        size_t result = 0;
        NAPI_CALL(env, napi_get_value_string_utf8(env, field, buf, bufLen, &result));
        fieldRef = buf;
        free(buf);
        buf = nullptr;
    } else {
        WIFI_LOGW("[Wifi Js] wifi napi js to str no property: %{public}s", fieldStr);
    }

error:
    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

static napi_value JsObjectToInt(const napi_env& env, const napi_value& object, const char* fieldStr, int& fieldRef)
{
    bool hasProperty = false;
    NAPI_CALL(env, napi_has_named_property(env, object, fieldStr, &hasProperty));
    if (hasProperty) {
        napi_value field;
        napi_valuetype valueType;

        napi_get_named_property(env, object, fieldStr, &field);
        NAPI_CALL(env, napi_typeof(env, field, &valueType));
        NAPI_ASSERT(env, valueType == napi_number, "Wrong argument type. Number expected.");
        napi_get_value_int32(env, field, &fieldRef);
    } else {
        WIFI_LOGW("[Wifi Js] wifi napi js to int no property: %{public}s", fieldStr);
    }

    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

static napi_value JsObjectToBool(const napi_env& env, const napi_value& object, const char* fieldStr, bool& fieldRef)
{
    bool hasProperty = false;
    NAPI_CALL(env, napi_has_named_property(env, object, fieldStr, &hasProperty));
    if (hasProperty) {
        napi_value field;
        napi_valuetype valueType;

        napi_get_named_property(env, object, fieldStr, &field);
        NAPI_CALL(env, napi_typeof(env, field, &valueType));
        NAPI_ASSERT(env, valueType == napi_boolean, "Wrong argument type. Bool expected.");
        napi_get_value_bool(env, field, &fieldRef);
    } else {
        WIFI_LOGW("[Wifi Js] wifi napi js to bool no property: %{public}s", fieldStr);
    }

    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

static napi_value Scan(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1];
    napi_value thisVar;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    NAPI_ASSERT(env, wifiScanPtr != nullptr, "[NAPI] Wifi scan instance is null.");
    ErrCode ret = wifiScanPtr->Scan();

    napi_value result;
    napi_get_boolean(env, ret == WIFI_OPT_SUCCESS, &result);
    return result;
}

static void SetValueUtf8String(const napi_env& env, const char* fieldStr, const char* str, napi_value& result)
{
    napi_value value;
    napi_create_string_utf8(env, str, NAPI_AUTO_LENGTH, &value);
    napi_set_named_property(env, result, fieldStr, value);
}

static void SetValueInt32(const napi_env& env, const char* fieldStr, const int intValue, napi_value& result)
{
    napi_value value;
    napi_create_int32(env, intValue, &value);
    napi_set_named_property(env, result, fieldStr, value);
}

static void SetValueInt64(const napi_env& env, const char* fieldStr, const int64_t intValue, napi_value& result)
{
    napi_value value;
    napi_create_int64(env, intValue, &value);
    napi_set_named_property(env, result, fieldStr, value);
}

static void ScanInfoToJsArray(const napi_env& env, const std::vector<JsWifiScanInfo>& vecScnIanfo,
    const int idx, napi_value& arrayResult)
{
    napi_value result;
    napi_create_object(env, &result);

    SetValueUtf8String(env, "ssid", vecScnIanfo[idx].ssid.c_str(), result);
    SetValueUtf8String(env, "bssid", vecScnIanfo[idx].bssid.c_str(), result);
    SetValueInt32(env, "securityType", vecScnIanfo[idx].securityType, result);
    SetValueInt32(env, "rssi", vecScnIanfo[idx].rssi, result);
    SetValueInt32(env, "band", vecScnIanfo[idx].band, result);
    SetValueInt32(env, "frequency", vecScnIanfo[idx].frequency, result);
    SetValueInt64(env, "timestamp", vecScnIanfo[idx].timestamp, result);

    napi_status status = napi_set_element(env, arrayResult, idx, result);
    if (status != napi_ok) {
        WIFI_LOGE("[Wifi Js] wifi napi set element error: %{public}d", status);
    }
}

static void NativeCppScanInfoToJsScanInfo(const std::vector<WifiScanInfo>& vecCppScanInfos,
    std::vector<JsWifiScanInfo>& vecJsScnIanfo)
{
    for (auto& e : vecCppScanInfos) {
        JsWifiScanInfo jsScanInfo;

        jsScanInfo.ssid = e.ssid;
        jsScanInfo.bssid = e.bssid;
        jsScanInfo.frequency = e.frequency;
        jsScanInfo.timestamp = e.timestamp;
        vecJsScnIanfo.push_back(jsScanInfo);
    }
}

static bool GetWifiScanInfoList(const napi_env env, napi_value& result)
{
    std::vector<WifiScanInfo> vecCppScanInfos;
    if (wifiScanPtr->GetScanInfoList(vecCppScanInfos) != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("[Wifi Js] Get Scaninf list error");
        return false;
    }

    WIFI_LOGI("[Wifi Js] GetScanInfoList, size: %{public}d", vecCppScanInfos.size());
    std::vector<JsWifiScanInfo> vecJsScnIanfo;
    NativeCppScanInfoToJsScanInfo(vecCppScanInfos, vecJsScnIanfo);
    if (vecJsScnIanfo.size() > 0) {
        for (size_t i = 0; i != vecJsScnIanfo.size(); ++i) {
            ScanInfoToJsArray(env, vecJsScnIanfo, i, result);
        }
    } else {
        WIFI_LOGW("[Wifi Js] wifi js scan info is null");
    }
    return true;
}

static napi_value ScanInfoToCallBack(const napi_env& env, AsyncCallbackInfo *asCallbackInfo,
    const size_t argc, const napi_value *argv)
{
    napi_value resourceName;
    napi_create_string_latin1(env, "getScanInfos", NAPI_AUTO_LENGTH, &resourceName);

    for (size_t i = 0; i != argc; ++i) {
        napi_valuetype valuetype;
        NAPI_CALL(env, napi_typeof(env, argv[i], &valuetype));
        NAPI_ASSERT(env, valuetype == napi_function, "Wrong argument type. Function expected.");
        napi_create_reference(env, argv[i], 1, &asCallbackInfo->callback[i]);
    }

    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void* data) {
            AsyncCallbackInfo *asCallbackInfo = (AsyncCallbackInfo *)data;
            napi_value result;
            napi_create_array(env, &result);
            asCallbackInfo->isSuccess = GetWifiScanInfoList(env, result);
            asCallbackInfo->result = result;
        },
        [](napi_env env, napi_status status, void* data) {
            AsyncCallbackInfo* asCallbackInfo = (AsyncCallbackInfo *)data;

            napi_value undefine;
            napi_get_undefined(env, &undefine);
            napi_value callback;
            if (asCallbackInfo->isSuccess) {
                napi_get_reference_value(env, asCallbackInfo->callback[0], &callback);
                napi_call_function(env, nullptr, callback, 1, &asCallbackInfo->result, &undefine);
            } else {
                if (asCallbackInfo->callback[1]) {
                    napi_get_reference_value(env, asCallbackInfo->callback[1], &callback);
                    napi_call_function(env, nullptr, callback, 1, &asCallbackInfo->result, &undefine);
                } else {
                    WIFI_LOGE("[Wifi Js] get scan info callback func is null");
                    napi_throw_error(env, "error", "get scan info callback func is null");
                }
            }

            if (asCallbackInfo->callback[0] != nullptr) {
                napi_delete_reference(env, asCallbackInfo->callback[0]);
            }
            if (asCallbackInfo->callback[1] != nullptr) {
                napi_delete_reference(env, asCallbackInfo->callback[1]);
            }
            napi_delete_async_work(env, asCallbackInfo->asyncWork);
            delete asCallbackInfo;
        },
        (void *)asCallbackInfo,
        &asCallbackInfo->asyncWork);
    NAPI_CALL(env, napi_queue_async_work(env, asCallbackInfo->asyncWork));
    return NULL;
}

static napi_value ScanInfoToPromise(const napi_env& env, AsyncCallbackInfo *asCallbackInfo, napi_value& promise)
{
    napi_value resourceName;
    napi_create_string_latin1(env, "getScanInfos", NAPI_AUTO_LENGTH, &resourceName);

    napi_deferred deferred;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    asCallbackInfo->deferred = deferred;

    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            AsyncCallbackInfo *asCallbackInfo = (AsyncCallbackInfo *)data;
            napi_value result;
            napi_create_array(env, &result);
            asCallbackInfo->isSuccess = GetWifiScanInfoList(env, result);
            asCallbackInfo->result = result;
        },
        [](napi_env env, napi_status status, void *data) {
            AsyncCallbackInfo *asCallbackInfo = (AsyncCallbackInfo *)data;
            if (asCallbackInfo->isSuccess) {
                napi_resolve_deferred(asCallbackInfo->env, asCallbackInfo->deferred, asCallbackInfo->result);
            } else {
                napi_reject_deferred(asCallbackInfo->env, asCallbackInfo->deferred, asCallbackInfo->result);
            }
            napi_delete_async_work(env, asCallbackInfo->asyncWork);
            delete asCallbackInfo;
        },
        (void *)asCallbackInfo,
        &asCallbackInfo->asyncWork);
    napi_queue_async_work(env, asCallbackInfo->asyncWork);
    return NULL;
}

static napi_value GetScanInfos(napi_env env, napi_callback_info info)
{
    size_t argc = 2;
    napi_value argv[argc];
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data));

    AsyncCallbackInfo *asCallbackInfo =
        new AsyncCallbackInfo{.env = env, .asyncWork = nullptr, .deferred = nullptr};

    if (argc >= 1) {
        return ScanInfoToCallBack(env, asCallbackInfo, argc, argv);
    } else {
        napi_value promise;
        ScanInfoToPromise(env, asCallbackInfo, promise);
        return promise;
    }
}

static void JsToDeviceConfig(const napi_env& env, const napi_value& object, JsWifiDeviceConfig& config)
{
    JsObjectToString(env, object, "ssid", 33, config.ssid); /* ssid max length is 32 + '\0' */
    JsObjectToString(env, object, "bssid", 12, config.bssid);
    JsObjectToString(env, object, "preSharedKey", 256, config.preSharedKey);
    JsObjectToBool(env, object, "isHiddenSsid", config.isHiddenSsid);
    JsObjectToInt(env, object, "securityType", config.securityType);
}

static void ConvertEncryptionMode(const int securityType, std::string& keyMgmt)
{
    switch (securityType) {
        case WIFI_SEC_TYPE_OPEN:
            keyMgmt = "NONE";
            break;

        case WIFI_SEC_TYPE_WEP:
            keyMgmt = "WEP";
            break;

        case WIFI_SEC_TYPE_PSK:
            keyMgmt = "WPA-PSK";
            break;

        case WIFI_SEC_TYPE_SAE:
            keyMgmt = "SAE";
            break;

        default:
            keyMgmt = "WPA-PSK";
            break;
    }
}

static void WifiConfigJsToNativeCpp(const JsWifiDeviceConfig& jsconfig, WifiDeviceConfig& cppConfig)
{
    cppConfig.ssid = jsconfig.ssid;
    cppConfig.bssid = jsconfig.bssid;
    cppConfig.preSharedKey = jsconfig.preSharedKey;
    cppConfig.hiddenSSID = jsconfig.isHiddenSsid;
    ConvertEncryptionMode(jsconfig.securityType, cppConfig.keyMgmt);
}

static napi_value AddDeviceConfigImpl(const napi_env& env, AsyncCallbackInfo *asCallbackInfo)
{
    NAPI_ASSERT(env, wifiDevicePtr != nullptr, "[NAPI] Wifi device instance is null.");
    int addResult = -1;
    int retValue = 0;
    WifiDeviceConfig cppConfig;
    WifiConfigJsToNativeCpp(*(JsWifiDeviceConfig *)asCallbackInfo->obj, cppConfig);
    ErrCode ret = wifiDevicePtr->AddDeviceConfig(cppConfig, addResult);
    if (addResult < 0 || ret != WIFI_OPT_SUCCESS) {
        retValue = -1;
    } else {
        retValue = addResult;
    }

    napi_value result;
    napi_create_int32(env, retValue, &result);
    asCallbackInfo->isSuccess = (ret == WIFI_OPT_SUCCESS);
    asCallbackInfo->result = result;
    return nullptr;
}

static napi_value AddDeviceConfigCallBack(const napi_env& env, AsyncCallbackInfo *asCallbackInfo,
    size_t argc, napi_value *argv)
{
    napi_value resourceName;
    napi_create_string_latin1(env, "addDeviceConfig", NAPI_AUTO_LENGTH, &resourceName);

    for (size_t i = 1; i != argc; ++i) {
        napi_valuetype valuetype;
        NAPI_CALL(env, napi_typeof(env, argv[i], &valuetype));
        NAPI_ASSERT(env, valuetype == napi_function, "Wrong argument type. Function expected.");
        napi_create_reference(env, argv[i], 1, &asCallbackInfo->callback[i - 1]);
    }

    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void* data) {
            AsyncCallbackInfo *asCallbackInfo = (AsyncCallbackInfo *)data;
            AddDeviceConfigImpl(env, asCallbackInfo);
        },
        [](napi_env env, napi_status status, void* data) {
            AsyncCallbackInfo* asCallbackInfo = (AsyncCallbackInfo *)data;

            napi_value undefine;
            napi_get_undefined(env, &undefine);
            napi_value callback;
            if (asCallbackInfo->isSuccess) {
                napi_get_reference_value(env, asCallbackInfo->callback[0], &callback);
                napi_call_function(env, nullptr, callback, 1, &asCallbackInfo->result, &undefine);
            } else {
                if (asCallbackInfo->callback[1]) {
                    napi_get_reference_value(env, asCallbackInfo->callback[1], &callback);
                    napi_call_function(env, nullptr, callback, 1, &asCallbackInfo->result, &undefine);
                } else {
                    WIFI_LOGE("[Wifi Js] get scan info callback func is null");
                    napi_throw_error(env, "error", "add wifi config callback func is null");
                }
            }

            if (asCallbackInfo->callback[0] != nullptr) {
                napi_delete_reference(env, asCallbackInfo->callback[0]);
            }
            if (asCallbackInfo->callback[1] != nullptr) {
                napi_delete_reference(env, asCallbackInfo->callback[1]);
            }
            napi_delete_async_work(env, asCallbackInfo->asyncWork);
            delete (JsWifiDeviceConfig *)asCallbackInfo->obj;
            delete asCallbackInfo;
        },
        (void *)asCallbackInfo,
        &asCallbackInfo->asyncWork);
    NAPI_CALL(env, napi_queue_async_work(env, asCallbackInfo->asyncWork));
    return NULL;
}

static napi_value AddDeviceConfigPromise(const napi_env& env, AsyncCallbackInfo *asCallbackInfo, napi_value& promise)
{
    napi_value resourceName;
    napi_create_string_latin1(env, "addDeviceConfig", NAPI_AUTO_LENGTH, &resourceName);

    napi_deferred deferred;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    asCallbackInfo->deferred = deferred;

    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            AsyncCallbackInfo *asCallbackInfo = (AsyncCallbackInfo *)data;
            AddDeviceConfigImpl(env, asCallbackInfo);
        },
        [](napi_env env, napi_status status, void *data) {
            AsyncCallbackInfo *asCallbackInfo = (AsyncCallbackInfo *)data;
            if (asCallbackInfo->isSuccess) {
                napi_resolve_deferred(asCallbackInfo->env, asCallbackInfo->deferred, asCallbackInfo->result);
            } else {
                napi_reject_deferred(asCallbackInfo->env, asCallbackInfo->deferred, asCallbackInfo->result);
            }
            napi_delete_async_work(env, asCallbackInfo->asyncWork);
            delete (JsWifiDeviceConfig *)asCallbackInfo->obj;
            delete asCallbackInfo;
        },
        (void *)asCallbackInfo,
        &asCallbackInfo->asyncWork);
    napi_queue_async_work(env, asCallbackInfo->asyncWork);
    return NULL;
}

static napi_value AddDeviceConfig(napi_env env, napi_callback_info info)
{
    size_t argc = 3;
    napi_value argv[argc];
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data));
    NAPI_ASSERT(env, argc >= 1, "Wrong number of arguments");

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_object, "Wrong argument type. Object expected for parameter 1.");

    AsyncCallbackInfo *asCallbackInfo =
        new AsyncCallbackInfo{.env = env, .asyncWork = nullptr, .deferred = nullptr};

    JsWifiDeviceConfig config;
    JsToDeviceConfig(env, argv[0], config);
    asCallbackInfo->obj = new JsWifiDeviceConfig(config);

    if (argc > 1) {
        return AddDeviceConfigCallBack(env, asCallbackInfo, argc, argv);
    } else {
        napi_value promise;
        AddDeviceConfigPromise(env, asCallbackInfo, promise);
        return promise;
    }
}

static napi_value ConnectToNetwork(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1];
    napi_value thisVar;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    NAPI_ASSERT(env, argc == 1, "Wrong number of arguments");

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_number, "Wrong argument type. napi_number expected.");

    int networkId = -1;
    napi_get_value_int32(env, argv[0], &networkId);

    NAPI_ASSERT(env, wifiDevicePtr != nullptr, "[NAPI] Wifi device instance is null.");
    ErrCode ret = wifiDevicePtr->ConnectTo(networkId);
    napi_value result;
    napi_get_boolean(env, ret == WIFI_OPT_SUCCESS, &result);
    return result;
}

static napi_value ConnectToDevice(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1];
    napi_value thisVar;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    NAPI_ASSERT(env, valueType == napi_object, "Wrong argument type. Object expected.");

    NAPI_ASSERT(env, wifiDevicePtr != nullptr, "[NAPI] Wifi device instance is null.");
    JsWifiDeviceConfig jsConfig;
    JsToDeviceConfig(env, argv[0], jsConfig);
    WifiDeviceConfig cppConfig;
    WifiConfigJsToNativeCpp(jsConfig, cppConfig);
    ErrCode ret = wifiDevicePtr->ConnectTo(cppConfig);

    napi_value result;
    napi_get_boolean(env, ret == WIFI_OPT_SUCCESS, &result);
    return result;
}

static napi_value DisConnect(napi_env env, napi_callback_info info)
{
    size_t argc = 1;
    napi_value argv[1];
    napi_value thisVar;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    NAPI_ASSERT(env, wifiDevicePtr != nullptr, "[NAPI] Wifi device instance is null.");
    ErrCode ret = wifiDevicePtr->Disconnect();
    napi_value result;
    napi_get_boolean(env, ret == WIFI_OPT_SUCCESS, &result);
    return result;
}

static napi_value GetSignalLevel(napi_env env, napi_callback_info info)
{
    size_t argc = 2;
    napi_value argv[2];
    napi_value thisVar;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    NAPI_ASSERT(env, argc == 2, "Wrong number of arguments");

    napi_valuetype type1;
    napi_valuetype type2;
    napi_typeof(env, argv[0], &type1);
    napi_typeof(env, argv[1], &type2);
    NAPI_ASSERT(env, type1 == napi_number, "Wrong argument type. napi_number expected.");
    NAPI_ASSERT(env, type2 == napi_number, "Wrong argument type. napi_number expected.");

    int rssi, band;
    napi_get_value_int32(env, argv[0], &rssi);
    napi_get_value_int32(env, argv[1], &band);

    NAPI_ASSERT(env, wifiDevicePtr != nullptr, "[NAPI] Wifi device instance is null.");
    int level = -1;
    ErrCode ret = wifiDevicePtr->GetSignalLevel(rssi, band, level);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGW("[Wifi Js] Get wifi signal level fail: %{public}d", ret);
    }

    napi_value result;
    napi_create_uint32(env, level, &result);
    return result;
}

EXTERN_C_START
/*
 * Module initialization function
 */
static napi_value Init(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("enableWifi", EnableWifi),
        DECLARE_NAPI_FUNCTION("disableWifi", DisableWifi),
        DECLARE_NAPI_FUNCTION("isWifiActive", IsWifiActive),
        DECLARE_NAPI_FUNCTION("scan", Scan),
        DECLARE_NAPI_FUNCTION("getScanInfos", GetScanInfos),
        DECLARE_NAPI_FUNCTION("addDeviceConfig", AddDeviceConfig),
        DECLARE_NAPI_FUNCTION("connectToNetwork", ConnectToNetwork),
        DECLARE_NAPI_FUNCTION("connectToDevice", ConnectToDevice),
        DECLARE_NAPI_FUNCTION("disConnect", DisConnect),
        DECLARE_NAPI_FUNCTION("getSignalLevel", GetSignalLevel)
    };

    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(napi_property_descriptor), desc));
    return exports;
}
EXTERN_C_END

static napi_module wifiJsModule = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = NULL,
    .nm_register_func = Init,
    .nm_modname = "wifi_native_js",
    .nm_priv = ((void *)0),
    .reserved = { 0 }
};

extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&wifiJsModule);
}
}  // namespace Wifi
}  // namespace OHOS
