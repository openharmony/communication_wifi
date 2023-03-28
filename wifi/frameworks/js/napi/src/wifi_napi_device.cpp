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

#include "wifi_napi_device.h"
#include <vector>
#include <functional>
#include "wifi_common_util.h"
#include "wifi_logger.h"
#include "wifi_napi_errcode.h"

namespace OHOS {
namespace Wifi {
DEFINE_WIFILOG_LABEL("WifiNAPIDevice");
static constexpr int DEFAULT_INVALID_VALUE = -1;

std::unique_ptr<WifiDevice> wifiDevicePtr = WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);
std::unique_ptr<WifiScan> wifiScanPtr = WifiScan::GetInstance(WIFI_SCAN_ABILITY_ID);

napi_value EnableWifi(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
    ErrCode ret = wifiDevicePtr->EnableWifi();
    WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
}

napi_value DisableWifi(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
    ErrCode ret = wifiDevicePtr->DisableWifi();
    WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
}

napi_value IsWifiActive(napi_env env, napi_callback_info info)
{
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
    bool activeStatus = false;
    ErrCode ret = wifiDevicePtr->IsWifiActive(activeStatus);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Get wifi active status fail: %{public}d", ret);
        WIFI_NAPI_ASSERT(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
    }
    napi_value result;
    napi_get_boolean(env, activeStatus, &result);
    return result;
}

napi_value Scan(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
    ErrCode ret = wifiScanPtr->Scan();
    WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
}

static SecTypeJs SecurityTypeNativeToJs(const WifiSecurity& cppSecurityType)
{
    SecTypeJs jsSecurityType = SecTypeJs::SEC_TYPE_INVALID;
    switch (cppSecurityType) {
        case WifiSecurity::OPEN:
            jsSecurityType = SecTypeJs::SEC_TYPE_OPEN;
            break;
        case WifiSecurity::WEP:
            jsSecurityType = SecTypeJs::SEC_TYPE_WEP;
            break;
        case WifiSecurity::PSK:
            jsSecurityType = SecTypeJs::SEC_TYPE_PSK;
            break;
        case WifiSecurity::SAE:
            jsSecurityType = SecTypeJs::SEC_TYPE_SAE;
            break;
        case WifiSecurity::EAP:
            jsSecurityType = SecTypeJs::SEC_TYPE_EAP;
            break;
        default:
            jsSecurityType = SecTypeJs::SEC_TYPE_INVALID;
            break;
    }
    return jsSecurityType;
}

static ErrCode NativeInfoElemsToJsObj(const napi_env& env,
    const std::vector<WifiInfoElem>& infoElems, napi_value& eachObj)
{
    napi_value arr;
    napi_create_array(env, &arr);
    uint8_t idx_ie = 0;
    napi_status status;
    int valueStep = 2;
    for (size_t i = 0; i < infoElems.size(); i++) {
        napi_value ieObj;
        napi_create_object(env, &ieObj);
        SetValueInt32(env, "eid", infoElems[i].id, ieObj);
        const char *uStr = &infoElems[i].content[0];
        size_t len = infoElems[i].content.size();
        size_t inLen = (infoElems[i].content.size()) * valueStep + 1;
        char *buf = (char *)calloc(inLen + 1, sizeof(char));
        if (buf == NULL) {
            return WIFI_OPT_FAILED;
        }
        int pos = 0;
        for (size_t k = 0; k < len; ++k) {
            pos = (k << 1);
            if (snprintf_s(buf + pos, inLen - pos, inLen - pos - 1, "%02x", uStr[k]) < 0) {
                free(buf);
                buf = NULL;
                return WIFI_OPT_FAILED;
            }
        }
        SetValueUtf8String(env, "content", (const char *)buf, ieObj, inLen - 1);
        status = napi_set_element(env, arr, idx_ie++, ieObj);
        if (status != napi_ok) {
            WIFI_LOGE("set content error");
            free(buf);
            buf = NULL;
            return WIFI_OPT_FAILED;
        }
        free(buf);
        buf = NULL;
    }
    status = napi_set_named_property(env, eachObj, "infoElems", arr);
    if (status != napi_ok) {
        WIFI_LOGE("set infoElems error");
        return WIFI_OPT_FAILED;
    }
    return WIFI_OPT_SUCCESS;
}

static ErrCode NativeScanInfosToJsObj(const napi_env& env,
    const std::vector<WifiScanInfo>& vecScnIanfos, napi_value& arrayResult)
{
    uint32_t idx = 0;
    for (auto& each : vecScnIanfos) {
        napi_value eachObj;
        napi_create_object(env, &eachObj);
        SetValueUtf8String(env, "ssid", each.ssid.c_str(), eachObj);
        SetValueUtf8String(env, "bssid", each.bssid.c_str(), eachObj);
        SetValueUtf8String(env, "capabilities", each.capabilities.c_str(), eachObj);
        SetValueInt32(env, "securityType", static_cast<int>(SecurityTypeNativeToJs(each.securityType)), eachObj);
        SetValueInt32(env, "rssi", each.rssi, eachObj);
        SetValueInt32(env, "band", each.band, eachObj);
        SetValueInt32(env, "frequency", each.frequency, eachObj);
        SetValueInt32(env, "channelWidth", static_cast<int>(each.channelWidth), eachObj);
        SetValueInt32(env, "centerFrequency0", each.centerFrequency0, eachObj);
        SetValueInt32(env, "centerFrequency1", each.centerFrequency1, eachObj);
        NativeInfoElemsToJsObj(env, each.infoElems, eachObj);
        SetValueInt64(env, "timestamp", each.timestamp, eachObj);
        napi_status status = napi_set_element(env, arrayResult, idx++, eachObj);
        if (status != napi_ok) {
            WIFI_LOGE("Wifi napi set element error: %{public}d, idx: %{public}d", status, idx - 1);
            return WIFI_OPT_FAILED;
        }
    }
    return WIFI_OPT_SUCCESS;
}

napi_value GetScanInfos(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    size_t argc = 2;
    napi_value argv[argc];
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data));
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);

    ScanInfoAsyncContext *asyncContext = new ScanInfoAsyncContext(env);
    WIFI_NAPI_ASSERT(env, asyncContext != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
    napi_create_string_latin1(env, "getScanInfos", NAPI_AUTO_LENGTH, &asyncContext->resourceName);

    asyncContext->executeFunc = [&](void* data) -> void {
        ScanInfoAsyncContext *context = static_cast<ScanInfoAsyncContext *>(data);
        TRACE_FUNC_CALL_NAME("wifiScanPtr->GetScanInfoList");
        context->errorCode = wifiScanPtr->GetScanInfoList(context->vecScanInfos);
        WIFI_LOGI("GetScanInfoList, size: %{public}zu", context->vecScanInfos.size());
    };

    asyncContext->completeFunc = [&](void* data) -> void {
        ScanInfoAsyncContext *context = static_cast<ScanInfoAsyncContext *>(data);
        napi_create_array_with_length(context->env, context->vecScanInfos.size(), &context->result);
        if (context->errorCode == WIFI_OPT_SUCCESS) {
            context->errorCode = NativeScanInfosToJsObj(context->env, context->vecScanInfos, context->result);
        }
        WIFI_LOGI("Push scan info list to client");
    };

    size_t nonCallbackArgNum = 0;
    asyncContext->sysCap = SYSCAP_WIFI_STA;
    return DoAsyncWork(env, asyncContext, argc, argv, nonCallbackArgNum);
}

napi_value GetScanResults(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
    std::vector<WifiScanInfo> scanInfos;
    ErrCode ret = wifiScanPtr->GetScanInfoList(scanInfos);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("GetScanInfoList return fail: %{public}d", ret);
    }

    WIFI_NAPI_ASSERT(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
    WIFI_LOGI("GetScanInfoList, size: %{public}zu", scanInfos.size());
    napi_value arrayResult;
    napi_create_array_with_length(env, scanInfos.size(), &arrayResult);
    ret = NativeScanInfosToJsObj(env, scanInfos, arrayResult);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("NativeScanInfosToJsObj return fail: %{public}d", ret);
    }
    return arrayResult;
}

static void ConvertEncryptionMode(const SecTypeJs& securityType, std::string& keyMgmt)
{
    switch (securityType) {
        case SecTypeJs::SEC_TYPE_OPEN:
            keyMgmt = KEY_MGMT_NONE;
            break;
        case SecTypeJs::SEC_TYPE_WEP:
            keyMgmt = KEY_MGMT_WEP;
            break;
        case SecTypeJs::SEC_TYPE_PSK:
            keyMgmt = KEY_MGMT_WPA_PSK;
            break;
        case SecTypeJs::SEC_TYPE_SAE:
            keyMgmt = KEY_MGMT_SAE;
            break;
        case SecTypeJs::SEC_TYPE_EAP:
            keyMgmt = KEY_MGMT_EAP;
            break;
        default:
            keyMgmt = KEY_MGMT_NONE;
            break;
    }
}

static void ProcessPassphrase(const SecTypeJs& securityType, WifiDeviceConfig& cppConfig)
{
    if (securityType == SecTypeJs::SEC_TYPE_WEP) {
        cppConfig.wepKeys[0] = cppConfig.preSharedKey;
        cppConfig.wepTxKeyIndex = 0;
        cppConfig.preSharedKey = "";
    }
}

static void ProcessEapPeapConfig(const napi_env& env, const napi_value& object, WifiEapConfig& eapConfig)
{
    // identity, password, phase2Method filed is necessary
    eapConfig.eap = EAP_METHOD_PEAP;
    JsObjectToString(env, object, "identity", NAPI_MAX_STR_LENT, eapConfig.identity);
    JsObjectToString(env, object, "password", NAPI_MAX_STR_LENT, eapConfig.password);

    int phase2 = static_cast<int>(Phase2Method::NONE);
    JsObjectToInt(env, object, "phase2Method", phase2);
    eapConfig.phase2Method = Phase2Method(phase2);
}

static void ProcessEapTlsConfig(const napi_env& env, const napi_value& object, WifiEapConfig& eapConfig)
{
    eapConfig.eap = EAP_METHOD_TLS;
    JsObjectToString(env, object, "identity", NAPI_MAX_STR_LENT, eapConfig.identity);
    JsObjectToString(env, object, "certPassword", NAPI_MAX_STR_LENT, eapConfig.certPassword);
    eapConfig.certEntry = JsObjectToU8Vector(env, object, "certEntry");
}

napi_value ProcessEapConfig(const napi_env& env, const napi_value& object, WifiDeviceConfig& devConfig)
{
    bool hasProperty = false;

    NAPI_CALL(env, napi_has_named_property(env, object, "eapConfig", &hasProperty));
    if (!hasProperty) {
        WIFI_LOGI("Js has no property: eapConfig.");
        return UndefinedNapiValue(env);
    }

    napi_value napiEap;
    napi_get_named_property(env, object, "eapConfig", &napiEap);
    int eapMethod = static_cast<int>(EapMethodJs::EAP_NONE);
    JsObjectToInt(env, napiEap, "eapMethod", eapMethod);
    WIFI_LOGI("ProcessEapConfig, eapMethod: %{public}d.", eapMethod);
    switch (EapMethodJs(eapMethod)) {
        case EapMethodJs::EAP_PEAP:
            ProcessEapPeapConfig(env, napiEap, devConfig.wifiEapConfig);
            break;
        case EapMethodJs::EAP_TLS:
            ProcessEapTlsConfig(env, napiEap, devConfig.wifiEapConfig);
            break;
        default:
            WIFI_LOGE("EapMethod: %{public}d unsupported", eapMethod);
            return UndefinedNapiValue(env);
    }
    return CreateInt32(env);
}

napi_value ConfigStaticIp(const napi_env& env, const napi_value& object, WifiDeviceConfig& cppConfig)
{
    bool hasProperty = false;
    NAPI_CALL(env, napi_has_named_property(env, object, "staticIp", &hasProperty));
    if (!hasProperty) {
        WIFI_LOGE("ConfigStaticIp, Js has no property: staticIp.");
        return UndefinedNapiValue(env);
    }
    napi_value staticIp;
    napi_value dnsServers;
    napi_value primaryDns;
    napi_value secondDns;
    napi_get_named_property(env, object, "staticIp", &staticIp);
    JsObjectToUint(env, staticIp, "ipAddress",
        cppConfig.wifiIpConfig.staticIpAddress.ipAddress.address.addressIpv4);
    cppConfig.wifiIpConfig.staticIpAddress.ipAddress.address.family = 0;
    JsObjectToUint(env, staticIp, "gateway", cppConfig.wifiIpConfig.staticIpAddress.gateway.addressIpv4);
    JsObjectToInt(env, staticIp, "prefixLength", cppConfig.wifiIpConfig.staticIpAddress.ipAddress.prefixLength);

    NAPI_CALL(env, napi_has_named_property(env, staticIp, "dnsServers", &hasProperty));
    if (!hasProperty) {
        WIFI_LOGE("ConfigStaticIp, Js has no property: dnsServers.");
        return UndefinedNapiValue(env);
    }
    uint32_t arrayLength = 0;
    const int DNS_NUM = 2;
    napi_get_named_property(env, staticIp, "dnsServers", &dnsServers);
    napi_get_array_length(env, dnsServers, &arrayLength);
    if (arrayLength != DNS_NUM) {
        WIFI_LOGE("ConfigStaticIp, It needs two dns servers.");
        return UndefinedNapiValue(env);
    }
    napi_get_element(env, dnsServers, 0, &primaryDns);
    napi_get_element(env, dnsServers, 1, &secondDns);
    napi_get_value_uint32(env, primaryDns, &cppConfig.wifiIpConfig.staticIpAddress.dnsServer1.addressIpv4);
    napi_get_value_uint32(env, secondDns, &cppConfig.wifiIpConfig.staticIpAddress.dnsServer2.addressIpv4);

    return CreateInt32(env);
}

static napi_value JsObjToDeviceConfig(const napi_env& env, const napi_value& object, WifiDeviceConfig& cppConfig)
{
    JsObjectToString(env, object, "ssid", NAPI_MAX_STR_LENT, cppConfig.ssid); /* ssid max length is 32 + '\0' */
    JsObjectToString(env, object, "bssid", NAPI_MAX_STR_LENT, cppConfig.bssid); /* max bssid length: 18 */
    WIFI_LOGE("JsObjToDeviceConfig, bssid length: %{public}d.", static_cast<int>(cppConfig.bssid.length()));
    JsObjectToString(env, object, "preSharedKey", NAPI_MAX_STR_LENT, cppConfig.preSharedKey);
    JsObjectToBool(env, object, "isHiddenSsid", cppConfig.hiddenSSID);
    int type = static_cast<int>(SecTypeJs::SEC_TYPE_INVALID);
    JsObjectToInt(env, object, "securityType", type);
    ConvertEncryptionMode(SecTypeJs(type), cppConfig.keyMgmt);
    ProcessPassphrase(SecTypeJs(type), cppConfig);
    /* "creatorUid" is not supported currently */
    /* "disableReason" is not supported currently */
    JsObjectToInt(env, object, "netId", cppConfig.networkId);
    /* "randomMacType" is not supported currently */
    /* "randomMacAddr" is not supported currently */
    int ipType = static_cast<int>(AssignIpMethod::UNASSIGNED);
    JsObjectToInt(env, object, "ipType", ipType);
    WIFI_LOGI("JsObjToDeviceConfig, ipType: %{public}d, type: %{public}d.", ipType, type);
    if (IpTypeJs(ipType) == IpTypeJs::IP_TYPE_DHCP) {
        cppConfig.wifiIpConfig.assignMethod = AssignIpMethod::DHCP;
    } else if (IpTypeJs(ipType) == IpTypeJs::IP_TYPE_STATIC) {
        cppConfig.wifiIpConfig.assignMethod = AssignIpMethod::STATIC;
        napi_valuetype valueType;
        napi_value ret = ConfigStaticIp(env, object, cppConfig);
        napi_typeof(env, ret, &valueType);
        if (valueType == napi_undefined) {
            WIFI_LOGI("JsObjToDeviceConfig, ConfigStaticIp return napi_undefined.");
            return UndefinedNapiValue(env);
        }
    }

    if (SecTypeJs(type) == SecTypeJs::SEC_TYPE_EAP) {
        return ProcessEapConfig(env, object, cppConfig);
    }
    return CreateInt32(env);
}

napi_value AddDeviceConfig(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    size_t argc = 3;
    napi_value argv[argc];
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data));
    WIFI_NAPI_ASSERT(env, argc >= 1, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    WIFI_NAPI_ASSERT(env, valueType == napi_object, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);

    DeviceConfigContext *asyncContext = new DeviceConfigContext(env);
    WIFI_NAPI_ASSERT(env, asyncContext != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
    napi_create_string_latin1(env, "addDeviceConfig", NAPI_AUTO_LENGTH, &asyncContext->resourceName);

    WifiDeviceConfig *config = new WifiDeviceConfig();
    if (config == nullptr) {
        delete asyncContext;
        return UndefinedNapiValue(env);
    }
    napi_value ret = JsObjToDeviceConfig(env, argv[0], *config);
    napi_typeof(env, ret, &valueType);
    WIFI_NAPI_ASSERT(env, valueType != napi_undefined, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);

    asyncContext->config = config;
    asyncContext->isCandidate = false;

    asyncContext->executeFunc = [&](void* data) -> void {
        DeviceConfigContext *context = static_cast<DeviceConfigContext *>(data);
        TRACE_FUNC_CALL_NAME("wifiDevicePtr->AddDeviceConfig");
        ErrCode ret = wifiDevicePtr->AddDeviceConfig(*context->config, context->networkId, context->isCandidate);
        if (context->networkId < 0 || ret != WIFI_OPT_SUCCESS) {
            context->networkId = -1;
        }
        context->errorCode = ret;
    };

    asyncContext->completeFunc = [&](void* data) -> void {
        DeviceConfigContext *context = static_cast<DeviceConfigContext *>(data);
        napi_create_int32(context->env, context->networkId, &context->result);
        if (context->config != nullptr) {
            delete context->config;
            context->config = nullptr;
        }
        WIFI_LOGI("Push add device config result to client");
    };

    size_t nonCallbackArgNum = 1;
    asyncContext->sysCap = SYSCAP_WIFI_STA;
    return DoAsyncWork(env, asyncContext, argc, argv, nonCallbackArgNum);
}

napi_value AddUntrustedConfig(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    size_t argc = 2;
    napi_value argv[argc];
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data));
    WIFI_NAPI_ASSERT(env, argc >= 1, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    WIFI_NAPI_ASSERT(env, valueType == napi_object, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);

    DeviceConfigContext *asyncContext = new DeviceConfigContext(env);
    WIFI_NAPI_ASSERT(env, asyncContext != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
    napi_create_string_latin1(env, "AddUntrustedConfig", NAPI_AUTO_LENGTH, &asyncContext->resourceName);

    WifiDeviceConfig *config = new WifiDeviceConfig();
    if (config == nullptr) {
        delete asyncContext;
        return UndefinedNapiValue(env);
    }
    napi_value ret = JsObjToDeviceConfig(env, argv[0], *config);
    napi_typeof(env, ret, &valueType);
    WIFI_NAPI_ASSERT(env, valueType != napi_undefined, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);
    asyncContext->config = config;
    asyncContext->isCandidate = true;

    asyncContext->executeFunc = [&](void* data) -> void {
        DeviceConfigContext *context = static_cast<DeviceConfigContext *>(data);
        TRACE_FUNC_CALL_NAME("wifiDevicePtr->AddUntrustedConfig");
        ErrCode ret = wifiDevicePtr->AddDeviceConfig(*context->config, context->networkId, context->isCandidate);
        if (context->networkId < 0 || ret != WIFI_OPT_SUCCESS) {
            context->networkId = -1;
        }
        context->errorCode = ret;
    };

    asyncContext->completeFunc = [&](void* data) -> void {
        DeviceConfigContext *context = static_cast<DeviceConfigContext *>(data);
        napi_get_boolean(context->env, (context->networkId >= 0), &context->result);
        if (context->config != nullptr) {
            delete context->config;
            context->config = nullptr;
        }
        WIFI_LOGI("Push add untrusted device config result to client");
    };

    size_t nonCallbackArgNum = 1;
    asyncContext->sysCap = SYSCAP_WIFI_STA;
    return DoAsyncWork(env, asyncContext, argc, argv, nonCallbackArgNum);
}

napi_value RemoveUntrustedConfig(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    size_t argc = 3;
    napi_value argv[argc];
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data));
    WIFI_NAPI_ASSERT(env, argc >= 1, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    WIFI_NAPI_ASSERT(env, valueType == napi_object, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);

    DeviceConfigContext *asyncContext = new DeviceConfigContext(env);
    WIFI_NAPI_ASSERT(env, asyncContext != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
    napi_create_string_latin1(env, "RemoveUntrustedConfig", NAPI_AUTO_LENGTH, &asyncContext->resourceName);

    WifiDeviceConfig *config = new WifiDeviceConfig();
    if (config == nullptr) {
        delete asyncContext;
        return UndefinedNapiValue(env);
    }
    napi_value ret = JsObjToDeviceConfig(env, argv[0], *config);
    napi_typeof(env, ret, &valueType);
    WIFI_NAPI_ASSERT(env, valueType != napi_undefined, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);
    asyncContext->config = config;

    asyncContext->executeFunc = [&](void* data) -> void {
        DeviceConfigContext *context = static_cast<DeviceConfigContext *>(data);
        TRACE_FUNC_CALL_NAME("wifiDevicePtr->RemoveCandidateConfig");
        context->errorCode = wifiDevicePtr->RemoveCandidateConfig(*context->config);
    };

    asyncContext->completeFunc = [&](void* data) -> void {
        DeviceConfigContext *context = static_cast<DeviceConfigContext *>(data);
        napi_get_boolean(context->env, context->errorCode == WIFI_OPT_SUCCESS, &context->result);
        if (context->config != nullptr) {
            delete context->config;
            context->config = nullptr;
        }
        WIFI_LOGI("Push remove untrusted device config result to client");
    };

    size_t nonCallbackArgNum = 1;
    asyncContext->sysCap = SYSCAP_WIFI_STA;
    return DoAsyncWork(env, asyncContext, argc, argv, nonCallbackArgNum);
}

napi_value AddCandidateConfig(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    size_t argc = 2;
    napi_value argv[argc];
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data));
    WIFI_NAPI_ASSERT(env, argc >= 1, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    WIFI_NAPI_ASSERT(env, valueType == napi_object, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);

    DeviceConfigContext *asyncContext = new DeviceConfigContext(env);
    WIFI_NAPI_ASSERT(env, asyncContext != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
    napi_create_string_latin1(env, "AddCandidateConfig", NAPI_AUTO_LENGTH, &asyncContext->resourceName);

    WifiDeviceConfig *config = new WifiDeviceConfig();
    if (config == nullptr) {
        delete asyncContext;
        return UndefinedNapiValue(env);
    }

    napi_value ret = JsObjToDeviceConfig(env, argv[0], *config);
    napi_typeof(env, ret, &valueType);
    WIFI_NAPI_ASSERT(env, valueType != napi_undefined, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);
    asyncContext->config = config;
    asyncContext->isCandidate = true;

    asyncContext->executeFunc = [&](void* data) -> void {
        DeviceConfigContext *context = static_cast<DeviceConfigContext *>(data);
        TRACE_FUNC_CALL_NAME("wifiDevicePtr->AddCandidateConfig");
        ErrCode ret = wifiDevicePtr->AddDeviceConfig(*context->config, context->networkId, context->isCandidate);
        if (context->networkId < 0 || ret != WIFI_OPT_SUCCESS) {
            WIFI_LOGE("Add candidate device config failed: %{public}d", static_cast<int>(ret));
            context->networkId = -1;
        }
        context->errorCode = ret;
    };

    asyncContext->completeFunc = [&](void* data) -> void {
        DeviceConfigContext *context = static_cast<DeviceConfigContext *>(data);
        napi_create_int32(context->env, context->networkId, &context->result);
        if (context->config != nullptr) {
            delete context->config;
            context->config = nullptr;
        }
        WIFI_LOGI("Push add candidate device config result to client");
    };

    size_t nonCallbackArgNum = 1;
    asyncContext->sysCap = SYSCAP_WIFI_STA;
    return DoAsyncWork(env, asyncContext, argc, argv, nonCallbackArgNum);
}

napi_value RemoveCandidateConfig(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    size_t argc = 3;
    napi_value argv[argc];
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data));
    WIFI_NAPI_ASSERT(env, argc >= 1, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    WIFI_NAPI_ASSERT(env, valueType == napi_number, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);

    DeviceConfigContext *asyncContext = new DeviceConfigContext(env);
    WIFI_NAPI_ASSERT(env, asyncContext != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
    napi_create_string_latin1(env, "RemoveCandidateConfig", NAPI_AUTO_LENGTH, &asyncContext->resourceName);

    napi_get_value_int32(env, argv[0], &asyncContext->networkId);
    asyncContext->executeFunc = [&](void* data) -> void {
        DeviceConfigContext *context = static_cast<DeviceConfigContext *>(data);
        context->errorCode = wifiDevicePtr->RemoveCandidateConfig(context->networkId);
    };

    asyncContext->completeFunc = [&](void* data) -> void {
        DeviceConfigContext *context = static_cast<DeviceConfigContext *>(data);
        napi_get_boolean(context->env, (context->errorCode == WIFI_OPT_SUCCESS), &context->result);
        if (context->config != nullptr) {
            delete context->config;
            context->config = nullptr;
        }
        WIFI_LOGI("Push remove candidate device config result to client");
    };

    size_t nonCallbackArgNum = 1;
    asyncContext->sysCap = SYSCAP_WIFI_STA;
    return DoAsyncWork(env, asyncContext, argc, argv, nonCallbackArgNum);
}

napi_value ConnectToCandidateConfig(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    size_t argc = 1;
    napi_value argv[1];
    napi_value thisVar;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    WIFI_NAPI_ASSERT(env, argc == 1, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    WIFI_NAPI_ASSERT(env, valueType == napi_number, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);

    int networkId = -1;
    napi_get_value_int32(env, argv[0], &networkId);
    bool isCandidate = true;

    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
    ErrCode ret = wifiDevicePtr->ConnectToNetwork(networkId, isCandidate);
    WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
}

napi_value ConnectToNetwork(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    size_t argc = 1;
    napi_value argv[1];
    napi_value thisVar;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    WIFI_NAPI_ASSERT(env, argc == 1, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    WIFI_NAPI_ASSERT(env, valueType == napi_number, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);

    int networkId = -1;
    napi_get_value_int32(env, argv[0], &networkId);
    bool isCandidate = false;

    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
    ErrCode ret = wifiDevicePtr->ConnectToNetwork(networkId, isCandidate);
    WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
}

napi_value ConnectToDevice(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    size_t argc = 1;
    napi_value argv[1];
    napi_value thisVar;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    WIFI_NAPI_ASSERT(env, valueType == napi_object, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);

    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
    WifiDeviceConfig config;
    napi_value napiRet = JsObjToDeviceConfig(env, argv[0], config);
    napi_typeof(env, napiRet, &valueType);
    WIFI_NAPI_ASSERT(env, valueType != napi_undefined, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);
    ErrCode ret = wifiDevicePtr->ConnectToDevice(config);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Connect to device fail: %{public}d", ret);
    }
    WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
}

napi_value IsConnected(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
    bool isConnected = false;
    ErrCode ret = wifiDevicePtr->IsConnected(isConnected);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("IsConnected return error: %{public}d", ret);
        WIFI_NAPI_ASSERT(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
    }
    napi_value result;
    napi_get_boolean(env, isConnected, &result);
    return result;
}

napi_value Disconnect(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
    ErrCode ret = wifiDevicePtr->Disconnect();
    WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
}

napi_value GetSignalLevel(napi_env env, napi_callback_info info)
{
    size_t argc = 2;
    const int PARAMS_NUM = 2;
    napi_value argv[2];
    napi_value thisVar;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    /* the input have 2 parameters */
    WIFI_NAPI_ASSERT(env, argc == PARAMS_NUM, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);

    napi_valuetype type1;
    napi_valuetype type2;
    napi_typeof(env, argv[0], &type1);
    napi_typeof(env, argv[1], &type2);
    WIFI_NAPI_ASSERT(env, type1 == napi_number, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);
    WIFI_NAPI_ASSERT(env, type2 == napi_number, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);

    int level = -1;
    int rssi = 0;
    int band = 0;
    napi_get_value_int32(env, argv[0], &rssi);
    napi_get_value_int32(env, argv[1], &band);
    ErrCode ret = wifiDevicePtr->GetSignalLevel(rssi, band, level);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Get wifi signal level fail: %{public}d", ret);
        WIFI_NAPI_ASSERT(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
    }
    napi_value result;
    napi_create_uint32(env, level, &result);
    return result;
}

napi_value ReConnect(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
    ErrCode ret = wifiDevicePtr->ReConnect();
    WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
}

napi_value ReAssociate(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
    ErrCode ret = wifiDevicePtr->ReAssociate();
    WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
}

static void IpInfoToJsObj(const napi_env& env, IpInfo& ipInfo, napi_value& result)
{
    napi_create_object(env, &result);
    SetValueUnsignedInt32(env, "ipAddress", ipInfo.ipAddress, result);
    SetValueUnsignedInt32(env, "gateway", ipInfo.gateway, result);
    SetValueUnsignedInt32(env, "netmask", ipInfo.netmask, result);
    SetValueUnsignedInt32(env, "primaryDns", ipInfo.primaryDns, result);
    SetValueUnsignedInt32(env, "secondDns", ipInfo.secondDns, result);
    SetValueUnsignedInt32(env, "serverIp", ipInfo.serverIp, result);
    SetValueUnsignedInt32(env, "leaseDuration", ipInfo.leaseDuration, result);
}

napi_value GetIpInfo(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);

    IpInfo ipInfo;
    napi_value result;
    ErrCode ret = wifiDevicePtr->GetIpInfo(ipInfo);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Get ip info fail: %{public}d", ret);
    }
    WIFI_NAPI_ASSERT(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
    IpInfoToJsObj(env, ipInfo, result);
    return result;
}

static void LinkedInfoToJs(const napi_env& env, WifiLinkedInfo& linkedInfo, napi_value& result)
{
    SetValueUtf8String(env, "ssid", linkedInfo.ssid.c_str(), result);
    SetValueUtf8String(env, "bssid", linkedInfo.bssid.c_str(), result);
    SetValueInt32(env, "networkId", linkedInfo.networkId, result);
    SetValueInt32(env, "rssi", linkedInfo.rssi, result);
    SetValueInt32(env, "band", linkedInfo.band, result);
    SetValueInt32(env, "linkSpeed", linkedInfo.linkSpeed, result);
    SetValueInt32(env, "frequency", linkedInfo.frequency, result);
    SetValueBool(env, "isHidden", linkedInfo.ifHiddenSSID, result);
    /* isRestricted not support now, set as default value */
    SetValueBool(env, "isRestricted", false, result);
    SetValueInt32(env, "chload", linkedInfo.chload, result);
    SetValueInt32(env, "snr", linkedInfo.snr, result);
    SetValueUtf8String(env, "macAddress", linkedInfo.macAddress.c_str(), result);
    SetValueInt32(env, "macType", linkedInfo.macType, result);
    SetValueUnsignedInt32(env, "ipAddress", linkedInfo.ipAddress, result);
    SetValueInt32(env, "suppState", static_cast<int>(linkedInfo.supplicantState), result);
    SetValueInt32(env, "connState", static_cast<int>(linkedInfo.connState), result);
}

/* This interface has not been fully implemented */
napi_value GetLinkedInfo(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    size_t argc = 2;
    napi_value argv[argc];
    napi_value thisVar = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, &data));
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);

    LinkedInfoAsyncContext *asyncContext = new LinkedInfoAsyncContext(env);
    WIFI_NAPI_ASSERT(env, asyncContext != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
    napi_create_string_latin1(env, "getLinkedInfo", NAPI_AUTO_LENGTH, &asyncContext->resourceName);

    asyncContext->executeFunc = [&](void* data) -> void {
        LinkedInfoAsyncContext *context = static_cast<LinkedInfoAsyncContext *>(data);
        TRACE_FUNC_CALL_NAME("wifiDevicePtr->GetLinkedInfo");
        context->errorCode = wifiDevicePtr->GetLinkedInfo(context->linkedInfo);
    };

    asyncContext->completeFunc = [&](void* data) -> void {
        LinkedInfoAsyncContext *context = static_cast<LinkedInfoAsyncContext *>(data);
        napi_create_object(context->env, &context->result);
        LinkedInfoToJs(context->env, context->linkedInfo, context->result);
        WIFI_LOGI("Push get linkedInfo result to client");
    };

    size_t nonCallbackArgNum = 0;
    asyncContext->sysCap = SYSCAP_WIFI_STA;
    return DoAsyncWork(env, asyncContext, argc, argv, nonCallbackArgNum);
}

napi_value RemoveDevice(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    size_t argc = 1;
    napi_value argv[1];
    napi_value thisVar;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    WIFI_NAPI_ASSERT(env, argc == 1, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    WIFI_NAPI_ASSERT(env, valueType == napi_number, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);

    int networkId = -1;
    napi_get_value_int32(env, argv[0], &networkId);
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);

    ErrCode ret = wifiDevicePtr->RemoveDevice(networkId);
    WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
}

napi_value RemoveAllNetwork(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
    ErrCode ret = wifiDevicePtr->RemoveAllDevice();
    WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
}

napi_value DisableNetwork(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    size_t argc = 1;
    napi_value argv[1];
    napi_value thisVar;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    WIFI_NAPI_ASSERT(env, argc == 1, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    WIFI_NAPI_ASSERT(env, valueType == napi_number, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);

    int networkId = -1;
    napi_get_value_int32(env, argv[0], &networkId);
    ErrCode ret = wifiDevicePtr->DisableDeviceConfig(networkId);
    WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
}

napi_value GetCountryCode(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_CORE);
    std::string countryCode;
    ErrCode ret = wifiDevicePtr->GetCountryCode(countryCode);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Get countryCode fail: %{public}d", ret);
    }
    WIFI_NAPI_ASSERT(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_CORE);
    napi_value cc;
    napi_create_string_utf8(env, countryCode.c_str(), NAPI_AUTO_LENGTH, &cc);
    return cc;
}

static SecTypeJs ConvertKeyMgmtToSecType(const std::string& keyMgmt)
{
    std::map<std::string, SecTypeJs> mapKeyMgmtToSecType = {
        {KEY_MGMT_NONE, SecTypeJs::SEC_TYPE_OPEN},
        {KEY_MGMT_WEP, SecTypeJs::SEC_TYPE_WEP},
        {KEY_MGMT_WPA_PSK, SecTypeJs::SEC_TYPE_PSK},
        {KEY_MGMT_SAE, SecTypeJs::SEC_TYPE_SAE},
        {KEY_MGMT_EAP, SecTypeJs::SEC_TYPE_EAP},
    };

    std::map<std::string, SecTypeJs>::iterator iter = mapKeyMgmtToSecType.find(keyMgmt);
    return iter == mapKeyMgmtToSecType.end() ? SecTypeJs::SEC_TYPE_OPEN : iter->second;
}

static void IpConfigToJs(const napi_env& env, const WifiIpConfig& wifiIpConfig, napi_value& ipCfgObj)
{
    SetValueInt32(env, "ipAddress", wifiIpConfig.staticIpAddress.ipAddress.address.addressIpv4, ipCfgObj);
    SetValueInt32(env, "gateway", wifiIpConfig.staticIpAddress.gateway.addressIpv4, ipCfgObj);

    const int DNS_NUM = 2;
    napi_value dnsArray;
    napi_create_array_with_length(env, DNS_NUM, &dnsArray);
    std::vector<unsigned int> vecDns = {wifiIpConfig.staticIpAddress.dnsServer1.addressIpv4,
        wifiIpConfig.staticIpAddress.dnsServer2.addressIpv4};
    for (int i = 0; i != DNS_NUM; ++i) {
        napi_value value;
        napi_status status = napi_create_int32(env, vecDns[i], &value);
        if (status != napi_ok) {
            WIFI_LOGE("Ip config to js create int32 error!");
            return;
        }
        status = napi_set_element(env, dnsArray, i, value);
        if (status != napi_ok) {
            WIFI_LOGE("Ip config to js set element error: %{public}d", status);
            return;
        }
    }
    if (napi_set_named_property(env, ipCfgObj, "dnsServers", dnsArray) != napi_ok) {
        WIFI_LOGE("Set dnsServers named property error!");
    }

    const int DOMAINS_NUM = 1;
    napi_value domainsArray;
    napi_create_array_with_length(env, DOMAINS_NUM, &domainsArray);
    std::vector<std::string> vecDomains = {wifiIpConfig.staticIpAddress.domains};
    for (int i = 0; i != DOMAINS_NUM; ++i) {
        napi_value value;
        napi_status status = napi_create_string_utf8(env, vecDomains[i].c_str(), NAPI_AUTO_LENGTH, &value);
        if (status != napi_ok) {
            WIFI_LOGE("Ip config to js create utf8 string error!");
            return;
        }
        status = napi_set_element(env, domainsArray, i, value);
        if (status != napi_ok) {
            WIFI_LOGE("Ip config to js set element error: %{public}d", status);
        }
    }
    if (napi_set_named_property(env, ipCfgObj, "domains", domainsArray) != napi_ok) {
        WIFI_LOGE("Set domains named property error!");
    }
}

static void UpdateSecurityTypeAndPreSharedKey(WifiDeviceConfig& cppConfig)
{
    if (cppConfig.keyMgmt != KEY_MGMT_NONE) {
        return;
    }
    for (int i = 0; i != WEPKEYS_SIZE; ++i) {
        if (!cppConfig.wepKeys[i].empty() && cppConfig.wepTxKeyIndex == i) {
            cppConfig.keyMgmt = KEY_MGMT_WEP;
            cppConfig.preSharedKey = cppConfig.wepKeys[i];
        }
    }
}

static void DeviceConfigToJsArray(const napi_env& env, std::vector<WifiDeviceConfig>& vecDeviceConfigs,
    const int idx, napi_value& arrayResult)
{
    UpdateSecurityTypeAndPreSharedKey(vecDeviceConfigs[idx]);
    napi_value result;
    napi_create_object(env, &result);
    SetValueUtf8String(env, "ssid", vecDeviceConfigs[idx].ssid.c_str(), result);
    SetValueUtf8String(env, "bssid", vecDeviceConfigs[idx].bssid.c_str(), result);
    SetValueUtf8String(env, "preSharedKey", vecDeviceConfigs[idx].preSharedKey.c_str(), result);
    SetValueBool(env, "isHiddenSsid", vecDeviceConfigs[idx].hiddenSSID, result);
    SetValueInt32(env, "securityType",
        static_cast<int>(ConvertKeyMgmtToSecType(vecDeviceConfigs[idx].keyMgmt)), result);
    SetValueInt32(env, "creatorUid", vecDeviceConfigs[idx].uid, result);
    /* not supported currently */
    SetValueInt32(env, "disableReason", DEFAULT_INVALID_VALUE, result);
    SetValueInt32(env, "netId", vecDeviceConfigs[idx].networkId, result);
    /* not supported currently */
    SetValueInt32(env, "randomMacType", DEFAULT_INVALID_VALUE, result);
    /* not supported currently */
    SetValueUtf8String(env, "randomMacAddr", std::string("").c_str(), result);
    if (vecDeviceConfigs[idx].wifiIpConfig.assignMethod == AssignIpMethod::STATIC) {
        SetValueInt32(env, "ipType", static_cast<int>(IpTypeJs::IP_TYPE_STATIC), result);
    } else {
        SetValueInt32(env, "ipType", static_cast<int>(IpTypeJs::IP_TYPE_DHCP), result);
    }
    napi_value ipCfgObj;
    napi_create_object(env, &ipCfgObj);
    IpConfigToJs(env, vecDeviceConfigs[idx].wifiIpConfig, ipCfgObj);
    napi_status status = napi_set_named_property(env, result, "staticIp", ipCfgObj);
    if (status != napi_ok) {
        WIFI_LOGE("Set staticIp field!");
    }
    status = napi_set_element(env, arrayResult, idx, result);
    if (status != napi_ok) {
        WIFI_LOGE("Wifi napi set element error: %{public}d", status);
    }
}

napi_value GetDeviceConfigs(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
    std::vector<WifiDeviceConfig> vecDeviceConfigs;
    bool isCandidate = false;
    ErrCode ret = wifiDevicePtr->GetDeviceConfigs(vecDeviceConfigs, isCandidate);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Get device configs fail: %{public}d", ret);
    }

    WIFI_NAPI_ASSERT(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
    WIFI_LOGI("Get device configs size: %{public}zu", vecDeviceConfigs.size());
    napi_value arrayResult;
    napi_create_array_with_length(env, vecDeviceConfigs.size(), &arrayResult);
    for (size_t i = 0; i != vecDeviceConfigs.size(); ++i) {
        DeviceConfigToJsArray(env, vecDeviceConfigs, i, arrayResult);
    }
    return arrayResult;
}

napi_value GetCandidateConfigs(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
    std::vector<WifiDeviceConfig> vecDeviceConfigs;
    bool isCandidate = true;
    ErrCode ret = wifiDevicePtr->GetDeviceConfigs(vecDeviceConfigs, isCandidate);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Get candidate device configs fail: %{public}d", ret);
    }

    WIFI_NAPI_ASSERT(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
    WIFI_LOGI("Get candidate device configs size: %{public}zu", vecDeviceConfigs.size());
    napi_value arrayResult;
    napi_create_array_with_length(env, vecDeviceConfigs.size(), &arrayResult);
    for (size_t i = 0; i != vecDeviceConfigs.size(); ++i) {
        DeviceConfigToJsArray(env, vecDeviceConfigs, i, arrayResult);
    }
    return arrayResult;
}

napi_value UpdateNetwork(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    size_t argc = 1;
    napi_value argv[1];
    napi_value thisVar;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    WIFI_NAPI_ASSERT(env, valueType == napi_object, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);

    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
    int updateResult;
    WifiDeviceConfig config;
    napi_value res = JsObjToDeviceConfig(env, argv[0], config);
    napi_typeof(env, res, &valueType);
    WIFI_NAPI_ASSERT(env, valueType != napi_undefined, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);
    ErrCode ret = wifiDevicePtr->UpdateDeviceConfig(config, updateResult);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Update device config fail: %{public}d", ret);
    }

    WIFI_NAPI_ASSERT(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
    napi_value result;
    napi_create_uint32(env, updateResult, &result);
    return result;
}

napi_value GetSupportedFeatures(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_CORE);
    long features = -1;
    ErrCode ret = wifiDevicePtr->GetSupportedFeatures(features);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Get supported features fail: %{public}d", ret);
    }

    WIFI_NAPI_ASSERT(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_CORE);
    napi_value result;
    napi_create_int64(env, features, &result);
    return result;
}

napi_value IsFeatureSupported(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    size_t argc = 1;
    napi_value argv[1];
    napi_value thisVar;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    WIFI_NAPI_ASSERT(env, argc == 1, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_CORE);

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    WIFI_NAPI_ASSERT(env, valueType == napi_number, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_CORE);
    long feature = -1;
    napi_get_value_int64(env, argv[0], (int64_t*)&feature);
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_CORE);
    bool isSupported = false;
    ErrCode ret = wifiDevicePtr->IsFeatureSupported(feature, isSupported);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Get supported features fail: %{public}d", ret);
        WIFI_NAPI_ASSERT(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_CORE);
    }

    napi_value result;
    napi_get_boolean(env, isSupported, &result);
    return result;
}

napi_value GetDeviceMacAddress(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
    std::string macAddr;
    ErrCode ret = wifiDevicePtr->GetDeviceMacAddress(macAddr);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Get mac address fail: %{public}d", ret);
    }

    WIFI_NAPI_ASSERT(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
    napi_value addr;
    napi_create_string_utf8(env, macAddr.c_str(), NAPI_AUTO_LENGTH, &addr);
    return addr;
}
}  // namespace Wifi
}  // namespace OHOS