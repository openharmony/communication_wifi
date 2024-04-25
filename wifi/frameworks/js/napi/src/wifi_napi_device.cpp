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
static const std::string EAP_METHOD[] = { "NONE", "PEAP", "TLS", "TTLS", "PWD", "SIM", "AKA", "AKA'" };

std::shared_ptr<WifiDevice> wifiDevicePtr = WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);
std::shared_ptr<WifiScan> wifiScanPtr = WifiScan::GetInstance(WIFI_SCAN_ABILITY_ID);

NO_SANITIZE("cfi") napi_value EnableWifi(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
    ErrCode ret = wifiDevicePtr->EnableWifi();
    WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
}

NO_SANITIZE("cfi") napi_value DisableWifi(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
    ErrCode ret = wifiDevicePtr->DisableWifi();
    WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
}

NO_SANITIZE("cfi") napi_value IsWifiActive(napi_env env, napi_callback_info info)
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

NO_SANITIZE("cfi") napi_value Scan(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
    bool compatible = true;
    ErrCode ret = wifiScanPtr->Scan(compatible);
    WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
}

NO_SANITIZE("cfi") napi_value StartScan(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
    bool compatible = false;
    ErrCode ret = wifiScanPtr->Scan(compatible);
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
        SetValueInt32(env, "bssidType", each.bssidType, eachObj);
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
        SetValueInt32(env, "supportedWifiCategory", static_cast<int>(each.supportedWifiCategory), eachObj);
        SetValueBool(env, "isHiLinkNetwork", each.isHiLinkNetwork, eachObj);
        napi_status status = napi_set_element(env, arrayResult, idx++, eachObj);
        if (status != napi_ok) {
            WIFI_LOGE("Wifi napi set element error: %{public}d, idx: %{public}d", status, idx - 1);
            return WIFI_OPT_FAILED;
        }
    }
    return WIFI_OPT_SUCCESS;
}

NO_SANITIZE("cfi") napi_value GetScanInfos(napi_env env, napi_callback_info info)
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
        context->vecScanInfos.clear();
        TRACE_FUNC_CALL_NAME("wifiScanPtr->GetScanInfoList");
        bool compatible = true;
        context->errorCode = wifiScanPtr->GetScanInfoList(context->vecScanInfos, compatible);
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

NO_SANITIZE("cfi") napi_value GetScanInfoResults(napi_env env, napi_callback_info info)
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
        context->vecScanInfos.clear();
        TRACE_FUNC_CALL_NAME("wifiScanPtr->GetScanInfoList");
        bool compatible = false;
        context->errorCode = wifiScanPtr->GetScanInfoList(context->vecScanInfos, compatible);
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

NO_SANITIZE("cfi") napi_value GetScanResults(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
    bool compatible = true;
    std::vector<WifiScanInfo> scanInfos;
    ErrCode ret = wifiScanPtr->GetScanInfoList(scanInfos, compatible);
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

NO_SANITIZE("cfi") napi_value GetScanInfoList(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
    bool compatible = false;
    std::vector<WifiScanInfo> scanInfos;
    ErrCode ret = wifiScanPtr->GetScanInfoList(scanInfos, compatible);
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

static std::string EapMethod2Str(const int& method)
{
    if (method < 0 || method >= static_cast<int>(sizeof(EAP_METHOD) / sizeof(EAP_METHOD[0]))) {
        return "NONE";
    }
    return EAP_METHOD[method];
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

    // EAP authentication mode
    JsObjectToInt(env, napiEap, "eapMethod", eapMethod);
    devConfig.wifiEapConfig.eap = EapMethod2Str(eapMethod);
    if (devConfig.wifiEapConfig.eap == EAP_METHOD_NONE) {
        return UndefinedNapiValue(env);
    }
    WIFI_LOGI("%{public}s eapMethod: %{public}d[%{public}s]",
        __func__, eapMethod, devConfig.wifiEapConfig.eap.c_str());

    int phase2 = static_cast<int>(Phase2Method::NONE);
    JsObjectToInt(env, napiEap, "phase2Method", phase2);
    devConfig.wifiEapConfig.phase2Method = Phase2Method(phase2);
    JsObjectToString(env, napiEap, "identity", NAPI_MAX_STR_LENT, devConfig.wifiEapConfig.identity);
    JsObjectToString(env, napiEap, "anonymousIdentity", NAPI_MAX_STR_LENT, devConfig.wifiEapConfig.anonymousIdentity);
    JsObjectToString(env, napiEap, "password", NAPI_MAX_STR_LENT, devConfig.wifiEapConfig.password);
    JsObjectToString(env, napiEap, "caCertAlias", NAPI_MAX_STR_LENT, devConfig.wifiEapConfig.caCertAlias);
    JsObjectToString(env, napiEap, "caPath", NAPI_MAX_STR_LENT, devConfig.wifiEapConfig.caCertPath);
    JsObjectToString(env, napiEap, "clientCertAlias", NAPI_MAX_STR_LENT, devConfig.wifiEapConfig.clientCert);
    devConfig.wifiEapConfig.certEntry = JsObjectToU8Vector(env, napiEap, "certEntry");

    std::string certPwd;
    JsObjectToString(env, napiEap, "certPassword", NAPI_MAX_STR_LENT, certPwd);
    if (strncpy_s(devConfig.wifiEapConfig.certPassword, sizeof(devConfig.wifiEapConfig.certPassword),
        certPwd.c_str(), certPwd.length()) != EOK) {
        WIFI_LOGE("%{public}s: failed to copy", __func__);
    }
    JsObjectToString(env, napiEap, "altSubjectMatch", NAPI_MAX_STR_LENT, devConfig.wifiEapConfig.altSubjectMatch);
    JsObjectToString(env, napiEap, "domainSuffixMatch", NAPI_MAX_STR_LENT, devConfig.wifiEapConfig.domainSuffixMatch);
    JsObjectToString(env, napiEap, "realm", NAPI_MAX_STR_LENT, devConfig.wifiEapConfig.realm);
    JsObjectToString(env, napiEap, "plmn", NAPI_MAX_STR_LENT, devConfig.wifiEapConfig.plmn);
    JsObjectToInt(env, napiEap, "eapSubId", devConfig.wifiEapConfig.eapSubId);
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
    if (arrayLength == 0 || arrayLength > DNS_NUM) {
        WIFI_LOGE("ConfigStaticIp, It needs dns servers or dns too much.");
        return UndefinedNapiValue(env);
    }
    napi_get_element(env, dnsServers, 0, &primaryDns);
    napi_get_element(env, dnsServers, 1, &secondDns);
    napi_get_value_uint32(env, primaryDns, &cppConfig.wifiIpConfig.staticIpAddress.dnsServer1.addressIpv4);
    napi_get_value_uint32(env, secondDns, &cppConfig.wifiIpConfig.staticIpAddress.dnsServer2.addressIpv4);

    return CreateInt32(env);
}

ErrCode ProcessProxyConfig(const napi_env& env, const napi_value& object, WifiDeviceConfig& cppConfig)
{
    bool hasProperty = false;
    NAPI_CALL_BASE(env, napi_has_named_property(env, object, "proxyConfig", &hasProperty), {});
    ErrCode ret = WIFI_OPT_SUCCESS;
    if (hasProperty) {
        napi_value proxyConfig;
        napi_get_named_property(env, object, "proxyConfig", &proxyConfig);
        napi_valuetype valueType;
        napi_typeof(env, proxyConfig, &valueType);
        if (valueType == napi_null || valueType == napi_undefined) {
            WIFI_LOGE("ProcessProxyConfig, proxyConfig is null.");
            return ret;
        }

        int proxyConfigMethod = static_cast<int>(ConfigureProxyMethod::CLOSED);
        JsObjectToInt(env, proxyConfig, "proxyMethod", proxyConfigMethod);
        cppConfig.wifiProxyconfig.configureMethod = ConfigureProxyMethod::CLOSED;
        switch (ConfigureProxyMethod(proxyConfigMethod)) {
            case ConfigureProxyMethod::AUTOCONFIGUE:
                cppConfig.wifiProxyconfig.configureMethod = ConfigureProxyMethod::AUTOCONFIGUE;
                JsObjectToString(env, proxyConfig, "pacWebAddress", NAPI_MAX_STR_LENT,
                    cppConfig.wifiProxyconfig.autoProxyConfig.pacWebAddress);
                ret = WIFI_OPT_NOT_SUPPORTED;
                break;
            case ConfigureProxyMethod::MANUALCONFIGUE:
                cppConfig.wifiProxyconfig.configureMethod = ConfigureProxyMethod::MANUALCONFIGUE;
                JsObjectToString(env, proxyConfig, "serverHostName", NAPI_MAX_STR_LENT,
                    cppConfig.wifiProxyconfig.manualProxyConfig.serverHostName);
                JsObjectToString(env, proxyConfig, "exclusionObjects", NAPI_MAX_STR_LENT,
                    cppConfig.wifiProxyconfig.manualProxyConfig.exclusionObjectList);
                JsObjectToInt(env, proxyConfig, "serverPort", cppConfig.wifiProxyconfig.manualProxyConfig.serverPort);
                if (cppConfig.wifiProxyconfig.manualProxyConfig.serverPort < 0) {
                    ret = WIFI_OPT_INVALID_PARAM;
                }
                break;
            case ConfigureProxyMethod::CLOSED:
                WIFI_LOGI("ProcessProxyConfig, configureMethod is closed.");
                break;
            default:
                WIFI_LOGE("ProcessProxyConfig, configureMethod %{public}d is not supported.", proxyConfigMethod);
                ret = WIFI_OPT_INVALID_PARAM;
        }
    }

    return ret;
}

static napi_value JsObjToDeviceConfig(const napi_env& env, const napi_value& object, WifiDeviceConfig& cppConfig)
{
    JsObjectToString(env, object, "ssid", NAPI_MAX_STR_LENT, cppConfig.ssid); /* ssid max length is 32 + '\0' */
    JsObjectToString(env, object, "bssid", NAPI_MAX_STR_LENT, cppConfig.bssid); /* max bssid length: 18 */
    cppConfig.bssidType = RANDOM_DEVICE_ADDRESS;
    JsObjectToInt(env, object, "bssidType", cppConfig.bssidType);
    WIFI_LOGE("JsObjToDeviceConfig, bssid length: %{public}d, bssidType: %{public}d",
        static_cast<int>(cppConfig.bssid.length()), cppConfig.bssidType);
    JsObjectToString(env, object, "preSharedKey", NAPI_MAX_STR_LENT, cppConfig.preSharedKey);
    JsObjectToBool(env, object, "isHiddenSsid", cppConfig.hiddenSSID);
    int type = static_cast<int>(SecTypeJs::SEC_TYPE_INVALID);
    JsObjectToInt(env, object, "securityType", type);
    ConvertEncryptionMode(SecTypeJs(type), cppConfig.keyMgmt);
    ProcessPassphrase(SecTypeJs(type), cppConfig);
    /* "creatorUid" is not supported currently */
    /* "disableReason" is not supported currently */
    JsObjectToInt(env, object, "netId", cppConfig.networkId);
    int randomMacType = static_cast<int>(WifiPrivacyConfig::RANDOMMAC);
    JsObjectToInt(env, object, "randomMacType", randomMacType);
    cppConfig.wifiPrivacySetting = WifiPrivacyConfig(randomMacType);
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
    ErrCode ret = ProcessProxyConfig(env, object, cppConfig);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
    }
    if (SecTypeJs(type) == SecTypeJs::SEC_TYPE_EAP) {
        return ProcessEapConfig(env, object, cppConfig);
    }
    return CreateInt32(env);
}

NO_SANITIZE("cfi") napi_value AddDeviceConfig(napi_env env, napi_callback_info info)
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

NO_SANITIZE("cfi") napi_value AddUntrustedConfig(napi_env env, napi_callback_info info)
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

NO_SANITIZE("cfi") napi_value RemoveUntrustedConfig(napi_env env, napi_callback_info info)
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

NO_SANITIZE("cfi") napi_value AddCandidateConfig(napi_env env, napi_callback_info info)
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

NO_SANITIZE("cfi") napi_value RemoveCandidateConfig(napi_env env, napi_callback_info info)
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

NO_SANITIZE("cfi") napi_value ConnectToCandidateConfig(napi_env env, napi_callback_info info)
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

NO_SANITIZE("cfi") napi_value ConnectToNetwork(napi_env env, napi_callback_info info)
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

NO_SANITIZE("cfi") napi_value ConnectToDevice(napi_env env, napi_callback_info info)
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

NO_SANITIZE("cfi") napi_value IsConnected(napi_env env, napi_callback_info info)
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

NO_SANITIZE("cfi") napi_value Disconnect(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
    ErrCode ret = wifiDevicePtr->Disconnect();
    WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
}

NO_SANITIZE("cfi") napi_value GetSignalLevel(napi_env env, napi_callback_info info)
{
    WIFI_LOGI("GetSignalLevel napi start...");
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
    WIFI_LOGI("GetSignalLevel device start...");
    ErrCode ret = wifiDevicePtr->GetSignalLevel(rssi, band, level);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Get wifi signal level fail: %{public}d", ret);
        WIFI_NAPI_ASSERT(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
    }
    napi_value result;
    napi_create_uint32(env, level, &result);
    WIFI_LOGI("GetSignalLevel napi end...");
    return result;
}

NO_SANITIZE("cfi") napi_value ReConnect(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
    ErrCode ret = wifiDevicePtr->ReConnect();
    WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
}

NO_SANITIZE("cfi") napi_value ReAssociate(napi_env env, napi_callback_info info)
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

static void IpV6InfoToJsObj(const napi_env& env, IpV6Info& ipInfo, napi_value& result)
{
    napi_create_object(env, &result);
    SetValueUtf8String(env, "linkIpv6Address", ipInfo.linkIpV6Address, result);
    SetValueUtf8String(env, "globalIpv6Address", ipInfo.globalIpV6Address, result);
    SetValueUtf8String(env, "randGlobalIpv6Address", ipInfo.randGlobalIpV6Address, result);
    SetValueUtf8String(env, "gateway", ipInfo.gateway, result);
    SetValueUtf8String(env, "netmask", ipInfo.netmask, result);
    SetValueUtf8String(env, "primaryDNS", ipInfo.primaryDns, result);
    SetValueUtf8String(env, "secondDNS", ipInfo.secondDns, result);
}

NO_SANITIZE("cfi") napi_value GetIpInfo(napi_env env, napi_callback_info info)
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

NO_SANITIZE("cfi") napi_value GetIpv6Info(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);

    IpV6Info ipInfo;
    napi_value result;
    ErrCode ret = wifiDevicePtr->GetIpv6Info(ipInfo);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Get ip info fail: %{public}d", ret);
    }
    WIFI_NAPI_ASSERT(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
    IpV6InfoToJsObj(env, ipInfo, result);
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
    SetValueBool(env, "isRestricted", linkedInfo.isDataRestricted, result);
    SetValueInt32(env, "chload", linkedInfo.chload, result);
    SetValueInt32(env, "snr", linkedInfo.snr, result);
    SetValueUtf8String(env, "macAddress", linkedInfo.macAddress.c_str(), result);
    SetValueInt32(env, "macType", linkedInfo.macType, result);
    SetValueUnsignedInt32(env, "ipAddress", linkedInfo.ipAddress, result);
    SetValueInt32(env, "suppState", static_cast<int>(linkedInfo.supplicantState), result);
    SetValueInt32(env, "connState", static_cast<int>(linkedInfo.connState), result);
    SetValueInt32(env, "wifiStandard", static_cast<int>(linkedInfo.wifiStandard), result);
    SetValueInt32(env, "maxSupportedRxLinkSpeed", static_cast<int>(linkedInfo.maxSupportedRxLinkSpeed), result);
    SetValueInt32(env, "maxSupportedTxLinkSpeed", static_cast<int>(linkedInfo.maxSupportedTxLinkSpeed), result);
    SetValueInt32(env, "rxLinkSpeed", static_cast<int>(linkedInfo.rxLinkSpeed), result);
    SetValueInt32(env, "linkSpeed", static_cast<int>(linkedInfo.txLinkSpeed), result);
    SetValueInt32(env, "channelWidth", static_cast<int>(linkedInfo.channelWidth), result);
    SetValueInt32(env, "supportedWifiCategory", static_cast<int>(linkedInfo.supportedWifiCategory), result);
    SetValueBool(env, "isHiLinkNetwork", linkedInfo.isHiLinkNetwork, result);
}

/* This interface has not been fully implemented */
NO_SANITIZE("cfi") napi_value GetLinkedInfo(napi_env env, napi_callback_info info)
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
        WIFI_LOGD("Push get linkedInfo result to client");
    };

    size_t nonCallbackArgNum = 0;
    asyncContext->sysCap = SYSCAP_WIFI_STA;
    return DoAsyncWork(env, asyncContext, argc, argv, nonCallbackArgNum);
}

NO_SANITIZE("cfi") napi_value GetDisconnectedReason(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_CORE);
    DisconnectedReason reason = DisconnectedReason::DISC_REASON_DEFAULT;
    ErrCode ret = wifiDevicePtr->GetDisconnectedReason(reason);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("GetDisconnectedReason failed:%{public}d", ret);
        WIFI_NAPI_ASSERT(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
    }
    napi_value value;
    napi_create_int32(env, static_cast<int>(reason), &value);
    return value;
}

NO_SANITIZE("cfi") napi_value IsMeteredHotspot(napi_env env, napi_callback_info info)
{
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
    bool isMeteredHotspot = false;
    ErrCode ret = wifiDevicePtr->IsMeteredHotspot(isMeteredHotspot);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Get isMeteredHotspot value fail: %{public}d", ret);
        WIFI_NAPI_ASSERT(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
    }
    napi_value result;
    napi_get_boolean(env, isMeteredHotspot, &result);
    return result;
}

NO_SANITIZE("cfi") napi_value RemoveDevice(napi_env env, napi_callback_info info)
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

NO_SANITIZE("cfi") napi_value RemoveAllNetwork(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
    ErrCode ret = wifiDevicePtr->RemoveAllDevice();
    WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
}

NO_SANITIZE("cfi") napi_value DisableNetwork(napi_env env, napi_callback_info info)
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

NO_SANITIZE("cfi") napi_value GetCountryCode(napi_env env, napi_callback_info info)
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

static void ProxyConfigToJs(const napi_env& env, const WifiDeviceConfig& wifiDeviceConfig, napi_value& result)
{
    napi_value proxyCfgObj;
    napi_create_object(env, &proxyCfgObj);
    SetValueInt32(env, "proxyMethod", static_cast<int>(wifiDeviceConfig.wifiProxyconfig.configureMethod), proxyCfgObj);
    switch (wifiDeviceConfig.wifiProxyconfig.configureMethod) {
        case ConfigureProxyMethod::CLOSED:
            WIFI_LOGI("%{public}s get config method closed", __FUNCTION__);
            break;
        case ConfigureProxyMethod::AUTOCONFIGUE:
            SetValueUtf8String(env, "preSharedKey",
                wifiDeviceConfig.wifiProxyconfig.autoProxyConfig.pacWebAddress.c_str(), proxyCfgObj);
            break;
        case ConfigureProxyMethod::MANUALCONFIGUE:
            SetValueUtf8String(env, "serverHostName",
                wifiDeviceConfig.wifiProxyconfig.manualProxyConfig.serverHostName.c_str(), proxyCfgObj);
            SetValueInt32(env, "serverPort",
                wifiDeviceConfig.wifiProxyconfig.manualProxyConfig.serverPort, proxyCfgObj);
            SetValueUtf8String(env, "exclusionObjects",
                wifiDeviceConfig.wifiProxyconfig.manualProxyConfig.exclusionObjectList.c_str(), proxyCfgObj);
            break;
        default:
            break;
    }
    napi_status status = napi_set_named_property(env, result, "proxyConfig", proxyCfgObj);
    if (status != napi_ok) {
        WIFI_LOGE("%{public}s set proxy config failed!", __FUNCTION__);
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

static int Str2EapMethod(const std::string& str)
{
    WIFI_LOGD("%{public}s: eapMethod is %{public}s", __func__, str.c_str());
    int len = sizeof(EAP_METHOD) / sizeof(EAP_METHOD[0]);
    for (int i = 0; i < len; i++) {
        if (EAP_METHOD[i] == str) {
            WIFI_LOGD("%{public}s: index is %{public}d", __func__, i);
            return i;
        }
    }
    return 0;
}

static void EapConfigToJs(const napi_env& env, const WifiEapConfig& wifiEapConfig, napi_value& cfgObj)
{
    SetValueInt32(env, "eapMethod", Str2EapMethod(wifiEapConfig.eap), cfgObj);
    SetValueInt32(env, "phase2Method", static_cast<int>(wifiEapConfig.phase2Method), cfgObj);
    SetValueUtf8String(env, "identity", wifiEapConfig.identity.c_str(), cfgObj);
    SetValueUtf8String(env, "anonymousIdentity", wifiEapConfig.anonymousIdentity.c_str(), cfgObj);
    SetValueUtf8String(env, "password", wifiEapConfig.password.c_str(), cfgObj);
    SetValueUtf8String(env, "caCertAlias", wifiEapConfig.caCertAlias.c_str(), cfgObj);
    SetValueUtf8String(env, "caPath", wifiEapConfig.caCertPath.c_str(), cfgObj);
    SetValueUtf8String(env, "clientCertAlias", wifiEapConfig.caCertAlias.c_str(), cfgObj);
    SetValueU8Vector(env, "certEntry", wifiEapConfig.certEntry, cfgObj);
    SetValueUtf8String(env, "certPassword", wifiEapConfig.certPassword, cfgObj);
    SetValueUtf8String(env, "altSubjectMatch", wifiEapConfig.altSubjectMatch.c_str(), cfgObj);
    SetValueUtf8String(env, "domainSuffixMatch", wifiEapConfig.domainSuffixMatch.c_str(), cfgObj);
    SetValueUtf8String(env, "realm", wifiEapConfig.realm.c_str(), cfgObj);
    SetValueUtf8String(env, "plmn", wifiEapConfig.plmn.c_str(), cfgObj);
    SetValueInt32(env, "eapSubId", wifiEapConfig.eapSubId, cfgObj);
}

static void DeviceConfigToJsArray(const napi_env& env, std::vector<WifiDeviceConfig>& vecDeviceConfigs,
    const int idx, napi_value& arrayResult)
{
    UpdateSecurityTypeAndPreSharedKey(vecDeviceConfigs[idx]);
    napi_value result;
    napi_create_object(env, &result);
    SetValueUtf8String(env, "ssid", vecDeviceConfigs[idx].ssid.c_str(), result);
    SetValueUtf8String(env, "bssid", vecDeviceConfigs[idx].bssid.c_str(), result);
    SetValueInt32(env, "bssidType", static_cast<int>(vecDeviceConfigs[idx].bssidType), result);
    SetValueUtf8String(env, "preSharedKey", vecDeviceConfigs[idx].preSharedKey.c_str(), result);
    SetValueBool(env, "isHiddenSsid", vecDeviceConfigs[idx].hiddenSSID, result);
    SetValueInt32(env, "securityType",
        static_cast<int>(ConvertKeyMgmtToSecType(vecDeviceConfigs[idx].keyMgmt)), result);
    SetValueInt32(env, "creatorUid", vecDeviceConfigs[idx].uid, result);
    /* not supported currently */
    SetValueInt32(env, "disableReason", DEFAULT_INVALID_VALUE, result);
    SetValueInt32(env, "netId", vecDeviceConfigs[idx].networkId, result);
    SetValueInt32(env, "randomMacType", static_cast<int>(vecDeviceConfigs[idx].wifiPrivacySetting), result);
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
    ProxyConfigToJs(env, vecDeviceConfigs[idx], result);

    napi_value eapCfgObj;
    napi_create_object(env, &eapCfgObj);
    EapConfigToJs(env, vecDeviceConfigs[idx].wifiEapConfig, eapCfgObj);
    status = napi_set_named_property(env, result, "eapConfig", eapCfgObj);
    if (status != napi_ok) {
        WIFI_LOGE("failed to set eapConfig!");
    }

    status = napi_set_element(env, arrayResult, idx, result);
    if (status != napi_ok) {
        WIFI_LOGE("Wifi napi set element error: %{public}d", status);
    }
}

NO_SANITIZE("cfi") napi_value GetDeviceConfigs(napi_env env, napi_callback_info info)
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

NO_SANITIZE("cfi") napi_value GetCandidateConfigs(napi_env env, napi_callback_info info)
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

NO_SANITIZE("cfi") napi_value UpdateNetwork(napi_env env, napi_callback_info info)
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

NO_SANITIZE("cfi") napi_value GetSupportedFeatures(napi_env env, napi_callback_info info)
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

NO_SANITIZE("cfi") napi_value IsFeatureSupported(napi_env env, napi_callback_info info)
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

NO_SANITIZE("cfi") napi_value GetDeviceMacAddress(napi_env env, napi_callback_info info)
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

NO_SANITIZE("cfi") napi_value IsBandTypeSupported(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);

    size_t argc = 1;
    napi_value argv[1];
    napi_value thisVar;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    WIFI_NAPI_ASSERT(env, argc == 1, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    WIFI_NAPI_ASSERT(env, valueType == napi_number, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);
    int bandType = 1;
    napi_get_value_int32(env, argv[0], &bandType);
    WIFI_NAPI_ASSERT(env, bandType > (int)WifiBandTypeJS::BAND_NONE && bandType <= (int)WifiBandTypeJS::BAND_60GHZ,
        WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);
    bool supported = false;
    ErrCode ret = wifiDevicePtr->IsBandTypeSupported(bandType, supported);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Get band type supported fail: %{public}d", ret);
        WIFI_NAPI_ASSERT(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
    }
    napi_value result;
    napi_get_boolean(env, supported, &result);
    return result;
}

NO_SANITIZE("cfi") napi_value Get5GHzChannelList(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
    std::vector<int> vec5GChannels;
    ErrCode ret = wifiDevicePtr->Get5GHzChannelList(vec5GChannels);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Get 5g channellist fail: %{public}d", ret);
    }

    WIFI_NAPI_ASSERT(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
    WIFI_LOGI("Get 5g channellist size: %{public}zu", vec5GChannels.size());
    napi_value arrayResult;
    napi_create_array_with_length(env, vec5GChannels.size(), &arrayResult);
    for (size_t i = 0; i != vec5GChannels.size(); ++i) {
        napi_value result;
        napi_create_uint32(env, vec5GChannels[i], &result);
        napi_status status = napi_set_element(env, arrayResult, i, result);
        if (status != napi_ok) {
            WIFI_LOGE("wifi napi set 56 list element error: %{public}d", status);
        }
    }
    return arrayResult;
}

NO_SANITIZE("cfi") napi_value StartPortalCertification(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);

    ErrCode ret = wifiDevicePtr->StartPortalCertification();
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("StartPortalCertification fail: %{public}d", ret);
        WIFI_NAPI_ASSERT(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
    }
    napi_value result;
    napi_create_uint32(env, ret, &result);
    return result;
}

NO_SANITIZE("cfi") napi_value SetScanOnlyAvailable(napi_env env, napi_callback_info info)
{
    WIFI_LOGI("wifi napi In SetScanOnlyAvailable");
    TRACE_FUNC_CALL;
    size_t argc = 1;
    napi_value argv[1];
    napi_value thisVar;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);

    bool bScanOnlyAvailableStatus = false;
    napi_get_value_bool(env, argv[0], &bScanOnlyAvailableStatus);

    ErrCode ret = wifiScanPtr->SetScanOnlyAvailable(bScanOnlyAvailableStatus);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Set wifi scanOnlyAvailable fail: %{public}d", ret);
        WIFI_NAPI_ASSERT(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_CORE);
    }

    napi_value result;
    napi_create_int32(env, (int32_t)ret, &result);
    return result;
}

NO_SANITIZE("cfi") napi_value GetScanOnlyAvailable(napi_env env, napi_callback_info info)
{
    bool bScanOnlyAvailableStatus = false;

    ErrCode ret = wifiScanPtr->GetScanOnlyAvailable(bScanOnlyAvailableStatus);
    if (ret != WIFI_OPT_SUCCESS) {
        WIFI_LOGE("Get wifi scanOnlyAvailable fail: %{public}d", ret);
        WIFI_NAPI_ASSERT(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_CORE);
    }

    napi_value result;
    napi_get_boolean(env, bScanOnlyAvailableStatus, &result);
    return result;
}

NO_SANITIZE("cfi") napi_value GetWifiProtect(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);

    size_t argc = 1;
    napi_value argv[1];
    napi_value thisVar;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    WIFI_NAPI_ASSERT(env, argc == 1, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);

    napi_valuetype valueType;
    napi_typeof(env, argv[0], &valueType);
    WIFI_NAPI_ASSERT(env, valueType == napi_number, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);

    int protectMode = 0;
    napi_get_value_int32(env, argv[0], &protectMode);
    WIFI_NAPI_ASSERT(env, protectMode >= (int)WifiProtectMode::WIFI_PROTECT_FULL &&
        protectMode <= (int)WifiProtectMode::WIFI_PROTECT_NO_HELD, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);

    ErrCode ret = wifiDevicePtr->GetWifiProtect(static_cast<WifiProtectMode>(protectMode));
    WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
}

NO_SANITIZE("cfi") napi_value PutWifiProtect(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
    ErrCode ret = wifiDevicePtr->PutWifiProtect();
    WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
}

NO_SANITIZE("cfi") napi_value FactoryReset(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);
    ErrCode ret = wifiDevicePtr->FactoryReset();
    WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
}

NO_SANITIZE("cfi") napi_value EnableHiLinkHandshake(napi_env env, napi_callback_info info)
{
    TRACE_FUNC_CALL;
    size_t argc = 3;
    napi_value argv[argc];
    napi_value thisVar;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, NULL));
    napi_valuetype valueType;
    napi_typeof(env, argv[2], &valueType);
    WIFI_NAPI_ASSERT(env, valueType == napi_object, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);
    WIFI_NAPI_ASSERT(env, wifiDevicePtr != nullptr, WIFI_OPT_FAILED, SYSCAP_WIFI_STA);

    bool uiFlag = false;
    napi_get_value_bool(env, argv[0], &uiFlag);
    std::string bssid;
    char tmp[NAPI_MAX_STR_LENT] = {0};
    size_t result = 0;
    napi_get_value_string_utf8(env, argv[1], tmp, NAPI_MAX_STR_LENT, &result);
    bssid = tmp;
    WifiDeviceConfig deviceConfig;
    napi_value napiRet = JsObjToDeviceConfig(env, argv[2], deviceConfig);
    napi_typeof(env, napiRet, &valueType);
    WIFI_NAPI_ASSERT(env, valueType != napi_undefined, WIFI_OPT_INVALID_PARAM, SYSCAP_WIFI_STA);

    ErrCode ret = wifiDevicePtr->EnableHiLinkHandshake(uiFlag, bssid, deviceConfig);
    WIFI_NAPI_RETURN(env, ret == WIFI_OPT_SUCCESS, ret, SYSCAP_WIFI_STA);
}
}  // namespace Wifi
}  // namespace OHOS
